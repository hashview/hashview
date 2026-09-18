"""Every request the agent makes must have a deadline.

requests blocks forever by default -- on connect AND on every read -- and the
agent set no timeout while mounting Retry(total=100). An agent whose server has
gone away therefore never gives up and never moves on, and each attempt leaves a
half-open connection behind on the server, which is the very thing that can
stall its TLS accept loop.

The read timeout is the gap BETWEEN bytes, not a deadline for the whole
response, so it must not be mistaken for a cap on download size: agents pull
multi-gigabyte wordlists through this same get().
"""

import builtins

import agent.http.http as agent_http
import pytest


class _Recorder:
    """Stands in for requests.Session, capturing how it was called."""

    def __init__(self, status=200, content=b'ok', text='ok'):
        self.calls = []
        self._status, self._content, self._text = status, content, text

    def _respond(self, **kwargs):
        self.calls.append(kwargs)

        class _Response:
            status_code = self._status
            content = self._content
            text = self._text
        return _Response()

    def get(self, path, **kwargs):
        return self._respond(**kwargs)

    def post(self, path, **kwargs):
        return self._respond(**kwargs)


@pytest.fixture()
def recorder(monkeypatch, tmp_path):
    # get()/post() read VERSION.TXT relative to the CWD and consult
    # builtins.state for debug logging (see test_agent_robustness.py).
    version = tmp_path / 'VERSION.TXT'
    version.write_text('0.8.3\n')
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(builtins, 'state', 'normal', raising=False)
    rec = _Recorder()
    monkeypatch.setattr(agent_http, 'http', rec)
    return rec


def test_get_sends_a_timeout(recorder):
    agent_http.get('/v1/wordlists')
    assert recorder.calls, 'no request was made'
    timeout = recorder.calls[-1].get('timeout')
    assert timeout is not None, (
        'GET has no timeout, so the agent waits on a dead server forever')
    connect, read = timeout
    assert connect > 0 and read > 0


def test_post_sends_a_timeout(recorder):
    agent_http.post('/v1/agents/heartbeat', {'hello': 'world'})
    timeout = recorder.calls[-1].get('timeout')
    assert timeout is not None, (
        'POST has no timeout; the heartbeat is the call that must never hang')
    connect, read = timeout
    assert connect > 0 and read > 0


def test_the_read_budget_is_generous_enough_for_a_slow_download():
    """A read timeout is the gap between bytes, but time-to-first-byte counts.

    The server may spend a while generating a dynamic wordlist before anything
    moves, so a tight read budget would abort exactly the request this matters
    most for.
    """
    _connect, read = agent_http._timeout()
    assert read >= 60, (
        f'a {read}s read budget will abort a dynamic wordlist download while '
        'the server is still generating it')


def test_a_missing_or_junk_config_value_falls_back_to_a_real_deadline():
    """An old config.conf has no timeout keys; it must not mean 'wait forever'."""
    for value in (None, '', 'not-a-number', '0', '-5'):
        assert agent_http._seconds(value, 42) == 42, (
            f'{value!r} produced something other than the default; a falsy or '
            'nonsensical timeout must never become "block forever"')
    assert agent_http._seconds('7', 42) == 7
    assert agent_http._seconds(7.5, 42) == 7.5


def test_a_timeout_is_handled_like_any_other_transport_failure(recorder,
                                                               monkeypatch):
    """Callers expect body-or-None; a timeout must not raise through them."""
    import requests

    def _timeout(*args, **kwargs):
        raise requests.exceptions.ConnectTimeout('took too long')

    monkeypatch.setattr(recorder, 'get', _timeout)
    monkeypatch.setattr(recorder, 'post', _timeout)

    assert agent_http.get('/v1/wordlists') is None
    assert agent_http.post('/v1/agents/heartbeat', {}) is None
