"""Mail must not be able to block a request thread forever.

Flask-Mail 0.10 builds its connection as ``smtplib.SMTP(server, port)`` with no
``timeout=``, so the socket inherits Python's "block indefinitely" default on
connect and on every command read. Hashview sends mail synchronously from
request handlers -- stopping a job notifies its owner, a crack upload can fire
job-completion mail -- and runs under werkzeug's threaded server, so a relay
that accepts a connection and then goes quiet parks that worker thread for good.

These tests assert on the timeout actually reaching smtplib, not on the config
value existing: MAIL_TIMEOUT that never reaches the socket would look identical
from the outside, and is precisely the failure being guarded against.
"""

import smtplib

import pytest

from hashview.utils.mail import (
    DEFAULT_MAIL_TIMEOUT,
    TimeoutConnection,
    TimeoutMail,
)

pytestmark = pytest.mark.security


class _FakeSMTP:
    """Records how smtplib was called, without opening a socket."""

    instances = []

    def __init__(self, host, port, timeout=None, **kwargs):
        self.host, self.port, self.timeout = host, port, timeout
        self.debuglevel = 0
        self.started_tls = False
        self.logged_in_as = None
        _FakeSMTP.instances.append(self)

    def set_debuglevel(self, level):
        self.debuglevel = level

    def starttls(self, *a, **kw):
        self.started_tls = True

    def login(self, user, password):
        self.logged_in_as = user

    def quit(self):
        pass


@pytest.fixture(autouse=True)
def _reset():
    _FakeSMTP.instances = []


def _mail_state(app, **overrides):
    app.config.update(overrides)
    mail = TimeoutMail()
    return mail.init_app(app)


def test_the_timeout_reaches_smtplib(app, monkeypatch):
    """The whole point: a real socket deadline, not just a config key."""
    monkeypatch.setattr(smtplib, 'SMTP', _FakeSMTP)
    state = _mail_state(app, MAIL_TIMEOUT=7, MAIL_USE_SSL=False,
                        MAIL_SUPPRESS_SEND=False)
    TimeoutConnection(state).configure_host()

    assert _FakeSMTP.instances, 'no SMTP connection was attempted'
    assert _FakeSMTP.instances[-1].timeout == 7, (
        'MAIL_TIMEOUT never reached the socket, so a dead relay still blocks '
        'forever -- which is the whole failure this guards against')


def test_the_ssl_path_is_bounded_too(app, monkeypatch):
    """SMTP_SSL is a separate constructor and an easy one to leave unbounded."""
    monkeypatch.setattr(smtplib, 'SMTP_SSL', _FakeSMTP)
    state = _mail_state(app, MAIL_TIMEOUT=5, MAIL_USE_SSL=True,
                        MAIL_SUPPRESS_SEND=False)
    TimeoutConnection(state).configure_host()

    assert _FakeSMTP.instances[-1].timeout == 5


def test_an_unset_timeout_still_has_a_deadline(app, monkeypatch):
    """A config.conf predating the key must not fall back to blocking forever."""
    monkeypatch.setattr(smtplib, 'SMTP', _FakeSMTP)
    app.config.pop('MAIL_TIMEOUT', None)
    state = _mail_state(app, MAIL_USE_SSL=False, MAIL_SUPPRESS_SEND=False)
    TimeoutConnection(state).configure_host()

    assert _FakeSMTP.instances[-1].timeout == DEFAULT_MAIL_TIMEOUT
    assert _FakeSMTP.instances[-1].timeout, 'a falsy timeout means block forever'


def test_starttls_and_login_still_happen(app, monkeypatch):
    """configure_host is overridden wholesale, so its other duties are re-tested."""
    monkeypatch.setattr(smtplib, 'SMTP', _FakeSMTP)
    state = _mail_state(app, MAIL_TIMEOUT=9, MAIL_USE_SSL=False,
                        MAIL_USE_TLS=True, MAIL_USERNAME='u', MAIL_PASSWORD='p',
                        MAIL_SUPPRESS_SEND=False)
    TimeoutConnection(state).configure_host()

    host = _FakeSMTP.instances[-1]
    assert host.started_tls, 'STARTTLS was dropped by the override'
    assert host.logged_in_as == 'u', 'authentication was dropped by the override'


def test_the_app_uses_the_timeout_aware_mail(app):
    """Wiring check: the extension the app actually installed must be ours.

    Subclassing is worthless if create_app still registers flask_mail.Mail.
    """
    assert isinstance(app.extensions['mail'].timeout, int), (
        'the installed mail extension carries no timeout; create_app is '
        'probably still using flask_mail.Mail'
    )
    assert app.extensions['mail'].timeout > 0


def test_sending_goes_through_the_bounded_connection(app, monkeypatch):
    """Mail.send must use TimeoutConnection, not flask_mail's Connection."""
    from flask_mail import Message

    monkeypatch.setattr(smtplib, 'SMTP', _FakeSMTP)
    with app.app_context():
        app.extensions['mail'].suppress = False
        app.extensions['mail'].default_sender = 'hashview@example.test'
        msg = Message('subject', recipients=['someone@example.test'], body='b')
        try:
            app.extensions['mail'].send(msg)
        except Exception:
            pass        # _FakeSMTP cannot actually deliver; the call is the point

    assert _FakeSMTP.instances, 'the send path did not build an SMTP connection'
    assert _FakeSMTP.instances[-1].timeout, (
        'the send path built an SMTP connection with no timeout')
