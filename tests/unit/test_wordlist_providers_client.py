"""Unit tests for ``hashview.utils.wordlist_providers`` (the provider HTTP client).

Covers: base-URL scheme validation, per-auth-type request kwargs, the health
probe, and the generate/materialize path — including the crawler-style contract
that any failure leaves the destination file untouched and never raises.
"""
import os
from types import SimpleNamespace
from unittest import mock

import pytest
import requests

from hashview.utils import wordlist_providers as wp


def _provider(**over):
    base = dict(
        id=1,
        name="P",
        base_url="https://api.example.com/hv",
        auth_type="bearer",
        username=None,
        provider_secret="tok",
        verify_tls=True,
        enabled=True,
    )
    base.update(over)
    return SimpleNamespace(**base)


# ---- validate_base_url ----

@pytest.mark.parametrize("url", ["file:///etc/passwd", "gopher://x", "ftp://h/x", "", "notaurl"])
def test_validate_base_url_rejects_non_http(url):
    with pytest.raises(ValueError):
        wp.validate_base_url(url)


def test_validate_base_url_strips_trailing_slash():
    assert wp.validate_base_url("https://h/api/") == "https://h/api"
    assert wp.validate_base_url("http://h") == "http://h"


# ---- build_request_kwargs ----

@pytest.mark.security
def test_build_request_kwargs_bearer(app):
    kwargs = wp.build_request_kwargs(_provider(auth_type="bearer", provider_secret="sekret"))
    assert kwargs["headers"]["Authorization"] == "Bearer sekret"
    assert kwargs["auth"] is None
    assert kwargs["verify"] is True


@pytest.mark.security
def test_build_request_kwargs_basic(app):
    kwargs = wp.build_request_kwargs(
        _provider(auth_type="basic", username="u", provider_secret="p", verify_tls=False))
    assert kwargs["auth"] == ("u", "p")
    assert "Authorization" not in kwargs["headers"]
    assert kwargs["verify"] is False


# ---- test_connection ----

@pytest.mark.security
def test_connection_ok(app):
    resp = mock.Mock(status_code=200)
    resp.json.return_value = {"status": "ok", "name": "Example"}
    with mock.patch.object(wp.requests, "get", return_value=resp) as g:
        ok, msg = wp.test_connection(_provider())
    assert ok is True
    assert "Example" in msg
    # health endpoint derived from base_url
    assert g.call_args[0][0] == "https://api.example.com/hv/health"


@pytest.mark.security
def test_connection_non_200(app):
    resp = mock.Mock(status_code=503)
    with mock.patch.object(wp.requests, "get", return_value=resp):
        ok, msg = wp.test_connection(_provider())
    assert ok is False
    assert "503" in msg


@pytest.mark.security
def test_connection_network_error(app):
    with mock.patch.object(wp.requests, "get",
                           side_effect=requests.exceptions.ConnectTimeout("boom")):
        ok, msg = wp.test_connection(_provider())
    assert ok is False
    assert "failed" in msg.lower()


# ---- generate_wordlist ----

def _post_returning(chunks, status_code=200):
    resp = mock.Mock(status_code=status_code)
    resp.iter_content.return_value = iter(chunks)
    return mock.Mock(return_value=resp)


@pytest.mark.security
def test_generate_wordlist_success_writes_and_replaces(app, tmp_path):
    dest = str(tmp_path / "out.txt")
    open(dest, "w").close()
    with mock.patch.object(wp.requests, "post",
                           _post_returning([b"alpha\n", b"bravo\n"])):
        written = wp.generate_wordlist(_provider(), "example.com", dest)
    assert written == len(b"alpha\nbravo\n")
    assert open(dest).read().splitlines() == ["alpha", "bravo"]


@pytest.mark.security
def test_generate_wordlist_non_200_leaves_file_untouched(app, tmp_path):
    dest = str(tmp_path / "out.txt")
    with open(dest, "w") as fh:
        fh.write("KEEP\n")
    with mock.patch.object(wp.requests, "post", _post_returning([b"x\n"], status_code=500)):
        result = wp.generate_wordlist(_provider(), "in", dest)
    assert result is None
    assert open(dest).read() == "KEEP\n"


@pytest.mark.security
def test_generate_wordlist_exception_leaves_file_untouched(app, tmp_path):
    dest = str(tmp_path / "out.txt")
    with open(dest, "w") as fh:
        fh.write("KEEP\n")
    with mock.patch.object(wp.requests, "post",
                           side_effect=requests.exceptions.ReadTimeout("slow")):
        result = wp.generate_wordlist(_provider(), "in", dest)
    assert result is None
    assert open(dest).read() == "KEEP\n"


@pytest.mark.security
def test_generate_wordlist_disabled_provider_noops(app, tmp_path):
    dest = str(tmp_path / "out.txt")
    with open(dest, "w") as fh:
        fh.write("KEEP\n")
    with mock.patch.object(wp.requests, "post") as post:
        result = wp.generate_wordlist(_provider(enabled=False), "in", dest)
    assert result is None
    post.assert_not_called()
    assert open(dest).read() == "KEEP\n"


@pytest.mark.security
def test_generate_wordlist_over_cap_leaves_file_untouched(app, tmp_path, monkeypatch):
    monkeypatch.setattr(wp, "MAX_WORDLIST_BYTES", 4)
    dest = str(tmp_path / "out.txt")
    with open(dest, "w") as fh:
        fh.write("KEEP\n")
    tmp_dir = os.path.join(app.root_path, "control/tmp")
    before = set(os.listdir(tmp_dir))
    with mock.patch.object(wp.requests, "post",
                           _post_returning([b"aaaa", b"bbbb"])):  # 8 bytes > cap of 4
        result = wp.generate_wordlist(_provider(), "in", dest)
    assert result is None
    assert open(dest).read() == "KEEP\n"
    # the over-cap temp file was cleaned up — no new stray file left behind
    assert set(os.listdir(tmp_dir)) == before
