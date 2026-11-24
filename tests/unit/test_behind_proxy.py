"""The opt-in behind_proxy mode (create_app wires ProxyFix + HTTPS-grade config).

Hashview is meant to run behind a TLS-terminating reverse proxy on localhost
(see install/deploy/ and hashview/utils/tls.py). With `behind_proxy` set,
create_app() must trust exactly one proxy hop's X-Forwarded-* headers -- so the
audit log records the real client IP, request.is_secure is True, and
url_for(_external=...) emits https -- and mark session cookies Secure. With it
off (the default direct-TLS deployment) those same headers must be IGNORED, or a
directly-exposed app would let any client spoof its source IP / scheme / host.

ProxyFix only rewrites the WSGI environ when a request flows through the WSGI
stack, so these assertions go through test_client (NOT test_request_context,
which would bypass the middleware) against a tiny probe route.
"""
from flask import jsonify, request, url_for

# Mirror tests/unit/conftest.py's base overrides (create_app(testing=True) skips
# Config, so SERVER_NAME etc. must come from overrides). SERVER_NAME stays
# localhost.test per the CLAUDE.md cookie-domain gotcha.
_BASE_OVERRIDES = {
    "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
    "SQLALCHEMY_TRACK_MODIFICATIONS": False,
    "SQLALCHEMY_ENGINE_OPTIONS": {"connect_args": {"check_same_thread": False}},
    "WTF_CSRF_ENABLED": False,
    "MAIL_SUPPRESS_SEND": True,
    "SECRET_KEY": "unit-test-secret",
    "SERVER_NAME": "localhost.test",
    "HASHVIEW_SKIP_SETUP": True,
    "HASHVIEW_SKIP_GUI_SETUP": True,
    "HASHVIEW_DISABLE_SCHEDULER": True,
}


def _build_app(behind_proxy):
    from hashview import create_app

    overrides = dict(_BASE_OVERRIDES)
    if behind_proxy:
        overrides["BEHIND_PROXY"] = True
    app = create_app(testing=True, config_overrides=overrides)

    # Probe route: reports what the app sees for a request, after any middleware.
    @app.route("/__proxy_probe__")
    def _proxy_probe():
        return jsonify(
            is_secure=request.is_secure,
            remote_addr=request.remote_addr,
            url_root=request.url_root,
            static_url=url_for("static", filename="x.css", _external=True),
        )

    return app


def test_behind_proxy_trusts_one_forwarded_hop():
    """behind_proxy on: ProxyFix honours X-Forwarded-Proto/Host/For, cookies are
    Secure, and external URLs are https."""
    from werkzeug.middleware.proxy_fix import ProxyFix

    app = _build_app(behind_proxy=True)

    assert isinstance(app.wsgi_app, ProxyFix)
    assert app.config["SESSION_COOKIE_SECURE"] is True
    assert app.config["REMEMBER_COOKIE_SECURE"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert app.config["PREFERRED_URL_SCHEME"] == "https"

    body = app.test_client().get(
        "/__proxy_probe__",
        headers={
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "localhost.test",
            "X-Forwarded-For": "203.0.113.9",
        },
    ).get_json()

    assert body["is_secure"] is True
    assert body["remote_addr"] == "203.0.113.9", "audit log must see the real client, not 127.0.0.1"
    assert body["url_root"].startswith("https://")
    assert body["static_url"].startswith("https://"), "url_for(_external) must emit https behind the proxy"


def test_without_behind_proxy_forwarded_headers_are_ignored():
    """Default (direct-TLS) deployment: no ProxyFix, no Secure-cookie forcing, and
    X-Forwarded-* from a client MUST NOT be trusted (spoofing guard)."""
    from werkzeug.middleware.proxy_fix import ProxyFix

    app = _build_app(behind_proxy=False)

    assert not isinstance(app.wsgi_app, ProxyFix)
    assert not app.config.get("SESSION_COOKIE_SECURE")

    body = app.test_client().get(
        "/__proxy_probe__",
        headers={"X-Forwarded-Proto": "https", "X-Forwarded-For": "203.0.113.9"},
    ).get_json()

    assert body["is_secure"] is False, "a directly-exposed app must not trust X-Forwarded-Proto"
    assert body["remote_addr"] == "127.0.0.1", "a directly-exposed app must not trust X-Forwarded-For"


def test_proxy_guard_refuses_direct_tls():
    """behind_proxy with the public direct-TLS server would trust spoofable
    headers from every client, so the CLI must refuse to start."""
    import pytest

    from hashview.utils.tls import check_proxy_deployment

    with pytest.raises(ValueError, match="requires --no-ssl"):
        check_proxy_deployment(True, no_ssl=False, host="127.0.0.1")


def test_proxy_guard_warns_on_non_loopback_bind():
    from hashview.utils.tls import check_proxy_deployment

    for host in ("0.0.0.0", "10.0.0.5", "::", "proxy-net.internal"):
        warning = check_proxy_deployment(True, no_ssl=True, host=host)
        assert warning and host in warning, host


def test_proxy_guard_quiet_for_loopback_and_when_off():
    from hashview.utils.tls import check_proxy_deployment

    for host in ("127.0.0.1", "127.0.0.2", "::1", "localhost"):
        assert check_proxy_deployment(True, no_ssl=True, host=host) is None, host
    # Off: the default deployment is never blocked, whatever the run mode.
    assert check_proxy_deployment(False, no_ssl=False, host="0.0.0.0") is None
    assert check_proxy_deployment(None, no_ssl=True, host="0.0.0.0") is None
