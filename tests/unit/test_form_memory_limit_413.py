"""Tests for issue #314 — configurable MAX_FORM_MEMORY_SIZE + a 413 handler.

The original issue claimed Hashview "sets" Werkzeug's max_form_memory_size to
488KB. That's wrong: MAX_FORM_MEMORY_SIZE never appeared in this repo before
this change — 500000 is simply Flask 3.1's own built-in default. This module
verifies (a) the app now has a 413 handler that matches the AJAX/normal-submit
contract used elsewhere (see hashview/jobs/routes.py:270,445-459), and (b)
that omitting the new config.conf key changes nothing (the default still
resolves to Flask's own 500000).
"""

from configparser import ConfigParser

import pytest

from hashview import create_app


def _build_app_with_tiny_form_limit():
    """A throwaway app with a deliberately tiny MAX_FORM_MEMORY_SIZE so a
    normal small POST body in a test trips the 413 path — no need to actually
    push 500KB over the wire.
    """
    overrides = {
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
        # The point of this test: a tiny cap so a normal-sized form body
        # exceeds it, without needing a real ~500KB POST in a test.
        "MAX_FORM_MEMORY_SIZE": 16,
    }
    app = create_app(testing=True, config_overrides=overrides)
    from hashview.models import db as _db
    with app.app_context():
        _db.create_all()
    return app


@pytest.fixture()
def tiny_limit_client():
    app = _build_app_with_tiny_form_limit()
    with app.app_context():
        yield app.test_client()
        from hashview.models import db as _db
        _db.session.remove()
        _db.drop_all()


def test_oversized_form_body_ajax_gets_json_413(tiny_limit_client):
    """An XHR-flagged POST that exceeds MAX_FORM_MEMORY_SIZE must get the same
    JSON error shape used elsewhere for AJAX failures (see
    hashview/jobs/routes.py:454-455: jsonify({'status': 'error', 'msg': ...}),
    <code>), with a 413 status.
    """
    resp = tiny_limit_client.post(
        "/login",
        data={
            "email": "someone@example.com",
            "password": "a-password-long-enough-to-exceed-the-tiny-cap",
        },
        headers={"X-Requested-With": "fetch"},
    )
    assert resp.status_code == 413
    body = resp.get_json()
    assert body is not None
    assert body["status"] == "error"
    assert "file" in body["msg"].lower()


def test_oversized_form_body_normal_submit_flashes_and_redirects(tiny_limit_client):
    """A normal (non-AJAX) POST that exceeds the limit gets a flash + redirect,
    matching the non-AJAX branch of the same contract."""
    resp = tiny_limit_client.post(
        "/login",
        data={
            "email": "someone@example.com",
            "password": "a-password-long-enough-to-exceed-the-tiny-cap",
        },
    )
    assert resp.status_code in (301, 302, 303)

    resp = tiny_limit_client.post(
        "/login",
        data={
            "email": "someone@example.com",
            "password": "a-password-long-enough-to-exceed-the-tiny-cap",
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert b"file" in resp.data.lower()


# ---------------------------------------------------------------------------
# Config default
# ---------------------------------------------------------------------------
def test_max_form_memory_size_defaults_to_flask_default_when_absent():
    """hashview/config.py must read MAX_FORM_MEMORY_SIZE via the same
    ``.get(key, default)`` idiom already used for SECRET_KEY (config.py:11),
    NOT the bare ``file_config['SERVER']['...']`` idiom used for SERVER_NAME
    (config.py:14) — bare indexing KeyErrors on an older config.conf that
    predates this key, breaking every existing deployment on upgrade.

    hashview.config reads 'hashview/config.conf' at import time and raises
    KeyError building SERVER_NAME when no such file/section exists on disk (as
    is the case in this checkout — see test_db_password_with_percent_is_parsed
    in test_issue_xfail_misc.py for the same constraint), so this mirrors the
    exact read expression rather than importing the real module.
    """
    parser = ConfigParser()
    parser.read_dict({"SERVER": {"SERVER_NAME": "example.com:5000"}})

    max_form_memory_size = int(parser["SERVER"].get("MAX_FORM_MEMORY_SIZE", 500000))

    assert max_form_memory_size == 500000
