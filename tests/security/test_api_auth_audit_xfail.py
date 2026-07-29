"""Regression tests for issue #370 — API-key authentication is never audited.

FINDING (MEDIUM): UI logins write ``user.login`` / ``user.login_failed`` audit
events (``hashview/users/routes.py``, ``hashview/auth/routes.py``), but the
``/v1`` API's auth gate — ``is_authorized()`` / ``userAuthorized()`` in
``hashview/api/routes.py`` — never calls ``log_event``. Consequences:

  - A user API key exercised only through read-only endpoints leaves ZERO
    trace in audit.log (no way to reconstruct API activity or spot key
    compromise from the Logs menu).
  - A rejected (wrong / brute-forced) API key is equally invisible, while the
    same guessing against the UI login form is logged per attempt.

Mutating /v1 routes do log their CRUD events, so this is specifically an
authentication/access-event gap, not a broken logger.

These are STRICT XFAILs (same pattern as tests/security/test_csrf_xfail.py
for #298): each test asserts the audit event IS written. Because it is not,
the assertion fails and the strict xfail flags the real, open finding. When
API auth events are implemented, the tests flip to visible FAILURES and the
``@pytest.mark.xfail`` markers should be removed. Tracks GitHub issue #370.

Expected event names (adjust the tests if the implementation picks others):
  - success: ``user.api_auth``
  - failure: ``user.api_auth_failed`` (outcome='failure')
"""

import json
import os

import pytest

from hashview import create_app
from hashview.models import Users
from hashview.models import db as _db
from hashview.utils.audit import AUDIT_FILE, configure_audit_logging, logs_dir

_BASE_OVERRIDES = {
    "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
    "SQLALCHEMY_TRACK_MODIFICATIONS": False,
    "MAIL_SUPPRESS_SEND": True,
    "SECRET_KEY": "security-test-secret",
    "SERVER_NAME": "localhost.test",
    "HASHVIEW_SKIP_SETUP": True,
    "HASHVIEW_SKIP_GUI_SETUP": True,
    "HASHVIEW_DISABLE_SCHEDULER": True,
    "WTF_CSRF_ENABLED": False,
}


@pytest.fixture()
def audit_app(tmp_path):
    """Dedicated in-memory app with the audit logger pointed into tmp_path."""
    overrides = dict(_BASE_OVERRIDES)
    overrides["HASHVIEW_LOGS_DIR"] = str(tmp_path / "logs")
    application = create_app(testing=True, config_overrides=overrides)
    with application.app_context():
        _db.create_all()
        configure_audit_logging(application)  # idempotent; re-point handlers
        yield application
        _db.session.remove()
        _db.drop_all()


@pytest.fixture()
def client(audit_app):
    return audit_app.test_client()


def _api_user(api_key="api-audit-key"):
    user = Users(
        first_name="Api",
        last_name="Auditee",
        email_address="api-auditee@example.test",
        password="x" * 60,
        admin=True,
        api_key=api_key,
    )
    _db.session.add(user)
    _db.session.commit()
    return user


def _audit_entries(app):
    path = os.path.join(logs_dir(app), AUDIT_FILE)
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


@pytest.mark.security
@pytest.mark.xfail(
    strict=True,
    reason=(
        "FINDING #370 (MEDIUM): a rejected API key never produces an audit "
        "event — userAuthorized()/is_authorized() in hashview/api/routes.py "
        "do not call log_event, so brute-forcing keys against /v1 is "
        "invisible in the Logs menu (unlike UI password guessing, which "
        "writes user.login_failed per attempt). Flips to a failure once "
        "user.api_auth_failed is emitted."
    ),
)
def test_rejected_api_key_writes_failure_audit_event(client, audit_app):
    """A wrong uuid cookie against a user API route must be audited."""
    _api_user(api_key="the-real-key")
    client.set_cookie("uuid", "not-the-real-key", domain="localhost.test")

    resp = client.get("/v1/customers")
    # The rejection itself works (redirect to /v1/not_authorized); only the
    # audit trail is missing.
    assert resp.status_code in (200, 302)

    failures = [
        e
        for e in _audit_entries(audit_app)
        if e["event"] == "user.api_auth_failed" and e["outcome"] == "failure"
    ]
    assert failures, (
        "No 'user.api_auth_failed' audit event was written for a rejected "
        "API key — failed /v1 authentication is invisible in the Logs menu"
    )


@pytest.mark.security
@pytest.mark.xfail(
    strict=True,
    reason=(
        "FINDING #370 (MEDIUM): a successful user API-key authentication "
        "never produces an audit event, so read-only API activity leaves "
        "zero trace in the Logs menu while an equivalent UI session writes "
        "user.login. Flips to a failure once user.api_auth is emitted."
    ),
)
def test_accepted_api_key_writes_auth_audit_event(client, audit_app):
    """A valid user API key on a read-only route must leave an audit trace."""
    user = _api_user(api_key="valid-audit-key")
    client.set_cookie("uuid", "valid-audit-key", domain="localhost.test")

    resp = client.get("/v1/customers")
    body = json.loads(resp.get_data(as_text=True))
    assert body["status"] == 200

    events = [
        e for e in _audit_entries(audit_app) if e["event"] == "user.api_auth"
    ]
    assert events and events[-1]["actor"] == user.email_address, (
        "No 'user.api_auth' audit event was written for a successful API-key "
        "GET — read-only API usage is invisible in the Logs menu"
    )
