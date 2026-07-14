"""Regression test for issue #298 — missing CSRF protection on form-reading routes.

FINDING (MEDIUM): No global ``CSRFProtect`` is installed (``hashview/__init__.py`` only
registers a ``csrf_token()`` template global). State-changing routes that read
``request.form`` directly instead of going through ``form.validate_on_submit()`` are NOT
CSRF-protected, e.g.:
  - ``hashview/customers/routes.py``  /customers/edit   (reads request.form)
  - ``hashview/customers/routes.py``  /customers/delete (reads request.form)
  - ``hashview/hashfiles/routes.py``  /hashfiles/delete (no token check)
  - ``hashview/agents/routes.py``     GET state-changers (authorize/deauthorize/delete)

This is a STRICT XFAIL using ``/customers/edit`` as the exemplar: the test asserts the
route IS protected (a token-less edit is rejected and the name is unchanged). Because the
route is actually unprotected, the rename goes through, the assertion fails, and the strict
xfail flags the real, open finding. When a global CSRF gate is added, the token-less edit
will be rejected, the assertion will pass, the strict xfail flips to a visible FAILURE, and
the ``@pytest.mark.xfail`` marker here should be removed. Tracks GitHub issue #298.
"""

import pytest

from hashview import create_app
from hashview.models import Customers, Users, db


_BASE_OVERRIDES = {
    "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
    "SQLALCHEMY_TRACK_MODIFICATIONS": False,
    "MAIL_SUPPRESS_SEND": True,
    "SECRET_KEY": "security-test-secret",
    "SERVER_NAME": "localhost.test",
    "HASHVIEW_SKIP_SETUP": True,
    "HASHVIEW_SKIP_GUI_SETUP": True,
    "HASHVIEW_DISABLE_SCHEDULER": True,
    # CSRF ENABLED — the shared unit app disables it; this finding only exists
    # with CSRF turned on, which is the production default.
    "WTF_CSRF_ENABLED": True,
}


@pytest.fixture()
def csrf_app():
    """A dedicated app with CSRF ENABLED (the shared unit app disables it)."""
    application = create_app(testing=True, config_overrides=dict(_BASE_OVERRIDES))
    with application.app_context():
        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()


def _seed_user(email="u@example.com", admin=False):
    u = Users(
        first_name="T",
        last_name="U",
        email_address=email,
        password="x" * 60,
        admin=admin,
    )
    db.session.add(u)
    db.session.commit()
    return u


def _login(client, user):
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True


@pytest.mark.security
@pytest.mark.xfail(
    strict=True,
    reason=(
        "FINDING #298 (MEDIUM): /customers/edit reads request.form directly and "
        "there is no global CSRFProtect, so a token-less cross-site POST mutates "
        "state. This strict-xfail PROVES the gap: the edit succeeds with no token. "
        "It will flip to a failure (alerting the maintainer) once the route is "
        "CSRF-protected."
    ),
)
def test_csrf_unprotected_edit_route_is_a_finding(csrf_app):
    """Document that /customers/edit is NOT CSRF protected.

    We assert the route IS protected (rename rejected without a token). Because it
    is actually unprotected, the rename goes through and this assertion fails ->
    strict xfail flags the real, open finding.
    """
    app = csrf_app
    user = _seed_user()
    cust = Customers(name="OrigName")
    db.session.add(cust)
    db.session.commit()
    cust_id = cust.id

    client = app.test_client()
    _login(client, user)

    client.post(
        "/customers/edit",
        data={"customer_id": cust_id, "name": "HijackedName"},
    )
    db.session.expire_all()
    renamed = Customers.query.get(cust_id).name
    # If the route were CSRF protected, the token-less edit would be rejected and
    # the name would still be 'OrigName'. Asserting that here makes the test FAIL
    # under the current (unprotected) code -> strict xfail = documented finding.
    assert renamed == "OrigName", (
        "CSRF-unprotected: /customers/edit mutated state without a token "
        f"(name is now {renamed!r})"
    )
