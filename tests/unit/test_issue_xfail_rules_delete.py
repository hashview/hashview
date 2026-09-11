"""Regression guards for issue #397 — DELETE /v1/rules/<id>.

These started life as ``xfail(strict=False)`` documentation for the missing
endpoint: the v1 API could create rules (``POST /v1/rules/add/<name>``) but
never delete one, so a duplicate or unwanted upload could not be removed by an
API-only client. The endpoint now exists and mirrors the web UI's
``rules_delete``, so all four assertions pass and the markers are dropped —
which is what the original spec said XPASS should trigger.

They are kept as the issue's acceptance record. The endpoint's fuller coverage
(authorization matrix, the task guard including inline j/k rules, duplicate
rows, auditing, and the file-on-disk behaviour) lives in
tests/unit/test_api_delete_rule.py.

Auth/cookie model mirrors tests/unit/test_api_issues_xfail.py: the ``uuid``
cookie is matched against ``Users.api_key``.
"""

import json

import pytest

from hashview.models import Rules, Tasks, Users
from hashview.models import db as _db


@pytest.fixture()
def admin_user(app):
    user = Users(
        first_name="Admin",
        last_name="User",
        email_address="admin@example.test",
        password="hashed-pw",
        admin=True,
        api_key="user-api-key-admin",
    )
    _db.session.add(user)
    _db.session.commit()
    return user


@pytest.fixture()
def other_user(app):
    user = Users(
        first_name="Other",
        last_name="User",
        email_address="other@example.test",
        password="hashed-pw",
        admin=False,
        api_key="user-api-key-other",
    )
    _db.session.add(user)
    _db.session.commit()
    return user


def _auth(client, value):
    client.set_cookie("uuid", value, domain="localhost.test")


def _json_body(resp):
    return json.loads(resp.get_data(as_text=True))


def _rule(owner, name="corp.rule", path="/tmp/does-not-matter.rule"):
    rule = Rules(name=name, owner_id=owner.id, path=path, size=1, checksum="x")
    _db.session.add(rule)
    _db.session.commit()
    return rule


def test_owner_can_delete_their_rule(app, client, admin_user):
    rule = _rule(admin_user)
    rule_id = rule.id
    _auth(client, admin_user.api_key)

    resp = client.delete(f"/v1/rules/{rule_id}")
    body = _json_body(resp)

    assert resp.status_code == 200
    assert body.get("status") == 200
    assert Rules.query.get(rule_id) is None


def test_delete_unowned_rule_is_forbidden(app, client, admin_user, other_user):
    rule = _rule(admin_user)
    rule_id = rule.id
    _auth(client, other_user.api_key)

    resp = client.delete(f"/v1/rules/{rule_id}")

    assert resp.status_code == 403
    assert Rules.query.get(rule_id) is not None


def test_delete_rule_used_by_task_is_refused(app, client, admin_user):
    rule = _rule(admin_user)
    rule_id = rule.id
    task = Tasks(name="uses-rule", hc_attackmode=0, owner_id=admin_user.id, rule_id=rule_id)
    _db.session.add(task)
    _db.session.commit()
    _auth(client, admin_user.api_key)

    resp = client.delete(f"/v1/rules/{rule_id}")

    assert resp.status_code in (400, 409)
    assert Rules.query.get(rule_id) is not None


def test_delete_missing_rule_is_404(app, client, admin_user):
    _auth(client, admin_user.api_key)

    resp = client.delete("/v1/rules/999999")

    assert resp.status_code == 404
