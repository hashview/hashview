"""Delete/edit routes must not 500 on a stale request.

Double-clicking a delete (or opening an edit for something just deleted in
another tab) used to dereference ``None`` (or hit ``db.session.delete(None)``)
→ HTTP 500. Every delete/edit route now checks existence first and flashes +
redirects instead. These tests hit each route with a non-existent id and assert
a redirect, never a 500; plus a double-delete happy/idempotent path.
"""

import pytest

from hashview.models import Rules, Users, db


def _admin():
    u = Users(first_name="Ad", last_name="Min", email_address="admin@example.com",
              password="x" * 60, admin=True)
    db.session.add(u)
    db.session.commit()
    return u


def _login(client, user):
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True


# (method, url, optional form-data) — every targeted route hit with a bogus id.
DELETE_ROUTES = [
    ("POST", "/jobs/delete/999999", None),
    ("POST", "/rules/delete/999999", None),
    ("POST", "/tasks/delete/999999", None),
    ("POST", "/wordlists/delete/999999", None),
    ("POST", "/task_groups/delete/999999", None),
    ("GET", "/notifications/delete/job/999999", None),
    ("GET", "/notifications/delete/hash/999999", None),
    ("POST", "/agents/delete/999999", None),
    ("POST", "/users/delete/999999", None),
    ("POST", "/hashfiles/delete/999999", None),
    ("POST", "/customers/delete/999999", None),
    ("POST", "/jobs/999999/remove_task/888888", None),
    ("GET", "/task_groups/assigned_tasks/999999/remove_task/888888", None),
]

EDIT_ROUTES = [
    ("POST", "/agents/edit/999999", None),
    ("POST", "/tasks/edit/999999", None),
    ("POST", "/rules/edit/999999", None),
    ("POST", "/users/edit/999999", None),
    ("POST", "/customers/edit", {"customer_id": "999999", "name": "X"}),
    ("POST", "/task_groups/edit", {"group_id": "999999"}),
]


def _hit(client, method, url, data):
    if method == "POST":
        return client.post(url, data=data or {}, follow_redirects=False)
    return client.get(url, follow_redirects=False)


@pytest.mark.parametrize("method,url,data", DELETE_ROUTES)
def test_delete_missing_id_redirects_not_500(app, client, method, url, data):
    _login(client, _admin())
    resp = _hit(client, method, url, data)
    assert resp.status_code != 500, f"{url} 500'd on a missing id"
    assert resp.status_code in (301, 302), f"{url} -> {resp.status_code}"


@pytest.mark.parametrize("method,url,data", EDIT_ROUTES)
def test_edit_missing_id_redirects_not_500(app, client, method, url, data):
    _login(client, _admin())
    resp = _hit(client, method, url, data)
    assert resp.status_code != 500, f"{url} 500'd on a missing id"
    assert resp.status_code in (301, 302), f"{url} -> {resp.status_code}"


def test_double_delete_is_idempotent(app, client):
    """Deleting the same row twice: first succeeds, second flashes (302), no 500."""
    admin = _admin()
    _login(client, admin)
    rule = Rules(name="r1", owner_id=admin.id, path="control/rules/r1.rule",
                 checksum="0" * 64, size=1)
    db.session.add(rule)
    db.session.commit()
    rule_id = rule.id

    first = client.post(f"/rules/delete/{rule_id}", follow_redirects=False)
    assert first.status_code in (301, 302)
    assert Rules.query.get(rule_id) is None              # actually deleted

    second = client.post(f"/rules/delete/{rule_id}", follow_redirects=False)
    assert second.status_code in (301, 302)              # not a 500
    # the flash on the redirected page reports the stale click
    follow = client.post(f"/rules/delete/{rule_id}", follow_redirects=True)
    assert b"already been deleted" in follow.data
