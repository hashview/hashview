"""xfail spec for issue #383 — catalog rows survive when their file is gone.

When a Rules/Wordlists row's file disappears from disk but the row survives,
nothing on the server notices: the row stays listed, agents retry the
download forever, and a task can still reference a file that can never be
fetched. The issue's primary suggested fix ("Surface it") is a ``missing``
flag on the catalog listing so a stale row is visible and excludable from
task pickers, rather than only failing at download time.

These tests assert that desired behavior and are marked
``xfail(strict=False)`` so the suite stays green whether it's still missing
(XFAIL) or has since been implemented (XPASS) — that XPASS is the signal to
drop the marker. The issue explicitly says the same reasoning applies to
wordlists as to rules, so both are covered here.
"""

import pytest

from hashview.models import Rules, Users, Wordlists
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


def _auth(client, value):
    client.set_cookie("uuid", value, domain="localhost.test")


@pytest.mark.xfail(strict=False, reason="issue #383: no missing-file flag on GET /v1/rules yet")
def test_rule_with_missing_file_is_flagged_in_listing(app, client, admin_user, tmp_path):
    rule = Rules(
        name="gone.rule",
        owner_id=admin_user.id,
        path=str(tmp_path / "gone.rule"),
        size=1,
        checksum="x",
    )
    _db.session.add(rule)
    _db.session.commit()
    _auth(client, admin_user.api_key)

    resp = client.get("/v1/rules")
    body = resp.get_json()

    matches = [r for r in body["rules"] if r["id"] == rule.id]
    assert len(matches) == 1
    assert matches[0].get("missing") is True


@pytest.mark.xfail(strict=False, reason="issue #383: no missing-file flag on GET /v1/wordlists yet")
def test_wordlist_with_missing_file_is_flagged_in_listing(app, client, admin_user, tmp_path):
    wl = Wordlists(
        name="gone.txt",
        owner_id=admin_user.id,
        type="static",
        path=str(tmp_path / "gone.txt"),
        size=1,
        byte_size=1,
        checksum="x",
    )
    _db.session.add(wl)
    _db.session.commit()
    _auth(client, admin_user.api_key)

    resp = client.get("/v1/wordlists")
    body = resp.get_json()

    matches = [w for w in body["wordlists"] if w["id"] == wl.id]
    assert len(matches) == 1
    assert matches[0].get("missing") is True
