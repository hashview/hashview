"""Issue #383 — catalog rows survive when their file is gone.

When a Rules/Wordlists row's file disappears from disk but the row survives,
nothing on the server used to notice: the row stayed listed, agents retried
the download forever, and a task could still reference a file that can never
be fetched. The issue's primary fix ("Surface it") is a ``missing`` flag on
the catalog listings so a stale row is visible and excludable from task
pickers, rather than only failing at download time.

These tests were the ``xfail(strict=False)`` spec for that behavior. It is
now implemented (utils.missing_rule_ids / missing_wordlist_ids, grafted onto
the /v1 list payloads), so the markers are gone and these are live regression
tests. The issue explicitly says the same reasoning applies to wordlists as
to rules, so both are covered here.
"""

import pytest

from hashview.models import Rules, Users, Wordlists
from hashview.models import db as _db
from tests.unit.helpers import make_rule_with_file, make_wordlist_with_file


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


def test_present_rule_is_flagged_missing_false(app, client, admin_user):
    """The key is always emitted, so an absent key means "server predates the
    flag" rather than "this row is fine"."""
    rule = make_rule_with_file(admin_user.id, name="present.rule")
    _auth(client, admin_user.api_key)

    body = client.get("/v1/rules").get_json()
    assert [r for r in body["rules"] if r["id"] == rule.id][0]["missing"] is False


def test_present_wordlist_is_flagged_missing_false(app, client, admin_user):
    wl = make_wordlist_with_file(admin_user.id, name="present.txt")
    _auth(client, admin_user.api_key)

    body = client.get("/v1/wordlists").get_json()
    assert [w for w in body["wordlists"] if w["id"] == wl.id][0]["missing"] is False


def test_dynamic_wordlist_is_never_flagged_missing(app, client, admin_user, tmp_path):
    """A dynamic list's file is regenerated per download, so its absence is not
    a fault -- flagging it would false-alarm on every install."""
    wl = Wordlists(
        name="(DYNAMIC) All Recovered Passwords",
        owner_id=admin_user.id,
        type="dynamic",
        path=str(tmp_path / "never-created.txt"),
        size=0,
        byte_size=0,
        checksum="x",
    )
    _db.session.add(wl)
    _db.session.commit()
    _auth(client, admin_user.api_key)

    body = client.get("/v1/wordlists").get_json()
    assert [w for w in body["wordlists"] if w["id"] == wl.id][0]["missing"] is False
