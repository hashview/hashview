"""Unit tests for POST /v1/search (PR #250 / issues #213, #236).

The search endpoint accepts exactly one of ``hash`` / ``plaintext`` /
``username`` (checked in that order) and always answers HTTP 200 with a JSON
``msg`` that is:

- an object, for a ``hash`` match (back-compatible shape);
- a list, for ``plaintext`` / ``username`` matches;
- the string "Search complete. No Results Found." when nothing matched; or
- "Invalid Search" (body ``status`` 500) for an empty/invalid body, or one
  carrying none of the three recognised keys.

These exercise the route via the in-memory SQLite app + Flask test_client
fixtures from ``tests/unit/conftest.py``. All tests are marked
``@pytest.mark.security`` so the parent (tests/) autouse fixtures that need
Playwright + a live HTTP server are skipped.

Auth model recap (see ``is_authorized``): the route is user-only
(``is_authorized(user=True, agent=False, ...)``), so the 'uuid' cookie must
match a ``Users.api_key``; an agent uuid, or no cookie, is refused with a
redirect to ``/v1/not_authorized``.
"""

import json

import pytest

from hashview.models import Agents, Hashes, HashfileHashes, Users
from hashview.models import db as _db

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


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
def authorized_agent(app):
    agent = Agents(
        name="agent-1",
        src_ip="127.0.0.1",
        uuid="agent-uuid-ok",
        status="Authorized",
    )
    _db.session.add(agent)
    _db.session.commit()
    return agent


def _json_body(resp):
    return json.loads(resp.get_data(as_text=True))


def _auth(client, user):
    client.set_cookie("uuid", user.api_key, domain="localhost.test")


def _search(client, payload=None, *, raw=None, content_type="application/json"):
    """POST to /v1/search. Pass a dict via ``payload`` or a raw string via ``raw``."""
    data = raw if raw is not None else json.dumps(payload)
    return client.post("/v1/search", data=data, content_type=content_type)


def _seed_hash(ciphertext, hash_type, cracked, plaintext=None):
    h = Hashes(
        sub_ciphertext="0" * 32,
        ciphertext=ciphertext,
        hash_type=hash_type,
        cracked=cracked,
        plaintext=plaintext,
    )
    _db.session.add(h)
    _db.session.commit()
    return h


def _link_username(hash_id, username, hashfile_id=1):
    _db.session.add(
        HashfileHashes(hash_id=hash_id, username=username, hashfile_id=hashfile_id)
    )
    _db.session.commit()


# ---------------------------------------------------------------------------
# Authorization
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_search_no_cookie_redirects_to_not_authorized(client):
    """No 'uuid' cookie is refused with a redirect to /v1/not_authorized."""
    resp = _search(client, {"hash": "deadbeef"})
    assert 300 <= resp.status_code < 400
    assert "not_authorized" in resp.headers.get("Location", "")


@pytest.mark.security
def test_search_rejects_agent_cookie(client, authorized_agent):
    """The route is user-only: a valid agent uuid must still be refused."""
    client.set_cookie("uuid", authorized_agent.uuid, domain="localhost.test")
    resp = _search(client, {"hash": "deadbeef"})
    assert 300 <= resp.status_code < 400
    assert "not_authorized" in resp.headers.get("Location", "")


# ---------------------------------------------------------------------------
# Invalid / empty bodies (issues #213, #236)
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_search_empty_body_returns_invalid_search(client, admin_user):
    """An empty body answers HTTP 200 with body status 500 'Invalid Search'."""
    _auth(client, admin_user)
    resp = _search(client, raw="")
    assert resp.status_code == 200
    body = _json_body(resp)
    assert body["status"] == 500
    assert body["msg"] == "Invalid Search"


@pytest.mark.security
def test_search_malformed_json_returns_invalid_search(client, admin_user):
    """Malformed JSON returns the JSON 'Invalid Search' answer, not Flask's
    HTML 400 page (issue #213: get_json(silent=True))."""
    _auth(client, admin_user)
    resp = _search(client, raw="{not valid json")
    assert resp.status_code == 200
    body = _json_body(resp)
    assert body["status"] == 500
    assert body["msg"] == "Invalid Search"


@pytest.mark.security
def test_search_body_without_known_keys_returns_invalid_search(client, admin_user):
    """A well-formed body carrying none of hash/plaintext/username is invalid
    (issue #236: must not KeyError -> HTML 500)."""
    _auth(client, admin_user)
    resp = _search(client, {"something": "else"})
    assert resp.status_code == 200
    body = _json_body(resp)
    assert body["status"] == 500
    assert body["msg"] == "Invalid Search"


# ---------------------------------------------------------------------------
# Search by hash
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_search_by_hash_returns_single_object(client, admin_user):
    """A cracked hash matched by exact ciphertext returns a single object
    (the back-compatible shape: hash_type / hash / plaintext)."""
    _seed_hash("8846F7EAEE8FB117AD06BDD830B7586C", 1000, True, "password")
    _auth(client, admin_user)

    resp = _search(client, {"hash": "8846F7EAEE8FB117AD06BDD830B7586C"})
    body = _json_body(resp)
    assert body["status"] == 200
    assert body["msg"] == {
        "hash_type": 1000,
        "hash": "8846F7EAEE8FB117AD06BDD830B7586C",
        "plaintext": "password",
    }


@pytest.mark.security
def test_search_by_hash_not_found_returns_message(client, admin_user):
    """An unknown ciphertext returns the not-found string."""
    _auth(client, admin_user)
    resp = _search(client, {"hash": "nope"})
    body = _json_body(resp)
    assert body["status"] == 200
    assert body["msg"] == "Search complete. No Results Found."


@pytest.mark.security
def test_search_by_hash_ignores_uncracked_match(client, admin_user):
    """A matching ciphertext that is NOT cracked is not a result."""
    _seed_hash("cafebabe", 1000, False)
    _auth(client, admin_user)
    resp = _search(client, {"hash": "cafebabe"})
    assert _json_body(resp)["msg"] == "Search complete. No Results Found."


# ---------------------------------------------------------------------------
# Search by plaintext
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_search_by_plaintext_returns_all_matches(client, admin_user):
    """plaintext returns EVERY cracked hash with that recovered plaintext."""
    _seed_hash("aaaa", 1000, True, "reused")
    _seed_hash("bbbb", 1800, True, "reused")
    # A different plaintext and an uncracked row with the same plaintext must
    # both be excluded.
    _seed_hash("cccc", 1000, True, "other")
    _seed_hash("dddd", 1000, False, "reused")
    _auth(client, admin_user)

    resp = _search(client, {"plaintext": "reused"})
    body = _json_body(resp)
    assert body["status"] == 200
    assert isinstance(body["msg"], list)
    by_hash = {entry["hash"]: entry for entry in body["msg"]}
    assert set(by_hash) == {"aaaa", "bbbb"}
    assert by_hash["aaaa"] == {"hash_type": 1000, "hash": "aaaa", "plaintext": "reused"}
    assert by_hash["bbbb"]["hash_type"] == 1800


@pytest.mark.security
def test_search_by_plaintext_not_found_returns_message(client, admin_user):
    """A plaintext with no cracked matches returns the not-found string."""
    _auth(client, admin_user)
    resp = _search(client, {"plaintext": "never-cracked"})
    assert _json_body(resp)["msg"] == "Search complete. No Results Found."


# ---------------------------------------------------------------------------
# Search by username
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_search_by_username_returns_list_with_nullable_plaintext(client, admin_user):
    """username returns the associated hash(es); plaintext is populated when
    the hash is cracked and null when it is not."""
    cracked = _seed_hash("1111", 1000, True, "secret")
    uncracked = _seed_hash("2222", 1000, False)
    _link_username(cracked.id, "admin")
    _link_username(uncracked.id, "admin")
    _auth(client, admin_user)

    resp = _search(client, {"username": "admin"})
    body = _json_body(resp)
    assert body["status"] == 200
    assert isinstance(body["msg"], list)
    by_hash = {entry["hash"]: entry for entry in body["msg"]}
    assert set(by_hash) == {"1111", "2222"}
    assert by_hash["1111"] == {
        "username": "admin",
        "hash_type": 1000,
        "hash": "1111",
        "plaintext": "secret",
    }
    assert by_hash["2222"]["plaintext"] is None


@pytest.mark.security
def test_search_by_username_dedupes_same_hash_across_hashfiles(client, admin_user):
    """A username mapping to the same hash in two hashfiles yields one result."""
    h = _seed_hash("3333", 1000, True, "pw")
    _link_username(h.id, "dupe", hashfile_id=1)
    _link_username(h.id, "dupe", hashfile_id=2)
    _auth(client, admin_user)

    resp = _search(client, {"username": "dupe"})
    body = _json_body(resp)
    assert body["status"] == 200
    assert len(body["msg"]) == 1
    assert body["msg"][0]["hash"] == "3333"


@pytest.mark.security
def test_search_by_username_not_found_returns_message(client, admin_user):
    """A username with no associated hashes returns the not-found string."""
    _auth(client, admin_user)
    resp = _search(client, {"username": "ghost"})
    assert _json_body(resp)["msg"] == "Search complete. No Results Found."


# ---------------------------------------------------------------------------
# Key precedence
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_search_hash_takes_precedence_over_plaintext_and_username(client, admin_user):
    """When multiple keys are supplied, hash is checked first (returns an
    object), regardless of the plaintext/username values."""
    _seed_hash("9999", 1000, True, "winner")
    _auth(client, admin_user)

    resp = _search(
        client,
        {"hash": "9999", "plaintext": "anything", "username": "anyone"},
    )
    body = _json_body(resp)
    assert body["status"] == 200
    # An object (hash match), not a list.
    assert body["msg"] == {"hash_type": 1000, "hash": "9999", "plaintext": "winner"}
