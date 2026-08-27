"""Regression guards for fixed search/encoding GitHub issues.

These tests started life as ``xfail(strict=False)`` documentation for open
issues; both issues are now fixed and closed, so they run as plain
regression guards.

Issues covered:
  * #22  (closed) - User search is case sensitive
  * #140 (closed) - Usernames with en dash (U+2013) can not be imported
"""

import io

from hashview.models import Customers, Hashes, HashfileHashes, Hashfiles, db
from hashview.searches.routes import get_rows
from hashview.utils.utils import text_from_field
from tests.unit.helpers import login, make_admin


def _seed_cracked(username="bob", plaintext="Hunter2", ciphertext="deadbeef"):
    """Seed a cracked Hashes + HashfileHashes pair (mirrors
    test_searches_routes._seed_cracked)."""
    cust = Customers(name="SearchCo")
    db.session.add(cust)
    db.session.commit()
    hf = Hashfiles(name="hf", customer_id=cust.id, owner_id=1)
    db.session.add(hf)
    db.session.commit()
    h = Hashes(sub_ciphertext="0" * 8, ciphertext=ciphertext, hash_type=1000,
               cracked=True, plaintext=plaintext)
    db.session.add(h)
    db.session.commit()
    hfh = HashfileHashes(hash_id=h.id, hashfile_id=hf.id, username=username)
    db.session.add(hfh)
    db.session.commit()
    return cust, hf, h, hfh


def test_user_search_is_case_insensitive(app, client):
    """A user search for 'bob' matches a stored username 'Bob'.

    Username search is case-insensitive (SQLite's LIKE is ASCII
    case-insensitive by default). Regression guard for closed issue #22.
    """
    admin = make_admin()
    login(client, admin)
    _seed_cracked(username="Bob")

    resp = client.post("/search", data={
        "search_type": "user", "query": "bob",
        "submit": "Search",
    })

    assert resp.status_code == 200
    assert b"Bob" in resp.data


def test_username_with_en_dash_round_trips(app):
    """A username containing an en dash (U+2013) survives storage and
    CSV export.

    The en dash round-trips through text_from_field (the storage
    normalizer used by import_hashfilehashes) and the get_rows CSV export.
    The old code latin-1 encoded usernames, which mangled non-latin-1
    characters; the UTF-8 path preserves it. Regression guard for closed
    issue #140.
    """
    en_dash_username = "alice–bob"

    # Normalise the field exactly as import_hashfilehashes does.
    stored = text_from_field(en_dash_username)

    cust, hf, h, hfh = _seed_cracked(username=stored, ciphertext="abc123")

    # Read it back from the DB.
    fetched = db.session.query(HashfileHashes).filter_by(id=hfh.id).one()
    assert fetched.username == en_dash_username

    # And verify it survives a CSV export via get_rows.
    str_io = io.StringIO()
    get_rows(str_io, [(h, fetched)], "hashfile", [cust], [hf])
    out = str_io.getvalue()
    assert "–" in out
    assert en_dash_username in out
