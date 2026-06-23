"""xfail tests documenting search/encoding GitHub issues.

Each test asserts the CORRECT/DESIRED behavior and is marked
``@pytest.mark.xfail(strict=False)`` so it documents the issue without
breaking the suite. Some of these issues are already fixed on this branch
(UTF-8 storage path), in which case the test XPASSes and acts as a
regression guard.

Issues covered:
  * #22  - User search is case sensitive
  * #140 - Usernames with en dash (U+2013) can not be imported
"""

import io

import pytest

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


@pytest.mark.xfail(reason="issue #22: user search is case sensitive", strict=False)
def test_user_search_is_case_insensitive(app, client):
    """A user search for 'bob' should match a stored username 'Bob'.

    DESIRED: username search is case-insensitive. SQLite's LIKE is ASCII
    case-insensitive by default, so on the current UTF-8 storage path this
    likely XPASSes and guards against a regression.
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


@pytest.mark.xfail(reason="issue #140: usernames with en dash can not be imported",
                   strict=False)
def test_username_with_en_dash_round_trips(app):
    """A username containing an en dash (U+2013) must survive storage and
    CSV export.

    DESIRED: the en dash round-trips through text_from_field (the storage
    normalizer used by import_hashfilehashes) and the get_rows CSV export.
    The old code latin-1 encoded usernames, which mangled non-latin-1
    characters; the current UTF-8 path should preserve it (XPASS = regression
    guard).
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
