"""Regression tests for searches routes + export helpers
(function-coverage batch: searches)."""

import io

from hashview.models import Customers, Hashes, HashfileHashes, Hashfiles, db
from hashview.searches.routes import export_results, get_rows
from tests.unit.helpers import login, make_admin


def _seed_cracked(username="bob", plaintext="Hunter2", ciphertext="deadbeef"):
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


def test_searches_list_get_renders(app, client):
    admin = make_admin()
    login(client, admin)
    resp = client.get("/search")
    assert resp.status_code == 200


def test_searches_list_password_search_finds_match(app, client):
    admin = make_admin()
    login(client, admin)
    _seed_cracked(plaintext="UniquePass1")
    resp = client.post("/search", data={
        "search_type": "password", "query": "UniquePass1",
        "submit": "Search",
    })
    assert resp.status_code == 200
    assert b"UniquePass1" in resp.data


def test_get_rows_writes_hashfile_csv(app):
    cust, hf, h, hfh = _seed_cracked(username="carol", plaintext="pw1", ciphertext="abc123")
    str_io = io.StringIO()
    get_rows(str_io, [(h, hfh)], "hashfile", [cust], [hf])
    out = str_io.getvalue()
    assert "Customer,Username,Hash,Plain Text" in out
    assert "SearchCo" in out
    assert "carol" in out
    assert "abc123" in out
    assert "pw1" in out


def test_get_rows_writes_hash_csv(app):
    cust, hf, h, hfh = _seed_cracked(plaintext="pw2", ciphertext="cafe01")
    str_io = io.StringIO()
    get_rows(str_io, [h], "hash", None, None)
    out = str_io.getvalue()
    assert "Recovered At,Hash Type,Cipher Text,Plain Text" in out
    assert "1000" in out  # hash_type
    assert "cafe01" in out
    assert "pw2" in out


def test_export_results_hashfile_returns_attachment(app):
    cust, hf, h, hfh = _seed_cracked(ciphertext="ffee00")
    # send_file needs a request context.
    with app.test_request_context("/search"):
        resp = export_results([(h, hfh)], "hashfile", customers=[cust], hashfiles=[hf])
    assert resp.status_code == 200
    assert resp.headers["Content-Disposition"].startswith("attachment")
    assert "search_hashfile.csv" in resp.headers["Content-Disposition"]


def test_export_results_hash_returns_attachment(app):
    cust, hf, h, hfh = _seed_cracked(ciphertext="ddcc11")
    # send_file needs a request context.
    with app.test_request_context("/search"):
        resp = export_results([h], "hash")
    assert resp.status_code == 200
    assert resp.headers["Content-Disposition"].startswith("attachment")
    assert "search_hash.csv" in resp.headers["Content-Disposition"]


def test_searches_hash_id_with_hashfile_match_renders(app, client):
    admin = make_admin()
    login(client, admin)
    cust, hf, h, hfh = _seed_cracked(ciphertext="abc123def")
    resp = client.get(f"/search?hash_id={h.id}")
    assert resp.status_code == 200
    # Form was pre-filled with the matched ciphertext.
    assert b"abc123def" in resp.data


def test_searches_hash_id_no_hashfile_match_redacted(app, client):
    admin = make_admin()
    login(client, admin)
    # A Hashes row NOT linked to any HashfileHashes -> redacted fallback path.
    h = Hashes(sub_ciphertext="0" * 8, ciphertext="orphanhash", hash_type=1000,
               cracked=False, plaintext="")
    db.session.add(h)
    db.session.commit()
    resp = client.get(f"/search?hash_id={h.id}")
    assert resp.status_code == 200


def test_searches_hash_id_nonexistent_flashes_no_results(app, client):
    admin = make_admin()
    login(client, admin)
    resp = client.get("/search?hash_id=999999", follow_redirects=True)
    assert resp.status_code == 200
    assert b"No results found" in resp.data


def test_searches_export_hash_returns_csv(app, client):
    admin = make_admin()
    login(client, admin)
    _seed_cracked(ciphertext="cafe9988", plaintext="ExpPw")
    resp = client.post("/search", data={
        "search_type": "hash", "query": "cafe9988", "submit": "Search",
        "export": "hash",
    })
    assert resp.status_code == 200
    assert resp.headers["Content-Disposition"].startswith("attachment")
    assert "search_hash.csv" in resp.headers["Content-Disposition"]
    assert b"cafe9988" in resp.data
    assert b"ExpPw" in resp.data


def test_searches_export_hashfile_returns_csv(app, client):
    admin = make_admin()
    login(client, admin)
    _seed_cracked(username="dave", plaintext="ExpPw2", ciphertext="beef7766")
    resp = client.post("/search", data={
        "search_type": "hash", "query": "beef7766", "submit": "Search",
        "export": "hashfile",
    })
    assert resp.status_code == 200
    assert resp.headers["Content-Disposition"].startswith("attachment")
    assert "search_hashfile.csv" in resp.headers["Content-Disposition"]
    assert b"dave" in resp.data
    assert b"SearchCo" in resp.data


def test_searches_invalid_search_option(app, client):
    """The `else: Invalid search option` branch in searches_list.

    The SearchForm.search_type SelectField declares fixed `choices` without
    `validate_choice=False`, so WTForms rejects any out-of-range value during
    validate_on_submit(). The else-branch is therefore unreachable via normal
    form submission. This test pins that reality.
    """
    admin = make_admin()
    login(client, admin)
    resp = client.post("/search", data={
        "search_type": "bogus", "query": "x", "submit": "Search",
    }, follow_redirects=True)
    assert resp.status_code == 200
    # SelectField validation fails, so we never hit the else-branch / its flash.
    assert b"Invalid search option" not in resp.data
