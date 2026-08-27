"""Unit tests for the hashfile / wordlist / rule download features.

  - Hashfile export route serves 4 formats (hashes / all / cracked / plains),
    hex-decoding stored plaintext, and offers them via a modal on the list page.
  - Wordlist download serves the stored file (static .gz / dynamic .txt).
  - Rule download serves the raw rule file.

Uses the in-memory SQLite app from tests/unit/conftest.py; UI routes are
authenticated via the login session. Files live under pytest tmp_path so no
real control dirs are touched (send_from_directory resolves abspath(dirname)).
"""

import gzip

from hashview.models import Hashes, HashfileHashes, Hashfiles, Rules, Users, Wordlists, db


def _admin():
    u = Users(first_name="A", last_name="D", email_address="a@e.com",
              password="x" * 60, admin=True, api_key="dl-key")
    db.session.add(u)
    db.session.commit()
    return u


def _login(client, user):
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True


def _make_hashfile_with_hashes(owner_id):
    """3 hashes: 2 cracked (plaintext stored as plain text), 1 uncracked."""
    hf = Hashfiles(name="corp dump", customer_id=1, owner_id=owner_id)
    db.session.add(hf)
    db.session.commit()
    specs = [
        ("aaa111", "Passw0rd!", True),
        ("bbb222", "letmein", True),
        ("ccc333", None, False),
    ]
    for ct, pt, cracked in specs:
        h = Hashes(sub_ciphertext="0" * 8, ciphertext=ct, hash_type=0,
                   cracked=cracked, plaintext=pt)
        db.session.add(h)
        db.session.commit()
        db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
        db.session.commit()
    return hf


# ---------------------------------------------------------------------------
# Hashfile export route
# ---------------------------------------------------------------------------

def test_hashfile_export_hashes_only(app, client):
    user = _admin()
    _login(client, user)
    hf = _make_hashfile_with_hashes(user.id)
    resp = client.get(f"/hashfiles/download/{hf.id}/hashes")
    assert resp.status_code == 200
    body = resp.data.decode("latin-1")
    assert set(body.split()) == {"aaa111", "bbb222", "ccc333"}
    assert "Passw0rd!" not in body and ":" not in body
    cd = resp.headers.get("Content-Disposition", "")
    assert "attachment" in cd and "corp_dump_hashes.txt" in cd


def test_hashfile_export_all(app, client):
    user = _admin()
    _login(client, user)
    hf = _make_hashfile_with_hashes(user.id)
    body = client.get(f"/hashfiles/download/{hf.id}/all").data.decode("latin-1")
    lines = body.split("\n")
    assert "aaa111:Passw0rd!" in lines
    assert "bbb222:letmein" in lines
    assert "ccc333" in lines              # uncracked -> bare hash
    assert "ccc333:" not in body          # not annotated


def test_hashfile_export_cracked_only(app, client):
    user = _admin()
    _login(client, user)
    hf = _make_hashfile_with_hashes(user.id)
    body = client.get(f"/hashfiles/download/{hf.id}/cracked").data.decode("latin-1")
    lines = [ln for ln in body.split("\n") if ln]
    assert sorted(lines) == sorted(["aaa111:Passw0rd!", "bbb222:letmein"])
    assert "ccc333" not in body


def test_hashfile_export_plains_only(app, client):
    user = _admin()
    _login(client, user)
    hf = _make_hashfile_with_hashes(user.id)
    body = client.get(f"/hashfiles/download/{hf.id}/plains").data.decode("latin-1")
    lines = [ln for ln in body.split("\n") if ln]
    assert sorted(lines) == sorted(["Passw0rd!", "letmein"])
    assert "aaa111" not in body and "bbb222" not in body


def test_hashfile_export_preserves_non_latin1_plaintext(app, client):
    """A cracked plaintext containing characters above U+00FF (emoji, CJK,
    Cyrillic -- the international-pwdump case) must round-trip through the
    download unchanged. The old latin-1/errors='replace' encode silently
    turned these into '?', corrupting the exported password file."""
    user = _admin()
    _login(client, user)
    hf = Hashfiles(name="intl dump", customer_id=1, owner_id=user.id)
    db.session.add(hf)
    db.session.commit()
    plain = "пароль-密码-🔒"          # Cyrillic + CJK + emoji, all > U+00FF
    h = Hashes(sub_ciphertext="0" * 8, ciphertext="ddd444", hash_type=0,
               cracked=True, plaintext=plain)
    db.session.add(h)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    db.session.commit()

    resp = client.get(f"/hashfiles/download/{hf.id}/plains")
    assert resp.status_code == 200
    body = resp.data.decode("utf-8")
    assert plain in body
    assert "?" not in body                # no lossy replacement occurred


def test_hashfile_export_invalid_format_404(app, client):
    user = _admin()
    _login(client, user)
    hf = _make_hashfile_with_hashes(user.id)
    assert client.get(f"/hashfiles/download/{hf.id}/bogus").status_code == 404


def test_hashfile_export_requires_login(app, client):
    user = _admin()
    hf = _make_hashfile_with_hashes(user.id)
    resp = client.get(f"/hashfiles/download/{hf.id}/hashes", follow_redirects=False)
    assert resp.status_code in (302, 401)   # redirected to login


def test_hashfiles_page_renders_download_modal(app, client):
    user = _admin()
    _login(client, user)
    Hashfiles.query.delete()
    db.session.commit()
    hf = Hashfiles(name="render dump", customer_id=1, owner_id=user.id)
    db.session.add(hf)
    db.session.commit()
    resp = client.get("/hashfiles")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert f"dl-{hf.id}" in html
    assert "Hashes only" in html and "Plaintext only" in html
    assert f"/hashfiles/download/{hf.id}/cracked" in html


# ---------------------------------------------------------------------------
# Wordlist download
# ---------------------------------------------------------------------------

def test_wordlist_download_static_gz(app, client, tmp_path):
    user = _admin()
    _login(client, user)
    gz = tmp_path / "abc.gz"
    with gzip.open(str(gz), "wb") as f:
        f.write(b"word1\nword2\n")
    wl = Wordlists(name="Rockyou", owner_id=user.id, type="static",
                   path=str(gz), checksum="0" * 64, size=2)
    db.session.add(wl)
    db.session.commit()

    resp = client.get(f"/wordlists/download/{wl.id}")
    assert resp.status_code == 200
    assert resp.data[:2] == b"\x1f\x8b"
    assert gzip.decompress(resp.data) == b"word1\nword2\n"
    assert resp.headers.get("Content-Disposition", "").endswith('Rockyou.gz') or \
           "Rockyou.gz" in resp.headers.get("Content-Disposition", "")


def test_wordlist_download_dynamic_txt(app, client, tmp_path):
    user = _admin()
    _login(client, user)
    txt = tmp_path / "dyn.txt"
    txt.write_bytes(b"alpha\nbravo\n")
    wl = Wordlists(name="(DYNAMIC) All Customers", owner_id=user.id, type="dynamic",
                   path=str(txt), checksum="0" * 64, size=2)
    db.session.add(wl)
    db.session.commit()

    resp = client.get(f"/wordlists/download/{wl.id}")
    assert resp.status_code == 200
    assert resp.data == b"alpha\nbravo\n"
    assert ".txt" in resp.headers.get("Content-Disposition", "")


def test_wordlist_download_missing_file_redirects(app, client, tmp_path):
    user = _admin()
    _login(client, user)
    wl = Wordlists(name="Gone", owner_id=user.id, type="static",
                   path=str(tmp_path / "nope.gz"), checksum="0" * 64, size=0)
    db.session.add(wl)
    db.session.commit()
    resp = client.get(f"/wordlists/download/{wl.id}", follow_redirects=False)
    assert resp.status_code == 302


def test_wordlists_page_renders_download_links(app, client, tmp_path):
    user = _admin()
    _login(client, user)
    wl = Wordlists(name="Rockyou", owner_id=user.id, type="static",
                   path=str(tmp_path / "abc.gz"), checksum="0" * 64, size=2)
    db.session.add(wl)
    db.session.commit()
    html = client.get("/wordlists").get_data(as_text=True)
    assert f"/wordlists/download/{wl.id}" in html


# ---------------------------------------------------------------------------
# Rule download
# ---------------------------------------------------------------------------

def test_rule_download(app, client, tmp_path):
    user = _admin()
    _login(client, user)
    rule_file = tmp_path / "best64.rule"
    rule_file.write_text(":\nl\nu\n")
    rule = Rules(name="Best64", owner_id=user.id, path=str(rule_file),
                 checksum="0" * 64, size=3)
    db.session.add(rule)
    db.session.commit()

    resp = client.get(f"/rules/download/{rule.id}")
    assert resp.status_code == 200
    assert resp.data == b":\nl\nu\n"
    assert "Best64.rule" in resp.headers.get("Content-Disposition", "")


def test_rule_download_missing_file_redirects(app, client, tmp_path):
    user = _admin()
    _login(client, user)
    rule = Rules(name="Gone", owner_id=user.id, path=str(tmp_path / "nope.rule"),
                 checksum="0" * 64, size=0)
    db.session.add(rule)
    db.session.commit()
    resp = client.get(f"/rules/download/{rule.id}", follow_redirects=False)
    assert resp.status_code == 302


def test_rules_page_renders_download_link(app, client, tmp_path):
    user = _admin()
    _login(client, user)
    rule = Rules(name="Best64", owner_id=user.id, path=str(tmp_path / "best64.rule"),
                 checksum="0" * 64, size=3)
    db.session.add(rule)
    db.session.commit()
    html = client.get("/rules").get_data(as_text=True)
    assert f"/rules/download/{rule.id}" in html
