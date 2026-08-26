"""Unit tests for the hashfile / wordlist / rule download features.

  - Hashfile export route serves 4 formats (hashes / all / cracked / plains),
    hex-decoding stored plaintext, and offers them via a modal on the list page.
  - Wordlist download serves the stored .gz for static lists, and regenerates
    dynamic lists from the database into a scratch .txt.
  - Rule download serves the raw rule file.

Uses the in-memory SQLite app from tests/unit/conftest.py; UI routes are
authenticated via the login session. Files live under pytest tmp_path so no
real control dirs are touched (send_from_directory resolves abspath(dirname)).
"""

import gzip
import os

from hashview.models import (
    Customers,
    Hashes,
    HashfileHashes,
    Hashfiles,
    Rules,
    Users,
    Wordlists,
    db,
)


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
    """A dynamic list is served as uncompressed text, built from the database
    rather than from whatever the last refresh left at wordlist.path."""
    user = _admin()
    _login(client, user)
    db.session.add_all([Customers(name="alpha"), Customers(name="bravo")])
    db.session.commit()
    txt = tmp_path / "dyn.txt"
    txt.write_bytes(b"")
    wl = Wordlists(name="(DYNAMIC) All Customers", owner_id=user.id, type="dynamic",
                   path=str(txt), checksum="0" * 64, size=0)
    db.session.add(wl)
    db.session.commit()

    resp = client.get(f"/wordlists/download/{wl.id}")
    assert resp.status_code == 200
    assert sorted(resp.data.decode().split()) == ["alpha", "bravo"]
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


# ---------------------------------------------------------------------------
# Dynamic wordlist download regenerates on demand
#
# Dynamic lists are derived from the database, and nothing writes the canonical
# file at wordlist.path except the manual "refresh" button -- so serving that
# file hands the operator whatever the last refresh left behind, which on a
# fresh install is the zero-byte seed placeholder. The download regenerates
# into a per-request temp file instead, matching GET /v1/wordlists/<id>.
# ---------------------------------------------------------------------------

def _tmp_dir_entries(app):
    return set(os.listdir(os.path.join(app.root_path, "control", "tmp")))


def _cracked(plaintext, ciphertext):
    h = Hashes(sub_ciphertext="0" * 8, ciphertext=ciphertext, hash_type=1000,
               cracked=True, plaintext=plaintext)
    db.session.add(h)
    db.session.commit()
    return h


def _dynamic_wordlist(owner_id, path, name="(DYNAMIC) All Recovered Passwords"):
    wl = Wordlists(name=name, owner_id=owner_id, type="dynamic",
                   path=str(path), checksum="0" * 64, size=0)
    db.session.add(wl)
    db.session.commit()
    return wl


def test_dynamic_wordlist_download_regenerates_from_database(app, client, tmp_path):
    """The seeded placeholder is empty; the download must still carry the
    recovered plaintexts that exist in the database."""
    user = _admin()
    _login(client, user)
    _cracked("Summer2026!", "aaa111")
    _cracked("Winter1", "bbb222")
    placeholder = tmp_path / "dynamic-all.txt"
    placeholder.write_bytes(b"")
    wl = _dynamic_wordlist(user.id, placeholder)

    resp = client.get(f"/wordlists/download/{wl.id}")

    assert resp.status_code == 200
    assert sorted(resp.data.decode().split()) == ["Summer2026!", "Winter1"]


def test_dynamic_wordlist_download_does_not_serve_stale_file(app, client, tmp_path):
    """Content left on disk by an earlier refresh must not be served once the
    database has moved on."""
    user = _admin()
    _login(client, user)
    _cracked("fresh-plain", "aaa111")
    stale = tmp_path / "dynamic-all.txt"
    stale.write_bytes(b"stale-plain\n")
    wl = _dynamic_wordlist(user.id, stale)

    body = client.get(f"/wordlists/download/{wl.id}").data.decode()

    assert "fresh-plain" in body
    assert "stale-plain" not in body


def test_dynamic_wordlist_download_works_when_file_missing(app, client, tmp_path):
    """A dynamic list is derived from the database, so a missing on-disk file
    is not an error -- it regenerates rather than redirecting."""
    user = _admin()
    _login(client, user)
    _cracked("only-plain", "aaa111")
    wl = _dynamic_wordlist(user.id, tmp_path / "never-created.txt")

    resp = client.get(f"/wordlists/download/{wl.id}", follow_redirects=False)

    assert resp.status_code == 200
    assert resp.data.decode().split() == ["only-plain"]


def test_dynamic_wordlist_download_leaves_canonical_file_untouched(app, client, tmp_path):
    """Regeneration goes to a per-request temp file, never the shared path, so
    concurrent downloads cannot truncate the file out from under each other."""
    user = _admin()
    _login(client, user)
    _cracked("fresh-plain", "aaa111")
    canonical = tmp_path / "dynamic-all.txt"
    canonical.write_bytes(b"stale-plain\n")
    wl = _dynamic_wordlist(user.id, canonical)

    client.get(f"/wordlists/download/{wl.id}")

    assert canonical.read_bytes() == b"stale-plain\n"
    assert wl.size == 0 and wl.checksum == "0" * 64


def test_dynamic_wordlist_download_cleans_up_its_temp_files(app, client, tmp_path):
    """The generated .txt is scratch; control/tmp must not accumulate it."""
    user = _admin()
    _login(client, user)
    _cracked("only-plain", "aaa111")
    wl = _dynamic_wordlist(user.id, tmp_path / "dynamic-all.txt")
    before = _tmp_dir_entries(app)

    assert client.get(f"/wordlists/download/{wl.id}").status_code == 200

    assert _tmp_dir_entries(app) == before


def test_dynamic_wordlist_download_names_the_attachment_after_the_wordlist(app, client, tmp_path):
    """The regenerated temp file's random name must not leak into the download."""
    user = _admin()
    _login(client, user)
    _cracked("only-plain", "aaa111")
    wl = _dynamic_wordlist(user.id, tmp_path / "dynamic-all.txt")

    cd = client.get(f"/wordlists/download/{wl.id}").headers.get("Content-Disposition", "")

    assert "attachment" in cd
    assert "DYNAMIC_All_Recovered_Passwords.txt" in cd


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
