"""Unit tests for ``hashview.utils.utils.update_dynamic_wordlist``.

The dispatcher routes by substring of the wordlist name:
    'Passwords' -> writes recovered plaintexts
    'Usernames' -> writes usernames (and splits DOMAIN\\user)
    'Customers' -> writes customer names (lowercased)
    'NTLM'      -> writes NTLM ciphertexts (hash_type 1000)

Before the v0.8.2 rename, the default seed used "All Recovered Hashes"
which matched none of these branches — the wordlist was silently never
populated. These tests lock in the dispatcher contract so a rename can't
silently break population again.
"""

import os

import pytest

from hashview.models import (
    Customers,
    Hashes,
    HashfileHashes,
    Users,
    Wordlists,
    db,
)
from hashview.utils.utils import update_dynamic_wordlist


def _make_user(app):
    user = Users(
        first_name="t",
        last_name="u",
        email_address="t@example.com",
        password="x" * 60,
        admin=True,
    )
    db.session.add(user)
    db.session.commit()
    return user


def _make_wordlist(app, tmp_path, name: str) -> Wordlists:
    path = str(tmp_path / f"{name.replace(' ', '_')}.txt")
    open(path, "w").close()  # touch
    wl = Wordlists(
        name=name,
        owner_id=1,
        type="dynamic",
        path=path,
        checksum="",
        size=0,
    )
    db.session.add(wl)
    db.session.commit()
    return wl


def _write_hash(plaintext_bytes: bytes, hash_type: int = 1000, ciphertext: str = None):
    """Insert a cracked hash row whose plaintext is stored as plain text."""
    h = Hashes(
        sub_ciphertext="0" * 32,
        ciphertext=ciphertext or ("a" * 32),
        hash_type=hash_type,
        cracked=True,
        plaintext=plaintext_bytes.decode("utf-8"),
    )
    db.session.add(h)
    db.session.commit()
    return h


@pytest.mark.security  # reuse existing marker so it auto-skips parent live_server
def test_passwords_branch_writes_cracked_plaintexts(app, tmp_path):
    _make_user(app)
    wl = _make_wordlist(app, tmp_path, "(DYNAMIC) All Recovered Passwords")
    _write_hash(b"hello")
    _write_hash(b"world", ciphertext="b" * 32)

    update_dynamic_wordlist(wl.id)

    contents = open(wl.path).read().splitlines()
    assert "hello" in contents
    assert "world" in contents


@pytest.mark.security
def test_dest_path_writes_there_and_leaves_row_metadata(app, tmp_path):
    """With dest_path (the on-demand download path), content goes to that file,
    the canonical wordlist.path is untouched, and the row metadata is NOT
    updated."""
    _make_user(app)
    wl = _make_wordlist(app, tmp_path, "(DYNAMIC) All Customers")
    db.session.add(Customers(name="AcmeCorp"))
    db.session.commit()

    dest = str(tmp_path / "per-request.txt")
    returned = update_dynamic_wordlist(wl.id, dest_path=dest)

    assert returned == dest
    assert open(dest).read().splitlines() == ["acmecorp"]
    assert open(wl.path).read() == ""          # canonical file untouched
    wl = Wordlists.query.get(wl.id)
    assert wl.size == 0 and wl.checksum == ""  # metadata skipped on download


@pytest.mark.security
def test_usernames_branch_splits_domain_user(app, tmp_path):
    _make_user(app)
    wl = _make_wordlist(app, tmp_path, "(DYNAMIC) All Usernames")
    # HashfileHashes stores username as plain text
    for raw in (b"alice", b"CORP\\bob", b"carol"):
        hfh = HashfileHashes(hash_id=1, hashfile_id=1, username=raw.decode("utf-8"))
        db.session.add(hfh)
    db.session.commit()

    update_dynamic_wordlist(wl.id)

    contents = set(open(wl.path).read().splitlines())
    # alice and carol pass through; CORP\bob splits into 3 entries
    assert "alice" in contents
    assert "carol" in contents
    assert "CORP" in contents
    assert "bob" in contents
    assert "CORP\\bob" in contents


@pytest.mark.security
def test_customers_branch_writes_lowercased_names(app, tmp_path):
    _make_user(app)
    wl = _make_wordlist(app, tmp_path, "(DYNAMIC) All Customers")
    for name in ("Acme Corp", "GLOBEX", "Initech"):
        db.session.add(Customers(name=name))
    db.session.commit()

    update_dynamic_wordlist(wl.id)

    contents = set(open(wl.path).read().splitlines())
    assert contents == {"acme corp", "globex", "initech"}


@pytest.mark.security
def test_ntlm_branch_writes_ciphertexts_for_hash_type_1000_only(app, tmp_path):
    _make_user(app)
    wl = _make_wordlist(app, tmp_path, "(DYNAMIC) All NTLM Hashes")
    # Two NTLM and one non-NTLM ciphertext; only the NTLM ones should land.
    _write_hash(b"x", hash_type=1000, ciphertext="aaaa1111")
    _write_hash(b"y", hash_type=1000, ciphertext="bbbb2222")
    _write_hash(b"z", hash_type=500, ciphertext="cccc3333")  # md5crypt — excluded

    update_dynamic_wordlist(wl.id)

    contents = open(wl.path).read().splitlines()
    assert "aaaa1111" in contents
    assert "bbbb2222" in contents
    assert "cccc3333" not in contents


@pytest.mark.security
def test_no_matching_branch_writes_empty_file(app, tmp_path):
    """A wordlist whose name matches no branch must still leave a valid file.

    Pre-rename behavior: the old "(Dynamic) All Recovered Hashes" name
    matched none of the four substrings, so the file ended up empty. This
    test pins that fall-through behavior so it isn't silently changed.
    """
    _make_user(app)
    wl = _make_wordlist(app, tmp_path, "Mystery Wordlist")
    update_dynamic_wordlist(wl.id)

    assert os.path.exists(wl.path)
    assert open(wl.path).read() == ""
