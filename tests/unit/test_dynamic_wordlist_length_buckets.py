"""Unit tests for length-bucketed dynamic wordlists.

Feature request hashview/hashview#353: alongside the existing
"(DYNAMIC) All Recovered Passwords" list, provide dynamic wordlists that
contain only recovered plaintexts of a given length. Buckets are a FIXED
set seeded like the other dynamic wordlists:

    (DYNAMIC) Recovered Passwords (length 0-5)   -> len <= 5  (combined)
    (DYNAMIC) Recovered Passwords (length 6)     -> len == 6
    (DYNAMIC) Recovered Passwords (length 7)     -> len == 7
    (DYNAMIC) Recovered Passwords (length 8)     -> len == 8
    (DYNAMIC) Recovered Passwords (length 9+)    -> len >= 9  (catch-all)

All generation flows through a single function,
hashview.utils.utils.generate_recovered_password_wordlist(path,
min_length, max_length): the app passes the length window to write. The
dispatcher (update_dynamic_wordlist) just parses the "(length ...)" token
from the wordlist name into those bounds and delegates.

$HEX[...] plaintexts are bucketed by their DECODED byte length, but are
STORED in the wordlist in their original $HEX[...] form (the length is
decoded only to decide which bucket the entry sorts into).

Buckets are seeded on fresh install and on upgrade from an install that
predates them, even with zero cracked passwords, so a task can reference
any bucket immediately.
"""

import os
from pathlib import Path

import pytest

from hashview.models import Hashes, Users, Wordlists, db
from hashview.setup import (
    _DYNAMIC_WORDLISTS,
    add_default_dynamic_wordlists,
    default_dynamic_wordlists_need_added,
)
from hashview.utils.utils import (
    dynamic_password_length_wordlists,
    generate_recovered_password_wordlist,
    update_dynamic_wordlist,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def _make_user():
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


def _make_wordlist(tmp_path, name: str) -> Wordlists:
    path = str(tmp_path / f"{name.replace(' ', '_').replace('/', '_')}.txt")
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


def _write_plain(plaintext: str, ciphertext: str):
    h = Hashes(
        sub_ciphertext="0" * 32,
        ciphertext=ciphertext,
        hash_type=1000,
        cracked=True,
        plaintext=plaintext,
    )
    db.session.add(h)
    db.session.commit()
    return h


@pytest.mark.security
def test_exact_length_bucket_writes_only_that_length(app, tmp_path):
    _make_user()
    wl = _make_wordlist(tmp_path, "(DYNAMIC) Recovered Passwords (length 8)")
    _write_plain("password", "a" * 32)   # 8 chars -> included
    _write_plain("hi", "b" * 32)          # 2 chars -> excluded
    _write_plain("elephantine", "c" * 32) # 11 chars -> excluded

    update_dynamic_wordlist(wl.id)

    contents = set(open(wl.path).read().splitlines())
    assert contents == {"password"}


@pytest.mark.security
def test_low_combined_bucket_includes_zero_through_five(app, tmp_path):
    _make_user()
    wl = _make_wordlist(tmp_path, "(DYNAMIC) Recovered Passwords (length 0-5)")
    _write_plain("a", "a" * 32)        # 1  -> included
    _write_plain("abcde", "b" * 32)    # 5  -> included (upper boundary)
    _write_plain("abcdef", "c" * 32)   # 6  -> excluded

    update_dynamic_wordlist(wl.id)

    contents = set(open(wl.path).read().splitlines())
    assert contents == {"a", "abcde"}


@pytest.mark.security
def test_high_catchall_bucket_includes_nine_and_up(app, tmp_path):
    _make_user()
    wl = _make_wordlist(tmp_path, "(DYNAMIC) Recovered Passwords (length 9+)")
    _write_plain("x" * 8, "a" * 32)   # 8  -> excluded
    _write_plain("y" * 9, "b" * 32)   # 9  -> included
    _write_plain("z" * 40, "c" * 32)  # 40 -> included

    update_dynamic_wordlist(wl.id)

    contents = set(open(wl.path).read().splitlines())
    assert contents == {"y" * 9, "z" * 40}


@pytest.mark.security
def test_hex_bucketed_by_decoded_length_but_stored_as_hex(app, tmp_path):
    _make_user()
    wl = _make_wordlist(tmp_path, "(DYNAMIC) Recovered Passwords (length 6)")
    # $HEX[414243444546] decodes to 6 bytes -> length-6 bucket, but is stored
    # in its original $HEX[...] form, NOT decoded.
    _write_plain("$HEX[414243444546]", "a" * 32)
    # $HEX[4142] decodes to 2 bytes -> excluded from the length-6 bucket.
    _write_plain("$HEX[4142]", "b" * 32)

    update_dynamic_wordlist(wl.id)

    contents = set(open(wl.path, encoding="utf-8").read().splitlines())
    assert contents == {"$HEX[414243444546]"}


@pytest.mark.security
def test_hex_non_utf8_stored_as_hex_in_correct_bucket(app, tmp_path):
    _make_user()
    # 0xFF 0xFE: 2 decoded bytes (not valid UTF-8) -> the 0-5 combined bucket.
    # Stored verbatim as the $HEX[...] wrapper.
    wl = _make_wordlist(tmp_path, "(DYNAMIC) Recovered Passwords (length 0-5)")
    _write_plain("$HEX[fffe]", "a" * 32)

    update_dynamic_wordlist(wl.id)

    contents = set(open(wl.path, encoding="utf-8").read().splitlines())
    assert contents == {"$HEX[fffe]"}


@pytest.mark.security
def test_empty_bucket_writes_valid_empty_file(app, tmp_path):
    _make_user()
    wl = _make_wordlist(tmp_path, "(DYNAMIC) Recovered Passwords (length 7)")
    _write_plain("hello", "a" * 32)  # 5 chars, no 7-char plaintext exists

    update_dynamic_wordlist(wl.id)

    assert os.path.exists(wl.path)
    assert open(wl.path).read() == ""


@pytest.mark.security
def test_unbucketed_all_passwords_still_writes_everything(app, tmp_path):
    """Regression: the plain "All Recovered Passwords" list (no length token)
    must keep writing every plaintext, not accidentally get length-filtered."""
    _make_user()
    wl = _make_wordlist(tmp_path, "(DYNAMIC) All Recovered Passwords")
    _write_plain("hi", "a" * 32)
    _write_plain("password", "b" * 32)
    _write_plain("z" * 40, "c" * 32)

    update_dynamic_wordlist(wl.id)

    contents = set(open(wl.path).read().splitlines())
    assert contents == {"hi", "password", "z" * 40}


# ---------------------------------------------------------------------------
# Single generation function: the app passes the length bounds directly.
# ---------------------------------------------------------------------------

@pytest.mark.security
def test_generate_function_exact_length(app, tmp_path):
    _make_user()
    _write_plain("password", "a" * 32)   # 8 -> included
    _write_plain("hi", "b" * 32)          # 2 -> excluded
    out = str(tmp_path / "out.txt")

    generate_recovered_password_wordlist(out, min_length=8, max_length=8)

    assert set(open(out).read().splitlines()) == {"password"}


@pytest.mark.security
def test_generate_function_inclusive_range(app, tmp_path):
    _make_user()
    _write_plain("a", "a" * 32)        # 1 -> included
    _write_plain("abcde", "b" * 32)    # 5 -> included (upper boundary)
    _write_plain("abcdef", "c" * 32)   # 6 -> excluded
    out = str(tmp_path / "out.txt")

    generate_recovered_password_wordlist(out, min_length=0, max_length=5)

    assert set(open(out).read().splitlines()) == {"a", "abcde"}


@pytest.mark.security
def test_generate_function_unbounded_upper(app, tmp_path):
    _make_user()
    _write_plain("x" * 8, "a" * 32)   # 8  -> excluded
    _write_plain("y" * 9, "b" * 32)   # 9  -> included
    out = str(tmp_path / "out.txt")

    # max_length=None (default) => no upper bound.
    generate_recovered_password_wordlist(out, min_length=9)

    assert set(open(out).read().splitlines()) == {"y" * 9}


@pytest.mark.security
def test_generate_function_buckets_hex_by_byte_length_stores_hex(app, tmp_path):
    _make_user()
    _write_plain("$HEX[414243444546]", "a" * 32)  # 6 decoded bytes -> included
    _write_plain("$HEX[4142]", "b" * 32)          # 2 decoded bytes -> excluded
    out = str(tmp_path / "out.txt")

    generate_recovered_password_wordlist(out, min_length=6, max_length=6)

    # Bucketed by decoded length (6) but stored in original $HEX[...] form.
    assert set(open(out, encoding="utf-8").read().splitlines()) == {"$HEX[414243444546]"}


# ---------------------------------------------------------------------------
# Seeding: buckets exist on fresh install AND on upgrade, even with no
# passwords that fit any bucket.
# ---------------------------------------------------------------------------

def test_length_buckets_registered_in_both_seed_lists():
    seeded = {name for name, _ in _DYNAMIC_WORDLISTS}
    for name, _ in dynamic_password_length_wordlists():
        assert name in seeded
    # hashview.py (standalone CLI setup) seeds via the same helper.
    assert "dynamic_password_length_wordlists" in (REPO_ROOT / "hashview.py").read_text()


def test_upgrade_seeds_buckets_even_with_no_matching_passwords(app, tmp_path, monkeypatch):
    """Simulates upgrading a v0.8.2 install that predates the buckets: the
    seeder must add every bucket (row + empty file) even though the DB has
    zero cracked passwords, so tasks can reference them immediately."""
    _make_user()  # owner_id=1 target for seeded wordlists
    # No cracked hashes at all.
    assert Hashes.query.filter_by(cracked=True).count() == 0

    # Redirect the seed list to the tmp dir so we never touch the real control
    # dir, mirroring the buckets the real _DYNAMIC_WORDLISTS carries.
    bucket_seed = tuple(
        (name, str(tmp_path / f"{name.replace(' ', '_').replace('/', '_')}.txt"))
        for name, _ in dynamic_password_length_wordlists()
    )
    monkeypatch.setattr("hashview.setup._DYNAMIC_WORDLISTS", bucket_seed)

    assert default_dynamic_wordlists_need_added(db) is True
    add_default_dynamic_wordlists(db)

    for name, path in bucket_seed:
        row = Wordlists.query.filter_by(name=name).first()
        assert row is not None and row.type == "dynamic" and row.size == 0
        assert os.path.exists(path)
    # Idempotent: a second pass adds nothing.
    assert default_dynamic_wordlists_need_added(db) is False
    add_default_dynamic_wordlists(db)
    for name, _ in bucket_seed:
        assert Wordlists.query.filter_by(name=name).count() == 1


def test_upgrade_backfills_buckets_from_preexisting_cracked_corpus(app, tmp_path, monkeypatch):
    """End-to-end upgrade: an install that ALREADY has a corpus of cracked
    passwords (of varied lengths) predates the buckets. The seeder adds empty
    bucket rows/files, then the first regeneration of each bucket must split
    the pre-existing corpus into the correct length windows.

    This is the composition the other tests only cover in halves: generation
    is exercised against a populated DB, and seeding against an empty one, but
    never the real upgrade sequence (existing cracked data -> seed -> refresh).
    """
    _make_user()  # owner_id=1 target for seeded wordlists

    # Pre-existing cracked corpus, one plaintext per length bucket boundary.
    _write_plain("ab", "a" * 32)            # len 2  -> 0-5
    _write_plain("abcde", "b" * 32)         # len 5  -> 0-5 (upper boundary)
    _write_plain("abcdef", "c" * 32)        # len 6  -> 6
    _write_plain("abcdefg", "d" * 32)       # len 7  -> 7
    _write_plain("password", "e" * 32)      # len 8  -> 8
    _write_plain("elephantine", "f" * 32)   # len 11 -> 9+
    _write_plain("$HEX[fffe]", "0" * 32)    # 2 non-UTF-8 bytes -> 0-5, stored as $HEX
    assert Hashes.query.filter_by(cracked=True).count() == 7

    # Redirect the seed list to the tmp dir so seeded rows carry tmp paths that
    # regeneration will write to (never touching the real control dir).
    bucket_seed = tuple(
        (name, str(tmp_path / f"{name.replace(' ', '_').replace('/', '_')}.txt"))
        for name, _ in dynamic_password_length_wordlists()
    )
    monkeypatch.setattr("hashview.setup._DYNAMIC_WORDLISTS", bucket_seed)

    # Upgrade: seeder adds empty bucket rows + files from the existing corpus.
    add_default_dynamic_wordlists(db)
    for _, path in bucket_seed:
        assert open(path).read() == ""  # seeded empty, not yet backfilled

    # First refresh of each bucket splits the pre-existing corpus by length.
    expected = {
        "(DYNAMIC) Recovered Passwords (length 0-5)": {"ab", "abcde", "$HEX[fffe]"},
        "(DYNAMIC) Recovered Passwords (length 6)": {"abcdef"},
        "(DYNAMIC) Recovered Passwords (length 7)": {"abcdefg"},
        "(DYNAMIC) Recovered Passwords (length 8)": {"password"},
        "(DYNAMIC) Recovered Passwords (length 9+)": {"elephantine"},
    }
    for name, path in bucket_seed:
        wl = Wordlists.query.filter_by(name=name).first()
        update_dynamic_wordlist(wl.id)
        contents = set(open(path, encoding="utf-8").read().splitlines())
        assert contents == expected[name], name
