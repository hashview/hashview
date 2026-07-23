"""Unit tests for length-bucketed dynamic wordlists.

Feature request hashview/hashview#353: alongside the existing
"(DYNAMIC) All Recovered Passwords" list, provide dynamic wordlists that
contain only recovered plaintexts of a given length. Buckets are a FIXED
set seeded like the other dynamic wordlists:

    (DYNAMIC) Recovered Passwords (length 0-4)   -> len <= 4  (combined)
    (DYNAMIC) Recovered Passwords (length 5)     -> len == 5
    (DYNAMIC) Recovered Passwords (length 6)     -> len == 6
    (DYNAMIC) Recovered Passwords (length 7)     -> len == 7
    (DYNAMIC) Recovered Passwords (length 8)     -> len == 8
    (DYNAMIC) Recovered Passwords (length 9+)    -> len >= 9  (catch-all)

The dispatcher in hashview.utils.utils.update_dynamic_wordlist must parse
the "(length ...)" token from the wordlist name and filter accordingly.
$HEX[...] plaintexts are DECODED first: bucketing uses the decoded byte
length, and the decoded value (not the $HEX[...] wrapper) is what gets
written to the bucket. Bytes that aren't valid UTF-8 are written raw.

The six bucket-behavior tests are marked ``xfail(strict=True)``: the
feature (hashview/hashview#353) is not implemented yet, so they fail
today and will flip to XPASS -> hard failure the moment the dispatcher
learns to length-filter, forcing the markers to be removed. The final
test (unbucketed "All Recovered Passwords") guards existing behavior and
must pass now.
"""

import os

import pytest

from hashview.models import Hashes, Users, Wordlists, db
from hashview.utils.utils import update_dynamic_wordlist


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
@pytest.mark.xfail(strict=True, reason="length buckets not implemented yet (hashview#353)")
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
@pytest.mark.xfail(strict=True, reason="length buckets not implemented yet (hashview#353)")
def test_low_combined_bucket_includes_zero_through_four(app, tmp_path):
    _make_user()
    wl = _make_wordlist(tmp_path, "(DYNAMIC) Recovered Passwords (length 0-4)")
    _write_plain("a", "a" * 32)       # 1
    _write_plain("abcd", "b" * 32)    # 4  -> included
    _write_plain("abcde", "c" * 32)   # 5  -> excluded

    update_dynamic_wordlist(wl.id)

    contents = set(open(wl.path).read().splitlines())
    assert contents == {"a", "abcd"}


@pytest.mark.security
@pytest.mark.xfail(strict=True, reason="length buckets not implemented yet (hashview#353)")
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
@pytest.mark.xfail(strict=True, reason="length buckets not implemented yet (hashview#353)")
def test_hex_plaintext_decoded_into_correct_bucket(app, tmp_path):
    _make_user()
    wl = _make_wordlist(tmp_path, "(DYNAMIC) Recovered Passwords (length 6)")
    # $HEX[414243444546] decodes to 6 bytes ("ABCDEF") -> length-6 bucket,
    # written as the decoded value, NOT the $HEX[...] wrapper.
    _write_plain("$HEX[414243444546]", "a" * 32)
    # $HEX[4142] decodes to 2 bytes -> excluded from the length-6 bucket.
    _write_plain("$HEX[4142]", "b" * 32)

    update_dynamic_wordlist(wl.id)

    contents = set(open(wl.path, encoding="utf-8").read().splitlines())
    assert contents == {"ABCDEF"}


@pytest.mark.security
@pytest.mark.xfail(strict=True, reason="length buckets not implemented yet (hashview#353)")
def test_hex_non_utf8_decoded_and_written_raw(app, tmp_path):
    _make_user()
    # 0xFF 0xFE: 2 decoded bytes (not valid UTF-8) -> the 0-4 combined bucket.
    # The decoded bytes must be written raw, not the $HEX[...] wrapper.
    wl = _make_wordlist(tmp_path, "(DYNAMIC) Recovered Passwords (length 0-4)")
    _write_plain("$HEX[fffe]", "a" * 32)

    update_dynamic_wordlist(wl.id)

    assert open(wl.path, "rb").read() == b"\xff\xfe\n"


@pytest.mark.security
@pytest.mark.xfail(strict=True, reason="length buckets not implemented yet (hashview#353)")
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
