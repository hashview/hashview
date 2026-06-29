"""Unit tests for Unicode-safe username/plaintext storage.

Usernames and recovered plaintext are stored as plain UTF-8 text (with a
hashcat-style $HEX[...] marker for non-UTF-8 bytes) instead of latin-1 hex.
Covers the encoding helpers, the hashfile-import path (the reported emoji
crash), the one-time legacy-hex backfill, and Unicode searchability. Uses the
in-memory SQLite app from tests/unit/conftest.py.
"""
import pytest

from hashview.models import Hashes, HashfileHashes, Settings
from hashview.models import db as _db
from hashview.utils import utils as U

NTLM_PW = '8846F7EAEE8FB117AD06BDD830B7586C'   # NTLM('password')
FAMILY = '👩‍👩‍👧‍👦'           # ZWJ family emoji


# --------------------------------------------------------------------------
# encoding helpers
# --------------------------------------------------------------------------

@pytest.mark.security
def test_bytes_to_text():
    assert U.bytes_to_text(b'password') == 'password'
    assert U.bytes_to_text('😺'.encode()) == '😺'
    assert U.bytes_to_text(FAMILY.encode('utf-8')) == FAMILY
    assert U.bytes_to_text(b'\xff\xfe') == '$HEX[fffe]'     # not valid UTF-8 -> lossless marker
    assert U.bytes_to_text(None) is None


@pytest.mark.security
def test_text_from_field():
    assert U.text_from_field('😺') == '😺'
    assert U.text_from_field('café') == 'café'
    # a str carrying surrogate-escaped invalid bytes (as produced by reading a
    # non-UTF-8 file with errors='surrogateescape') -> $HEX
    assert U.text_from_field(b'\xff\xfe'.decode('utf-8', 'surrogateescape')) == '$HEX[fffe]'
    assert U.text_from_field(None) is None


@pytest.mark.security
def test_hexplain_to_text():
    assert U.hexplain_to_text('70617373776f7264') == 'password'   # hashcat hex_plain
    assert U.hexplain_to_text('F09F98BA') == '😺'                 # UTF-8 of 😺 (upper hex)
    assert U.hexplain_to_text('fffe') == '$HEX[fffe]'             # binary -> marker
    assert U.hexplain_to_text('not-hex') == 'not-hex'            # defensive fallback


@pytest.mark.security
def test_decode_hex_plain():
    # Inverse of the $HEX[...] marker, used so length/analytics measure the real
    # password rather than the wrapper (issue #291).
    assert U.decode_hex_plain('password') == 'password'           # plain passes through
    assert U.decode_hex_plain('$HEX[' + 'pässwörd'.encode().hex() + ']') == 'pässwörd'
    assert len(U.decode_hex_plain('$HEX[70c3a4737377c3b67264]')) == 8   # not 26
    assert U.decode_hex_plain('$HEX[fffe]') == '\xff\xfe'         # binary -> latin-1 fallback
    assert U.decode_hex_plain('$HEX[zz]') == '$HEX[zz]'           # bad hex -> unchanged
    assert U.decode_hex_plain(None) == ''                         # None -> '' (safe for len())
    # round-trips bytes_to_text for UTF-8 content
    assert U.decode_hex_plain(U.bytes_to_text('café'.encode())) == 'café'


# --------------------------------------------------------------------------
# hashfile import (the reported crash)
# --------------------------------------------------------------------------

@pytest.mark.security
def test_import_hashfile_with_emojis_no_crash(app, tmp_path):
    p = tmp_path / 'emoji.txt'
    p.write_text(
        '😺:%s\n' % NTLM_PW
        + 'Catword😺:%s\n' % NTLM_PW
        + '%s:%s\n' % (FAMILY, NTLM_PW),
        encoding='utf-8',
    )
    assert U.import_hashfilehashes(hashfile_id=1, hashfile_path=str(p),
                                   file_type='user_hash', hash_type='1000') is True
    names = {h.username for h in HashfileHashes.query.filter_by(hashfile_id=1).all()}
    assert names == {'😺', 'Catword😺', FAMILY}     # stored as text, not hex


@pytest.mark.security
def test_import_non_utf8_file_no_crash(app, tmp_path):
    p = tmp_path / 'latin.txt'
    # raw 0xE9 (latin-1 'é') is not valid UTF-8 -> read survives, stored as $HEX
    p.write_bytes(b'\xe9user:%s\n' % NTLM_PW.encode())
    assert U.import_hashfilehashes(hashfile_id=2, hashfile_path=str(p),
                                   file_type='user_hash', hash_type='1000') is True
    u = HashfileHashes.query.filter_by(hashfile_id=2).first().username
    assert u.startswith('$HEX[') and u.endswith(']')


# --------------------------------------------------------------------------
# one-time legacy-hex backfill
# --------------------------------------------------------------------------

@pytest.mark.security
def test_decode_legacy_hex_backfill(app):
    from hashview.setup import decode_legacy_hex_if_needed
    _db.session.add(Settings(passwords_decoded=False))
    _db.session.commit()
    # legacy rows: ascii username (round-trips), latin-1 'café' (-> $HEX), emoji
    # plaintext stored as the agent's utf-8 hex (-> correct text, un-mojibake'd)
    hh_ascii = HashfileHashes(hash_id=1, hashfile_id=1, username='alice'.encode('latin-1').hex())
    hh_latin = HashfileHashes(hash_id=2, hashfile_id=1, username='café'.encode('latin-1').hex())
    h_emoji = Hashes(hash_type=0, sub_ciphertext='0' * 8, ciphertext='aa', cracked=True,
                     plaintext='😺'.encode().hex())
    _db.session.add_all([hh_ascii, hh_latin, h_emoji])
    _db.session.commit()
    ascii_id, latin_id, emoji_id = hh_ascii.id, hh_latin.id, h_emoji.id

    decode_legacy_hex_if_needed(_db)

    assert HashfileHashes.query.get(ascii_id).username == 'alice'
    assert HashfileHashes.query.get(latin_id).username == '$HEX[636166e9]'   # lossless
    assert Hashes.query.get(emoji_id).plaintext == '😺'
    assert Settings.query.first().passwords_decoded is True

    # idempotent: a 2nd run leaves already-decoded values untouched
    decode_legacy_hex_if_needed(_db)
    assert HashfileHashes.query.get(ascii_id).username == 'alice'
    assert Hashes.query.get(emoji_id).plaintext == '😺'


@pytest.mark.security
def test_backfill_leaves_oversized_hex_untouched(app):
    """A legacy hex value that would decode to a $HEX[...] string longer than the
    VARCHAR(256) column must be left as-is (no crash, no data loss, no stall)."""
    from hashview.setup import decode_legacy_hex_if_needed
    _db.session.add(Settings(passwords_decoded=False))
    _db.session.commit()
    # 126 non-UTF-8 bytes -> '$HEX[' + 252 hex + ']' = 258 chars > 256 column limit
    big_hex = 'ff' * 126
    assert len(big_hex) <= 256                      # the hex itself still fits to insert
    hh = HashfileHashes(hash_id=1, hashfile_id=1, username=big_hex)
    _db.session.add(hh)
    _db.session.commit()

    decode_legacy_hex_if_needed(_db)                # must not raise

    assert HashfileHashes.query.get(hh.id).username == big_hex   # preserved as hex
    assert Settings.query.first().passwords_decoded is True      # backfill still completed


@pytest.mark.security
def test_backfill_skipped_when_flag_set(app):
    from hashview.setup import decode_legacy_hex_if_needed
    _db.session.add(Settings(passwords_decoded=True))      # fresh install
    _db.session.commit()
    hh = HashfileHashes(hash_id=1, hashfile_id=1, username='deadbeef')  # valid hex, but already text
    _db.session.add(hh)
    _db.session.commit()
    decode_legacy_hex_if_needed(_db)
    assert HashfileHashes.query.get(hh.id).username == 'deadbeef'       # untouched (flag was set)


# --------------------------------------------------------------------------
# searchability
# --------------------------------------------------------------------------

@pytest.mark.security
def test_unicode_username_searchable(app):
    _db.session.add(HashfileHashes(hash_id=1, hashfile_id=9, username='😺Catword'))
    _db.session.commit()
    found = HashfileHashes.query.filter(HashfileHashes.username.like('%😺%')).all()
    assert len(found) == 1 and found[0].username == '😺Catword'
