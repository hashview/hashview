"""Regression tests for hashcat ``$HEX[...]`` support in the crack-import
verifiers (hashview/utils/utils.py).

hashcat wraps a recovered password in ``$HEX[<hex>]`` whenever it contains
bytes that are ambiguous in the plain outfile (leading/trailing whitespace,
delimiters, non-UTF-8 bytes). Before the fix the verifiers hashed the literal
string ``"$HEX[..]"`` and rejected the whole upload with
"Plaintext for hash ... was found to be invalid."
"""

import hashlib

from hashview.utils.utils import (
    _hashcat_hex_bytes,
    get_cracked_hash_verifier,
    ntlm_hash_hex,
)


def _hex(s: bytes) -> str:
    return "$HEX[" + s.hex() + "]"


def test_hashcat_hex_bytes_roundtrip():
    assert _hashcat_hex_bytes("$HEX[4142]") == b"AB"
    assert _hashcat_hex_bytes("plain") is None
    assert _hashcat_hex_bytes("$HEX[zz]") is None  # not valid hex


def test_ntlm_verifier_accepts_hex_with_trailing_space():
    verify = get_cracked_hash_verifier("1000")
    pw = "%032023RC$ "  # trailing space -> hashcat emits $HEX
    ct = ntlm_hash_hex(pw)  # digest of the real password
    assert verify(_hex(pw.encode("latin-1")), ct)
    # literal-string plaintext must NOT verify against the real digest
    assert not verify(_hex(pw.encode("latin-1")), ntlm_hash_hex("wrong"))


def test_ntlm_verifier_accepts_hex_highbyte():
    verify = get_cracked_hash_verifier("1000")
    raw = bytes([0xA8]) + b"33514163Ww"  # 0xA8 is not valid UTF-8 on its own
    # hashcat NTLM zero-extends the raw bytes -> latin-1 code points
    ct = ntlm_hash_hex(raw.decode("latin-1"))
    assert verify(_hex(raw), ct)


def test_md5_verifier_accepts_hex():
    verify = get_cracked_hash_verifier("0")
    raw = b" spaced "  # leading/trailing space
    ct = hashlib.md5(raw).hexdigest()
    assert verify(_hex(raw), ct)


def test_plain_plaintext_still_verifies():
    verify = get_cracked_hash_verifier("1000")
    assert verify("password", "8846F7EAEE8FB117AD06BDD830B7586C")
    assert not verify("password", "0" * 32)
