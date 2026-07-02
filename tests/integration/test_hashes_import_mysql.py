"""MySQL/MariaDB integration coverage for the cracked-hash import lookup.

The unit suite (``tests/unit/test_api_endpoints.py``) exercises the full
``POST /v1/hashes/import/<hash_type>`` handler, but only against in-memory
SQLite. SQLite's default text comparison is case-SENSITIVE while MySQL's
default collation is case-INSENSITIVE, and the import's correctness hinges on
how the ``ciphertext`` / ``sub_ciphertext`` columns round-trip and compare on
the real engine.

These tests pin the DB-dialect behaviour the SQLite suite can't see: a hash
stored LOWERCASED (as the hashfile import path stores it) is still found and
marked cracked when the submitted ciphertext is UPPERCASE — the exact
lookup+update ``v1_api_hashes_import`` performs. This guards the
case-normalisation fix (look up on ``ciphertext.lower()``) against a real
MySQL backend.

Marked ``mysql`` and gated on ``HASHVIEW_TEST_DATABASE_URI`` via the
``mysql_session`` fixture, so a normal local ``pytest tests/`` run collects but
skips them (mirroring ``test_mysql_smoke.py``).
"""

import pytest

pytestmark = pytest.mark.mysql

# Pinned vectors (identical to the unit suite's constants).
NTLM_PASSWORD_HASH = "8846F7EAEE8FB117AD06BDD830B7586C"   # NTLM("password")
MD5_PASSWORD = "5f4dcc3b5aa765d61d8327deb882cf99"         # MD5(b"password")
# MSSQL 2012/2014 of 'Password1' with salt 1234abcd; SHA512(utf16le(pw)+salt).
MSSQL_PASSWORD1 = (
    "0x02001234abcd7e4913c2b5c68839b47533dabb696065dc8a67938aad08ffee049633"
    "c034bd1ce2a3cc474dd7b0095cf6f81a304f976764be5ba86909b0cb7b9540ee19128441"
)

# (hash_type, canonical_ciphertext, plaintext) — one raw-hex, one salted-inline,
# one NTLM, covering the distinct verifier shapes.
_CASES = [
    (1000, NTLM_PASSWORD_HASH, "password"),
    (1731, MSSQL_PASSWORD1, "Password1"),
    (0, MD5_PASSWORD, "password"),
]


@pytest.mark.parametrize("hash_type,ciphertext,plaintext", _CASES)
def test_import_lookup_and_update_round_trip_on_mysql(
    mysql_session, hash_type, ciphertext, plaintext
):
    """Reproduce the import lookup+update against real MySQL for an UPPERCASE
    submission of a hash stored lowercased.

    Mirrors ``hashview.api.routes.v1_api_hashes_import``: verify the plaintext
    with the production verifier, look the record up by
    ``get_md5_hash(ciphertext.lower())``, and mark it cracked.
    """
    from hashview.models import Hashes
    from hashview.utils.utils import get_cracked_hash_verifier, get_md5_hash

    lower = ciphertext.lower()
    record = Hashes(
        sub_ciphertext=get_md5_hash(lower),
        ciphertext=lower,
        hash_type=hash_type,
        cracked=False,
    )
    mysql_session.add(record)
    mysql_session.commit()

    # A user pasting hashcat/tooling output may submit the hash UPPERCASE.
    submitted = ciphertext.upper()

    verifier = get_cracked_hash_verifier(hash_type)
    assert verifier is not None
    assert verifier(plaintext, submitted)

    # Exactly the lookup v1_api_hashes_import runs, on the live engine.
    found = Hashes.query.filter_by(
        hash_type=hash_type,
        sub_ciphertext=get_md5_hash(submitted.lower()),
        cracked="0",
    ).first()
    assert found is not None, "lowercased-stored hash not found for uppercase submission"
    assert found.id == record.id

    found.plaintext = plaintext
    found.cracked = 1
    mysql_session.commit()

    refetched = Hashes.query.get(record.id)
    assert refetched.cracked
    assert refetched.plaintext == plaintext


def test_wrong_plaintext_is_not_matched_on_mysql(mysql_session):
    """An unverifiable plaintext must never resolve to a stored hash: the
    verifier rejects it, so the import would 500 and commit nothing."""
    from hashview.utils.utils import get_cracked_hash_verifier

    verifier = get_cracked_hash_verifier(0)
    assert verifier is not None
    assert not verifier("not-the-password", MD5_PASSWORD)
