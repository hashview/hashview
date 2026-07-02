"""Tests for POST /v1/hashes/import/<hash_type> (NTLM cracked-hash import).

Two bugs made NTLM import silently do nothing on main:

1. The route compared the ``<int:hash_type>`` URL arg to the *string* '1000'
   (``hash_type == '1000'``), which is always False, so every request fell
   through to ``403 'Unsupported Hashtype'``. Clients that only look for a
   response reported this as "Success: Unsupported Hashtype" and no hashes
   were ever marked cracked.
2. Even past that, the import loop treated the plaintext as a list
   (``line.split(':')[1:]``) and hashed via ``hashlib.new('md4', ...)``,
   which raises on OpenSSL 3.x builds without the legacy provider.

These tests pin the NTLM hashing helper against a known vector (exercising
the pure-Python MD4 fallback) and verify the endpoint actually marks a
matching uncracked hash as cracked.
"""

import pytest

from hashview.models import db, Hashes, Users
from hashview.utils.utils import ntlm_hash_hex, get_md5_hash


# NTLM("password") — canonical test vector.
KNOWN_PLAINTEXT = "password"
KNOWN_NTLM = "8846F7EAEE8FB117AD06BDD830B7586C"
# hashcat emits NTLM hashes in lowercase hex; Hashview stores/serves them the
# same way. The import compare must be case-insensitive against ntlm_hash_hex,
# which returns uppercase.
KNOWN_NTLM_LOWER = KNOWN_NTLM.lower()


def test_ntlm_hash_hex_matches_known_vector():
    assert ntlm_hash_hex(KNOWN_PLAINTEXT) == KNOWN_NTLM


def test_ntlm_hash_hex_handles_unicode():
    # UTF-16LE(MD4) of a non-ASCII password must not raise and must be stable.
    digest = ntlm_hash_hex("pässwörd")
    assert len(digest) == 32
    assert digest == ntlm_hash_hex("pässwörd")


@pytest.fixture()
def seeded(app):
    """One uncracked NTLM hash whose ciphertext is NTLM('password')."""
    with app.app_context():
        user = Users(
            first_name="Api",
            last_name="User",
            email_address="api@example.com",
            password="x",
            admin=True,
            api_key="test-api-key",
        )
        db.session.add(user)
        db.session.commit()

        h = Hashes(
            sub_ciphertext=get_md5_hash(KNOWN_NTLM),
            ciphertext=KNOWN_NTLM,
            hash_type=1000,
            cracked=False,
        )
        db.session.add(h)
        db.session.commit()
        return {"api_key": user.api_key, "hash_id": h.id, "user_id": user.id}


def test_import_marks_hash_cracked(client, seeded, app):
    client.set_cookie("uuid", seeded["api_key"])
    resp = client.post(
        "/v1/hashes/import/1000",
        data=f"{KNOWN_NTLM}:{KNOWN_PLAINTEXT}\n",
        content_type="text/plain",
    )
    body = resp.get_json()
    assert body["status"] == 200, body
    assert body["msg"] == "OK"
    with app.app_context():
        h = Hashes.query.get(seeded["hash_id"])
        assert h.cracked
        assert h.recovered_by == seeded["user_id"]
        # main stores plaintext as latin-1 hex; decode to verify round-trip.
        assert bytes.fromhex(h.plaintext).decode("latin-1") == KNOWN_PLAINTEXT


@pytest.fixture()
def seeded_lowercase(app):
    """One uncracked NTLM hash stored in lowercase hex, as hashcat/Hashview do."""
    with app.app_context():
        user = Users(
            first_name="Api",
            last_name="User",
            email_address="lower@example.com",
            password="x",
            admin=True,
            api_key="test-api-key-lower",
        )
        db.session.add(user)
        db.session.commit()

        h = Hashes(
            sub_ciphertext=get_md5_hash(KNOWN_NTLM_LOWER),
            ciphertext=KNOWN_NTLM_LOWER,
            hash_type=1000,
            cracked=False,
        )
        db.session.add(h)
        db.session.commit()
        return {"api_key": user.api_key, "hash_id": h.id, "user_id": user.id}


def test_import_marks_hash_cracked_lowercase_hash(client, seeded_lowercase, app):
    """Regression: a lowercase hash (as hashcat emits) must verify and import.

    ntlm_hash_hex returns uppercase hex, so a case-sensitive compare rejected
    every real hashcat upload with 'Plaintext ... was found to be invalid.'
    """
    client.set_cookie("uuid", seeded_lowercase["api_key"])
    resp = client.post(
        "/v1/hashes/import/1000",
        data=f"{KNOWN_NTLM_LOWER}:{KNOWN_PLAINTEXT}\n",
        content_type="text/plain",
    )
    body = resp.get_json()
    assert body["status"] == 200, body
    assert body["msg"] == "OK"
    with app.app_context():
        h = Hashes.query.get(seeded_lowercase["hash_id"])
        assert h.cracked
        assert h.recovered_by == seeded_lowercase["user_id"]


def test_import_rejects_unsupported_hash_type(client, seeded):
    client.set_cookie("uuid", seeded["api_key"])
    resp = client.post(
        "/v1/hashes/import/9999",
        data="deadbeef:whatever\n",
        content_type="text/plain",
    )
    body = resp.get_json()
    assert body["status"] == 403
    assert body["msg"] == "Unsupported Hashtype"
