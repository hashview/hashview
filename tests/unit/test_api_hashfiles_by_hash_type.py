"""Tests for GET /v1/hashfiles/hash_type/<hash_type>.

Backported from v0.8.3-dev. API clients use this endpoint to discover which
hashfiles hold hashes of a given hash_type (with total/cracked counts) so they
can pick one to build a job against instead of hardcoding an ID. main lacked
the endpoint, so those clients 404'd and fell back to manual ID entry.
"""

import json

import pytest

from hashview.models import (
    db,
    Customers,
    HashfileHashes,
    Hashes,
    Hashfiles,
    Users,
)


@pytest.fixture()
def seeded(app):
    """Two hashfiles: one holds NTLM (type 1000) hashes (one cracked, one not),
    the other holds only an md5 (type 0) hash. Lets us assert filtering and the
    per-type total/cracked counts."""
    with app.app_context():
        user = Users(
            first_name="Api",
            last_name="User",
            email_address="api@example.com",
            password="x",
            admin=True,
            api_key="test-api-key",
        )
        customer = Customers(name="Acme")
        db.session.add_all([user, customer])
        db.session.commit()

        ntlm_file = Hashfiles(name="ntlm", customer_id=customer.id, owner_id=user.id)
        md5_file = Hashfiles(name="md5", customer_id=customer.id, owner_id=user.id)
        db.session.add_all([ntlm_file, md5_file])
        db.session.commit()

        h1 = Hashes(sub_ciphertext="a", ciphertext="aa", hash_type=1000, cracked=True)
        h2 = Hashes(sub_ciphertext="b", ciphertext="bb", hash_type=1000, cracked=False)
        h3 = Hashes(sub_ciphertext="c", ciphertext="cc", hash_type=0, cracked=False)
        db.session.add_all([h1, h2, h3])
        db.session.commit()
        db.session.add_all([
            HashfileHashes(hash_id=h1.id, hashfile_id=ntlm_file.id),
            HashfileHashes(hash_id=h2.id, hashfile_id=ntlm_file.id),
            HashfileHashes(hash_id=h3.id, hashfile_id=md5_file.id),
        ])
        db.session.commit()

        return {
            "api_key": user.api_key,
            "customer_id": customer.id,
            "ntlm_file_id": ntlm_file.id,
            "md5_file_id": md5_file.id,
        }


def test_lists_only_hashfiles_of_that_type_with_counts(client, seeded):
    client.set_cookie("uuid", seeded["api_key"])
    resp = client.get("/v1/hashfiles/hash_type/1000")
    body = resp.get_json()
    assert body["status"] == 200, body
    files = body["hashfiles"]
    assert len(files) == 1
    entry = files[0]
    assert entry["id"] == seeded["ntlm_file_id"]
    assert entry["name"] == "ntlm"
    assert entry["hash_type"] == 1000
    assert entry["total_hashes"] == 2
    assert entry["cracked_hashes"] == 1


def test_returns_empty_list_for_type_with_no_hashfiles(client, seeded):
    client.set_cookie("uuid", seeded["api_key"])
    resp = client.get("/v1/hashfiles/hash_type/9999")
    body = resp.get_json()
    assert body["status"] == 200
    assert body["hashfiles"] == []


def test_requires_authorization(client):
    # No auth cookie -> redirect to the not_authorized route.
    resp = client.get("/v1/hashfiles/hash_type/1000")
    assert resp.status_code in (301, 302)
    assert "/v1/not_authorized" in resp.headers["Location"]
