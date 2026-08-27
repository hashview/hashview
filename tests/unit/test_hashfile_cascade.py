"""Hashfile delete cascade tests.

CHANGELOG v0.8.2 claims hashfile deletion "properly cascades through all
related records" and explicitly calls out that the prior implementation
"removed hashes that belonged to other hashfiles". These tests pin that:

1. Deleting hashfile A removes its own HashfileHashes rows.
2. A hash that was *only* referenced by A and is uncracked gets pruned.
3. A hash that was *shared* with hashfile B must SURVIVE (the bug fixed).
4. A *cracked* hash referenced only by A must SURVIVE (cracked hashes are
   user-valuable and not cascaded).
"""

import pytest

from hashview.models import (
    Customers,
    Hashes,
    HashfileHashes,
    Hashfiles,
    Jobs,
    Users,
    db,
)


def _make_admin():
    admin = Users(
        first_name="A",
        last_name="D",
        email_address="admin@example.com",
        password="x" * 60,
        admin=True,
    )
    db.session.add(admin)
    db.session.commit()
    return admin


def _make_user(email="user@example.com"):
    u = Users(first_name="U", last_name="U", email_address=email,
              password="x" * 60, admin=False)
    db.session.add(u)
    db.session.commit()
    return u


def _make_customer():
    c = Customers(name="X")
    db.session.add(c)
    db.session.commit()
    return c


def _login(client, user_id):
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user_id)
        sess["_fresh"] = True


@pytest.mark.security
def test_hashfile_delete_keeps_shared_hash_and_cracked_hash(app, client):
    admin = _make_admin()
    cust = _make_customer()

    # Two hashfiles
    hf_a = Hashfiles(name="A", customer_id=cust.id, owner_id=admin.id)
    hf_b = Hashfiles(name="B", customer_id=cust.id, owner_id=admin.id)
    db.session.add_all([hf_a, hf_b])
    db.session.commit()

    # Three hashes:
    #   only_in_a_uncracked    — should be pruned when A is deleted
    #   shared_a_and_b         — must survive (was the bug)
    #   only_in_a_cracked      — must survive (cracked hashes are user data)
    only_a = Hashes(sub_ciphertext="0" * 32, ciphertext="aaaa",
                    hash_type=0, cracked=False)
    shared = Hashes(sub_ciphertext="1" * 32, ciphertext="bbbb",
                    hash_type=0, cracked=False)
    cracked = Hashes(sub_ciphertext="2" * 32, ciphertext="cccc",
                     hash_type=0, cracked=True, plaintext="70617373")  # 'pass'
    db.session.add_all([only_a, shared, cracked])
    db.session.commit()

    db.session.add_all([
        HashfileHashes(hashfile_id=hf_a.id, hash_id=only_a.id),
        HashfileHashes(hashfile_id=hf_a.id, hash_id=shared.id),
        HashfileHashes(hashfile_id=hf_b.id, hash_id=shared.id),
        HashfileHashes(hashfile_id=hf_a.id, hash_id=cracked.id),
    ])
    db.session.commit()

    only_a_id = only_a.id
    shared_id = shared.id
    cracked_id = cracked.id
    hf_a_id = hf_a.id
    hf_b_id = hf_b.id

    _login(client, admin.id)
    resp = client.post(f"/hashfiles/delete/{hf_a_id}", follow_redirects=False)
    assert resp.status_code in (200, 302)

    # Hashfile A is gone; hashfile B remains.
    assert Hashfiles.query.get(hf_a_id) is None
    assert Hashfiles.query.get(hf_b_id) is not None

    # The shared hash MUST survive (the original bug).
    assert Hashes.query.get(shared_id) is not None, (
        "Shared hash was deleted with hashfile A — cascade bug regression."
    )
    # B's HashfileHashes link to it must also survive.
    assert HashfileHashes.query.filter_by(
        hashfile_id=hf_b_id, hash_id=shared_id
    ).first() is not None

    # The cracked-only-in-A hash must also survive.
    assert Hashes.query.get(cracked_id) is not None, (
        "Cracked hash should never be cascade-deleted by a hashfile delete."
    )

    # The orphan uncracked hash that A solely owned should be pruned.
    assert Hashes.query.get(only_a_id) is None


# ---------------------------------------------------------------------------
# Bulk delete (issue #311)
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_bulk_delete_deletes_free_and_skips_in_job(app, client):
    """Free hashfiles are deleted; one attached to a job is skipped, and the
    flash reports a per-outcome summary (batch not aborted on the skip)."""
    admin = _make_admin()
    cust = _make_customer()
    free = Hashfiles(name="free", customer_id=cust.id, owner_id=admin.id)
    locked = Hashfiles(name="locked", customer_id=cust.id, owner_id=admin.id)
    db.session.add_all([free, locked])
    db.session.commit()
    db.session.add(Jobs(name="j", status="Running", customer_id=cust.id,
                        owner_id=admin.id, hashfile_id=locked.id))
    db.session.commit()
    free_id, locked_id = free.id, locked.id

    _login(client, admin.id)
    resp = client.post("/hashfiles/bulk_delete",
                       data={"hashfile_ids": [str(free_id), str(locked_id)]},
                       follow_redirects=True)
    assert resp.status_code == 200
    assert b"1 deleted" in resp.data
    assert b"associated with a job" in resp.data
    assert Hashfiles.query.get(free_id) is None          # free deleted
    assert Hashfiles.query.get(locked_id) is not None    # in-job retained


@pytest.mark.security
def test_bulk_delete_reuses_cascade(app, client):
    """Bulk delete applies the same cascade as single delete: orphaned uncracked
    hashes pruned, cracked hashes retained."""
    admin = _make_admin()
    cust = _make_customer()
    hf = Hashfiles(name="bulk", customer_id=cust.id, owner_id=admin.id)
    db.session.add(hf)
    db.session.commit()
    unc = Hashes(sub_ciphertext="0" * 32, ciphertext="a", hash_type=0, cracked=False)
    crk = Hashes(sub_ciphertext="1" * 32, ciphertext="b", hash_type=0,
                 cracked=True, plaintext="70617373")
    db.session.add_all([unc, crk])
    db.session.commit()
    db.session.add_all([
        HashfileHashes(hashfile_id=hf.id, hash_id=unc.id),
        HashfileHashes(hashfile_id=hf.id, hash_id=crk.id),
    ])
    db.session.commit()
    hf_id, unc_id, crk_id = hf.id, unc.id, crk.id

    _login(client, admin.id)
    resp = client.post("/hashfiles/bulk_delete",
                       data={"hashfile_ids": [str(hf_id)]}, follow_redirects=True)
    assert resp.status_code == 200
    assert Hashfiles.query.get(hf_id) is None
    assert Hashes.query.get(unc_id) is None       # orphaned uncracked pruned
    assert Hashes.query.get(crk_id) is not None    # cracked retained


@pytest.mark.security
def test_bulk_delete_skips_non_owned(app, client):
    """A non-admin cannot bulk-delete a hashfile they don't own."""
    admin = _make_admin()
    cust = _make_customer()
    other = _make_user("other@example.com")
    hf = Hashfiles(name="admins", customer_id=cust.id, owner_id=admin.id)
    db.session.add(hf)
    db.session.commit()
    hf_id = hf.id

    _login(client, other.id)
    resp = client.post("/hashfiles/bulk_delete",
                       data={"hashfile_ids": [str(hf_id)]}, follow_redirects=True)
    assert resp.status_code == 200
    assert b"insufficient rights" in resp.data
    assert Hashfiles.query.get(hf_id) is not None


@pytest.mark.security
def test_bulk_delete_empty_selection(app, client):
    """Posting no ids reports nothing to do rather than erroring."""
    admin = _make_admin()
    _login(client, admin.id)
    resp = client.post("/hashfiles/bulk_delete", data={}, follow_redirects=True)
    assert resp.status_code == 200
    assert b"No hashfiles selected" in resp.data
