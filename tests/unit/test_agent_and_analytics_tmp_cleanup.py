"""Regression tests for #421/#424: agent and analytics downloads must not leave files in control/tmp.

Agent download uses tarfile instead of os.system, and analytics downloads stream
instead of writing to disk. Both must clean up or never touch control/tmp.
"""

import os

from hashview.models import (
    Customers,
    Hashes,
    HashfileHashes,
    Hashfiles,
    Users,
    db,
)


def _admin(email=None):
    """Create and return an admin user."""
    if email is None:
        email = "a@e.com"
    u = Users(
        first_name="A",
        last_name="D",
        email_address=email,
        password="x" * 60,
        admin=True,
    )
    db.session.add(u)
    db.session.commit()
    return u


def _login(client, user):
    """Log in a user."""
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True


def _tmp_dir_entries(app):
    """Snapshot the current contents of control/tmp."""
    return set(os.listdir(os.path.join(app.root_path, "control", "tmp")))


def _seed_analytics(owner_id=None):
    """Create a customer, hashfile, and some hashes for analytics tests."""
    customer = Customers(name="test_customer")
    db.session.add(customer)
    db.session.commit()

    if owner_id is None:
        owner_id = _admin(email="analytics_seed@e.com").id

    hashfile = Hashfiles(name="test_hashfile", customer_id=customer.id, owner_id=owner_id)
    db.session.add(hashfile)
    db.session.commit()

    # Add both cracked and uncracked hashes
    for i, (ct, pt) in enumerate([
        ("aaa111", "Password1"),
        ("bbb222", "SecretPass"),
        ("ccc333", None),
    ]):
        h = Hashes(
            sub_ciphertext=f"{i}" * 8,
            ciphertext=ct,
            hash_type=1000,
            cracked=pt is not None,
            plaintext=pt,
        )
        db.session.add(h)
        db.session.commit()
        db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hashfile.id))
        db.session.commit()

    return customer, hashfile


# ---------------------------------------------------------------------------
# Agent download
# ---------------------------------------------------------------------------


def test_agent_download_leaves_no_temp_files(app, client):
    """Agent download builds the tarball in memory and streams it without
    ever touching control/tmp.

    The filename is deterministic (hashview-agent.<version>.tgz), so a plain
    before/after set comparison is vacuously true if a prior run already left
    that exact file behind -- which is exactly how the original disk-based
    implementation's leak (write path and send_generated_file's delete path
    disagreed on 'hashview/control/tmp/...' vs 'control/tmp/...", so the
    unlink silently no-op'd on FileNotFoundError) went undetected. Assert the
    specific filename is absent both before and after, not just that the two
    snapshots match.
    """
    import hashview

    user = _admin()
    _login(client, user)

    expected_name = f"hashview-agent.{hashview.__version__}.tgz"
    tmp_dir = os.path.join(app.root_path, "control", "tmp")
    stale = os.path.join(tmp_dir, expected_name)
    if os.path.exists(stale):
        os.remove(stale)  # clean up a leak from a previous (buggy) run

    before = _tmp_dir_entries(app)
    assert expected_name not in before

    resp = client.get("/agents/download")

    after = _tmp_dir_entries(app)

    assert resp.status_code == 200
    assert resp.data[:2] == b"\x1f\x8b"  # gzip magic bytes
    assert expected_name not in after, (
        f"{expected_name} was left in control/tmp -- the agent download "
        "wrote it to disk instead of building it in memory"
    )
    assert before == after, f"Agent download left new files: {after - before}"


# ---------------------------------------------------------------------------
# Analytics downloads
# ---------------------------------------------------------------------------


def test_analytics_download_hashes_leaves_no_temp_files(app, client):
    """Analytics hash download (type=found) streams without touching disk."""
    user = _admin(email="analytics_found@e.com")
    _login(client, user)
    customer, hashfile = _seed_analytics(owner_id=user.id)

    before = _tmp_dir_entries(app)
    resp = client.get(
        f"/analytics/download?type=found&customer_id={customer.id}&hashfile_id={hashfile.id}"
    )
    after = _tmp_dir_entries(app)

    assert resp.status_code == 200
    assert b"Password1" in resp.data
    # No new files should be left behind
    assert before == after, f"Analytics download left new files: {after - before}"


def test_analytics_download_hashes_left_leaves_no_temp_files(app, client):
    """Analytics hash download (type=left) streams without touching disk."""
    user = _admin(email="analytics_left@e.com")
    _login(client, user)
    customer, hashfile = _seed_analytics(owner_id=user.id)

    before = _tmp_dir_entries(app)
    resp = client.get(
        f"/analytics/download?type=left&customer_id={customer.id}&hashfile_id={hashfile.id}"
    )
    after = _tmp_dir_entries(app)

    assert resp.status_code == 200
    assert b"ccc333" in resp.data  # uncracked hash
    # No new files should be left behind
    assert before == after, f"Analytics download left new files: {after - before}"


def test_analytics_download_fig8_leaves_no_temp_files(app, client):
    """Analytics fig8 (password == username) download streams without touching disk."""
    user = _admin(email="analytics_fig8@e.com")
    _login(client, user)

    # Create a hashfile with a user whose password matches username
    customer = Customers(name="test_customer_fig8")
    db.session.add(customer)
    db.session.commit()

    hashfile = Hashfiles(name="test_hashfile_fig8", customer_id=customer.id, owner_id=user.id)
    db.session.add(hashfile)
    db.session.commit()

    h = Hashes(
        sub_ciphertext="0" * 8,
        ciphertext="aaa111",
        hash_type=1000,
        cracked=True,
        plaintext="testuser",  # password = username
    )
    db.session.add(h)
    db.session.commit()

    db.session.add(HashfileHashes(
        hash_id=h.id,
        hashfile_id=hashfile.id,
        username="testuser",
    ))
    db.session.commit()

    before = _tmp_dir_entries(app)
    resp = client.get(f"/analytics/download/fig8?customer_id={customer.id}")
    after = _tmp_dir_entries(app)

    assert resp.status_code == 200
    assert b"testuser" in resp.data
    # No new files should be left behind
    assert before == after, f"Analytics fig8 download left new files: {after - before}"


def test_analytics_download_fig9_leaves_no_temp_files(app, client):
    """Analytics fig9 (shared passwords) download streams without touching disk."""
    user = _admin(email="analytics_fig9@e.com")
    _login(client, user)

    # Create a hashfile with accounts that share the same hash
    customer = Customers(name="test_customer_fig9")
    db.session.add(customer)
    db.session.commit()

    hashfile = Hashfiles(name="test_hashfile_fig9", customer_id=customer.id, owner_id=user.id)
    db.session.add(hashfile)
    db.session.commit()

    # Create one hash that is referenced by two usernames (shared password scenario)
    h = Hashes(
        sub_ciphertext="0" * 8,
        ciphertext="aaa111",
        hash_type=1000,
        cracked=True,
        plaintext="SharedPass",
    )
    db.session.add(h)
    db.session.commit()

    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hashfile.id, username="user1"))
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hashfile.id, username="user2"))
    db.session.commit()

    before = _tmp_dir_entries(app)
    resp = client.get(f"/analytics/download/fig9?customer_id={customer.id}")
    after = _tmp_dir_entries(app)

    assert resp.status_code == 200
    # Both usernames share the one password, so both must be present.
    assert b"user1" in resp.data
    assert b"user2" in resp.data
    # No new files should be left behind
    assert before == after, f"Analytics fig9 download left new files: {after - before}"
