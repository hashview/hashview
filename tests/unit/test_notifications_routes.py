"""Regression tests for notifications routes/helpers (function-coverage batch)."""

from hashview.models import (
    Hashes,
    HashfileHashes,
    HashNotifications,
    JobNotifications,
    Settings,
    db,
)
from tests.unit.helpers import login, make_admin, make_user


def test_hash_type_names_maps_modes(app):
    from hashview.notifications.routes import _hash_type_names
    names = _hash_type_names()
    assert isinstance(names, dict)
    assert "1000" in names


def test_notifications_list_renders_with_seeded_notification(app, client):
    admin = make_admin()
    login(client, admin)
    db.session.add(Settings(email_enabled=True, pushover_enabled=True, slack_enabled=False))
    h = Hashes(sub_ciphertext="0" * 8, ciphertext="abc", hash_type=1000, cracked=False)
    db.session.add(h)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=1, username="alice"))
    db.session.add(HashNotifications(owner_id=admin.id, hash_id=h.id, method="email"))
    db.session.commit()
    resp = client.get("/notifications")
    assert resp.status_code == 200


# ------------------------------------------------------- bulk delete

def test_notifications_list_shows_bulk_controls(app, client):
    """Both notification tables render a select checkbox and the shared bulk bar."""
    admin = make_admin()
    login(client, admin)
    db.session.add(Settings(email_enabled=True, pushover_enabled=True, slack_enabled=False))
    h = Hashes(sub_ciphertext="0" * 8, ciphertext="abc", hash_type=1000, cracked=True, plaintext="pw")
    db.session.add(h)
    db.session.commit()
    db.session.add(HashNotifications(owner_id=admin.id, hash_id=h.id, method="email"))
    db.session.add(JobNotifications(owner_id=admin.id, job_id=1, method="email"))
    db.session.commit()

    resp = client.get("/notifications")
    assert resp.status_code == 200
    assert b"notif-bulkbar" in resp.data
    assert b'value="job:' in resp.data
    assert b'value="hash:' in resp.data


def test_notifications_bulk_delete_removes_selected(app, client):
    """Owner bulk-deletes a mix of job and hash notifications in one POST."""
    admin = make_admin()
    login(client, admin)
    h = Hashes(sub_ciphertext="0" * 8, ciphertext="abc", hash_type=1000, cracked=True, plaintext="pw")
    db.session.add(h)
    db.session.commit()
    jn = JobNotifications(owner_id=admin.id, job_id=1, method="email")
    hn1 = HashNotifications(owner_id=admin.id, hash_id=h.id, method="email")
    hn2 = HashNotifications(owner_id=admin.id, hash_id=h.id, method="push")
    db.session.add_all([jn, hn1, hn2])
    db.session.commit()

    resp = client.post("/notifications/bulk_delete",
                       data={"notification_ids": [f"job:{jn.id}", f"hash:{hn1.id}", f"hash:{hn2.id}"]},
                       follow_redirects=True)
    assert resp.status_code == 200
    assert b"3 deleted" in resp.data
    assert JobNotifications.query.get(jn.id) is None
    assert HashNotifications.query.get(hn1.id) is None
    assert HashNotifications.query.get(hn2.id) is None


def test_notifications_bulk_delete_enforces_ownership(app, client):
    """A non-admin can only delete their own notifications; forged ids for another
    user's rows (or missing ids) are skipped, and the skips don't abort the batch."""
    owner = make_user()
    other = make_admin(email="other-notif@example.com")
    login(client, owner)
    mine = JobNotifications(owner_id=owner.id, job_id=1, method="email")
    theirs = JobNotifications(owner_id=other.id, job_id=2, method="email")
    db.session.add_all([mine, theirs])
    db.session.commit()

    resp = client.post("/notifications/bulk_delete",
                       data={"notification_ids": [f"job:{mine.id}", f"job:{theirs.id}", "job:999999"]},
                       follow_redirects=True)
    assert resp.status_code == 200
    assert b"1 deleted" in resp.data
    assert b"insufficient rights" in resp.data
    assert b"not found" in resp.data
    assert JobNotifications.query.get(mine.id) is None          # deleted
    assert JobNotifications.query.get(theirs.id) is not None    # protected


def test_notifications_bulk_delete_admin_deletes_any(app, client):
    """An admin can bulk-delete another user's notification."""
    admin = make_admin()
    victim = make_user(email="victim-notif@example.com")
    login(client, admin)
    hn = HashNotifications(owner_id=victim.id, hash_id=1, method="email")
    db.session.add(hn)
    db.session.commit()

    resp = client.post("/notifications/bulk_delete",
                       data={"notification_ids": [f"hash:{hn.id}"]},
                       follow_redirects=True)
    assert resp.status_code == 200
    assert b"1 deleted" in resp.data
    assert HashNotifications.query.get(hn.id) is None


def test_notifications_bulk_delete_none_selected_warns(app, client):
    """Posting nothing flashes a warning rather than an empty success."""
    admin = make_admin()
    login(client, admin)
    resp = client.post("/notifications/bulk_delete", data={}, follow_redirects=True)
    assert resp.status_code == 200
    assert b"No notifications selected" in resp.data
