"""Regression tests for the job "alert hashes" page
(GET /jobs/<id>/notifications/<method>/hashes -> jobs_assign_notification_hashes).

The page lists a job's uncracked hashes with a checkbox per hash, pre-checking
the ones the current user already has a notification for. The pre-check used to
be a nested template loop over a LAZY HashNotifications query, re-executed once
per hash -> O(hashes x notifications), which pegged the server (6.5 GB / a full
core) for a user with many notifications. The route now passes a materialized
SET of notified hash_ids and the template does an O(1) membership test.

These pin the rendered behavior: a checkbox per hash, the right ones pre-checked,
and exactly one checkbox per hash even when it has notifications on >1 channel.
"""

import pytest

from hashview.models import (
    Hashes,
    HashfileHashes,
    Hashfiles,
    HashNotifications,
    Jobs,
    db,
)
from tests.unit.helpers import login, make_admin, make_customer


def _seed_job_with_hashes(owner, n=3):
    """A job over a hashfile with n uncracked hashes; returns (job, [Hashes])."""
    cust = make_customer()
    hf = Hashfiles(name="hf", customer_id=cust.id, owner_id=owner.id)
    db.session.add(hf)
    db.session.commit()
    job = Jobs(name="j", owner_id=owner.id, customer_id=cust.id,
               hashfile_id=hf.id, status="Ready", priority=3)
    db.session.add(job)
    db.session.commit()
    hashes = []
    for i in range(n):
        h = Hashes(sub_ciphertext=f"{i:032x}", ciphertext=f"cipher{i}",
                   hash_type=1000, cracked=False)
        db.session.add(h)
        db.session.commit()
        db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id,
                                      username=f"user{i}"))
        hashes.append(h)
    db.session.commit()
    return job, hashes


@pytest.mark.security
def test_alert_hashes_prechecks_only_notified_hashes(app, client):
    admin = make_admin()
    job, hashes = _seed_job_with_hashes(admin, n=3)
    notified, plain1, plain2 = hashes
    # admin already has an email notification on the first hash only
    db.session.add(HashNotifications(owner_id=admin.id, hash_id=notified.id, method="email"))
    db.session.commit()

    login(client, admin)
    resp = client.get(f"/jobs/{job.id}/notifications/email/hashes")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)

    # one checkbox per hash
    for h in hashes:
        assert f'value="{h.id}"' in html
    # the notified hash is pre-checked; the others are not
    assert f'value="{notified.id}" checked' in html
    assert f'value="{plain1.id}" checked' not in html
    assert f'value="{plain2.id}" checked' not in html


@pytest.mark.security
def test_alert_hashes_one_checkbox_even_with_multiple_channels(app, client):
    # A hash notified on >1 channel must still render exactly ONE checkbox
    # (the old nested loop emitted one per matching notification row).
    admin = make_admin()
    job, hashes = _seed_job_with_hashes(admin, n=1)
    h = hashes[0]
    for m in ("email", "push", "slack"):
        db.session.add(HashNotifications(owner_id=admin.id, hash_id=h.id, method=m))
    db.session.commit()

    login(client, admin)
    resp = client.get(f"/jobs/{job.id}/notifications/email,push,slack/hashes")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert html.count(f'value="{h.id}"') == 1
    assert f'value="{h.id}" checked' in html


@pytest.mark.security
def test_alert_hashes_ignores_other_users_notifications(app, client):
    # Pre-check must be scoped to the current user: another user's notification
    # on the same hash must NOT pre-check it here.
    admin = make_admin()
    other = make_admin(email="other@example.com")
    job, hashes = _seed_job_with_hashes(admin, n=1)
    h = hashes[0]
    db.session.add(HashNotifications(owner_id=other.id, hash_id=h.id, method="email"))
    db.session.commit()

    login(client, admin)
    resp = client.get(f"/jobs/{job.id}/notifications/email/hashes")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert f'value="{h.id}"' in html
    assert f'value="{h.id}" checked' not in html      # other user's notif doesn't count
