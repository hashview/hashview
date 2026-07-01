"""Regression test for POST /v1/jobs/add notification creation.

Bug: the route built ``JobNotifications(job_id=..., notify_email=...,
notify_pushover=...)``, but that model only has the columns ``owner_id``,
``job_id`` and ``method``. The bogus kwargs raised a TypeError which the
route's ``except`` turned into an HTTP 500 "Failed to add job" — *after* the
Jobs row had already been committed. So every job created through the API
reported failure and never got its notifications recorded.

The fix builds one ``JobNotifications`` row per requested channel using the
real columns (``owner_id``/``method``). These tests assert the endpoint now
returns 200 and that the expected notification rows exist.
"""

import json

import pytest

from hashview.models import (
    db,
    Customers,
    HashfileHashes,
    Hashes,
    Hashfiles,
    JobNotifications,
    Jobs,
    Tasks,
    Users,
)


@pytest.fixture()
def seeded(app):
    """Seed the minimal object graph so /v1/jobs/add reaches the notification
    block: an api-keyed user, a customer, a hashfile with one hash, and a
    cracked hash attributed to a task (so the 'most effective tasks' query is
    non-empty and the route doesn't bail out early)."""
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

        task = Tasks(name="dict", hc_attackmode=0, owner_id=user.id)
        db.session.add(task)
        db.session.commit()

        hashfile = Hashfiles(name="hf", customer_id=customer.id, owner_id=user.id)
        db.session.add(hashfile)
        db.session.commit()

        cracked = Hashes(
            sub_ciphertext="abc",
            ciphertext="deadbeef",
            hash_type=0,
            cracked=True,
            task_id=task.id,
        )
        db.session.add(cracked)
        db.session.commit()
        db.session.add(HashfileHashes(hash_id=cracked.id, hashfile_id=hashfile.id))
        db.session.commit()

        return {
            "api_key": user.api_key,
            "user_id": user.id,
            "customer_id": customer.id,
            "hashfile_id": hashfile.id,
        }


def _post_job(client, seeded, **extra):
    client.set_cookie("uuid", seeded["api_key"])
    payload = {
        "name": "job1",
        "hashfile_id": seeded["hashfile_id"],
        "customer_id": seeded["customer_id"],
    }
    payload.update(extra)
    return client.post(
        "/v1/jobs/add",
        data=json.dumps(payload),
        content_type="application/json",
    )


def test_jobs_add_with_notifications_returns_200(client, seeded):
    resp = _post_job(client, seeded, notify_email=True, notify_pushover=True)
    body = resp.get_json()
    assert body["status"] == 200, body
    assert body["msg"] == "Job added"


def test_jobs_add_records_requested_channels(client, seeded, app):
    _post_job(client, seeded, notify_email=True, notify_pushover=True)
    with app.app_context():
        rows = JobNotifications.query.all()
        assert {r.method for r in rows} == {"email", "push"}
        assert all(r.owner_id == seeded["user_id"] for r in rows)


def test_jobs_add_without_notifications_creates_none(client, seeded, app):
    resp = _post_job(client, seeded)
    assert resp.get_json()["status"] == 200
    with app.app_context():
        assert JobNotifications.query.count() == 0
        # The job itself must still have been created.
        assert Jobs.query.count() == 1
