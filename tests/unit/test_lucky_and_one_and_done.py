"""Unit tests for two job-lifecycle features.

1. ``GET /jobs/<job_id>/assign_task/lucky`` (hashview.jobs.routes)
   should add JobTasks for the historically most effective tasks of the
   hashfile's hash_type — i.e. it should look up tasks that previously
   recovered the most hashes of the same hash_type, and append them.

2. ``POST /v1/uploadCrackFile/<job_task_id>`` (hashview.api.routes) is the
   route an agent calls when it recovers hashes. When the job has
   ``limit_recovered`` set ("one-and-done") and at least one hash was
   recovered, all of the job's JobTasks should be canceled.

Both tests use the in-memory SQLite fixtures from
``tests/unit/conftest.py`` and are marked ``@pytest.mark.security`` so
the parent autouse fixtures (Playwright live_server) are skipped.
"""

from datetime import datetime

import json

import pytest

from hashview.models import (
    Agents,
    Customers,
    HashfileHashes,
    Hashes,
    Hashfiles,
    JobTasks,
    Jobs,
    Tasks,
    Users,
)
from hashview.utils.utils import get_md5_hash


def _login(client, user_id):
    """Mark the test client session as logged in as ``user_id``."""
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user_id)
        sess["_fresh"] = True


@pytest.mark.security
def test_lucky_assigns_historically_effective_tasks_for_hash_type(
    app, client, db_session
):
    """``/jobs/<id>/assign_task/lucky`` adds the top tasks for the hash_type.

    Seed two historical tasks that previously cracked hashes of hash_type
    1000 (T1 with 3 cracks, T2 with 1 crack). Then create a new Job whose
    hashfile contains a single uncracked hash_type=1000 hash, and hit the
    lucky endpoint. Both T1 and T2 must be added as JobTasks for the new
    job, and the response must redirect back to the job's tasks page.
    """
    admin = Users(
        first_name="A",
        last_name="D",
        email_address="admin@example.com",
        password="x" * 60,
        admin=True,
        api_key="k",
    )
    db_session.add(admin)
    db_session.commit()

    cust = Customers(name="X")
    db_session.add(cust)
    db_session.commit()

    hf = Hashfiles(name="hf", customer_id=cust.id, owner_id=admin.id)
    db_session.add(hf)
    db_session.commit()

    # The single uncracked target hash for the job's hashfile. The lucky
    # handler looks this up via HashfileHashes -> Hashes to derive the
    # hash_type used for the "most effective tasks" lookup.
    target_hash = Hashes(
        sub_ciphertext="0" * 32,
        ciphertext="AAA",
        hash_type=1000,
        cracked=False,
    )
    db_session.add(target_hash)
    db_session.commit()

    hfh = HashfileHashes(hash_id=target_hash.id, hashfile_id=hf.id)
    db_session.add(hfh)
    db_session.commit()

    t1 = Tasks(name="T1", owner_id=admin.id, hc_attackmode=0)
    t2 = Tasks(name="T2", owner_id=admin.id, hc_attackmode=0)
    db_session.add_all([t1, t2])
    db_session.commit()

    # Three historical cracks attributed to T1, one to T2 — all hash_type=1000.
    for i in range(3):
        db_session.add(
            Hashes(
                sub_ciphertext=f"{i:032x}",
                ciphertext=f"T1-CT-{i}",
                hash_type=1000,
                cracked=True,
                task_id=t1.id,
            )
        )
    db_session.add(
        Hashes(
            sub_ciphertext="a" * 32,
            ciphertext="T2-CT-0",
            hash_type=1000,
            cracked=True,
            task_id=t2.id,
        )
    )
    db_session.commit()

    job = Jobs(
        name="J",
        owner_id=admin.id,
        customer_id=cust.id,
        hashfile_id=hf.id,
        status="Ready",
    )
    db_session.add(job)
    db_session.commit()

    _login(client, admin.id)

    resp = client.post(
        f"/jobs/{job.id}/assign_task/lucky",
        follow_redirects=False,
    )

    assert resp.status_code in (301, 302, 303, 307, 308)
    location = resp.headers.get("Location", "")
    assert location.endswith(f"/jobs/{job.id}/tasks")

    job_tasks = JobTasks.query.filter_by(job_id=job.id).all()
    assert len(job_tasks) == 2
    assert {jt.task_id for jt in job_tasks} == {t1.id, t2.id}


@pytest.mark.security
def test_lucky_caps_at_ten_tasks_when_more_are_effective(app, client, db_session):
    """``/jobs/<id>/assign_task/lucky`` never adds more than 10 tasks.

    Seed 12 historically effective tasks (T0..T11) for the job's hash_type,
    each with a distinct, decreasing crack count so ordering is
    unambiguous, then hit the lucky endpoint. The query in
    ``jobs_assign_lucky_task_group`` (hashview/jobs/routes.py ~620) is
    hard-coded to ``.limit(10)``, so only the top 10 (T0..T9) should be
    assigned — T10 and T11 must be excluded. This locks in the hard cap of
    10, which is the correct behavior (issue #379's actual bug was the
    button label, previously mismatched at "top 5"; see
    test_jobs_tasks_page_lucky_button_label_matches_backend_top_ten in
    test_jobs_routes.py), so it can't be accidentally made unbounded.
    """
    admin = Users(
        first_name="A",
        last_name="D",
        email_address="admin@example.com",
        password="x" * 60,
        admin=True,
        api_key="k",
    )
    db_session.add(admin)
    db_session.commit()

    cust = Customers(name="X")
    db_session.add(cust)
    db_session.commit()

    hf = Hashfiles(name="hf", customer_id=cust.id, owner_id=admin.id)
    db_session.add(hf)
    db_session.commit()

    target_hash = Hashes(
        sub_ciphertext="0" * 32,
        ciphertext="AAA",
        hash_type=1000,
        cracked=False,
    )
    db_session.add(target_hash)
    db_session.commit()

    hfh = HashfileHashes(hash_id=target_hash.id, hashfile_id=hf.id)
    db_session.add(hfh)
    db_session.commit()

    # 12 distinct tasks, each with a distinct, decreasing crack count of
    # hash_type=1000, so T0 is the most effective and T11 the least.
    tasks = [Tasks(name=f"T{i}", owner_id=admin.id, hc_attackmode=0) for i in range(12)]
    db_session.add_all(tasks)
    db_session.commit()

    for rank, t in enumerate(tasks):
        crack_count = 12 - rank
        for i in range(crack_count):
            db_session.add(
                Hashes(
                    sub_ciphertext=f"{rank:02x}{i:030x}",
                    ciphertext=f"T{rank}-CT-{i}",
                    hash_type=1000,
                    cracked=True,
                    task_id=t.id,
                )
            )
    db_session.commit()

    job = Jobs(
        name="J",
        owner_id=admin.id,
        customer_id=cust.id,
        hashfile_id=hf.id,
        status="Ready",
    )
    db_session.add(job)
    db_session.commit()

    _login(client, admin.id)

    resp = client.post(
        f"/jobs/{job.id}/assign_task/lucky",
        follow_redirects=False,
    )
    assert resp.status_code in (301, 302, 303, 307, 308)

    job_tasks = JobTasks.query.filter_by(job_id=job.id).all()
    assert len(job_tasks) == 10

    assigned_task_ids = {jt.task_id for jt in job_tasks}
    top_ten_ids = {t.id for t in tasks[:10]}
    excluded_ids = {t.id for t in tasks[10:]}
    assert assigned_task_ids == top_ten_ids
    assert assigned_task_ids.isdisjoint(excluded_ids)


@pytest.mark.security
def test_one_and_done_cancels_remaining_tasks_when_hash_recovered(
    app, client, db_session, monkeypatch
):
    """``/v1/uploadCrackFile`` cancels all sibling JobTasks for one-and-done.

    When a job has ``limit_recovered=True`` and a crack-file upload
    recovers at least one hash, every JobTask belonging to the parent
    Job must be transitioned to status ``Canceled`` — including the
    Running task that did the recovering and any Queued siblings.
    """
    # All notification senders now live in hashview.utils.utils (api/routes calls
    # process_recovered_hash_notifications, which dispatches through them). Patch
    # the utils senders so the test never touches the network / mail server.
    monkeypatch.setattr(
        "hashview.utils.utils.send_email", lambda *a, **kw: True
    )
    monkeypatch.setattr(
        "hashview.utils.utils.send_pushover", lambda *a, **kw: None
    )
    monkeypatch.setattr(
        "hashview.utils.utils.send_html_email", lambda *a, **kw: None
    )
    monkeypatch.setattr(
        "hashview.utils.utils.send_slack", lambda *a, **kw: None
    )

    admin = Users(
        first_name="A",
        last_name="D",
        email_address="admin@example.com",
        password="x" * 60,
        admin=True,
        api_key="k",
    )
    db_session.add(admin)
    db_session.commit()

    cust = Customers(name="X")
    db_session.add(cust)
    db_session.commit()

    hf = Hashfiles(name="hf", customer_id=cust.id, owner_id=admin.id)
    db_session.add(hf)
    db_session.commit()

    # The route uppercases the plaintext token from the agent's payload
    # and matches against sub_ciphertext = md5(ciphertext). Both hashes
    # are seeded as uncracked so the route is the one flipping them.
    h1 = Hashes(
        sub_ciphertext=get_md5_hash("AAAA"),
        ciphertext="AAAA",
        hash_type=1000,
        cracked=False,
    )
    h2 = Hashes(
        sub_ciphertext=get_md5_hash("BBBB"),
        ciphertext="BBBB",
        hash_type=1000,
        cracked=False,
    )
    db_session.add_all([h1, h2])
    db_session.commit()

    db_session.add_all([
        HashfileHashes(hash_id=h1.id, hashfile_id=hf.id),
        HashfileHashes(hash_id=h2.id, hashfile_id=hf.id),
    ])
    db_session.commit()

    t1 = Tasks(name="T1", owner_id=admin.id, hc_attackmode=0)
    t2 = Tasks(name="T2", owner_id=admin.id, hc_attackmode=0)
    db_session.add_all([t1, t2])
    db_session.commit()

    started_at = datetime.now()   # a datetime object (SQLite rejects strings in DateTime cols)

    job = Jobs(
        name="J",
        owner_id=admin.id,
        customer_id=cust.id,
        hashfile_id=hf.id,
        status="Running",
        limit_recovered=True,
        started_at=started_at,
    )
    db_session.add(job)
    db_session.commit()

    jt1 = JobTasks(
        job_id=job.id,
        task_id=t1.id,
        status="Running",
        started_at=started_at,
    )
    jt2 = JobTasks(
        job_id=job.id,
        task_id=t2.id,
        status="Queued",
    )
    db_session.add_all([jt1, jt2])
    db_session.commit()

    agent = Agents(
        name="a",
        src_ip="1.1.1.1",
        uuid="agent-uuid-1",
        status="Authorized",
        last_checkin=started_at,
    )
    db_session.add(agent)
    db_session.commit()

    client.set_cookie("uuid", "agent-uuid-1", domain="localhost.test")

    resp = client.post(
        f"/v1/uploadCrackFile/{jt1.id}",
        data=json.dumps({"file": "AAAA:pass"}),
        content_type="application/json",
    )

    assert resp.status_code == 200
    body = json.loads(resp.get_data(as_text=True))
    assert body["msg"] == "OK"

    db_session.refresh(h1)
    assert h1.cracked == 1

    job_tasks = JobTasks.query.filter_by(job_id=job.id).all()
    assert job_tasks, "expected JobTasks rows to still exist after cancel"
    for jt in job_tasks:
        assert jt.status == "Canceled"
