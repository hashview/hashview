"""Regression tests for jobs routes (function-coverage batch: jobs).

Covers the 13 previously-uncovered jobs route handlers plus the JobsForm
``validate_job`` validator. Behavior is asserted via status codes, redirects,
and DB side effects against the in-memory app.
"""

import io

from hashview.jobs.forms import JobsForm
from hashview.models import (
    Hashes,
    HashfileHashes,
    Hashfiles,
    JobNotifications,
    Jobs,
    JobTasks,
    Settings,
    TaskGroups,
    Tasks,
    Wordlists,
    db,
)
from hashview.utils.utils import ingest_static_wordlist_file
from tests.unit.helpers import login, make_admin, make_customer


def _job(owner, customer, status="Ready", name="j1", hashfile_id=None):
    job = Jobs(name=name, status=status, owner_id=owner.id,
               customer_id=customer.id, hashfile_id=hashfile_id)
    db.session.add(job)
    db.session.commit()
    return job


def _task(owner, name="t1", wl_id=None, attackmode=0):
    t = Tasks(name=name, hc_attackmode=attackmode, owner_id=owner.id, wl_id=wl_id)
    db.session.add(t)
    db.session.commit()
    return t


def _assign(job, task, status="Not Started", priority=3):
    jt = JobTasks(job_id=job.id, task_id=task.id, status=status, priority=priority)
    db.session.add(jt)
    db.session.commit()
    return jt


def _hashfile_with_hash(customer, owner, cracked=False):
    hf = Hashfiles(name="hf", customer_id=customer.id, owner_id=owner.id)
    db.session.add(hf)
    db.session.commit()
    h = Hashes(sub_ciphertext="0" * 8, ciphertext="abcd", hash_type=0,
               cracked=cracked, plaintext="pw" if cracked else None)
    db.session.add(h)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    db.session.commit()
    return hf, h


def _static_wl(owner, tmp_path, content=b"a\nb\n", name="WL"):
    src = tmp_path / (name + ".txt")
    src.write_bytes(content)
    wl = ingest_static_wordlist_file(str(src), owner.id, name)
    db.session.add(wl)
    db.session.commit()
    return wl


# --- list / add ------------------------------------------------------------

def test_jobs_list_shows_job(app, client):
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    _job(admin, cust, name="VisibleJob")
    resp = client.get("/jobs")
    assert resp.status_code == 200
    assert b"VisibleJob" in resp.data


def test_jobs_add_get_renders(app, client):
    admin = make_admin()
    login(client, admin)
    make_customer()
    resp = client.get("/jobs/add")
    assert resp.status_code == 200


def test_jobs_add_post_creates_job(app, client):
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    Settings(retention_period=0, enabled_job_weights=False)  # ensure a Settings row exists
    db.session.add(Settings(enabled_job_weights=False))
    db.session.commit()
    resp = client.post("/jobs/add", data={
        "name": "BrandNewJob", "priority": "3",
        "customer_id": str(cust.id), "submit": "Next",
    }, follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert Jobs.query.filter_by(name="BrandNewJob").first() is not None


# --- hashfile assignment ---------------------------------------------------

def test_jobs_assigned_hashfile_get_renders(app, client):
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    _hashfile_with_hash(cust, admin)
    job = _job(admin, cust)
    resp = client.get(f"/jobs/{job.id}/assigned_hashfile/")
    assert resp.status_code == 200


def test_jobs_assigned_hashfile_select_existing(app, client):
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    hf, _ = _hashfile_with_hash(cust, admin)
    job = _job(admin, cust)
    resp = client.post(f"/jobs/{job.id}/assigned_hashfile/",
                       data={"hashfile_id": str(hf.id)}, follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert Jobs.query.get(job.id).hashfile_id == hf.id


def test_jobs_assigned_hashfile_cracked_flashes_count(app, client):
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    hf, _ = _hashfile_with_hash(cust, admin, cracked=True)
    job = _job(admin, cust, hashfile_id=hf.id)
    resp = client.get(f"/jobs/{job.id}/assigned_hashfile/{hf.id}",
                      follow_redirects=True)
    assert resp.status_code == 200
    assert b"instacracked" in resp.data


# --- task listing / assignment ---------------------------------------------

def test_jobs_list_tasks_renders(app, client):
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    job = _job(admin, cust)
    _task(admin, name="AvailableTask")
    resp = client.get(f"/jobs/{job.id}/tasks")
    assert resp.status_code == 200
    assert b"AvailableTask" in resp.data


def test_jobs_assign_task_creates_jobtask(app, client):
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    job = _job(admin, cust)
    task = _task(admin)
    resp = client.post(f"/jobs/{job.id}/assign_task/{task.id}", follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert JobTasks.query.filter_by(job_id=job.id, task_id=task.id).count() == 1


def test_jobs_assign_task_group_creates_one_per_task(app, client):
    import json
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    job = _job(admin, cust)
    t1, t2 = _task(admin, name="g1"), _task(admin, name="g2")
    tg = TaskGroups(name="grp", owner_id=admin.id,
                    tasks=json.dumps([t1.id, t2.id]))
    db.session.add(tg)
    db.session.commit()
    resp = client.post(f"/jobs/{job.id}/assign_task_group/{tg.id}", follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert JobTasks.query.filter_by(job_id=job.id).count() == 2


# --- task reordering -------------------------------------------------------

def _ordered_task_ids(job):
    return [jt.task_id for jt in
            JobTasks.query.filter_by(job_id=job.id).order_by(JobTasks.id).all()]


def test_jobs_reorder_tasks_swaps_order(app, client):
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    job = _job(admin, cust)
    t1, t2 = _task(admin, name="first"), _task(admin, name="second")
    _assign(job, t1)
    _assign(job, t2)
    assert _ordered_task_ids(job) == [t1.id, t2.id]
    resp = client.post(f"/jobs/{job.id}/reorder_tasks",
                       data={"order": f"{t2.id},{t1.id}"}, follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert _ordered_task_ids(job) == [t2.id, t1.id]


def test_jobs_reorder_tasks_bad_order_is_noop(app, client):
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    job = _job(admin, cust)
    t1, t2 = _task(admin, name="first"), _task(admin, name="second")
    _assign(job, t1)
    _assign(job, t2)
    # not a permutation of the job's rows -> rejected, order unchanged
    client.post(f"/jobs/{job.id}/reorder_tasks",
                data={"order": f"{t1.id}"}, follow_redirects=False)
    assert _ordered_task_ids(job) == [t1.id, t2.id]


def test_jobs_remove_all_tasks_clears(app, client):
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    job = _job(admin, cust)
    _assign(job, _task(admin, name="a"))
    _assign(job, _task(admin, name="b"))
    resp = client.post(f"/jobs/{job.id}/remove_all_tasks", follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert JobTasks.query.filter_by(job_id=job.id).count() == 0


# --- summary / start / stop ------------------------------------------------

def test_jobs_summary_renders_for_seeded_job(app, client, tmp_path):
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    hf, _ = _hashfile_with_hash(cust, admin)
    job = _job(admin, cust, hashfile_id=hf.id)
    wl = _static_wl(admin, tmp_path)
    _assign(job, _task(admin, wl_id=wl.id))
    db.session.add(Settings(enabled_job_weights=False))
    db.session.commit()
    resp = client.get(f"/jobs/{job.id}/summary")
    assert resp.status_code == 200


def test_jobs_summary_without_tasks_redirects(app, client):
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    job = _job(admin, cust)
    resp = client.get(f"/jobs/{job.id}/summary", follow_redirects=False)
    assert resp.status_code in (301, 302)


def test_jobs_start_queues_job(app, client, tmp_path):
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    hf, _ = _hashfile_with_hash(cust, admin)
    job = _job(admin, cust, status="Ready", hashfile_id=hf.id)
    wl = _static_wl(admin, tmp_path)
    _assign(job, _task(admin, wl_id=wl.id))
    resp = client.post(f"/jobs/start/{job.id}", follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert Jobs.query.get(job.id).status == "Queued"
    assert JobTasks.query.filter_by(job_id=job.id).first().status == "Queued"


def test_jobs_stop_cancels_running_job(app, client):
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    job = _job(admin, cust, status="Running")
    jt = _assign(job, _task(admin), status="Running")
    resp = client.post(f"/jobs/stop/{job.id}", follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert Jobs.query.get(job.id).status == "Canceled"
    assert JobTasks.query.get(jt.id).status == "Canceled"


def test_jobs_stop_non_running_flashes(app, client):
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    job = _job(admin, cust, status="Ready")
    resp = client.post(f"/jobs/stop/{job.id}", follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert Jobs.query.get(job.id).status == "Ready"


# --- form validator --------------------------------------------------------

def test_validate_job_rejects_duplicate_name(app):
    admin = make_admin()
    cust = make_customer()
    _job(admin, cust, name="DupName")
    import pytest
    from wtforms.validators import ValidationError

    class _Field:
        data = "DupName"

    form = JobsForm()
    with pytest.raises(ValidationError):
        form.validate_name(_Field())


def test_validate_job_allows_unique_name(app):
    form = JobsForm()

    class _Field:
        data = "TotallyUniqueName"

    # No exception -> passes
    assert form.validate_name(_Field()) is None
