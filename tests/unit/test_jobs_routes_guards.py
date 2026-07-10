"""Behavior-pinning tests for the jobs routes guard branches.

Covers jobs_delete (owner cascade + non-owner denied), the
jobs_assign_task / jobs_remove_task round trip (including duplicate-assign
behavior for static vs dynamic wordlists) and the jobs_assigned_hashfile GET
view (own hashfiles listed, another customer's hashfiles not offered).
"""

from hashview.models import (
    Customers,
    Hashfiles,
    Jobs,
    JobTasks,
    Tasks,
    Users,
    Wordlists,
    db,
)


def _admin():
    u = Users(first_name="Ad", last_name="Min", email_address="admin@example.com",
              password="x" * 60, admin=True)
    db.session.add(u)
    db.session.commit()
    return u


def _nonadmin():
    u = Users(first_name="No", last_name="Body", email_address="user@example.com",
              password="x" * 60, admin=False)
    db.session.add(u)
    db.session.commit()
    return u


def _login(client, user):
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True


def _make_customer(name="Acme"):
    c = Customers(name=name)
    db.session.add(c)
    db.session.commit()
    return c


def _make_job(owner_id, customer_id, name="job-guards", status="Incomplete"):
    job = Jobs(name=name, status=status, customer_id=customer_id,
               owner_id=owner_id)
    db.session.add(job)
    db.session.commit()
    return job


def _make_wordlist(owner_id, name="wl-jobs", wl_type="static"):
    wl = Wordlists(name=name, owner_id=owner_id, type=wl_type,
                   path=f"control/wordlists/{name}.gz", size=10,
                   checksum="0" * 64)
    db.session.add(wl)
    db.session.commit()
    return wl


def _make_task(owner_id, wl_id, name="task-jobs"):
    task = Tasks(name=name, owner_id=owner_id, wl_id=wl_id, rule_id=None,
                 hc_attackmode=0, loopback=False)
    db.session.add(task)
    db.session.commit()
    return task


# ----------------------------------------------------------------- jobs_delete

def test_jobs_delete_owner_cascades_jobtasks(app, client):
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    wl = _make_wordlist(user.id)
    task = _make_task(user.id, wl.id)
    db.session.add(JobTasks(job_id=job.id, task_id=task.id, status="Not Started"))
    db.session.commit()
    job_id = job.id
    _login(client, user)

    resp = client.post(f"/jobs/delete/{job_id}", follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert Jobs.query.get(job_id) is None
    assert JobTasks.query.filter_by(job_id=job_id).count() == 0  # cascaded


def test_jobs_delete_non_owner_denied(app, client):
    admin = _admin()
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(admin.id, customer.id)
    _login(client, user)

    resp = client.post(f"/jobs/delete/{job.id}", follow_redirects=True)
    assert b"do not have rights to delete this job" in resp.data
    assert Jobs.query.get(job.id) is not None  # NOT deleted


# --------------------------------------------- jobs_assign_task / remove_task

def test_jobs_assign_then_remove_task_round_trip(app, client):
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    wl = _make_wordlist(user.id)
    task = _make_task(user.id, wl.id)
    _login(client, user)

    resp = client.post(f"/jobs/{job.id}/assign_task/{task.id}",
                      follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert JobTasks.query.filter_by(job_id=job.id, task_id=task.id).count() == 1

    resp = client.post(f"/jobs/{job.id}/remove_task/{task.id}",
                      follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert JobTasks.query.filter_by(job_id=job.id, task_id=task.id).count() == 0


def test_jobs_assign_duplicate_static_wordlist_task_rejected(app, client):
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    wl = _make_wordlist(user.id, wl_type="static")
    task = _make_task(user.id, wl.id)
    _login(client, user)

    client.post(f"/jobs/{job.id}/assign_task/{task.id}")
    resp = client.post(f"/jobs/{job.id}/assign_task/{task.id}",
                      follow_redirects=True)
    assert b"already assigned" in resp.data
    assert JobTasks.query.filter_by(job_id=job.id, task_id=task.id).count() == 1  # no dupe
    assert JobTasks.query.filter_by(job_id=job.id, task_id=task.id).count() == 1


def test_jobs_assign_duplicate_dynamic_wordlist_task_allowed(app, client):
    # Tasks whose wordlist is dynamic may be assigned repeatedly (the wordlist
    # content changes between runs).
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    wl = _make_wordlist(user.id, name="wl-dyn", wl_type="dynamic")
    task = _make_task(user.id, wl.id)
    _login(client, user)

    client.post(f"/jobs/{job.id}/assign_task/{task.id}")
    client.post(f"/jobs/{job.id}/assign_task/{task.id}")
    assert JobTasks.query.filter_by(job_id=job.id, task_id=task.id).count() == 2


# ------------------------------------------------------ jobs_assigned_hashfile

def test_jobs_assigned_hashfile_lists_own_customers_hashfiles_only(app, client):
    user = _nonadmin()
    customer = _make_customer("Mine")
    other_customer = _make_customer("Theirs")
    job = _make_job(user.id, customer.id)
    own_hf = Hashfiles(name="own-hashfile.txt", customer_id=customer.id,
                       owner_id=user.id)
    foreign_hf = Hashfiles(name="foreign-hashfile.txt",
                           customer_id=other_customer.id, owner_id=user.id)
    db.session.add_all([own_hf, foreign_hf])
    db.session.commit()
    _login(client, user)

    resp = client.get(f"/jobs/{job.id}/assigned_hashfile/")
    assert resp.status_code == 200
    assert b"own-hashfile.txt" in resp.data           # offered
    assert b"foreign-hashfile.txt" not in resp.data   # other customer's: not offered


def test_jobs_assigned_hashfile_select_existing_sets_job_hashfile(app, client):
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    hf = Hashfiles(name="picked.txt", customer_id=customer.id, owner_id=user.id)
    db.session.add(hf)
    db.session.commit()
    _login(client, user)

    resp = client.post(f"/jobs/{job.id}/assigned_hashfile/",
                       data={"hashfile_id": str(hf.id)},
                       follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert resp.headers["Location"].endswith(f"/jobs/{job.id}/notifications")
    assert int(Jobs.query.get(job.id).hashfile_id) == hf.id


# ------------------------------------------------------ wizard / list helpers

def _settings(**overrides):
    from hashview.models import Settings
    kwargs = dict(retention_period=30, max_runtime_jobs=0, max_runtime_tasks=0)
    kwargs.update(overrides)
    s = Settings(**kwargs)
    db.session.add(s)
    db.session.commit()
    return s


def _attach_hashfile(job, owner_id, cracked=False, name="hf-jobs.txt"):
    from hashview.models import Hashes, HashfileHashes
    hf = Hashfiles(name=name, customer_id=job.customer_id, owner_id=owner_id)
    db.session.add(hf)
    db.session.commit()
    h = Hashes(sub_ciphertext="e" * 32, ciphertext="f" * 32, hash_type=1000,
               cracked=cracked, plaintext="pw" if cracked else None)
    db.session.add(h)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    job.hashfile_id = hf.id
    db.session.commit()
    return hf, h


# -------------------------------------------------------------------- jobs_list

def test_jobs_list_renders_progress_runtime_and_filter(app, client):
    from datetime import datetime, timedelta
    from hashview.models import JobNotifications
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id, name="listed-job")
    _attach_hashfile(job, user.id, cracked=True)
    job.started_at = datetime.utcnow() - timedelta(hours=2)
    job.ended_at = datetime.utcnow()
    db.session.add(JobNotifications(owner_id=user.id, job_id=job.id, method="email"))
    db.session.commit()
    _login(client, user)

    resp = client.get("/jobs")
    assert resp.status_code == 200
    assert b"listed-job" in resp.data

    resp = client.get("/jobs?show_only_mine=true")
    assert resp.status_code == 200
    assert b"listed-job" in resp.data


# --------------------------------------------------------------------- jobs_add

def test_jobs_add_get_renders(app, client):
    user = _nonadmin()
    _settings()
    _make_customer()
    _login(client, user)
    resp = client.get("/jobs/add")
    assert resp.status_code == 200


def test_jobs_add_post_creates_job_default_priority(app, client):
    user = _nonadmin()
    _settings()  # enabled_job_weights defaults False -> priority forced to 3
    customer = _make_customer()
    _login(client, user)

    resp = client.post("/jobs/add", data={
        "name": "created-job",
        "priority": "5",
        "customer_id": str(customer.id),
    }, follow_redirects=False)
    assert resp.status_code in (301, 302)
    job = Jobs.query.filter_by(name="created-job").first()
    assert job is not None
    assert job.status == "Incomplete"
    assert job.owner_id == user.id
    assert int(job.customer_id) == customer.id
    assert job.priority == 3  # weights disabled -> forced to normal
    assert resp.headers["Location"].endswith(f"{job.id}/assigned_hashfile/")


def test_jobs_add_post_honors_priority_when_weights_enabled(app, client):
    user = _nonadmin()
    _settings(enabled_job_weights=True)
    customer = _make_customer()
    _login(client, user)

    client.post("/jobs/add", data={
        "name": "weighted-job",
        "priority": "5",
        "customer_id": str(customer.id),
    })
    job = Jobs.query.filter_by(name="weighted-job").first()
    assert job is not None and int(job.priority) == 5


# ------------------------------------------- jobs_assigned_hashfile_cracked

def test_jobs_assigned_hashfile_cracked_flashes_instacracks(app, client):
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    hf, _ = _attach_hashfile(job, user.id, cracked=True)
    _login(client, user)

    resp = client.get(f"/jobs/{job.id}/assigned_hashfile/{hf.id}",
                      follow_redirects=False)
    assert resp.status_code == 200
    assert b"instacracked" in resp.data


# ------------------------------------------------------------ jobs_list_tasks

def test_jobs_list_tasks_renders(app, client):
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    _attach_hashfile(job, user.id)
    wl = _make_wordlist(user.id)
    task = _make_task(user.id, wl.id, name="assignable")
    _login(client, user)

    resp = client.get(f"/jobs/{job.id}/tasks")
    assert resp.status_code == 200
    assert b"assignable" in resp.data


# ------------------------------------------------------- jobs_assign_task_group

def test_jobs_assign_task_group_assigns_all_and_skips_static_dupes(app, client):
    import json as _json
    from hashview.models import TaskGroups
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    wl = _make_wordlist(user.id, wl_type="static")
    t1 = _make_task(user.id, wl.id, name="tg-task-1")
    t2 = _make_task(user.id, wl.id, name="tg-task-2")
    tg = TaskGroups(name="group-1", owner_id=user.id,
                    tasks=_json.dumps([str(t1.id), str(t2.id)]))
    db.session.add(tg)
    db.session.commit()
    _login(client, user)

    resp = client.post(f"/jobs/{job.id}/assign_task_group/{tg.id}",
                      follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert JobTasks.query.filter_by(job_id=job.id).count() == 2

    # re-assigning the group: static-wordlist tasks are not duplicated
    client.post(f"/jobs/{job.id}/assign_task_group/{tg.id}")
    assert JobTasks.query.filter_by(job_id=job.id).count() == 2


# ------------------------------------------------------- jobs_reorder_tasks

def _job_with_two_tasks(user):
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    wl = _make_wordlist(user.id)
    t1 = _make_task(user.id, wl.id, name="order-1")
    t2 = _make_task(user.id, wl.id, name="order-2")
    db.session.add(JobTasks(job_id=job.id, task_id=t1.id, status="Not Started"))
    db.session.add(JobTasks(job_id=job.id, task_id=t2.id, status="Not Started"))
    db.session.commit()
    return job, t1, t2


def _task_order(job_id):
    return [jt.task_id for jt in
            JobTasks.query.filter_by(job_id=job_id).order_by(JobTasks.id).all()]


def test_jobs_reorder_tasks_reorders(app, client):
    user = _nonadmin()
    job, t1, t2 = _job_with_two_tasks(user)
    _login(client, user)

    resp = client.post(f"/jobs/{job.id}/reorder_tasks",
                       data={"order": f"{t2.id},{t1.id}"}, follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert _task_order(job.id) == [t2.id, t1.id]


def test_jobs_reorder_tasks_rejects_non_permutation(app, client):
    """A submitted order that isn't a permutation of the job's rows (stale page /
    tampering) is rejected and the queue is left unchanged."""
    user = _nonadmin()
    job, t1, t2 = _job_with_two_tasks(user)
    _login(client, user)

    resp = client.post(f"/jobs/{job.id}/reorder_tasks",
                       data={"order": f"{t1.id},999999"}, follow_redirects=True)
    assert b"out of date" in resp.data
    assert _task_order(job.id) == [t1.id, t2.id]  # unchanged


def test_add_task_dropdown_drops_assigned_static_keeps_dynamic(app, client):
    """The Add-Task dropdown removes an assigned task unless it uses a dynamic
    wordlist (so a non-dynamic task can't be added twice). The assign_task form
    only appears in the dropdown, so its presence/absence is the signal."""
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    static_wl = _make_wordlist(user.id, name="static-wl", wl_type="static")
    dynamic_wl = _make_wordlist(user.id, name="dyn-wl", wl_type="dynamic")
    t_static = _make_task(user.id, static_wl.id, name="static-task")
    t_dynamic = _make_task(user.id, dynamic_wl.id, name="dynamic-task")
    t_unassigned = _make_task(user.id, static_wl.id, name="unassigned-task")
    # assign the static + dynamic tasks; leave t_unassigned off the job
    db.session.add(JobTasks(job_id=job.id, task_id=t_static.id, status="Not Started"))
    db.session.add(JobTasks(job_id=job.id, task_id=t_dynamic.id, status="Not Started"))
    db.session.commit()
    _login(client, user)

    html = client.get(f"/jobs/{job.id}/tasks").get_data(as_text=True)
    assert f"/assign_task/{t_static.id}" not in html       # assigned + static -> dropped
    assert f"/assign_task/{t_dynamic.id}" in html          # assigned + dynamic -> stays
    assert f"/assign_task/{t_unassigned.id}" in html       # unassigned -> shown


def test_task_queue_renders_cards_with_meta(app, client):
    """The queue renders draggable .tq-item cards with the task name + a
    type-and-wordlist subtitle (mode-0 no-rule task -> 'Dictionary')."""
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    wl = _make_wordlist(user.id, name="rockyou", wl_type="static")
    t = _make_task(user.id, wl.id, name="rockyou-dict")   # hc_attackmode 0, rule_id None
    db.session.add(JobTasks(job_id=job.id, task_id=t.id, status="Not Started"))
    db.session.commit()
    _login(client, user)

    html = client.get(f"/jobs/{job.id}/tasks").get_data(as_text=True)
    assert 'class="tq-item"' in html and 'draggable="true"' in html
    assert "rockyou-dict" in html        # task name
    assert "Dictionary" in html          # type label (mode 0, no rule)
    assert "rockyou" in html             # wordlist name in the subtitle


# ---------------------------------------------------- notifications wizard step

def test_jobs_notifications_get_renders(app, client):
    user = _nonadmin()
    _settings()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    _login(client, user)

    resp = client.get(f"/jobs/{job.id}/notifications")
    assert resp.status_code == 200


def test_jobs_notifications_post_creates_job_notifications_once(app, client):
    from hashview.models import JobNotifications
    user = _nonadmin()
    _settings()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    _login(client, user)

    data = {"job_completion_email": "y", "job_completion_pushover": "y"}
    resp = client.post(f"/jobs/{job.id}/notifications", data=data,
                       follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert resp.headers["Location"].endswith(f"/jobs/{job.id}/tasks")
    assert JobNotifications.query.filter_by(job_id=job.id, method="email").count() == 1
    assert JobNotifications.query.filter_by(job_id=job.id, method="push").count() == 1

    # idempotent: posting again does not duplicate rows
    client.post(f"/jobs/{job.id}/notifications", data=data)
    assert JobNotifications.query.filter_by(job_id=job.id).count() == 2


def test_jobs_notifications_post_hash_methods_redirects_to_hash_picker(app, client):
    user = _nonadmin()
    _settings()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    _login(client, user)

    resp = client.post(f"/jobs/{job.id}/notifications",
                       data={"hash_completion_email": "y",
                             "hash_completion_pushover": "y"},
                       follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert resp.headers["Location"].endswith(
        f"/jobs/{job.id}/notifications/email,push/hashes")


def test_jobs_assign_notification_hashes_post_creates_rows(app, client):
    from hashview.models import HashNotifications
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    _, h = _attach_hashfile(job, user.id, cracked=False)
    _login(client, user)

    resp = client.post(f"/jobs/{job.id}/notifications/email/hashes",
                       data={"selected": [str(h.id)]},
                       follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert HashNotifications.query.filter_by(
        hash_id=h.id, owner_id=user.id, method="email").count() == 1

    # repeat POST does not duplicate the (hash, channel) pairing
    client.post(f"/jobs/{job.id}/notifications/email/hashes",
                data={"selected": [str(h.id)]})
    assert HashNotifications.query.filter_by(hash_id=h.id, method="email").count() == 1


# ------------------------------------------------------------------ jobs_summary

def _full_wizard_job(user, status="Incomplete"):
    customer = _make_customer()
    job = _make_job(user.id, customer.id, status=status)
    _attach_hashfile(job, user.id)
    wl = _make_wordlist(user.id)
    task = _make_task(user.id, wl.id, name="wizard-task")
    jt = JobTasks(job_id=job.id, task_id=task.id, status="Not Started")
    db.session.add(jt)
    db.session.commit()
    return job, task, jt


def test_jobs_summary_redirects_when_no_tasks(app, client):
    user = _nonadmin()
    _settings()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    _login(client, user)

    resp = client.get(f"/jobs/{job.id}/summary", follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert resp.headers["Location"].endswith(f"/jobs/{job.id}/tasks")


def test_jobs_summary_get_renders(app, client):
    user = _nonadmin()
    _settings()
    job, task, _ = _full_wizard_job(user)
    _login(client, user)

    resp = client.get(f"/jobs/{job.id}/summary")
    assert resp.status_code == 200
    assert b"wizard-task" in resp.data


def test_jobs_summary_post_queues_job_and_tasks(app, client):
    user = _nonadmin()
    _settings()
    job, task, jt = _full_wizard_job(user)
    _login(client, user)

    resp = client.post(f"/jobs/{job.id}/summary", data={"submit": "Create & Queue Job"},
                       follow_redirects=False)
    assert resp.status_code in (301, 302)
    # Create & Queue lands on the dashboard ("/"), not the jobs listing ("/jobs").
    assert resp.headers.get("Location", "").endswith("/")
    db.session.expire_all()
    job = Jobs.query.get(job.id)
    jt = JobTasks.query.filter_by(job_id=job.id).first()
    assert job.status == "Queued"
    assert job.queued_at is not None
    assert jt.status == "Queued"
    assert jt.command  # hashcat command pre-built for the agent


# --------------------------------------------------------- jobs_start / stop

def test_jobs_start_owner_queues(app, client):
    user = _nonadmin()
    job, task, jt = _full_wizard_job(user)
    _login(client, user)

    resp = client.post(f"/jobs/start/{job.id}", follow_redirects=False)
    assert resp.status_code in (301, 302)
    db.session.expire_all()
    assert Jobs.query.get(job.id).status == "Queued"
    assert JobTasks.query.filter_by(job_id=job.id).first().status == "Queued"


def test_jobs_start_non_owner_denied(app, client):
    admin = _admin()
    user = _nonadmin()
    job, task, jt = _full_wizard_job(admin)
    _login(client, user)

    resp = client.post(f"/jobs/start/{job.id}", follow_redirects=True)
    assert b"do not have rights to start this job" in resp.data
    assert Jobs.query.get(job.id).status == "Incomplete"  # unchanged


def test_jobs_start_without_tasks_errors(app, client):
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    _login(client, user)

    resp = client.post(f"/jobs/start/{job.id}", follow_redirects=True)
    assert b"Error in starting job" in resp.data


def test_jobs_stop_running_job_cancels(app, client):
    user = _nonadmin()
    job, task, jt = _full_wizard_job(user, status="Running")
    jt.status = "Running"
    db.session.commit()
    _login(client, user)

    resp = client.post(f"/jobs/stop/{job.id}", follow_redirects=False)
    assert resp.status_code in (301, 302)
    db.session.expire_all()
    assert Jobs.query.get(job.id).status == "Canceled"
    assert Jobs.query.get(job.id).ended_at is not None
    assert JobTasks.query.filter_by(job_id=job.id).first().status == "Canceled"


def test_jobs_stop_not_running_flashes(app, client):
    user = _nonadmin()
    job, task, jt = _full_wizard_job(user, status="Incomplete")
    _login(client, user)

    resp = client.post(f"/jobs/stop/{job.id}", follow_redirects=True)
    assert b"not activly running" in resp.data
    assert Jobs.query.get(job.id).status == "Incomplete"  # unchanged


def test_jobs_stop_non_owner_denied(app, client):
    admin = _admin()
    user = _nonadmin()
    job, task, jt = _full_wizard_job(admin, status="Running")
    _login(client, user)

    resp = client.post(f"/jobs/stop/{job.id}", follow_redirects=True)
    assert b"do not have rights to stop this job" in resp.data
    assert Jobs.query.get(job.id).status == "Running"  # unchanged
