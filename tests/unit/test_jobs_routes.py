"""Regression tests for jobs routes (function-coverage batch: jobs).

Covers the 13 previously-uncovered jobs route handlers plus the JobsForm
``validate_job`` validator. Behavior is asserted via status codes, redirects,
and DB side effects against the in-memory app.
"""


from hashview.jobs.forms import JobsForm, JobsNewHashFileForm
from hashview.models import (
    Hashes,
    HashfileHashes,
    Hashfiles,
    Jobs,
    JobTasks,
    Settings,
    TaskGroups,
    Tasks,
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


def test_jobs_list_batched_cracked_progress(app, client):
    """The /jobs list computes cracked/total/pct per hashfile in one grouped query.
    Pin the rendered numbers: 3 cracked of 7 (total=7 in the recovered cell) and
    42.9%. Two jobs share the hashfile (grouped-dict lookup must serve both) and a
    third job has no hashfile (must default to 0/0 without error)."""
    admin = make_admin()
    login(client, admin)
    cust = make_customer()

    hf = Hashfiles(name="hf-batch", customer_id=cust.id, owner_id=admin.id)
    db.session.add(hf)
    db.session.commit()
    for i in range(7):
        h = Hashes(sub_ciphertext=("z" + str(i)).ljust(32, "0")[:32],
                   ciphertext=("y" + str(i)).ljust(32, "0")[:32],
                   hash_type=1000, cracked=(i < 3), plaintext="pw" if i < 3 else None)
        db.session.add(h)
        db.session.commit()
        db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    db.session.commit()

    _job(admin, cust, name="SharedA", hashfile_id=hf.id)
    _job(admin, cust, name="SharedB", hashfile_id=hf.id)
    _job(admin, cust, name="NoHashfile")  # hashfile_id=None -> 0/0 default

    resp = client.get("/jobs")
    assert resp.status_code == 200
    assert b"SharedA" in resp.data and b"SharedB" in resp.data and b"NoHashfile" in resp.data
    # total (batched COUNT) and pct (batched cracked SUM) both render; the recovered
    # cell shows "3/7" with the whole X/Y wrapped in the analytics link.
    assert b"/7</span></a>" in resp.data
    assert b" hashes recovered" in resp.data
    assert b"42.9" in resp.data


def test_jobs_list_recovered_links_to_analytics(app, client):
    """The recovered "X" in the /jobs list links to the job's hashfile analytics."""
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    hf = Hashfiles(name="hf-link", customer_id=cust.id, owner_id=admin.id)
    db.session.add(hf)
    db.session.commit()
    h = Hashes(sub_ciphertext="0" * 8, ciphertext="abc", hash_type=1000,
               cracked=True, plaintext="pw")
    db.session.add(h)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    db.session.commit()
    _job(admin, cust, name="LinkJob", hashfile_id=hf.id)

    resp = client.get("/jobs")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert 'class="rec-x-link"' in html
    assert f'customer_id={cust.id}' in html
    assert f'hashfile_id={hf.id}' in html
    # the whole "X/Y" is inside the anchor (the /Y denominator closes the link)
    assert '/1</span></a>' in html


def test_jobs_add_get_renders(app, client):
    admin = make_admin()
    login(client, admin)
    make_customer()
    resp = client.get("/jobs/add")
    assert resp.status_code == 200


def test_jobs_add_customer_dropdown_lists_add_new_first(app, client):
    """#133: '+ Add new customer...' must precede every customer option so it's
    reachable without scrolling past an alphabetized customer list."""
    admin = make_admin()
    login(client, admin)
    make_customer(name="Acme Corp")
    make_customer(name="Zeta Inc")

    resp = client.get("/jobs/add")
    assert resp.status_code == 200
    body = resp.data

    add_new = body.index(b"value='add_new'")
    assert add_new < body.index(b"Acme Corp")
    assert add_new < body.index(b"Zeta Inc")
    # --SELECT-- stays first so it remains the default-selected placeholder
    assert body.index(b"--SELECT--") < add_new


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


# --- chunked tasks read as ONE attack in the editor ------------------------

def _chunk(job, task, chunk_no, chunk_total, status="Queued"):
    """A single chunk row of a split task (queue-time fan-out)."""
    jt = JobTasks(job_id=job.id, task_id=task.id, status=status, priority=3,
                  chunk_no=chunk_no, chunk_total=chunk_total)
    db.session.add(jt)
    db.session.commit()
    return jt


def test_jobs_tasks_page_lucky_button_label_matches_backend_top_ten(app, client):
    """The "I'm Feeling Lucky" button must promise what the backend does.

    jobs_assign_lucky_task_group (hashview/jobs/routes.py) queries the top
    10 historically effective tasks; the button label must say "top 10",
    not the previously mismatched "top 5" (issue #379).
    """
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    job = _job(admin, cust)
    body = client.get(f"/jobs/{job.id}/tasks").get_data(as_text=True)
    assert "Feeling Lucky — top 10" in body
    assert "top 5" not in body


def test_jobs_list_collapses_chunked_task_to_one_card(app, client):
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    job = _job(admin, cust)
    task = _task(admin, name="MaskAttack")
    for n in range(1, 4):                 # one task fanned into 3 chunk rows
        _chunk(job, task, n, 3)
    body = client.get(f"/jobs/{job.id}/tasks").get_data(as_text=True)
    assert body.count(f'data-task-id="{task.id}"') == 1     # one card, not three
    assert "split into 3 chunks" in body


def test_jobs_remove_chunked_task_deletes_all_chunks(app, client):
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    job = _job(admin, cust)
    task = _task(admin, name="MaskAttack")
    for n in range(1, 4):
        _chunk(job, task, n, 3)
    resp = client.post(f"/jobs/{job.id}/remove_task/{task.id}", follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert JobTasks.query.filter_by(job_id=job.id, task_id=task.id).count() == 0


def test_jobs_reorder_does_not_multiply_chunked_task(app, client):
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    job = _job(admin, cust)
    t1 = _task(admin, name="mask")
    t2 = _task(admin, name="dict")
    for n in range(1, 4):                 # t1 split into 3 chunks
        _chunk(job, t1, n, 3)
    _assign(job, t2)                      # t2 whole
    # collapsed order is [t1, t2]; reorder to [t2, t1]
    resp = client.post(f"/jobs/{job.id}/reorder_tasks",
                       data={"order": f"{t2.id},{t1.id}"}, follow_redirects=False)
    assert resp.status_code in (301, 302)
    rows = JobTasks.query.filter_by(job_id=job.id).order_by(JobTasks.id).all()
    # t1 collapses to ONE whole row (the old code recreated 3 -> re-chunk x3)
    assert sum(1 for r in rows if r.task_id == t1.id) == 1
    assert [r.task_id for r in rows] == [t2.id, t1.id]     # order swapped
    assert all(r.chunk_total is None for r in rows)        # de-chunked; re-chunks at next queue


def test_jobs_dynamic_duplicate_tasks_stay_separate(app, client):
    # A dynamic-wordlist task may be assigned more than once (separate WHOLE rows,
    # never chunked). Those must stay distinct cards, and removing one leaves the rest.
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    job = _job(admin, cust)
    task = _task(admin, name="DynTask")
    _assign(job, task)                    # two whole rows, same task_id
    _assign(job, task)
    body = client.get(f"/jobs/{job.id}/tasks").get_data(as_text=True)
    assert body.count(f'data-task-id="{task.id}"') == 2     # two cards
    client.post(f"/jobs/{job.id}/remove_task/{task.id}", follow_redirects=False)
    assert JobTasks.query.filter_by(job_id=job.id, task_id=task.id).count() == 1


def test_jobs_list_counts_chunked_task_as_one_attack(app, client):
    # Jobs list "N attacks queued" must count the attack once, not once per chunk.
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    job = _job(admin, cust, name="chunked-job")
    task = _task(admin, name="MaskAttack")
    for n in range(1, 4):
        _chunk(job, task, n, 3)
    body = client.get("/jobs").get_data(as_text=True)
    assert "1 attack queued" in body
    assert "3 attacks queued" not in body


def test_task_detail_used_in_jobs_dedupes_chunks(app, client):
    # Task info modal "Used in N jobs" counts a job once even when the task was
    # split across N chunk rows in it.
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    job = _job(admin, cust)
    task = _task(admin, name="MaskAttack")
    for n in range(1, 4):
        _chunk(job, task, n, 3)
    body = client.get("/tasks").get_data(as_text=True)
    assert "Used in 1 job" in body
    assert "Used in 3 jobs" not in body


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


def test_jobs_summary_scales_with_assigned_tasks_not_library(app, client, tmp_path):
    """Issue #422: job summary should only query assigned task names, not the
    entire tasks table. Response size must scale with assigned task count, not
    total task library size."""
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    hf, _ = _hashfile_with_hash(cust, admin)
    job = _job(admin, cust, hashfile_id=hf.id)

    # Seed 50 extra tasks in the library.
    wl = _static_wl(admin, tmp_path)
    for i in range(50):
        _task(admin, name=f"ignored-{i}", wl_id=wl.id)

    # Assign exactly 2 tasks to the job.
    assigned_task1 = _task(admin, name="assigned-1", wl_id=wl.id)
    assigned_task2 = _task(admin, name="assigned-2", wl_id=wl.id)
    _assign(job, assigned_task1)
    _assign(job, assigned_task2)

    db.session.add(Settings(enabled_job_weights=False))
    db.session.commit()

    # The old nested-loop template only ever *rendered* task.name for rows
    # where task.id == a.task_id, so absence of "ignored-N" text and a
    # response-size threshold cannot distinguish the fix from the O(assigned
    # x library) bug at this fixture's scale (2 assigned x 52 library tasks is
    # only ~4KB of loop whitespace either way). What actually distinguishes
    # them is the query issued: the fixed route filters Tasks by the assigned
    # ids; the old route loaded every row via Tasks.query.all(). Inspect the
    # SQL the same way test_rules_pagination.py does for the equivalent bug.
    from sqlalchemy import event

    statements = []

    def record(conn, cursor, statement, parameters, context, executemany):
        statements.append(" ".join(statement.split()).lower())

    engine = db.engine
    event.listen(engine, "before_cursor_execute", record)
    try:
        resp = client.get(f"/jobs/{job.id}/summary")
    finally:
        event.remove(engine, "before_cursor_execute", record)

    assert resp.status_code == 200

    # Verify both assigned task names appear in the rendered output, in order.
    assert b"assigned-1" in resp.data
    assert b"assigned-2" in resp.data
    assert b"01</span>assigned-1" in resp.data
    assert b"02</span>assigned-2" in resp.data

    # Verify that ignored (unassigned) library tasks do NOT appear.
    for i in range(50):
        assert f"ignored-{i}".encode() not in resp.data

    # The decisive check: no query against `tasks` may be an unfiltered
    # full-table scan (Tasks.query.all() has no WHERE clause at all).
    row_loads = [s for s in statements
                 if s.startswith("select") and " from tasks" in s
                 and "count(" not in s]
    assert any("id in" in s for s in row_loads), \
        f"no id-scoped task lookup found; saw: {row_loads}"
    unfiltered = [s for s in row_loads if " where " not in s]
    assert not unfiltered, f"unrestricted scan of tasks: {unfiltered}"


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


def test_jobs_new_hashfile_form_pwdump_hash_type_default(app):
    """Test that an unbound JobsNewHashFileForm has pwdump_hash_type defaulting to '1000'."""
    form = JobsNewHashFileForm()
    assert form.pwdump_hash_type.data == '1000'


# --- cracked hashes pagination (#422) ---

def test_cracked_hashes_view_paginates_at_twenty_per_page(app, client):
    """The cracked-hashes view must paginate, rendering only 20 rows per page."""
    admin = make_admin()
    login(client, admin)
    cust = make_customer()

    # Create a hashfile with 35 cracked hashes
    hf = Hashfiles(name="hf-paged", customer_id=cust.id, owner_id=admin.id)
    db.session.add(hf)
    db.session.commit()
    for i in range(35):
        h = Hashes(
            sub_ciphertext=f"{i:032d}",
            ciphertext=f"hash_{i}",
            hash_type=1000,
            cracked=True,
            plaintext=f"password_{i}",
        )
        db.session.add(h)
        db.session.commit()
        db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    db.session.commit()

    job = _job(admin, cust, hashfile_id=hf.id)

    # Page 1 should show exactly 20 rows
    resp = client.get(f"/jobs/{job.id}/assigned_hashfile/{hf.id}")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # Count the number of ic-row rows in the table body
    row_count = body.count('<tr class="ic-row">')
    assert row_count == 20, f"Expected 20 rows on page 1, got {row_count}"


def test_cracked_hashes_second_page_shows_remainder(app, client):
    """Second page of cracked hashes must show the remaining rows without overlap."""
    admin = make_admin()
    login(client, admin)
    cust = make_customer()

    # Create a hashfile with 35 cracked hashes with distinct plaintexts
    hf = Hashfiles(name="hf-page2", customer_id=cust.id, owner_id=admin.id)
    db.session.add(hf)
    db.session.commit()
    for i in range(35):
        h = Hashes(
            sub_ciphertext=f"{i:032d}",
            ciphertext=f"hash_{i:03d}",
            hash_type=1000,
            cracked=True,
            plaintext=f"password_{i:03d}",
        )
        db.session.add(h)
        db.session.commit()
        db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    db.session.commit()

    job = _job(admin, cust, hashfile_id=hf.id)

    # Get page 1 passwords
    page1_passwords = set()
    for i in range(20):
        page1_passwords.add(f"password_{i:03d}")

    # Get page 2
    page2 = client.get(f"/jobs/{job.id}/assigned_hashfile/{hf.id}?page=2").get_data(as_text=True)
    page2_passwords = set()
    for i in range(20, 35):
        page2_passwords.add(f"password_{i:03d}")

    # Verify page 2 has different rows
    for pwd in page2_passwords:
        assert pwd in page2, f"Password {pwd} should be on page 2"
    for pwd in page1_passwords:
        assert pwd not in page2, f"Password {pwd} should not appear on page 2"


def test_cracked_hashes_flash_message_shows_total_count(app, client):
    """Flash message must show total count, not page count."""
    admin = make_admin()
    login(client, admin)
    cust = make_customer()

    # Create a hashfile with 25 cracked hashes
    hf = Hashfiles(name="hf-flash", customer_id=cust.id, owner_id=admin.id)
    db.session.add(hf)
    db.session.commit()
    for i in range(25):
        h = Hashes(
            sub_ciphertext=f"{i:032d}",
            ciphertext=f"hash_{i}",
            hash_type=1000,
            cracked=True,
            plaintext=f"password_{i}",
        )
        db.session.add(h)
        db.session.commit()
        db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    db.session.commit()

    job = _job(admin, cust, hashfile_id=hf.id)

    # Check page 2 (only 5 rows)
    resp = client.get(f"/jobs/{job.id}/assigned_hashfile/{hf.id}?page=2")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # Flash message should show "25 instacracked Hashes!" not "5 instacracked Hashes!"
    assert "25 instacracked Hashes!" in body


def test_cracked_hashes_server_side_filter_narrows_results(app, client):
    """Server-side search filter must narrow results by plaintext."""
    admin = make_admin()
    login(client, admin)
    cust = make_customer()

    # Create a hashfile with mixed cracked hashes
    hf = Hashfiles(name="hf-search", customer_id=cust.id, owner_id=admin.id)
    db.session.add(hf)
    db.session.commit()

    passwords = ["apple", "application", "banana", "apricot", "cherry"]
    for i, pwd in enumerate(passwords):
        h = Hashes(
            sub_ciphertext=f"{i:032d}",
            ciphertext=f"hash_{i}",
            hash_type=1000,
            cracked=True,
            plaintext=pwd,
        )
        db.session.add(h)
        db.session.commit()
        db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    db.session.commit()

    job = _job(admin, cust, hashfile_id=hf.id)

    # Search for "app" should find "apple", "application"
    resp = client.get(f"/jobs/{job.id}/assigned_hashfile/{hf.id}?q=app")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "apple" in body
    assert "application" in body
    assert "banana" not in body
    assert "apricot" not in body
    assert "cherry" not in body


def test_cracked_hashes_filter_with_no_matches_shows_correct_empty_state(app, client):
    """A filter matching nothing must say so -- not fall through to the
    generic 'no previously cracked hashes found' message. pagination.total is
    the FILTERED count (0 here), so the empty-state branch must key off
    search_filter being set, not off pagination.total > 0."""
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    hf = Hashfiles(name="hf-nomatch", customer_id=cust.id, owner_id=admin.id)
    db.session.add(hf)
    db.session.commit()
    h = Hashes(sub_ciphertext="0" * 32, ciphertext="hash_0", hash_type=1000,
                cracked=True, plaintext="apple")
    db.session.add(h)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    db.session.commit()

    job = _job(admin, cust, hashfile_id=hf.id)

    resp = client.get(f"/jobs/{job.id}/assigned_hashfile/{hf.id}?q=zzz-no-such-term")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "No cracked hashes match" in body
    assert "No previously cracked hashes found." not in body


def test_cracked_hashes_flash_shows_hashfile_total_not_filtered_count(app, client):
    """The flash message reports the hashfile's whole cracked count, not the
    filtered result count -- matches the pre-pagination behavior of always
    reporting how many hashes this hashfile has cracked in total."""
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    hf = Hashfiles(name="hf-flash-filter", customer_id=cust.id, owner_id=admin.id)
    db.session.add(hf)
    db.session.commit()
    for i, pwd in enumerate(["apple", "banana", "cherry"]):
        h = Hashes(sub_ciphertext=f"{i:032d}", ciphertext=f"hash_{i}",
                    hash_type=1000, cracked=True, plaintext=pwd)
        db.session.add(h)
        db.session.commit()
        db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    db.session.commit()

    job = _job(admin, cust, hashfile_id=hf.id)

    # Filtering to just "apple" (1 of 3) must still flash the hashfile's
    # total of 3, not 1.
    resp = client.get(f"/jobs/{job.id}/assigned_hashfile/{hf.id}?q=apple",
                       follow_redirects=True)
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "3 instacracked Hashes!" in body


def test_cracked_hashes_pages_partition_the_result_set(app, client):
    """Every row across all pages must be distinct and their union must equal
    the full result set -- proves pagination has a deterministic order
    (order_by), not just that page 2 happens to differ from page 1 by
    insertion-order accident."""
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    hf = Hashfiles(name="hf-partition", customer_id=cust.id, owner_id=admin.id)
    db.session.add(hf)
    db.session.commit()
    all_passwords = set()
    for i in range(35):
        pwd = f"partition_pw_{i:03d}"
        all_passwords.add(pwd)
        h = Hashes(sub_ciphertext=f"{i:032d}", ciphertext=f"hash_{i}",
                    hash_type=1000, cracked=True, plaintext=pwd)
        db.session.add(h)
        db.session.commit()
        db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    db.session.commit()

    job = _job(admin, cust, hashfile_id=hf.id)

    seen = set()
    for page in (1, 2):
        resp = client.get(f"/jobs/{job.id}/assigned_hashfile/{hf.id}?page={page}")
        assert resp.status_code == 200
        body = resp.get_data(as_text=True)
        page_matches = {pwd for pwd in all_passwords if pwd in body}
        assert not (page_matches & seen), (
            f"page {page} repeated rows from an earlier page: {page_matches & seen}"
        )
        seen |= page_matches
    assert seen == all_passwords, f"missing rows across all pages: {all_passwords - seen}"


def test_cracked_hashes_server_side_filter_by_username(app, client):
    """Server-side search filter must also narrow by username."""
    admin = make_admin()
    login(client, admin)
    cust = make_customer()

    # Create a hashfile with hashes that have usernames
    hf = Hashfiles(name="hf-user-search", customer_id=cust.id, owner_id=admin.id)
    db.session.add(hf)
    db.session.commit()

    users = ["alice", "bob", "charlie"]
    for i, username in enumerate(users):
        h = Hashes(
            sub_ciphertext=f"{i:032d}",
            ciphertext=f"hash_{i}",
            hash_type=1000,
            cracked=True,
            plaintext=f"pwd_{i}",
        )
        db.session.add(h)
        db.session.commit()
        hfh = HashfileHashes(hash_id=h.id, hashfile_id=hf.id, username=username)
        db.session.add(hfh)
    db.session.commit()

    job = _job(admin, cust, hashfile_id=hf.id)

    # Search for "ali" should find "alice"
    resp = client.get(f"/jobs/{job.id}/assigned_hashfile/{hf.id}?q=ali")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "alice" in body
    assert "bob" not in body
    assert "charlie" not in body


def test_cracked_hashes_server_side_filter_by_ciphertext(app, client):
    """Server-side search filter must also narrow by ciphertext."""
    admin = make_admin()
    login(client, admin)
    cust = make_customer()

    # Create a hashfile with distinct ciphertexts
    hf = Hashfiles(name="hf-cipher-search", customer_id=cust.id, owner_id=admin.id)
    db.session.add(hf)
    db.session.commit()

    ciphers = ["abc123", "def456", "ghi789"]
    for i, cipher in enumerate(ciphers):
        h = Hashes(
            sub_ciphertext=f"{i:032d}",
            ciphertext=cipher,
            hash_type=1000,
            cracked=True,
            plaintext=f"pwd_{i}",
        )
        db.session.add(h)
        db.session.commit()
        db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    db.session.commit()

    job = _job(admin, cust, hashfile_id=hf.id)

    # Search for "123" should find "abc123"
    resp = client.get(f"/jobs/{job.id}/assigned_hashfile/{hf.id}?q=123")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "abc123" in body
    assert "def456" not in body
    assert "ghi789" not in body


def test_cracked_hashes_query_shape_has_limit(app, client):
    """Query shape test: pagination must issue a LIMIT clause."""
    from sqlalchemy import event

    admin = make_admin()
    login(client, admin)
    cust = make_customer()

    # Create a hashfile with 25 cracked hashes
    hf = Hashfiles(name="hf-limit", customer_id=cust.id, owner_id=admin.id)
    db.session.add(hf)
    db.session.commit()
    for i in range(25):
        h = Hashes(
            sub_ciphertext=f"{i:032d}",
            ciphertext=f"hash_{i}",
            hash_type=1000,
            cracked=True,
            plaintext=f"password_{i}",
        )
        db.session.add(h)
        db.session.commit()
        db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    db.session.commit()

    job = _job(admin, cust, hashfile_id=hf.id)

    statements = []

    def record(conn, cursor, statement, parameters, context, executemany):
        statements.append(" ".join(statement.split()).lower())

    engine = db.engine
    event.listen(engine, "before_cursor_execute", record)
    try:
        client.get(f"/jobs/{job.id}/assigned_hashfile/{hf.id}")
    finally:
        event.remove(engine, "before_cursor_execute", record)

    # Look for SELECT statements that query from hashes and hashfilehashes
    main_queries = [
        s
        for s in statements
        if s.startswith("select") and " from hashes" in s and "count(" not in s
    ]

    # At least one query should have LIMIT (the paginated query)
    limit_queries = [s for s in main_queries if " limit " in s]
    assert limit_queries, f"No LIMIT clause found; queries: {main_queries}"
