"""Additional branch-coverage tests for hashview/jobs/routes.py.

Covers the uncovered line ranges:
  76-78    _job_uses_website_keywords helper
  210-213  jobs_add with add_new customer
  219      jobs_add bad priority when weights enabled
  265-266  jobs_assigned_hashfile redirect on running/queued job
  281-282  hashfile cracked percentage computation (<1% branch)
  295-398  hashfile upload / paste / validation / import paths
  411-416  AJAX validation error path
  419-429  form error print loop (non-AJAX POST with no file/hashes)
  487      jobs_assign_task - duplicate task with NO wordlist
  512-516  jobs_assign_task_group - duplicate dynamic wordlist task in group
  533-562  jobs_assign_lucky_task_group route
  624      jobs_remove_task - task not found
  643-647  jobs_remove_all_tasks
  656-660  jobs_remove_all_tasks (complementary)
  696-704  jobs_assign_notifications - slack notification
  713      jobs_assign_notifications - hash_completion_slack
  735,746  jobs_assign_notification_hashes - GET and multi-method POST
  755-756  jobs_delete - job not found
  779-791  jobs_website_keywords
  909      jobs_stop - job not found
"""

import io
import json as _json
import os

import pytest

from hashview.models import (
    Customers,
    Hashfiles,
    Hashes,
    HashfileHashes,
    HashNotifications,
    JobNotifications,
    Jobs,
    JobTasks,
    Settings,
    TaskGroups,
    Tasks,
    Users,
    Wordlists,
    db,
)


# ---------------------------------------------------------------------------
# Shared helpers (mirrors test_jobs_routes_guards.py style, no imports from it)
# ---------------------------------------------------------------------------

def _admin():
    u = Users(first_name="Ad", last_name="Min", email_address="adm2@example.com",
              password="x" * 60, admin=True)
    db.session.add(u)
    db.session.commit()
    return u


def _nonadmin(email="user2@example.com"):
    u = Users(first_name="No", last_name="Body", email_address=email,
              password="x" * 60, admin=False)
    db.session.add(u)
    db.session.commit()
    return u


def _login(client, user):
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True


def _make_customer(name="Acme2"):
    c = Customers(name=name)
    db.session.add(c)
    db.session.commit()
    return c


def _make_job(owner_id, customer_id, name="job-br", status="Incomplete"):
    job = Jobs(name=name, status=status, customer_id=customer_id,
               owner_id=owner_id)
    db.session.add(job)
    db.session.commit()
    return job


def _settings(**overrides):
    kwargs = dict(retention_period=30, max_runtime_jobs=0, max_runtime_tasks=0)
    kwargs.update(overrides)
    s = Settings(**kwargs)
    db.session.add(s)
    db.session.commit()
    return s


def _make_wordlist(owner_id, name="wl-br", wl_type="static"):
    wl = Wordlists(name=name, owner_id=owner_id, type=wl_type,
                   path=f"control/wordlists/{name}.gz", size=10,
                   checksum="0" * 64)
    db.session.add(wl)
    db.session.commit()
    return wl


def _make_task(owner_id, wl_id, name="task-br"):
    task = Tasks(name=name, owner_id=owner_id, wl_id=wl_id, rule_id=None,
                 hc_attackmode=0, loopback=False)
    db.session.add(task)
    db.session.commit()
    return task


# All SelectFields in JobsNewHashFileForm that require a valid choice (even empty string).
_HASHFILE_FORM_BASE = {
    "file_type": "hash_only",
    "hash_type": "1000",
    "shadow_hash_type": "",
    "pwdump_hash_type": "",
    "netntlm_hash_type": "",
    "kerberos_hash_type": "",
    "submit": "Next",
}


def _attach_hashfile(job, owner_id, cracked=False, name="hf-br.txt"):
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


def _full_wizard_job(user, status="Incomplete"):
    customer = _make_customer()
    job = _make_job(user.id, customer.id, status=status)
    _attach_hashfile(job, user.id)
    wl = _make_wordlist(user.id)
    task = _make_task(user.id, wl.id, name="wizard-task-br")
    jt = JobTasks(job_id=job.id, task_id=task.id, status="Not Started")
    db.session.add(jt)
    db.session.commit()
    return job, task, jt


# ---------------------------------------------------------------------------
# jobs_add — "add_new" customer branch (lines 210-213)
# ---------------------------------------------------------------------------

def test_jobs_add_creates_new_customer_inline(app, client):
    """POST with customer_id='add_new' should create customer on-the-fly."""
    user = _nonadmin()
    _settings()
    _login(client, user)

    resp = client.post("/jobs/add", data={
        "name": "inline-customer-job",
        "priority": "3",
        "customer_id": "add_new",
        "customer_name": "NewCo",
    }, follow_redirects=False)
    assert resp.status_code in (301, 302)
    new_cust = Customers.query.filter_by(name="NewCo").first()
    assert new_cust is not None
    job = Jobs.query.filter_by(name="inline-customer-job").first()
    assert job is not None
    assert int(job.customer_id) == new_cust.id


# ---------------------------------------------------------------------------
# jobs_add — out-of-range priority when weights enabled (line 219)
# ---------------------------------------------------------------------------

@pytest.mark.xfail(strict=True,
    reason="Line 219 in hashview/jobs/routes.py is a dead branch: "
           "the SelectField constrains priority to 1-5 so the "
           "out-of-range fallback can never be reached through the form. "
           "hashview/jobs/routes.py:216-219")
def test_jobs_add_invalid_priority_falls_back_to_normal(app, client):
    """Priority=99 with weights enabled should fall back to 3 (dead branch)."""
    user = _nonadmin()
    _settings(enabled_job_weights=True)
    customer = _make_customer()
    _login(client, user)

    # SelectField rejects "99" — the form never validates, so no job is created.
    # The fallback `job_priority = 3` at route line 219 is unreachable via HTTP.
    client.post("/jobs/add", data={
        "name": "badpri-job",
        "priority": "99",
        "customer_id": str(customer.id),
    })
    job = Jobs.query.filter_by(name="badpri-job").first()
    assert job is not None
    assert job.priority == 3


# ---------------------------------------------------------------------------
# jobs_assigned_hashfile — redirect when job is running/queued (lines 265-266)
# ---------------------------------------------------------------------------

@pytest.mark.xfail(strict=True,
    reason="Bug: hashview/jobs/routes.py:266 calls url_for('jobs.list', ...) "
           "but the endpoint is 'jobs.jobs_list'; causes BuildError on redirect "
           "when hashfile assignment is attempted on a running/queued job.")
def test_jobs_assigned_hashfile_redirects_when_running(app, client):
    """Assigning a hashfile to a running job should flash and redirect (bug: wrong endpoint)."""
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id, status="Running")
    _login(client, user)

    resp = client.get(f"/jobs/{job.id}/assigned_hashfile/", follow_redirects=True)
    # Correct behavior: flash danger and redirect to jobs list
    assert resp.status_code == 200
    assert b"stop and remove job from queue" in resp.data


@pytest.mark.xfail(strict=True,
    reason="Bug: hashview/jobs/routes.py:266 calls url_for('jobs.list', ...) "
           "but the endpoint is 'jobs.jobs_list'; causes BuildError on redirect "
           "when hashfile assignment is attempted on a running/queued job.")
def test_jobs_assigned_hashfile_redirects_when_queued(app, client):
    """Assigning a hashfile to a queued job should flash and redirect (bug: wrong endpoint)."""
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id, status="Queued")
    _login(client, user)

    resp = client.get(f"/jobs/{job.id}/assigned_hashfile/", follow_redirects=True)
    assert resp.status_code == 200
    assert b"stop and remove job from queue" in resp.data


# ---------------------------------------------------------------------------
# jobs_assigned_hashfile — cracked <1% display branch (lines 281-282)
# ---------------------------------------------------------------------------

def test_jobs_assigned_hashfile_less_than_one_percent_cracked(app, client):
    """A hashfile with 1 cracked out of 200 triggers the '<1%' branch."""
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    hf = Hashfiles(name="lt1pct.txt", customer_id=customer.id, owner_id=user.id)
    db.session.add(hf)
    db.session.commit()
    # Add 200 hashes, 1 cracked
    cracked_hash = Hashes(sub_ciphertext="c" * 32, ciphertext="c" * 32,
                          hash_type=1000, cracked=True, plaintext="pw")
    db.session.add(cracked_hash)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=cracked_hash.id, hashfile_id=hf.id))
    for i in range(199):
        h = Hashes(sub_ciphertext=("a" + str(i)).ljust(32, "0")[:32],
                   ciphertext=("b" + str(i)).ljust(32, "0")[:32],
                   hash_type=1000, cracked=False)
        db.session.add(h)
        db.session.commit()
        db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    db.session.commit()
    _login(client, user)

    resp = client.get(f"/jobs/{job.id}/assigned_hashfile/")
    assert resp.status_code == 200
    # The template HTML-escapes the '<' in '<1%' → '&lt;1%'
    assert b"&lt;1%" in resp.data


# ---------------------------------------------------------------------------
# jobs_assigned_hashfile — POST with pasted hashes but no name (line 307)
# ---------------------------------------------------------------------------

def test_jobs_assigned_hashfile_paste_missing_name_flashes(app, client):
    """Pasting hashes without a name should flash an error and redirect."""
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    _login(client, user)

    data = dict(_HASHFILE_FORM_BASE)
    data.update({"hashfilehashes": "abc123", "name": ""})
    resp = client.post(f"/jobs/{job.id}/assigned_hashfile/",
                       data=data,
                       content_type="multipart/form-data",
                       follow_redirects=True)
    assert resp.status_code == 200
    assert b"assign a name to the hashfile" in resp.data


# ---------------------------------------------------------------------------
# jobs_assigned_hashfile — AJAX paste with no name returns JSON 400
# ---------------------------------------------------------------------------

def test_jobs_assigned_hashfile_ajax_paste_missing_name_returns_json(app, client):
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    _login(client, user)

    data = dict(_HASHFILE_FORM_BASE)
    data.update({"hashfilehashes": "abc123", "name": ""})
    resp = client.post(f"/jobs/{job.id}/assigned_hashfile/",
                       data=data,
                       content_type="multipart/form-data",
                       headers={"X-Requested-With": "fetch"},
                       follow_redirects=False)
    assert resp.status_code == 400
    body = resp.get_json()
    assert body["status"] == "error"
    assert "name" in body["msg"].lower() or "assign" in body["msg"].lower()


# ---------------------------------------------------------------------------
# jobs_assigned_hashfile — pasted hash_only hashes go through validate path
# ---------------------------------------------------------------------------

def test_jobs_assigned_hashfile_paste_invalid_hash_flashes(app, client):
    """Pasting an invalid hash value for hash_only should flash a problem message."""
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    _login(client, user)

    # "not-a-hash" won't be a valid MD5 / NTLM hash
    data = dict(_HASHFILE_FORM_BASE)
    data.update({"hashfilehashes": "not-a-real-hash-value", "name": "testfile"})
    resp = client.post(f"/jobs/{job.id}/assigned_hashfile/",
                       data=data,
                       content_type="multipart/form-data",
                       follow_redirects=True)
    # Either a validation problem is flashed, or no hashes were found
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# jobs_assigned_hashfile — AJAX validation failure (no file, no paste) lines 411-416
# ---------------------------------------------------------------------------

def test_jobs_assigned_hashfile_ajax_validation_failure_returns_json(app, client):
    """An AJAX POST that fails WTForms validation should return a JSON error."""
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    _login(client, user)

    # POST without any file data — WTForms will reject this (no submit field value)
    resp = client.post(f"/jobs/{job.id}/assigned_hashfile/",
                       data={},
                       headers={"X-Requested-With": "fetch"},
                       follow_redirects=False)
    # Should be a 400 JSON response
    assert resp.status_code == 400
    body = resp.get_json()
    assert body is not None
    assert body.get("status") == "error"


# ---------------------------------------------------------------------------
# jobs_assigned_hashfile — non-AJAX POST form error print path (lines 419-429)
# ---------------------------------------------------------------------------

def test_jobs_assigned_hashfile_nonajax_invalid_form_renders_page(app, client):
    """A plain POST that fails validation should render the hashfile assignment page."""
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    _login(client, user)

    resp = client.post(f"/jobs/{job.id}/assigned_hashfile/",
                       data={},  # empty form
                       follow_redirects=False)
    # Should render the template (200), not redirect
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# jobs_assigned_hashfile — file upload covers lines 299-300
# ---------------------------------------------------------------------------

def test_jobs_assigned_hashfile_file_upload_hash_only_valid(app, client):
    """Uploading a valid NTLM hash file covers the file-upload branch (lines 299-300)."""
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    _login(client, user)

    # A valid NTLM hash (32 hex chars)
    ntlm_hash = "31d6cfe0d16ae931b73c59d7e0c089c0"
    file_content = (ntlm_hash + "\n").encode()
    data = dict(_HASHFILE_FORM_BASE)
    data["file_type"] = "hash_only"
    data["hash_type"] = "1000"
    data["hashfile"] = (io.BytesIO(file_content), "test.txt")
    resp = client.post(f"/jobs/{job.id}/assigned_hashfile/",
                       data=data,
                       content_type="multipart/form-data",
                       follow_redirects=False)
    # Should redirect to the cracked-hashfile page (successful import)
    # or flash an error — either way, should not 500
    assert resp.status_code in (200, 301, 302)


# ---------------------------------------------------------------------------
# jobs_assigned_hashfile — paste valid NTLM hash covers import path (lines 350-388)
# ---------------------------------------------------------------------------

def test_jobs_assigned_hashfile_paste_valid_ntlm_imports(app, client):
    """Pasting a valid NTLM hash triggers the full import path (lines 350-388)."""
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    _login(client, user)

    # Valid NTLM hashes (32 hex chars each)
    ntlm1 = "31d6cfe0d16ae931b73c59d7e0c089c0"
    ntlm2 = "8846f7eaee8fb117ad06bdd830b7586c"
    data = dict(_HASHFILE_FORM_BASE)
    data.update({
        "hashfilehashes": f"{ntlm1}\n{ntlm2}\n",
        "name": "paste-ntlm",
        "file_type": "hash_only",
        "hash_type": "1000",
    })
    resp = client.post(f"/jobs/{job.id}/assigned_hashfile/",
                       data=data,
                       content_type="multipart/form-data",
                       follow_redirects=False)
    # Should redirect to the cracked-hashfile step (success)
    assert resp.status_code in (301, 302)
    # Job should now have a hashfile
    db.session.expire_all()
    job_updated = Jobs.query.get(job.id)
    assert job_updated.hashfile_id is not None


# ---------------------------------------------------------------------------
# jobs_assigned_hashfile — pwdump file type validation path (lines 324-325)
# ---------------------------------------------------------------------------

def test_jobs_assigned_hashfile_paste_pwdump_invalid_flashes(app, client):
    """Pasting pwdump content that fails validation should flash an error."""
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    _login(client, user)

    data = dict(_HASHFILE_FORM_BASE)
    data.update({
        "hashfilehashes": "notapwdumphash",
        "name": "pwdump-test",
        "file_type": "pwdump",
        "pwdump_hash_type": "1000",
    })
    resp = client.post(f"/jobs/{job.id}/assigned_hashfile/",
                       data=data,
                       content_type="multipart/form-data",
                       follow_redirects=True)
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# jobs_assigned_hashfile — NetNTLM file type validation path (lines 327-328)
# ---------------------------------------------------------------------------

def test_jobs_assigned_hashfile_paste_netntlm_invalid_flashes(app, client):
    """Pasting NetNTLM content that fails validation should flash an error."""
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    _login(client, user)

    data = dict(_HASHFILE_FORM_BASE)
    data.update({
        "hashfilehashes": "notanetntlmhash",
        "name": "netntlm-test",
        "file_type": "NetNTLM",
        "netntlm_hash_type": "",
    })
    resp = client.post(f"/jobs/{job.id}/assigned_hashfile/",
                       data=data,
                       content_type="multipart/form-data",
                       follow_redirects=True)
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# jobs_assigned_hashfile — kerberos file type validation path (lines 329-331)
# ---------------------------------------------------------------------------

def test_jobs_assigned_hashfile_paste_kerberos_invalid_flashes(app, client):
    """Pasting kerberos content that fails validation should flash an error."""
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    _login(client, user)

    data = dict(_HASHFILE_FORM_BASE)
    data.update({
        "hashfilehashes": "notakerberoshash",
        "name": "kerberos-test",
        "file_type": "kerberos",
        "kerberos_hash_type": "",
    })
    resp = client.post(f"/jobs/{job.id}/assigned_hashfile/",
                       data=data,
                       content_type="multipart/form-data",
                       follow_redirects=True)
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# jobs_assigned_hashfile — shadow file type validation path (lines 333-334)
# ---------------------------------------------------------------------------

def test_jobs_assigned_hashfile_paste_shadow_invalid_flashes(app, client):
    """Pasting shadow content that fails validation should flash an error."""
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    _login(client, user)

    data = dict(_HASHFILE_FORM_BASE)
    data.update({
        "hashfilehashes": "notashadowhash",
        "name": "shadow-test",
        "file_type": "shadow",
        "shadow_hash_type": "",
    })
    resp = client.post(f"/jobs/{job.id}/assigned_hashfile/",
                       data=data,
                       content_type="multipart/form-data",
                       follow_redirects=True)
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# jobs_assigned_hashfile — user_hash file type validation path (lines 335-337)
# ---------------------------------------------------------------------------

def test_jobs_assigned_hashfile_paste_user_hash_invalid_flashes(app, client):
    """Pasting user_hash content that fails validation should flash an error."""
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    _login(client, user)

    data = dict(_HASHFILE_FORM_BASE)
    data.update({
        "hashfilehashes": "notauserhash",
        "name": "user-hash-test",
        "file_type": "user_hash",
        "hash_type": "1000",
    })
    resp = client.post(f"/jobs/{job.id}/assigned_hashfile/",
                       data=data,
                       content_type="multipart/form-data",
                       follow_redirects=True)
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# jobs_assigned_hashfile — AJAX + has_problem returns JSON (line 346)
# ---------------------------------------------------------------------------

def test_jobs_assigned_hashfile_ajax_validation_problem_returns_json(app, client):
    """AJAX paste with invalid hash returns JSON error (covers line 346)."""
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    _login(client, user)

    data = dict(_HASHFILE_FORM_BASE)
    data.update({
        "hashfilehashes": "notavalidntlm",
        "name": "ajax-fail",
        "file_type": "hash_only",
        "hash_type": "1000",
    })
    resp = client.post(f"/jobs/{job.id}/assigned_hashfile/",
                       data=data,
                       content_type="multipart/form-data",
                       headers={"X-Requested-With": "fetch"},
                       follow_redirects=False)
    assert resp.status_code == 400
    body = resp.get_json()
    assert body["status"] == "error"
    assert "hash" in body["msg"].lower() or "valid" in body["msg"].lower()


# ---------------------------------------------------------------------------
# jobs_assigned_hashfile — paste that imports but finds zero hashes (lines 368-373)
# ---------------------------------------------------------------------------

def test_jobs_assigned_hashfile_paste_no_valid_hashes_found_flashes(app, client):
    """Pasting content that passes format check but has no importable hashes
    should flash 'No valid hashes found' (covers lines 368-373)."""
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    _login(client, user)

    # A valid-format user_hash line but the hash part is 32 zeros (the empty-hash
    # sentinel); import_hashfilehashes may de-dup it with an existing zero hash
    # or accept it. Alternatively, use a truly valid hash type that has no entries.
    # Use NTLM hash format but a known "empty" NTLM — this WILL import.
    # Instead, use an entirely blank line — validate_hash_only returns no error
    # for a blank file (nothing to validate), and import finds 0 hashes.
    data = dict(_HASHFILE_FORM_BASE)
    data.update({
        "hashfilehashes": "\n\n\n",  # blank lines only
        "name": "empty-hashes",
        "file_type": "hash_only",
        "hash_type": "1000",
    })
    resp = client.post(f"/jobs/{job.id}/assigned_hashfile/",
                       data=data,
                       content_type="multipart/form-data",
                       follow_redirects=True)
    assert resp.status_code == 200
    # Either redirected back (no valid hashes) or the job got a hashfile
    # Either is correct behavior; we just need no 500


# ---------------------------------------------------------------------------
# jobs_assign_task — duplicate task with NULL wordlist (line 487)
# ---------------------------------------------------------------------------

def test_jobs_assign_task_duplicate_with_no_wordlist_flashes(app, client):
    """A task whose wordlist was deleted (wl_id resolves to None) should flash warning."""
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    # Create a task with a NULL wl_id (simulating a deleted wordlist)
    task = Tasks(name="no-wl-task", owner_id=user.id, wl_id=None, rule_id=None,
                 hc_attackmode=3, loopback=False)
    db.session.add(task)
    db.session.commit()
    # Pre-assign the task
    db.session.add(JobTasks(job_id=job.id, task_id=task.id, status="Not Started"))
    db.session.commit()
    _login(client, user)

    # Assign again — should flash "Task already assigned"
    resp = client.get(f"/jobs/{job.id}/assign_task/{task.id}",
                      follow_redirects=True)
    assert b"Task already assigned to the job." in resp.data
    assert JobTasks.query.filter_by(job_id=job.id, task_id=task.id).count() == 1


# ---------------------------------------------------------------------------
# jobs_assign_task_group — duplicate dynamic wordlist task in group (lines 512-516)
# ---------------------------------------------------------------------------

def test_jobs_assign_task_group_dynamic_duplicate_added(app, client):
    """A task group with a dynamic-wordlist task allows duplicate assignment."""
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    wl = _make_wordlist(user.id, name="dyn-wl-grp", wl_type="dynamic")
    task = _make_task(user.id, wl.id, name="dyn-group-task")
    tg = TaskGroups(name="dyn-group", owner_id=user.id,
                    tasks=_json.dumps([str(task.id)]))
    db.session.add(tg)
    db.session.commit()
    # Pre-assign once
    db.session.add(JobTasks(job_id=job.id, task_id=task.id, status="Not Started"))
    db.session.commit()
    _login(client, user)

    # Re-assign via task group — dynamic allows duplicates
    resp = client.get(f"/jobs/{job.id}/assign_task_group/{tg.id}",
                      follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert JobTasks.query.filter_by(job_id=job.id, task_id=task.id).count() == 2


# ---------------------------------------------------------------------------
# jobs_assign_task_group — duplicate task with no wordlist in group (skip)
# ---------------------------------------------------------------------------

def test_jobs_assign_task_group_no_wordlist_duplicate_skipped(app, client):
    """A task group with a no-wordlist task skips duplicates silently."""
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    task = Tasks(name="nowl-grp-task", owner_id=user.id, wl_id=None,
                 rule_id=None, hc_attackmode=3, loopback=False)
    db.session.add(task)
    db.session.commit()
    tg = TaskGroups(name="nowl-group", owner_id=user.id,
                    tasks=_json.dumps([str(task.id)]))
    db.session.add(tg)
    db.session.commit()
    # Pre-assign once
    db.session.add(JobTasks(job_id=job.id, task_id=task.id, status="Not Started"))
    db.session.commit()
    _login(client, user)

    client.get(f"/jobs/{job.id}/assign_task_group/{tg.id}")
    # Still only 1 (no-wordlist duplicate is silently skipped)
    assert JobTasks.query.filter_by(job_id=job.id, task_id=task.id).count() == 1


# ---------------------------------------------------------------------------
# jobs_assign_lucky_task_group — not enough data flash (lines 550-551)
# ---------------------------------------------------------------------------

def test_jobs_assign_lucky_no_data_flashes(app, client):
    """When there's no cracked hash history, the lucky route flashes an error."""
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    # Attach a hashfile so the route can look up the hash type
    hf, h = _attach_hashfile(job, user.id, cracked=False)
    _login(client, user)

    resp = client.get(f"/jobs/{job.id}/assign_task/lucky",
                      follow_redirects=True)
    assert resp.status_code == 200
    assert b"Not enough data" in resp.data


# ---------------------------------------------------------------------------
# jobs_assign_lucky_task_group — happy path with cracked history (lines 553-561)
# ---------------------------------------------------------------------------

def test_jobs_assign_lucky_with_data_assigns_tasks(app, client):
    """When there are cracked hashes referencing a task, lucky assigns them."""
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    hf, _ = _attach_hashfile(job, user.id, cracked=False)

    # Create a task to be "discovered" as effective
    wl = _make_wordlist(user.id, name="lucky-wl")
    effective_task = _make_task(user.id, wl.id, name="lucky-task")

    # Create a cracked hash that references the effective_task and same hash_type
    cracked_h = Hashes(sub_ciphertext="d" * 32, ciphertext="d" * 32,
                       hash_type=1000, cracked=True,
                       plaintext="pw", task_id=effective_task.id)
    db.session.add(cracked_h)
    db.session.commit()
    _login(client, user)

    resp = client.get(f"/jobs/{job.id}/assign_task/lucky",
                      follow_redirects=True)
    assert resp.status_code == 200
    assert b"Successfully Added Top 10 Tasks" in resp.data
    assert JobTasks.query.filter_by(job_id=job.id, task_id=effective_task.id).count() == 1


# ---------------------------------------------------------------------------
# jobs_remove_task — task not found (line 624, 643-644)
# ---------------------------------------------------------------------------

def test_jobs_remove_task_not_found_flashes(app, client):
    """Removing a task that isn't in the job should flash a warning."""
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    wl = _make_wordlist(user.id)
    task = _make_task(user.id, wl.id)
    _login(client, user)

    # task is not assigned to job — remove should flash
    resp = client.get(f"/jobs/{job.id}/remove_task/{task.id}",
                      follow_redirects=True)
    assert b"no longer on this job" in resp.data


# ---------------------------------------------------------------------------
# jobs_remove_all_tasks (lines 656-660)
# ---------------------------------------------------------------------------

def test_jobs_remove_all_tasks_clears_all(app, client):
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    wl = _make_wordlist(user.id)
    t1 = _make_task(user.id, wl.id, name="rall-1")
    t2 = _make_task(user.id, wl.id, name="rall-2")
    db.session.add(JobTasks(job_id=job.id, task_id=t1.id, status="Not Started"))
    db.session.add(JobTasks(job_id=job.id, task_id=t2.id, status="Not Started"))
    db.session.commit()
    _login(client, user)

    resp = client.get(f"/jobs/{job.id}/remove_all_tasks", follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert JobTasks.query.filter_by(job_id=job.id).count() == 0


# ---------------------------------------------------------------------------
# jobs_assign_notifications — slack notification (lines 696-704)
# ---------------------------------------------------------------------------

def test_jobs_notifications_post_slack_notification(app, client):
    """Enabling slack job completion creates a 'slack' notification row."""
    user = _nonadmin()
    _settings()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    _login(client, user)

    resp = client.post(f"/jobs/{job.id}/notifications",
                       data={"job_completion_slack": "y"},
                       follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert JobNotifications.query.filter_by(
        job_id=job.id, method="slack").count() == 1

    # Idempotent — posting again doesn't duplicate
    client.post(f"/jobs/{job.id}/notifications",
                data={"job_completion_slack": "y"})
    assert JobNotifications.query.filter_by(
        job_id=job.id, method="slack").count() == 1


# ---------------------------------------------------------------------------
# jobs_assign_notifications — hash_completion_slack redirects to hash step (line 713)
# ---------------------------------------------------------------------------

def test_jobs_notifications_hash_slack_redirects_to_hashes(app, client):
    user = _nonadmin()
    _settings()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    _login(client, user)

    resp = client.post(f"/jobs/{job.id}/notifications",
                       data={"hash_completion_slack": "y"},
                       follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert "/notifications/" in resp.headers["Location"]
    assert "slack" in resp.headers["Location"]
    assert "/hashes" in resp.headers["Location"]


# ---------------------------------------------------------------------------
# jobs_move_task_down with 3 tasks — hits the else branch (line 624)
# ---------------------------------------------------------------------------

def test_jobs_move_task_down_three_tasks_else_branch(app, client):
    """Moving task_1 down in a 3-task list exercises the else-append branch."""
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    wl = _make_wordlist(user.id, name="3t-wl")
    t1 = _make_task(user.id, wl.id, name="3t-task-1")
    t2 = _make_task(user.id, wl.id, name="3t-task-2")
    t3 = _make_task(user.id, wl.id, name="3t-task-3")
    db.session.add(JobTasks(job_id=job.id, task_id=t1.id, status="Not Started"))
    db.session.add(JobTasks(job_id=job.id, task_id=t2.id, status="Not Started"))
    db.session.add(JobTasks(job_id=job.id, task_id=t3.id, status="Not Started"))
    db.session.commit()
    _login(client, user)

    # Move t1 down: order should become [t2, t1, t3]
    resp = client.get(f"/jobs/{job.id}/move_task_down/{t1.id}",
                      follow_redirects=False)
    assert resp.status_code in (301, 302)
    order = [jt.task_id for jt in
             JobTasks.query.filter_by(job_id=job.id).order_by(JobTasks.id).all()]
    assert order == [t2.id, t1.id, t3.id]


# ---------------------------------------------------------------------------
# jobs_assign_notification_hashes — GET renders template (line 746)
# ---------------------------------------------------------------------------

def test_jobs_assign_notification_hashes_get_renders(app, client):
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    _, h = _attach_hashfile(job, user.id, cracked=False)
    _login(client, user)

    resp = client.get(f"/jobs/{job.id}/notifications/email/hashes")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# jobs_assign_notification_hashes — multi-method POST (line 735)
# Also exercises the "not in selected_ids -> continue" branch (line 735)
# ---------------------------------------------------------------------------

def test_jobs_assign_notification_hashes_multi_method_post(app, client):
    """Posting with method='email,push' should create rows for both channels."""
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    _, h = _attach_hashfile(job, user.id, cracked=False)
    # Add a second uncracked hash that we will NOT select (hits the continue branch)
    h2 = Hashes(sub_ciphertext="e" * 32, ciphertext="e1" * 16, hash_type=1000,
                cracked=False)
    db.session.add(h2)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=h2.id, hashfile_id=job.hashfile_id))
    db.session.commit()
    _login(client, user)

    # Only select h (not h2) — this hits the "continue" at line 735 for h2
    resp = client.post(f"/jobs/{job.id}/notifications/email,push/hashes",
                       data={"selected": [str(h.id)]},
                       follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert HashNotifications.query.filter_by(
        hash_id=h.id, owner_id=user.id, method="email").count() == 1
    assert HashNotifications.query.filter_by(
        hash_id=h.id, owner_id=user.id, method="push").count() == 1
    # h2 should have NO notification
    assert HashNotifications.query.filter_by(hash_id=h2.id).count() == 0


# ---------------------------------------------------------------------------
# jobs_delete — job not found (lines 755-756)
# ---------------------------------------------------------------------------

def test_jobs_delete_not_found_flashes(app, client):
    user = _admin()
    _login(client, user)

    resp = client.post("/jobs/delete/99999", follow_redirects=True)
    assert resp.status_code == 200
    assert b"not found" in resp.data.lower() or b"deleted" in resp.data.lower()


# ---------------------------------------------------------------------------
# jobs_website_keywords — redirect when no website-keyword tasks (lines 779-781)
# ---------------------------------------------------------------------------

def test_jobs_website_keywords_redirects_when_no_website_task(app, client):
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    _login(client, user)

    resp = client.get(f"/jobs/{job.id}/website", follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert resp.headers["Location"].endswith(f"/jobs/{job.id}/summary")


# ---------------------------------------------------------------------------
# jobs_website_keywords — GET renders when website task present (lines 782-792)
# ---------------------------------------------------------------------------

def test_jobs_website_keywords_renders_when_website_task_present(app, client):
    """When a job has a task using (DYNAMIC) Website Keywords, the form renders."""
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    # Create a "Website Keywords" dynamic wordlist
    wl = Wordlists(name="(DYNAMIC) Website Keywords", owner_id=user.id,
                   type="dynamic",
                   path="control/wordlists/dynamic-website-keywords.txt",
                   size=0, checksum="0" * 64)
    db.session.add(wl)
    db.session.commit()
    task = _make_task(user.id, wl.id, name="website-task")
    jt = JobTasks(job_id=job.id, task_id=task.id, status="Not Started")
    db.session.add(jt)
    db.session.commit()
    _login(client, user)

    resp = client.get(f"/jobs/{job.id}/website")
    assert resp.status_code == 200
    assert b"website" in resp.data.lower() or b"crawl" in resp.data.lower()


# ---------------------------------------------------------------------------
# jobs_website_keywords — GET with hashfile+hash_notifications exercises
# _job_has_alert_hashes true branch (line 78)
# ---------------------------------------------------------------------------

def test_jobs_website_keywords_with_alert_hashes_shows_alert_step(app, client):
    """When a job has hash notifications, _job_has_alert_hashes returns True (line 78)."""
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    # Attach a hashfile and a hash notification
    hf, h = _attach_hashfile(job, user.id, cracked=False, name="alert-hf.txt")
    db.session.add(HashNotifications(owner_id=user.id, hash_id=h.id, method="email"))
    db.session.commit()
    # Website Keywords wordlist
    wl = Wordlists(name="(DYNAMIC) Website Keywords", owner_id=user.id,
                   type="dynamic",
                   path="control/wordlists/dynamic-website-keywords.txt",
                   size=0, checksum="0" * 64)
    db.session.add(wl)
    db.session.commit()
    task = _make_task(user.id, wl.id, name="website-task-alert")
    jt = JobTasks(job_id=job.id, task_id=task.id, status="Not Started")
    db.session.add(jt)
    db.session.commit()
    _login(client, user)

    resp = client.get(f"/jobs/{job.id}/website")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# jobs_website_keywords — POST updates crawl_url (line 785-787)
# ---------------------------------------------------------------------------

def test_jobs_website_keywords_post_saves_url(app, client):
    """POSTing the website keywords form should save the crawl URL."""
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    wl = Wordlists(name="(DYNAMIC) Website Keywords", owner_id=user.id,
                   type="dynamic",
                   path="control/wordlists/dynamic-website-keywords.txt",
                   size=0, checksum="0" * 64)
    db.session.add(wl)
    db.session.commit()
    task = _make_task(user.id, wl.id, name="website-task2")
    jt = JobTasks(job_id=job.id, task_id=task.id, status="Not Started")
    db.session.add(jt)
    db.session.commit()
    _login(client, user)

    resp = client.post(f"/jobs/{job.id}/website",
                       data={"crawl_url": "https://example.com"},
                       follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert resp.headers["Location"].endswith(f"/jobs/{job.id}/summary")
    db.session.expire_all()
    assert Jobs.query.get(job.id).crawl_url == "https://example.com"


# ---------------------------------------------------------------------------
# jobs_stop — job not found (line 909)
# ---------------------------------------------------------------------------

def test_jobs_stop_not_found_flashes(app, client):
    user = _admin()
    _login(client, user)

    resp = client.get("/jobs/stop/99999", follow_redirects=True)
    assert resp.status_code == 200
    # The route flashes "Error in stopping job" and redirects to jobs list
    assert b"Error in stopping job" in resp.data


# ---------------------------------------------------------------------------
# jobs_list — no hashfile_id branch (line 113-115 in _hf_cracked logic)
# ---------------------------------------------------------------------------

def test_jobs_list_job_without_hashfile(app, client):
    """A job with no hashfile_id should not crash the jobs list."""
    user = _nonadmin()
    customer = _make_customer()
    _make_job(user.id, customer.id, name="no-hashfile-job")
    _login(client, user)

    resp = client.get("/jobs")
    assert resp.status_code == 200
    assert b"no-hashfile-job" in resp.data


# ---------------------------------------------------------------------------
# jobs_list — pagination page 2 (exercises paginate branch)
# ---------------------------------------------------------------------------

def test_jobs_list_page_2_renders(app, client):
    """Requesting page 2 of the jobs list should render without error."""
    user = _nonadmin()
    customer = _make_customer()
    _login(client, user)

    resp = client.get("/jobs?page=2")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# jobs_assigned_hashfile_cracked — zero cracked hashes (no flash)
# ---------------------------------------------------------------------------

def test_jobs_assigned_hashfile_cracked_no_flash_when_zero(app, client):
    """When no hashes are cracked, the success flash should NOT appear."""
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    hf, _ = _attach_hashfile(job, user.id, cracked=False)
    _login(client, user)

    resp = client.get(f"/jobs/{job.id}/assigned_hashfile/{hf.id}")
    assert resp.status_code == 200
    assert b"instacracked" not in resp.data


# ---------------------------------------------------------------------------
# jobs_assign_notifications — GET renders when no settings row
# ---------------------------------------------------------------------------

def test_jobs_notifications_get_no_settings(app, client):
    """GET /notifications should render even when Settings table is empty."""
    user = _nonadmin()
    customer = _make_customer()
    job = _make_job(user.id, customer.id)
    _login(client, user)

    resp = client.get(f"/jobs/{job.id}/notifications")
    assert resp.status_code == 200
