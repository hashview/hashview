"""XFAIL regression tests documenting open GitHub issues in the task lifecycle.

Each test asserts the CORRECT / DESIRED behavior and is marked
``@pytest.mark.xfail(strict=False)`` so it shows up as XFAIL while the bug is
live and flips to XPASS once fixed. These are executable specifications of the
fixes, not assertions of current (buggy) behavior.

Issues covered:
  - #139  Canceled tasks retain assigned agent
  - #130  Tasks remain active after all hashes cracked
  - #64   hc_cracked filename collisions across JobTasks
  - #129  Blank Hashfile Name from pasted (whitespace-only) hashes

Infra/fixtures come from tests/unit/conftest.py (``app``, ``client``,
``db_session``) and tests/unit/helpers.py.
"""

import inspect
import json
from datetime import datetime

import pytest

from hashview.models import (
    Agents,
    Customers,
    Hashes,
    HashfileHashes,
    Hashfiles,
    Jobs,
    JobTasks,
    Settings,
    Tasks,
    Users,
    db,
)
from hashview.utils.utils import build_hashcat_command, get_md5_hash


DOMAIN = "localhost.test"


def _agent_version_cookie(client):
    import hashview
    client.set_cookie("agent_version", hashview.__version__, domain=DOMAIN)


# ---------------------------------------------------------------------------
# #139 — Canceled tasks retain assigned agent
# ---------------------------------------------------------------------------
@pytest.mark.xfail(
    reason="issue #139: a 'Working' heartbeat for a Canceled JobTasks returns "
           "msg='Canceled' but never clears job_task.agent_id "
           "(hashview/api/routes.py ~263-274), so the row stays bound to the "
           "agent and the next Idle heartbeat resumes it",
    strict=False,
)
def test_canceled_task_clears_agent_assignment(app, client):
    """A Working heartbeat against a Canceled JobTasks should release the agent.

    Seed an Authorized agent holding a JobTasks row whose status is already
    'Canceled'. Drive a 'Working' heartbeat: the route detects the cancel and
    returns msg='Canceled', but the DESIRED behavior is that it also clears
    job_task.agent_id so a subsequent Idle heartbeat doesn't pick the stale
    (canceled) task back up via the already-assigned branch (~api/routes.py:317).
    """
    db.session.add(Settings(retention_period=30, max_runtime_tasks=0,
                            max_runtime_jobs=0))
    admin = Users(first_name="A", last_name="D",
                  email_address="a139@example.test", password="x" * 60,
                  admin=True, api_key="k139")
    db.session.add(admin)
    db.session.commit()

    cust = Customers(name="C139")
    db.session.add(cust)
    db.session.commit()
    hf = Hashfiles(name="hf139", customer_id=cust.id, owner_id=admin.id)
    db.session.add(hf)
    db.session.commit()

    job = Jobs(name="J139", owner_id=admin.id, customer_id=cust.id,
               hashfile_id=hf.id, status="Running", limit_recovered=False,
               started_at=datetime.now())
    db.session.add(job)
    db.session.commit()
    task = Tasks(name="T139", owner_id=admin.id, hc_attackmode=0)
    db.session.add(task)
    db.session.commit()

    agent = Agents(name="agent139", src_ip="1.1.1.1", uuid="uuid-139",
                   status="Working", last_checkin=datetime.now())
    db.session.add(agent)
    db.session.commit()

    jt = JobTasks(job_id=job.id, task_id=task.id, status="Canceled",
                  agent_id=agent.id, started_at=datetime.now())
    db.session.add(jt)
    db.session.commit()
    jt_id = jt.id

    client.set_cookie("uuid", agent.uuid, domain=DOMAIN)
    _agent_version_cookie(client)
    resp = client.post(
        "/v1/agents/heartbeat",
        data=json.dumps({"agent_status": "Working", "hc_status": "stopped"}),
        content_type="application/json",
    )
    assert resp.status_code == 200
    body = json.loads(resp.get_data(as_text=True))
    assert body["msg"] == "Canceled"

    db.session.expire_all()
    refreshed = JobTasks.query.get(jt_id)
    # DESIRED: the canceled task no longer holds the agent.
    assert refreshed.agent_id is None


# ---------------------------------------------------------------------------
# #130 — Tasks remain active after all hashes cracked (normal job)
# ---------------------------------------------------------------------------
@pytest.mark.xfail(
    reason="issue #130: when all hashes are cracked on a NORMAL job "
           "(limit_recovered=False), only limit_recovered jobs transition "
           "their JobTasks (hashview/api/routes.py ~1382-1402); a normal job "
           "leaves the JobTasks 'Running'",
    strict=False,
)
def test_all_hashes_cracked_completes_running_tasks(app, client):
    """Cracking the only hash on a normal job should Complete its JobTasks.

    POST the single (= all) hash as cracked to /v1/uploadCrackFile/<jt>. The
    hash IS flipped to cracked (asserted), but on a normal (limit_recovered=
    False) job the route never transitions tasks, so the JobTasks stays
    'Running'. DESIRED: with every hash in the file cracked the task is
    'Completed'.
    """
    db.session.add(Settings(retention_period=30, max_runtime_tasks=0,
                            max_runtime_jobs=0))
    admin = Users(first_name="A", last_name="D",
                  email_address="a130@example.test", password="x" * 60,
                  admin=True, api_key="k130")
    db.session.add(admin)
    db.session.commit()

    cust = Customers(name="C130")
    db.session.add(cust)
    db.session.commit()
    hf = Hashfiles(name="hf130", customer_id=cust.id, owner_id=admin.id)
    db.session.add(hf)
    db.session.commit()

    h = Hashes(sub_ciphertext=get_md5_hash("AAAA"), ciphertext="AAAA",
               hash_type=1000, cracked=False)
    db.session.add(h)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    db.session.commit()
    h_id = h.id

    task = Tasks(name="T130", owner_id=admin.id, hc_attackmode=0)
    db.session.add(task)
    db.session.commit()

    job = Jobs(name="J130", owner_id=admin.id, customer_id=cust.id,
               hashfile_id=hf.id, status="Running", limit_recovered=False,
               started_at=datetime.now())
    db.session.add(job)
    db.session.commit()

    agent = Agents(name="agent130", src_ip="1.1.1.1", uuid="uuid-130",
                   status="Authorized", last_checkin=datetime.now())
    db.session.add(agent)
    db.session.commit()

    jt = JobTasks(job_id=job.id, task_id=task.id, status="Running",
                  agent_id=agent.id, started_at=datetime.now())
    db.session.add(jt)
    db.session.commit()
    jt_id = jt.id

    client.set_cookie("uuid", agent.uuid, domain=DOMAIN)
    resp = client.post(
        f"/v1/uploadCrackFile/{jt_id}",
        data=json.dumps({"file": "AAAA:secret"}),
        content_type="application/json",
    )
    assert resp.status_code == 200

    db.session.expire_all()
    # The hash is indeed cracked by the upload...
    assert Hashes.query.get(h_id).cracked == 1
    # ...so the only task should be Completed (all hashes recovered).
    assert JobTasks.query.get(jt_id).status == "Completed"


# ---------------------------------------------------------------------------
# #64 — hc_cracked filename collisions across JobTasks
# ---------------------------------------------------------------------------
@pytest.mark.xfail(
    reason="issue #64: build_hashcat_command names the crack outfile "
           "hc_cracked_<job.id>_<task.id>.txt keyed on Tasks.id, not the "
           "JobTasks row (hashview/utils/utils.py ~675), so two JobTasks for "
           "the same job+task collide and overwrite each other",
    strict=False,
)
def test_hc_cracked_filename_unique_per_jobtask(app):
    """Two JobTasks for the same job+task must get distinct crack-file names.

    build_hashcat_command(job_id, task_id) embeds only job.id and task.id in
    --outfile, so seeding two distinct JobTasks rows for the same (job, task)
    yields identical crack-file names. DESIRED: the name is keyed on the
    JobTasks row so the two generated commands reference different files.
    """
    admin = Users(first_name="A", last_name="D",
                  email_address="a64@example.test", password="x" * 60,
                  admin=True, api_key="k64")
    db.session.add(admin)
    db.session.commit()

    cust = Customers(name="C64")
    db.session.add(cust)
    db.session.commit()
    hf = Hashfiles(name="hf64", customer_id=cust.id, owner_id=admin.id)
    db.session.add(hf)
    db.session.commit()

    h = Hashes(sub_ciphertext=get_md5_hash("CAFE"), ciphertext="CAFE",
               hash_type=1000, cracked=False)
    db.session.add(h)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    db.session.commit()

    task = Tasks(name="T64", owner_id=admin.id, hc_attackmode=3,
                 hc_mask="?d?d?d?d")
    db.session.add(task)
    db.session.commit()

    job = Jobs(name="J64", owner_id=admin.id, customer_id=cust.id,
               hashfile_id=hf.id, status="Running", limit_recovered=False,
               started_at=datetime.now())
    db.session.add(job)
    db.session.commit()

    # Two distinct JobTasks rows for the SAME job + task.
    jt1 = JobTasks(job_id=job.id, task_id=task.id, status="Queued")
    jt2 = JobTasks(job_id=job.id, task_id=task.id, status="Queued")
    db.session.add_all([jt1, jt2])
    db.session.commit()

    cmd1 = build_hashcat_command(job.id, task.id)
    cmd2 = build_hashcat_command(job.id, task.id)

    def _crackfile(cmd):
        parts = cmd.split()
        return parts[parts.index("--outfile") + 1]

    name1 = _crackfile(cmd1)
    name2 = _crackfile(cmd2)
    # DESIRED: per-jobtask crack files, so the two names differ.
    assert name1 != name2


# ---------------------------------------------------------------------------
# #129 — Blank Hashfile Name from pasted (whitespace-only) hashes
# ---------------------------------------------------------------------------
@pytest.mark.xfail(
    reason="issue #129: the blank-name guard in jobs_assigned_hashfile uses "
           "`len(name.data) == 0` (hashview/jobs/routes.py ~305), so a "
           "whitespace-only name slips through and creates a blank hashfile "
           "name; the guard should be strip-aware",
    strict=False,
)
def test_pasted_hashes_blank_name_guard_strips_whitespace(app):
    """The pasted-hashes name guard should reject whitespace-only names.

    Limitation: the full paste -> import code path isn't reachable at the unit
    level (it needs control/tmp writes, file-type validators, and a populated
    upload form), so instead of driving the route we inspect the source of
    hashview.jobs.routes.jobs_assigned_hashfile and assert the DESIRED
    strip-aware guard (``name.data.strip()``) is present. It currently is not:
    the live guard is the whitespace-blind ``len(name.data) == 0``.
    """
    from hashview.jobs.routes import jobs_assigned_hashfile

    src = inspect.getsource(jobs_assigned_hashfile)
    # DESIRED: the guard strips before measuring emptiness, e.g.
    #   if len(name.data.strip()) == 0:  /  if not name.data.strip():
    assert "name.data.strip()" in src
