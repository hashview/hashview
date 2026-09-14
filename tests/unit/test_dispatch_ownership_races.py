"""Ownership and race guards on the agent-facing job-task endpoints.

Three holes, all of which let one agent's work be corrupted by another:

  * DISPATCH had no locking of any kind. The candidate SELECT is a snapshot read
    -- under MySQL's default REPEATABLE READ it cannot see another agent's
    concurrent commit -- so two agents heartbeating together both picked the same
    row and the second plain write simply won. It was survivable only because
    GET /v1/jobTasks/<id> ignored its own path parameter and returned
    filter_by(agent_id=...).first(), so the loser got null and bailed.

  * GET /v1/jobTasks/<id> ignored job_task_id. That was accidentally safe (an
    agent could only see its own row) but returned an ARBITRARY row when an agent
    held more than one, so the agent could run one command while naming another
    row's temp files. Honouring the parameter without an ownership check would
    turn the accident into a cross-agent command disclosure, so the two changes
    belong together.

  * POST /v1/jobtask/status had no ownership check at all: any authorized agent
    could set any job task to any string. It also meant an agent whose slice had
    been reclaimed could still mark Completed work another agent was part-way
    through -- and that slice would then never be re-run.
"""

import json
from datetime import datetime

import pytest

import hashview
from hashview.models import (
    AgentBenchmarks,
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

DOMAIN = "localhost.test"
pytestmark = pytest.mark.security


def _cookies(client, uuid):
    client.set_cookie("uuid", uuid, domain=DOMAIN)
    client.set_cookie("agent_version", hashview.__version__, domain=DOMAIN)


def _body(resp):
    return json.loads(resp.get_data(as_text=True))


def _seed(rows=1, status="Queued"):
    user = Users(first_name="A", last_name="D", email_address="a@b.com",
                 password="x" * 60, admin=True)
    db.session.add(user)
    db.session.commit()
    db.session.add(Settings(retention_period=30, max_runtime_jobs=0, max_runtime_tasks=0))
    cust = Customers(name="C")
    db.session.add(cust)
    db.session.commit()
    hf = Hashfiles(name="h", customer_id=cust.id, owner_id=user.id)
    db.session.add(hf)
    db.session.commit()
    h = Hashes(sub_ciphertext="0" * 32, ciphertext="AAA", hash_type=1000, cracked=False)
    db.session.add(h)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    task = Tasks(name="t", owner_id=user.id, hc_attackmode=0, loopback=False)
    db.session.add(task)
    db.session.commit()
    job = Jobs(name="j", owner_id=user.id, customer_id=cust.id, hashfile_id=hf.id,
               status="Running", priority=3, started_at=datetime.now())
    db.session.add(job)
    db.session.commit()
    made = []
    for _ in range(rows):
        jt = JobTasks(job_id=job.id, task_id=task.id, status=status, priority=3,
                      command='["@HASHCATBINPATH@","-m","1000"]')
        db.session.add(jt)
        db.session.commit()
        made.append(jt)
    return job, made


def _agents(*uuids):
    """Idle agents that already carry a benchmark for the seeded hash type.

    Without one the heartbeat answers BENCHMARK instead of dispatching -- the
    benchmark-first gate runs ahead of the candidate loop.
    """
    out = []
    for u in uuids:
        a = Agents(name=u, src_ip="127.0.0.1", uuid=u, status="Idle")
        db.session.add(a)
        db.session.commit()
        db.session.add(AgentBenchmarks(agent_id=a.id, hash_type=1000, speed=1000))
        db.session.commit()
        out.append(a)
    return out


# --- dispatch ---------------------------------------------------------------

def test_one_queued_row_goes_to_exactly_one_of_two_agents(client, app):
    """Two idle agents, one row: one gets START, the other gets no work."""
    _seed(rows=1)
    a, b = _agents("agent-a", "agent-b")

    _cookies(client, a.uuid)
    first = _body(client.post("/v1/agents/heartbeat",
                              data=json.dumps({"agent_status": "Idle", "hc_status": ""}),
                              content_type="application/json"))
    _cookies(client, b.uuid)
    second = _body(client.post("/v1/agents/heartbeat",
                               data=json.dumps({"agent_status": "Idle", "hc_status": ""}),
                               content_type="application/json"))

    assert first["msg"] == "START"
    assert second["msg"] == "OK", "the row was already claimed; no second START"
    assert JobTasks.query.filter_by(status="Running").count() == 1


def test_a_lost_claim_moves_on_to_the_next_candidate(client, app, monkeypatch):
    """Losing the race on one row must not waste the beat: try the next one.

    Simulated by having the first conditional UPDATE report 0 rows changed, which
    is exactly what a concurrent claim produces.
    """
    _seed(rows=2)
    (a,) = _agents("agent-a")
    real_update = db.session.query(JobTasks).__class__.update
    calls = {"n": 0}

    def flaky_update(self, values, **kw):
        # Only interfere with the dispatch claim (it sets agent_id + status).
        if isinstance(values, dict) and values.get("status") == "Running":
            calls["n"] += 1
            if calls["n"] == 1:
                return 0
        return real_update(self, values, **kw)

    monkeypatch.setattr(type(db.session.query(JobTasks)), "update", flaky_update)

    _cookies(client, a.uuid)
    resp = _body(client.post("/v1/agents/heartbeat",
                             data=json.dumps({"agent_status": "Idle", "hc_status": ""}),
                             content_type="application/json"))

    assert calls["n"] >= 2, "the first claim must have been retried on another row"
    assert resp["msg"] == "START"


def test_a_queued_row_naming_an_agent_is_not_handed_back(client, app):
    """A Start on an already-running job leaves Queued rows with agent_id set.

    Those are not assignments in progress, and handing one back here would run it
    while dispatch was also free to give it to someone else.
    """
    _job, rows = _seed(rows=1, status="Queued")
    (a,) = _agents("agent-a")
    rows[0].agent_id = a.id
    db.session.commit()

    _cookies(client, a.uuid)
    resp = _body(client.post("/v1/agents/heartbeat",
                             data=json.dumps({"agent_status": "Idle", "hc_status": ""}),
                             content_type="application/json"))

    # It is dispatched through the normal claim path (which clears the stale
    # agent_id by overwriting it), not short-circuited by the already-assigned branch.
    assert resp["msg"] == "START"
    assert JobTasks.query.get(rows[0].id).status == "Running"


# --- GET /v1/jobTasks/<id> --------------------------------------------------

def test_get_jobtask_honours_its_path_parameter(client, app):
    _job, rows = _seed(rows=2, status="Running")
    (a,) = _agents("agent-a")
    for r in rows:
        r.agent_id = a.id
    db.session.commit()

    _cookies(client, a.uuid)
    body = _body(client.get(f"/v1/jobTasks/{rows[1].id}"))
    assert body["job_task"]["id"] == rows[1].id, "returned some other row"


def test_get_jobtask_refuses_another_agents_row(client, app):
    _job, rows = _seed(rows=1, status="Running")
    a, b = _agents("agent-a", "agent-b")
    rows[0].agent_id = a.id
    db.session.commit()

    _cookies(client, b.uuid)
    resp = client.get(f"/v1/jobTasks/{rows[0].id}")
    # Answered exactly like "you have no assignment" (issue #218's 200 + null),
    # so the agent's existing bail-out path handles it and the other agent's row
    # -- including its command -- is never disclosed.
    assert resp.status_code == 200
    assert _body(resp)["job_task"] is None


def test_file_key_falls_back_to_the_row_id_when_the_command_names_no_outfile(client, app):
    """The fallback branch. _seed stamps a command with no --outfile, so nothing
    is parseable and the row id is the answer -- which is also the key
    _set_job_task_command would have baked in. Named for the branch it actually
    exercises: it used to be called test_get_jobtask_states_the_file_key, which
    implied it covered the derivation. It never did, and the derivation went
    untested until the test below.
    """
    _job, rows = _seed(rows=1, status="Running")
    (a,) = _agents("agent-a")
    rows[0].agent_id = a.id
    db.session.commit()

    _cookies(client, a.uuid)
    body = _body(client.get(f"/v1/jobTasks/{rows[0].id}"))
    assert body["job_task"]["file_key"] == rows[0].id


def test_file_key_reports_the_last_outfile_because_hashcat_honours_the_last(client, app):
    """A repeated --outfile resolves to the LAST, matching hashcat.

    Verified against hashcat v6.2.6: `--outfile A --outfile B` writes B and never
    creates A. Reachable without any tampering -- the Hashcat Mask field is
    free-form and split on whitespace into argv elements that land after the
    server's own --outfile, so a mask of '?d?d --outfile ...' emits a second one.
    Reporting the first would point the agent at a file hashcat never writes.
    """
    _job, rows = _seed(rows=1, status="Running")
    (a,) = _agents("agent-a")
    rows[0].agent_id = a.id
    rows[0].command = json.dumps([
        "@HASHCATBINPATH@", "-m", "1000",
        "--outfile", "control/outfiles/hc_cracked_1_111.txt",
        "control/hashes/hashfile_1_111.txt", "?d?d",
        "--outfile", "control/outfiles/hc_cracked_1_222.txt",
    ])
    db.session.commit()

    _cookies(client, a.uuid)
    body = _body(client.get(f"/v1/jobTasks/{rows[0].id}"))
    assert str(body["job_task"]["file_key"]) == "222"


def test_file_key_is_read_out_of_the_command_not_the_row_id(client, app):
    """The wire field must restate the command, never second-guess it.

    Deriving it from the row id made it an independent opinion, and the agent
    believed the opinion over the command: it saved the target hashfile under a
    name hashcat was never told to open. Any row whose command carries some other
    key -- a row stamped by an older server, or built without an explicit
    job_task_id, as the e2e-crack seeder did -- must be reported with THAT key, so
    the two halves of this one payload cannot contradict each other.
    """
    _job, rows = _seed(rows=1, status="Running")
    (a,) = _agents("agent-a")
    rows[0].agent_id = a.id
    rows[0].command = json.dumps([
        "@HASHCATBINPATH@", "-m", "1000",
        "--potfile-path", "control/outfiles/hc_potfile_1_777.pot",
        "--outfile", "control/outfiles/hc_cracked_1_777.txt",
        "control/hashes/hashfile_1_777.txt", "control/wordlists/a.gz",
    ])
    db.session.commit()
    assert rows[0].id != 777                     # the point of the test

    _cookies(client, a.uuid)
    body = _body(client.get(f"/v1/jobTasks/{rows[0].id}"))
    assert str(body["job_task"]["file_key"]) == "777"


# --- POST /v1/jobtask/status ------------------------------------------------

def _post_status(client, job_task_id, status):
    return client.post("/v1/jobtask/status",
                       data=json.dumps({"job_task_id": job_task_id,
                                        "task_status": status}),
                       content_type="application/json")


def test_status_update_requires_ownership(client, app):
    _job, rows = _seed(rows=1, status="Running")
    a, b = _agents("agent-a", "agent-b")
    rows[0].agent_id = a.id
    db.session.commit()

    _cookies(client, b.uuid)
    body = _body(_post_status(client, rows[0].id, "Completed"))

    assert body["status"] == 409
    assert JobTasks.query.get(rows[0].id).status == "Running", "must not have been changed"


def test_the_owner_can_complete_its_own_row(client, app):
    _job, rows = _seed(rows=1, status="Running")
    (a,) = _agents("agent-a")
    rows[0].agent_id = a.id
    db.session.commit()

    _cookies(client, a.uuid)
    body = _body(_post_status(client, rows[0].id, "Completed"))

    assert body["status"] == 200
    assert JobTasks.query.get(rows[0].id).status == "Completed"


def test_a_repeated_report_of_the_same_status_is_a_no_op(client, app):
    """The agent defensively re-POSTs 'Running'; that must not be rejected."""
    _job, rows = _seed(rows=1, status="Running")
    (a,) = _agents("agent-a")
    rows[0].agent_id = a.id
    db.session.commit()

    _cookies(client, a.uuid)
    assert _body(_post_status(client, rows[0].id, "Running"))["status"] == 200
    assert JobTasks.query.get(rows[0].id).status == "Running"


def test_a_reclaimed_slice_cannot_be_completed_by_its_old_owner(client, app):
    """The whole point of the ownership check.

    The agent went quiet, the health sweep queued its slice for someone else, and
    then the original agent finished and reported Completed. Accepting that would
    mark work complete that nobody has actually run to the end.
    """
    _job, rows = _seed(rows=1, status="Running")
    (a,) = _agents("agent-a")
    rows[0].agent_id = a.id
    db.session.commit()

    # The reclaim, as _reclaim_stranded_job_tasks performs it.
    rows[0].status = "Queued"
    rows[0].agent_id = None
    db.session.commit()

    _cookies(client, a.uuid)
    body = _body(_post_status(client, rows[0].id, "Completed"))

    assert body["status"] == 409
    assert JobTasks.query.get(rows[0].id).status == "Queued", "still available to re-run"
