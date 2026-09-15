"""Dispatch over the ledger: queue order, and the cancellation gate.

The gate is the dangerous part. Every cancel path in Hashview works by setting
existing JobTasks rows to 'Canceled'. Against a fully-materialised plan that is
total -- there are no other rows. Against a cursor it is not: more slices are
always waiting to be born, so cancelling only the rows leaves the attack mintable
and the very next heartbeat issues slice N+1, cancels it, issues N+2. One slice
burned per agent per heartbeat, forever, on a job the operator already stopped.

So every cancellation has to close the LEDGER, and these tests assert the
observable consequence: after a stop, no heartbeat ever returns START for that
attack again.
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
    JobTaskLedger,
    JobTasks,
    Rules,
    Settings,
    Tasks,
    Users,
    Wordlists,
    db,
)
from hashview.utils.utils import build_job_task_commands, job_assignments

DOMAIN = "localhost.test"
pytestmark = pytest.mark.security


def _cookies(client, uuid):
    client.set_cookie("uuid", uuid, domain=DOMAIN)
    client.set_cookie("agent_version", hashview.__version__, domain=DOMAIN)


def _body(resp):
    return json.loads(resp.get_data(as_text=True))


def _beat(client, uuid):
    _cookies(client, uuid)
    return _body(client.post("/v1/agents/heartbeat",
                             data=json.dumps({"agent_status": "Idle", "hc_status": ""}),
                             content_type="application/json"))


def _seed(task_count=1, job_status="Running"):
    user = Users(first_name="A", last_name="D", email_address="a@b.com",
                 password="x" * 60, admin=True)
    db.session.add(user)
    db.session.commit()
    db.session.add(Settings(retention_period=30, max_runtime_jobs=0, max_runtime_tasks=0,
                            enabled_chunking=True, chunk_target_duration=60))
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
    wl = Wordlists(name="wl", owner_id=user.id, type="static",
                   path="control/wordlists/wl.gz", size=100_000, checksum="0" * 64)
    db.session.add(wl)
    db.session.commit()
    rule = Rules(name="r", owner_id=user.id, path="control/rules/r.rule",
                 checksum="0" * 64, size=100)
    db.session.add(rule)
    db.session.commit()
    job = Jobs(name="j", owner_id=user.id, customer_id=cust.id, hashfile_id=hf.id,
               status=job_status, priority=3, started_at=datetime.now())
    db.session.add(job)
    db.session.commit()
    tasks = []
    for i in range(task_count):
        task = Tasks(name=f"t{i}", owner_id=user.id, hc_attackmode=0, wl_id=wl.id,
                     rule_id=rule.id, loopback=False)
        db.session.add(task)
        db.session.commit()
        db.session.add(JobTasks(job_id=job.id, task_id=task.id, status="Not Started"))
        db.session.commit()
        tasks.append(task)
    build_job_task_commands(job)
    db.session.commit()
    return job, tasks


def _agent(uuid, speed=1000):
    a = Agents(name=uuid, src_ip="1.1.1.1", uuid=uuid, status="Idle")
    db.session.add(a)
    db.session.commit()
    db.session.add(AgentBenchmarks(agent_id=a.id, hash_type=1000, speed=speed))
    db.session.commit()
    return a


def test_an_agent_is_handed_a_sized_slice(app, client):
    job, _ = _seed()
    _agent("a", speed=1000)

    body = _beat(client, "a")
    assert body["msg"] == "START"
    row = JobTasks.query.get(body["job_task_id"])
    assert row.chunk_skip == 0
    assert row.chunk_limit == 600           # 1000 H/s * 60s / amp 100
    assert "--skip" in row.command and "--limit" in row.command


def test_two_agents_get_adjacent_slices_of_one_attack(app, client):
    job, _ = _seed()
    _agent("a", speed=1000)
    _agent("b", speed=2000)

    first = JobTasks.query.get(_beat(client, "a")["job_task_id"])
    second = JobTasks.query.get(_beat(client, "b")["job_task_id"])

    assert first.id != second.id
    assert second.chunk_skip == first.chunk_skip + first.chunk_limit
    assert second.chunk_limit == 2 * first.chunk_limit, "sized per agent"
    ledger = JobTaskLedger.query.filter_by(job_id=job.id).one()
    assert ledger.keyspace_pos == first.chunk_limit + second.chunk_limit


def test_an_attack_is_exhausted_before_the_next_one_starts(app, client):
    """Queue order lives on the ledger now. min(JobTasks.id) cannot express it:
    an attack whose first slice is issued late gets a HIGHER min id than one that
    started at the beginning, which silently inverts the queue."""
    job, tasks = _seed(task_count=2)
    _agent("a", speed=1_000_000_000)        # one bite swallows the whole attack

    first = JobTasks.query.get(_beat(client, "a")["job_task_id"])
    assert first.task_id == tasks[0].id
    assert first.chunk_limit == 100_000, "clamped to what is left of the attack"

    # An agent holds one slice at a time, so finish it before asking again --
    # otherwise the heartbeat just hands the same assignment back.
    first.status = "Completed"
    first.agent_id = None
    db.session.commit()

    second = JobTasks.query.get(_beat(client, "a")["job_task_id"])
    assert second.task_id == tasks[1].id, "second attack only after the first is exhausted"


def test_stopping_a_job_stops_it_issuing_more_slices(app, client):
    """The infinite-mint loop guard.

    Cancelling the rows alone leaves the attack mintable, so the next heartbeat
    would issue a fresh slice of a stopped job -- and keep doing it forever.
    """
    job, _ = _seed()
    _agent("a", speed=1000)
    assert _beat(client, "a")["msg"] == "START"

    from hashview.utils.utils import close_ledger
    job.status = "Canceled"
    db.session.commit()
    close_ledger(job.id, "job_stopped")

    for _ in range(3):
        assert _beat(client, "a")["msg"] == "OK", "a stopped job must never START again"
    assert JobTaskLedger.query.filter_by(job_id=job.id).one().state == "Closed"


def test_a_closed_attack_is_skipped_but_the_next_one_still_runs(app, client):
    job, tasks = _seed(task_count=2)
    _agent("a", speed=1000)

    from hashview.utils.utils import close_ledger
    close_ledger(job.id, "canceled", task_id=tasks[0].id)

    body = _beat(client, "a")
    assert body["msg"] == "START"
    assert JobTasks.query.get(body["job_task_id"]).task_id == tasks[1].id


def test_closing_one_attack_does_not_cancel_the_others(app, client):
    """close_ledger scoped to one attack must not widen to the whole job -- not
    even when no ledger matches the filter and it falls back to rows."""
    job, tasks = _seed(task_count=2)
    from hashview.utils.utils import close_ledger
    close_ledger(job.id, "canceled", task_id=tasks[0].id)

    survivor = JobTasks.query.filter_by(job_id=job.id, task_id=tasks[1].id).one()
    assert survivor.status == "Queued"
    ledgers = {ledger.task_id: ledger.state
               for ledger in JobTaskLedger.query.filter_by(job_id=job.id)}
    assert ledgers == {tasks[0].id: "Closed", tasks[1].id: "Ready"}


def test_a_reclaimed_slice_is_reissued_before_a_new_one_is_cut(app, client):
    """An outstanding slice is a hole below the cursor. Minting past it only
    widens the frontier, so a row waiting to be re-run comes first."""
    job, _ = _seed()
    _agent("a", speed=1000)
    first = JobTasks.query.get(_beat(client, "a")["job_task_id"])

    # The reclaim, as the agent-health sweep performs it.
    first.status = "Queued"
    first.agent_id = None
    first.started_at = None
    db.session.commit()

    again = _beat(client, "a")
    assert again["job_task_id"] == first.id, "re-issued, not skipped over"
    assert JobTaskLedger.query.filter_by(job_id=job.id).one().keyspace_pos == \
        first.chunk_limit, "the cursor must not advance for a re-issue"


# --- job editing against a live queue ----------------------------------------

def _login_admin(client):
    from tests.unit.helpers import login, make_admin
    admin = make_admin(email="editor@example.com")
    login(client, admin)
    return admin


def test_starting_an_already_running_job_is_refused(app, client):
    """Re-queueing a live job flips its rows back to 'Queued' while their agent_id
    still names an agent, so the agent keeps running a row dispatch is free to
    hand to someone else -- the way an agent ends up owning two rows and one is
    orphaned 'Running' forever. The API route always refused this; the web route
    did not."""
    job, _ = _seed()
    _agent("a", speed=1000)
    started = _beat(client, "a")
    assert started["msg"] == "START"
    job.status = "Running"
    db.session.commit()

    _login_admin(client)
    resp = client.post(f"/jobs/start/{job.id}", follow_redirects=False)
    assert resp.status_code in (301, 302)

    row = JobTasks.query.get(started["job_task_id"])
    assert row.status == "Running", "the in-flight slice must be untouched"
    assert row.agent_id is not None


def test_reordering_a_running_job_leaves_in_flight_work_alone(app, client):
    """This used to delete every row and re-create it -- on a running job that
    silently destroyed rows an agent was actively cracking, with no cancel and no
    agent_id cleanup."""
    job, tasks = _seed(task_count=2)
    _agent("a", speed=1000)
    started = _beat(client, "a")
    running = JobTasks.query.get(started["job_task_id"])
    running_id, running_agent = running.id, running.agent_id

    _login_admin(client)
    from hashview.utils.utils import job_assignments
    ids = {e["task_id"]: e["entry_id"] for e in job_assignments([job.id])[job.id]}
    resp = client.post(f"/jobs/{job.id}/reorder_tasks",
                       data={"order": f"{ids[tasks[1].id]},{ids[tasks[0].id]}"},
                       follow_redirects=False)
    assert resp.status_code in (301, 302)

    survivor = JobTasks.query.get(running_id)
    assert survivor is not None, "the running slice must not be deleted"
    assert survivor.status == "Running"
    assert survivor.agent_id == running_agent
    order = [ledger.task_id for ledger in
             JobTaskLedger.query.filter_by(job_id=job.id)
             .order_by(JobTaskLedger.position).all()]
    assert order == [tasks[1].id, tasks[0].id]


def test_removing_an_attack_cancels_it_before_deleting_it(app, client):
    job, tasks = _seed(task_count=2)
    _agent("a", speed=1000)
    started = _beat(client, "a")
    running = JobTasks.query.get(started["job_task_id"])
    agent_id = running.agent_id

    _login_admin(client)
    resp = client.post(f"/jobs/{job.id}/remove_task/{running.task_id}",
                       follow_redirects=False)
    assert resp.status_code in (301, 302)

    assert JobTasks.query.get(running.id) is None
    assert JobTaskLedger.query.filter_by(job_id=job.id, task_id=tasks[0].id).count() == 0
    # The agent is released, so it is not left looking assigned.
    assert Agents.query.get(agent_id).hc_status == ""
    # The other attack survives, and its position is compacted.
    survivor = JobTaskLedger.query.filter_by(job_id=job.id).one()
    assert survivor.task_id == tasks[1].id
    assert survivor.position == 0


def test_stopping_one_unledgered_chunk_does_not_cancel_the_whole_job(app, client):
    """close_ledger must never widen when it is scoped at an attack that is not there.

    A row can legitimately carry no ledger_id -- queue_late_assignments creates
    one when a task is added to an already-running job. Passing that NULL as a
    scope used to fall through every filter and close EVERY ledger of the job,
    cancelling every active row: a single-chunk stop button taking the whole job
    down with it.
    """
    from hashview.utils.utils import close_ledger

    job, tasks = _seed(task_count=2)
    _agent("a", speed=1000)
    started = _beat(client, "a")
    running = JobTasks.query.get(started["job_task_id"])

    stray = JobTasks(job_id=job.id, task_id=tasks[1].id, status="Queued",
                     command='["@HASHCATBINPATH@"]')
    db.session.add(stray)
    db.session.commit()
    assert stray.ledger_id is None

    assert close_ledger(job.id, "canceled", ledger_id=stray.ledger_id) == 0

    assert JobTasks.query.get(running.id).status == "Running", "untouched"
    assert {ledger.state for ledger in JobTaskLedger.query.filter_by(job_id=job.id)} == {"Ready"}


def test_an_unscoped_close_still_stops_the_whole_job(app, client):
    """The job-wide form must keep working -- that is what jobs_stop relies on."""
    from hashview.utils.utils import close_ledger

    job, _ = _seed(task_count=2)
    _agent("a", speed=1000)
    _beat(client, "a")

    assert close_ledger(job.id, "job_stopped") == 2
    assert {ledger.state for ledger in JobTaskLedger.query.filter_by(job_id=job.id)} == {"Closed"}


def _new_task(name="late-task"):
    wl = Wordlists.query.first()
    rule = Rules.query.first()
    task = Tasks(name=name, owner_id=1, hc_attackmode=0, wl_id=wl.id,
                 rule_id=rule.id, loopback=False)
    db.session.add(task)
    db.session.commit()
    return task


def test_a_late_assignment_gets_a_ledger_and_is_visible(app, client):
    """A task added to a job already in flight must show up in the UI.

    queue_late_assignments stamped the row Queued but minted no ledger, and
    job_assignments reads ledgers first and then SKIPS every raw row of a job
    that has one. So the attack was invisible everywhere the UI looks while the
    legacy ledger_id IS NULL dispatch branch still handed it to an agent: the
    operator added a task, the page looked unchanged, and an agent quietly
    started cracking it.
    """
    job, tasks = _seed(task_count=1, job_status="Running")
    late = _new_task()

    _login_admin(client)
    client.post(f"/jobs/{job.id}/assign_task/{late.id}", follow_redirects=False)

    visible = [a["task_id"] for a in job_assignments([job.id])[job.id]]
    assert visible == [tasks[0].id, late.id]

    entry = JobTaskLedger.query.filter_by(job_id=job.id, task_id=late.id).one()
    assert entry.position == 1              # appended, not renumbered over
    assert entry.chunkable is False         # a late assignment runs whole
    assert JobTasks.query.filter_by(job_id=job.id,
                                    task_id=late.id).one().ledger_id == entry.id


def test_a_late_assignment_can_be_removed_on_its_own(app, client):
    """Removing a late attack cleans up BOTH the row and the entry this fix mints.

    This passes against the old code too, and deliberately so: the route could
    always delete a ledger-less row, so what was missing was never the route but
    the card -- with no ledger the tasks page rendered no entry and therefore no
    remove button. What this pins is that the new ledger entry does not leak when
    the attack is removed, i.e. the fix does not recreate the orphaned-ledger bug
    it sits next to.
    """
    job, tasks = _seed(task_count=1, job_status="Running")
    late = _new_task()
    _login_admin(client)
    client.post(f"/jobs/{job.id}/assign_task/{late.id}", follow_redirects=False)

    client.post(f"/jobs/{job.id}/remove_task/{late.id}", follow_redirects=False)

    assert JobTaskLedger.query.filter_by(job_id=job.id, task_id=late.id).count() == 0
    assert JobTasks.query.filter_by(job_id=job.id, task_id=late.id).count() == 0
    # The original attack survives untouched.
    assert [a["task_id"] for a in job_assignments([job.id])[job.id]] == [tasks[0].id]


def test_a_late_assignment_on_a_pre_ledger_job_mints_nothing(app, client):
    """The guard that keeps this fix from causing the very bug it repairs.

    Cannot fail against the old code -- which minted nothing, ever -- so it is a
    regression pin on the guard rather than a reproduction of the bug.

    A job queued by a pre-ledger server has rows and no ledger, and
    job_assignments falls back to grouping those rows. Minting an entry for the
    late row alone would make the job "ledgered", and every OTHER row would then
    be skipped -- turning a gap in one attack into a gap in all of them.
    """
    job, tasks = _seed(task_count=2, job_status="Running")
    JobTaskLedger.query.filter_by(job_id=job.id).delete()
    for row in JobTasks.query.filter_by(job_id=job.id).all():
        row.ledger_id = None
    db.session.commit()
    late = _new_task()

    _login_admin(client)
    client.post(f"/jobs/{job.id}/assign_task/{late.id}", follow_redirects=False)

    assert JobTaskLedger.query.filter_by(job_id=job.id).count() == 0
    visible = sorted(a["task_id"] for a in job_assignments([job.id])[job.id])
    assert visible == sorted([tasks[0].id, tasks[1].id, late.id])
