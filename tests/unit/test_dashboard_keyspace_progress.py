"""Dashboard progress measured in keyspace, not in rows.

Both progress bars used to divide by len() of the materialised JobTasks rows for
an attack. That is fine while the whole plan exists up front and useless once
slices are issued on demand: the denominator GROWS through the run, so the bar
races toward 100% and then jumps backwards every time a new slice appears.

The keyspace is the honest denominator. It is fixed when the attack is queued (or
when an agent measures it), it is actual work rather than a row count, and it
makes the un-issued tail of an attack visible for the first time.

The status derivation matters just as much: with slices issued on demand there
are moments when an attack has NO materialised row at all, and the old
"completed == total" arm read that gap as Completed.
"""

import pytest

from hashview.main.routes import _job_task_groups
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
from hashview.utils.utils import build_job_task_commands, issue_slice

pytestmark = pytest.mark.security


def _seed(wl_size=100_000):
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
                   path="control/wordlists/wl.gz", size=wl_size, checksum="0" * 64)
    db.session.add(wl)
    db.session.commit()
    rule = Rules(name="r", owner_id=user.id, path="control/rules/r.rule",
                 checksum="0" * 64, size=100)
    db.session.add(rule)
    db.session.commit()
    task = Tasks(name="t", owner_id=user.id, hc_attackmode=0, wl_id=wl.id,
                 rule_id=rule.id, loopback=False)
    db.session.add(task)
    db.session.commit()
    job = Jobs(name="j", owner_id=user.id, customer_id=cust.id, hashfile_id=hf.id,
               status="Running", priority=3)
    db.session.add(job)
    db.session.commit()
    db.session.add(JobTasks(job_id=job.id, task_id=task.id, status="Not Started"))
    db.session.commit()
    build_job_task_commands(job)
    db.session.commit()
    agent = Agents(name="ag", src_ip="1.1.1.1", uuid="u1", status="Idle")
    db.session.add(agent)
    db.session.commit()
    db.session.add(AgentBenchmarks(agent_id=agent.id, hash_type=1000, speed=1000))
    db.session.commit()
    return job, agent, JobTaskLedger.query.filter_by(job_id=job.id).one()


def _groups(job):
    return _job_task_groups([job], JobTasks.query.all(),
                            {t.id: t for t in Tasks.query.all()},
                            {a.id: a for a in Agents.query.all()}, {}, {})


def _mint(job, ledger, agent, row=None):
    return issue_slice(job=job, ledger=JobTaskLedger.query.get(ledger.id),
                       agent_id=agent.id, hash_type=1000, target_seconds=60, row=row)


def test_the_denominator_does_not_move_as_slices_are_issued(app, db_session):
    """The whole point. A row count grows through the run; the keyspace does not."""
    job, agent, ledger = _seed()
    seed_row = JobTasks.query.filter_by(ledger_id=ledger.id).one()

    seen = []
    row = _mint(job, ledger, agent, row=seed_row)
    for _ in range(3):
        seen.append(_groups(job)[job.id]["groups"][0]["ks_total"])
        row.status = "Completed"
        row.agent_id = None
        db.session.commit()
        row = _mint(job, ledger, agent)

    assert len(set(seen)) == 1, f"denominator moved: {seen}"
    assert seen[0] == 100_000


def test_completed_running_and_unissued_account_for_the_whole_keyspace(app, db_session):
    job, agent, ledger = _seed()
    seed_row = JobTasks.query.filter_by(ledger_id=ledger.id).one()
    done = _mint(job, ledger, agent, row=seed_row)
    done.status = "Completed"
    done.agent_id = None
    db.session.commit()
    _mint(job, ledger, agent)

    group = _groups(job)[job.id]["groups"][0]
    assert group["ks_done"] + group["ks_running"] + group["ks_unissued"] == group["ks_total"]
    assert group["ks_done"] == done.chunk_limit
    assert group["ks_unissued"] > 0, "the tail is visible for the first time"


def test_an_attack_between_slices_is_not_reported_complete(app, db_session):
    """The hard case: every materialised row is Completed, but most of the
    keyspace has never been issued. The row-count test called this Completed."""
    job, agent, ledger = _seed()
    seed_row = JobTasks.query.filter_by(ledger_id=ledger.id).one()
    row = _mint(job, ledger, agent, row=seed_row)
    row.status = "Completed"
    row.agent_id = None
    db.session.commit()

    rows = JobTasks.query.filter_by(ledger_id=ledger.id).all()
    assert all(r.status == "Completed" for r in rows), "no row is outstanding"
    assert JobTaskLedger.query.get(ledger.id).keyspace_pos < ledger.keyspace

    assert _groups(job)[job.id]["groups"][0]["status"] == "Queued"


def test_an_exhausted_and_finished_attack_is_complete(app, db_session):
    # 600 units is exactly one bite at 1000 H/s x 60s over an amplifier of 100,
    # so a single slice exhausts the attack.
    job, agent, ledger = _seed(wl_size=600)
    seed_row = JobTasks.query.filter_by(ledger_id=ledger.id).one()
    row = _mint(job, ledger, agent, row=seed_row)
    row.status = "Completed"
    row.agent_id = None
    db.session.commit()

    fresh = JobTaskLedger.query.get(ledger.id)
    assert fresh.keyspace_pos == fresh.keyspace
    assert _groups(job)[job.id]["groups"][0]["status"] == "Completed"


def test_a_chunk_row_never_renders_the_literal_none(app, db_session):
    """There is no jinja_env.finalize, so {{ None }} renders the string 'None' --
    the chunk label is built server-side instead."""
    job, agent, ledger = _seed()
    seed_row = JobTasks.query.filter_by(ledger_id=ledger.id).one()
    row = _mint(job, ledger, agent, row=seed_row)
    row.chunk_no = None                 # a whole run carries no chunk number
    db.session.commit()

    chunks = _groups(job)[job.id]["groups"][0]["active_chunks"]
    assert chunks, "one slice is running"
    assert all(c["label"] and "None" not in c["label"] for c in chunks)


def test_an_unmeasured_mask_attack_shows_as_measuring(app, db_session):
    job, agent, ledger = _seed()
    ledger.state = "Pending"
    ledger.keyspace = None
    db.session.commit()

    group = _groups(job)[job.id]["groups"][0]
    assert group["status"] == "Measuring"
    assert group["ks_total"] == 0, "no denominator to draw a bar from yet"
