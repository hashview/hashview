"""Reclaiming a JobTasks row held by an agent that stopped checking in.

Before this existed, work assigned to an agent that died was lost outright:

  * the runtime caps (Settings.max_runtime_tasks / max_runtime_jobs) are only
    evaluated inside the heartbeat handler, so if the only agent on a job dies
    there are no heartbeats and neither cap can fire;
  * the agent health check notified admins about the agent but never looked at
    its work; and
  * the single code path that put a Running row back to Queued was DELETING the
    agent.

So the row sat 'Running' forever. That lost the slice AND -- because the row
never reached a terminal status -- meant the job could never finish either.

These tests drive _agent_health_check_inner directly (the outer wrapper swallows
exceptions) and pin the reclaim, the cases it must NOT touch, and the started_at
reset that keeps a reclaimed task from being instantly killed by the runtime cap.
"""

from datetime import datetime, timedelta

import pytest

from hashview.models import (
    Agents,
    Customers,
    Hashfiles,
    Jobs,
    JobTasks,
    Settings,
    Tasks,
    Users,
    db,
)
from hashview.scheduler import _agent_health_check_inner

pytestmark = pytest.mark.security


class _Logger:
    """Collects log lines so a test can assert the reclaim was reported."""

    def __init__(self):
        self.lines = []

    def _record(self, msg, *args):
        self.lines.append(msg % args if args else msg)

    info = warning = error = debug = exception = _record


def _seed(agent_last_checkin, job_status="Running", task_status="Running",
          timeout_minutes=60):
    user = Users(first_name="A", last_name="D", email_address="a@b.com",
                 password="x" * 60, admin=True)
    db.session.add(user)
    db.session.commit()
    db.session.add(Settings(retention_period=30, max_runtime_jobs=0,
                            max_runtime_tasks=0, agent_timeout_minutes=timeout_minutes))
    cust = Customers(name="C")
    db.session.add(cust)
    db.session.commit()
    hf = Hashfiles(name="h", customer_id=cust.id, owner_id=user.id)
    db.session.add(hf)
    db.session.commit()
    task = Tasks(name="t", owner_id=user.id, hc_attackmode=0, loopback=False)
    db.session.add(task)
    agent = Agents(name="ag", src_ip="1.1.1.1", uuid="u1", status="Working",
                   last_checkin=agent_last_checkin)
    db.session.add(agent)
    db.session.commit()
    job = Jobs(name="j", owner_id=user.id, customer_id=cust.id, hashfile_id=hf.id,
               status=job_status, priority=3, started_at=datetime.utcnow())
    db.session.add(job)
    db.session.commit()
    jt = JobTasks(job_id=job.id, task_id=task.id, status=task_status, priority=3,
                  agent_id=agent.id, started_at=datetime.utcnow() - timedelta(hours=9),
                  chunk_no=2, chunk_total=4, chunk_skip=500, chunk_limit=500,
                  command='["@HASHCATBINPATH@","-m","1000"]')
    db.session.add(jt)
    db.session.commit()
    return job, jt, agent


def _run():
    logger = _Logger()
    _agent_health_check_inner(db, logger)
    return logger


def test_a_dead_agents_running_row_is_requeued(app, db_session):
    job, jt, agent = _seed(agent_last_checkin=datetime.utcnow() - timedelta(hours=5))
    logger = _run()

    row = JobTasks.query.get(jt.id)
    assert row.status == "Queued"
    assert row.agent_id is None
    assert any("reclaimed job_task" in line for line in logger.lines)


def test_the_reclaimed_row_keeps_its_slice_and_command(app, db_session):
    """The slice is what the row IS. Reclaiming re-assigns it, it does not re-plan it.

    Keeping command byte-identical is what lets a DIFFERENT agent pick the row up:
    the temp-file names inside it are keyed on the row's own id, which travels
    with the row rather than with whoever is running it.
    """
    job, jt, agent = _seed(agent_last_checkin=datetime.utcnow() - timedelta(hours=5))
    before = (jt.chunk_skip, jt.chunk_limit, jt.chunk_no, jt.chunk_total, jt.command)
    _run()

    row = JobTasks.query.get(jt.id)
    assert (row.chunk_skip, row.chunk_limit, row.chunk_no, row.chunk_total,
            row.command) == before


def test_started_at_is_cleared_so_the_runtime_cap_does_not_instantly_kill_it(app, db_session):
    """started_at is never otherwise reset, and _parent_task_started_at is a MIN
    across the task's rows -- a stale stamp would cancel the task the moment it
    was picked back up."""
    job, jt, agent = _seed(agent_last_checkin=datetime.utcnow() - timedelta(hours=5))
    assert jt.started_at is not None
    _run()

    assert JobTasks.query.get(jt.id).started_at is None


def test_a_live_agents_row_is_left_alone(app, db_session):
    job, jt, agent = _seed(agent_last_checkin=datetime.utcnow() - timedelta(minutes=1))
    _run()

    row = JobTasks.query.get(jt.id)
    assert row.status == "Running"
    assert row.agent_id == agent.id


def test_a_completed_row_is_not_resurrected(app, db_session):
    job, jt, agent = _seed(agent_last_checkin=datetime.utcnow() - timedelta(hours=5),
                           task_status="Completed")
    _run()

    assert JobTasks.query.get(jt.id).status == "Completed"


def test_a_row_on_a_stopped_job_is_retired_not_requeued(app, db_session):
    """Re-queueing onto a cancelled job would create work nothing ever collects."""
    job, jt, agent = _seed(agent_last_checkin=datetime.utcnow() - timedelta(hours=5),
                           job_status="Canceled")
    _run()

    row = JobTasks.query.get(jt.id)
    assert row.status == "Canceled"
    assert row.agent_id is None


def test_reclaim_is_idempotent_across_sweeps(app, db_session):
    """The sweep runs every 5 minutes; a second pass must not disturb the row it
    already queued (it no longer matches status == 'Running')."""
    job, jt, agent = _seed(agent_last_checkin=datetime.utcnow() - timedelta(hours=5))
    _run()
    first = JobTasks.query.get(jt.id).status
    logger = _run()

    assert first == "Queued"
    assert JobTasks.query.get(jt.id).status == "Queued"
    assert not any("reclaimed job_task" in line for line in logger.lines)
