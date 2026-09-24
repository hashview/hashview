"""JobTasks.ended_at: when this attempt stopped.

Nothing reads the column yet, which is exactly why it needs tests. A value that
is only written and never checked rots silently, and it cannot be backfilled --
a row that finished before the column existed has no end time to recover. Its
purpose is to make a job's ACTIVE time computable later: the union of its rows'
[started_at, ended_at] intervals, which is neither wall-clock since the job
started (that counts time a higher-priority job starved it) nor the sum of the
rows' runtimes (that counts parallel chunks twice).

Two properties, and the second is the one that will actually break:

* every path that ends a row stamps it -- and there are five of them, because
  four bypass update_job_task_status entirely;
* every path that re-queues a row CLEARS it, or the interval left over from the
  previous attempt describes a stretch of time this one never ran.
"""
import secrets
from datetime import timedelta

from hashview.models import (
    Agents,
    Customers,
    Hashes,
    HashfileHashes,
    Hashfiles,
    Jobs,
    JobTaskLedger,
    JobTasks,
    Settings,
    Tasks,
    Users,
    db,
)
from hashview.utils.clock import utcnow
from hashview.utils.utils import update_job_task_status
from tests.unit.helpers import login, make_admin


def _owner(email="ended@example.com"):
    user = Users(first_name="E", last_name="A", email_address=email,
                 password="x" * 60, admin=True)
    db.session.add(user)
    db.session.commit()
    return user


def _hashfile(owner, customer):
    """A hashfile with one hash -- build_job_task_commands and issue_slice both
    resolve the job's hash type through it."""
    hashfile = Hashfiles(name="hf", customer_id=customer.id, owner_id=owner.id)
    db.session.add(hashfile)
    db.session.commit()
    # Distinct per hashfile: hashes carries a uniqueness constraint on
    # (sub_ciphertext, hash_type), and a test that builds two jobs builds two.
    hash_row = Hashes(sub_ciphertext=secrets.token_hex(16), ciphertext="AAA",
                      hash_type=3000, cracked=False)
    db.session.add(hash_row)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=hash_row.id, hashfile_id=hashfile.id))
    db.session.commit()
    return hashfile


def _job_and_row(owner, status="Running", hours_ago=1, job_status="Running"):
    customer = Customers.query.first() or Customers(name="Ended Customer")
    db.session.add(customer)
    db.session.commit()
    started = utcnow() - timedelta(hours=hours_ago)
    job = Jobs(name="ended-job", status=job_status, customer_id=customer.id,
               owner_id=owner.id, priority=3, started_at=started,
               hashfile_id=_hashfile(owner, customer).id)
    task = Tasks(name="ended-task", owner_id=owner.id, hc_attackmode=3,
                 hc_mask="?d?d?d?d")
    db.session.add_all([job, task])
    db.session.commit()
    row = JobTasks(job_id=job.id, task_id=task.id, status=status, priority=3,
                   started_at=started)
    db.session.add(row)
    db.session.commit()
    return job, task, row


# --- stamped -----------------------------------------------------------------

def test_a_running_row_has_no_end_time(app):
    _job, _task, row = _job_and_row(_owner("mid@example.com"))
    assert JobTasks.query.get(row.id).ended_at is None


def test_completing_a_row_stamps_it(app):
    owner = _owner()
    _job, _task, row = _job_and_row(owner)

    update_job_task_status(row.id, "Completed")

    ended = JobTasks.query.get(row.id).ended_at
    assert ended is not None
    assert ended >= JobTasks.query.get(row.id).started_at


def test_cancelling_and_expiring_stamp_it_too(app):
    """Not just Completed. A cancelled or expired attempt still occupied an
    agent for exactly as long as it ran, and a runtime built from intervals that
    omit those is not a runtime."""
    for index, status in enumerate(("Canceled", "Expired")):
        _job, _task, row = _job_and_row(_owner(f"term{index}@example.com"))
        update_job_task_status(row.id, status)
        assert JobTasks.query.get(row.id).ended_at is not None, status


def test_the_runtime_cap_stamps_it(app):
    from hashview.utils.utils import expire_job_over_runtime

    owner = _owner()
    db.session.add(Settings(retention_period=30, max_runtime_jobs=1,
                            max_runtime_tasks=0))
    db.session.commit()
    job, _task, row = _job_and_row(owner, hours_ago=5)
    job.processing_seconds = 5 * 3600      # the clock the cap reads
    db.session.commit()

    assert expire_job_over_runtime(job, 1) is True

    assert JobTasks.query.get(row.id).status == "Expired"
    assert JobTasks.query.get(row.id).ended_at is not None


def test_stopping_a_job_from_the_web_stamps_it(app, client):
    # jobs_stop writes the rows directly rather than through
    # update_job_task_status, so the gate does not cover it.
    admin = make_admin(email="webstop@example.com")
    login(client, admin)
    job, _task, row = _job_and_row(admin)

    client.post(f"/jobs/stop/{job.id}", follow_redirects=False)

    assert JobTasks.query.get(row.id).status == "Canceled"
    assert JobTasks.query.get(row.id).ended_at is not None


def test_stopping_a_job_through_the_api_stamps_it(app, client):
    admin = make_admin(email="apistop@example.com")
    login(client, admin)
    admin.api_key = "a" * 32
    db.session.commit()
    job, _task, row = _job_and_row(admin)
    client.set_cookie("uuid", admin.api_key, domain="localhost.test")

    client.post(f"/v1/jobs/stop/{job.id}")

    assert JobTasks.query.get(row.id).status == "Canceled"
    assert JobTasks.query.get(row.id).ended_at is not None


def test_retiring_a_stranded_row_stamps_it(app):
    # The reclaim sweep retires (rather than re-queues) a row whose job is no
    # longer runnable, with a bulk UPDATE that also bypasses the gate.
    import logging

    from hashview.scheduler import _reclaim_stranded_job_tasks

    owner = _owner()
    agent = Agents(name="dead", src_ip="127.0.0.1", uuid="d" * 32, status="Idle",
                   last_checkin=utcnow() - timedelta(hours=5))
    db.session.add(agent)
    db.session.commit()
    _job, _task, row = _job_and_row(owner, job_status="Canceled")
    row.agent_id = agent.id
    db.session.commit()

    _reclaim_stranded_job_tasks(db, logging.getLogger("t"),
                                utcnow() - timedelta(minutes=10))

    assert JobTasks.query.get(row.id).status == "Canceled"
    assert JobTasks.query.get(row.id).ended_at is not None


# --- cleared ------------------------------------------------------------------

def test_reclaiming_a_row_clears_it(app):
    """A reclaimed row is going to run again, so it must carry no end time.

    Leaving one behind would make [started_at, ended_at] describe an interval
    that ended before the attempt it now belongs to even began.
    """
    import logging

    from hashview.scheduler import _reclaim_stranded_job_tasks

    owner = _owner()
    agent = Agents(name="gone", src_ip="127.0.0.1", uuid="g" * 32, status="Idle",
                   last_checkin=utcnow() - timedelta(hours=5))
    db.session.add(agent)
    db.session.commit()
    _job, _task, row = _job_and_row(owner, job_status="Running")
    row.agent_id = agent.id
    row.ended_at = utcnow() - timedelta(hours=2)      # a stale leftover
    db.session.commit()

    _reclaim_stranded_job_tasks(db, logging.getLogger("t"),
                                utcnow() - timedelta(minutes=10))

    requeued = JobTasks.query.get(row.id)
    assert requeued.status == "Queued"
    assert requeued.started_at is None
    assert requeued.ended_at is None, "a re-queued row kept the last run's end time"


def test_deleting_an_agent_clears_it_on_the_rows_it_held(app, client):
    admin = make_admin(email="agentdel@example.com")
    login(client, admin)
    agent = Agents(name="doomed", src_ip="127.0.0.1", uuid="x" * 32, status="Idle")
    db.session.add(agent)
    db.session.commit()
    _job, _task, row = _job_and_row(admin)
    row.agent_id = agent.id
    row.ended_at = utcnow() - timedelta(hours=2)
    db.session.commit()

    client.post(f"/agents/delete/{agent.id}", follow_redirects=False)

    requeued = JobTasks.query.get(row.id)
    assert requeued.status == "Queued"
    assert requeued.ended_at is None


def test_re_queueing_a_job_clears_it(app):
    """Re-running a finished job is a new attempt for every one of its rows."""
    from hashview.utils.utils import build_job_task_commands

    owner = _owner()
    db.session.add(Settings(retention_period=30, max_runtime_jobs=0,
                            max_runtime_tasks=0, enabled_chunking=False))
    db.session.commit()
    job, _task, row = _job_and_row(owner, status="Completed")
    row.ended_at = utcnow() - timedelta(hours=2)
    db.session.commit()

    build_job_task_commands(job)
    db.session.commit()

    assert JobTasks.query.get(row.id).status == "Queued"
    assert JobTasks.query.get(row.id).ended_at is None


def test_the_column_survives_a_round_trip_through_the_migration_chain(app):
    """The column exists in the schema the ORM builds, so a model/migration
    mismatch shows up here rather than on a production upgrade."""
    columns = {c["name"] for c in db.inspect(db.engine).get_columns("job_tasks")}
    assert "ended_at" in columns


def test_a_ledger_row_minted_for_an_agent_starts_with_no_end_time(app):
    # Mint claims a row and starts it; a row that was previously terminal and is
    # being re-used must not carry its old end time into the new slice.
    owner = _owner()
    customer = Customers.query.first() or Customers(name="Mint Customer")
    db.session.add(customer)
    db.session.commit()
    job = Jobs(name="mint", status="Running", customer_id=customer.id,
               owner_id=owner.id, priority=3, started_at=utcnow(),
               hashfile_id=_hashfile(owner, customer).id)
    task = Tasks(name="mint-task", owner_id=owner.id, hc_attackmode=3,
                 hc_mask="?d?d?d?d")
    db.session.add_all([job, task])
    db.session.commit()
    ledger = JobTaskLedger(job_id=job.id, task_id=task.id, position=0,
                           state="Ready", keyspace=1000, keyspace_pos=0,
                           chunkable=True, amp=1, min_slice=1)
    db.session.add(ledger)
    db.session.commit()
    row = JobTasks(job_id=job.id, task_id=task.id, status="Queued", priority=3,
                   ledger_id=ledger.id, ended_at=utcnow() - timedelta(hours=3))
    db.session.add(row)
    agent = Agents(name="minter", src_ip="127.0.0.1", uuid="m" * 32, status="Idle")
    db.session.add(agent)
    db.session.commit()

    from hashview.utils.utils import issue_slice
    issue_slice(job=job, ledger=JobTaskLedger.query.get(ledger.id),
                agent_id=agent.id, hash_type=3000, target_seconds=60, row=row)
    db.session.commit()

    assert JobTasks.query.get(row.id).ended_at is None
