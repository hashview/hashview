"""Job roll-up: a job is finished only when no task still owes compute.

The old predicate asked "is any JobTasks row Queued/Running/Importing right
now?" and, if not, declared the job Completed -- stamping ended_at, adding the
run to Hashfiles.runtime, and firing AND DELETING the job's notification rows.

That is an ABSENCE test over a row set, and it was wrong in four ways that these
tests pin:

  * a Canceled row is terminal but it is not DONE, so a job whose every task was
    cancelled reported itself Completed. That rule has since been REVERSED on
    purpose: reaching the end of the queue is what Completed means, and what
    stopped an individual attack does not change whether the job ran its course.
    A job that WAS cut short is stamped directly -- 'Expired' by the job runtime
    cap, 'Canceled' by an operator -- and never reaches the roll-up, so
    'Incomplete' now means only "created but never queued";
  * a 'Not Started' row (which jobs_assign_task creates when a task is added to
    an already-running job) was invisible to BOTH the predicate and the dispatch
    query, so the job completed with a task that never ran a candidate;
  * two agents finishing the last two tasks concurrently both observed "nothing
    active" and both ran the completion block -- two ended_at stamps, the runtime
    counted twice, two sets of notifications;
  * notification rows were deleted as they were sent, so a job's notification
    setup was destroyed by its first completion and a re-run notified nobody.

The gap case (test_job_does_not_complete_while_a_task_still_owes_compute) is the
one that matters most going forward: once chunks are minted on demand there are
moments when a task has no materialised row at all, and an absence test reads
that as "done".
"""

from datetime import timedelta

import pytest

from hashview.models import (
    Customers,
    Hashes,
    HashfileHashes,
    Hashfiles,
    JobNotifications,
    Jobs,
    JobTasks,
    Settings,
    Tasks,
    Users,
    Wordlists,
    db,
)
from hashview.utils.clock import utcnow
from hashview.utils.utils import finalize_job_if_complete, update_job_task_status

pytestmark = pytest.mark.security


def _seed(task_count=2, job_status="Running"):
    user = Users(first_name="A", last_name="D", email_address="a@b.com",
                 password="x" * 60, admin=True)
    db.session.add(user)
    db.session.commit()
    db.session.add(Settings(retention_period=30, max_runtime_jobs=0, max_runtime_tasks=0,
                            enabled_chunking=False, chunk_target_duration=60))
    cust = Customers(name="C")
    db.session.add(cust)
    db.session.commit()
    hf = Hashfiles(name="h", customer_id=cust.id, owner_id=user.id, runtime=0)
    db.session.add(hf)
    db.session.commit()
    h = Hashes(sub_ciphertext="0" * 32, ciphertext="AAA", hash_type=1000, cracked=False)
    db.session.add(h)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    wl = Wordlists(name="wl", owner_id=user.id, type="static",
                   path="control/wordlists/wl.gz", size=100, checksum="0" * 64)
    db.session.add(wl)
    db.session.commit()
    job = Jobs(name="j", owner_id=user.id, customer_id=cust.id, hashfile_id=hf.id,
               status=job_status, priority=3,
               started_at=utcnow() - timedelta(seconds=120))
    db.session.add(job)
    db.session.commit()
    rows = []
    for i in range(task_count):
        task = Tasks(name=f"t{i}", owner_id=user.id, hc_attackmode=0, wl_id=wl.id,
                     loopback=False)
        db.session.add(task)
        db.session.commit()
        jt = JobTasks(job_id=job.id, task_id=task.id, status="Running", priority=3)
        db.session.add(jt)
        db.session.commit()
        rows.append(jt)
    db.session.add(JobNotifications(owner_id=user.id, job_id=job.id, method="email"))
    db.session.commit()
    return job, rows, hf


def test_job_does_not_complete_while_a_task_still_owes_compute(app, db_session):
    job, rows, hf = _seed(task_count=2)
    update_job_task_status(rows[0].id, "Completed")

    assert Jobs.query.get(job.id).status == "Running"
    assert Jobs.query.get(job.id).ended_at is None
    assert Hashfiles.query.get(hf.id).runtime == 0
    assert JobNotifications.query.filter_by(job_id=job.id).count() == 1


def test_job_completes_when_every_task_completed(app, db_session):
    job, rows, hf = _seed(task_count=2)
    update_job_task_status(rows[0].id, "Completed")
    update_job_task_status(rows[1].id, "Completed")

    refreshed = Jobs.query.get(job.id)
    assert refreshed.status == "Completed"
    assert refreshed.ended_at is not None
    assert Hashfiles.query.get(hf.id).runtime > 0


def test_a_job_whose_queue_ran_out_is_completed_whatever_stopped_its_tasks(app,
                                                                           db_session):
    """Reaching the end of the queue is what Completed means.

    These two used to assert Incomplete. The job itself was never cut short --
    if it had been, the job-level cap would have written Expired and an operator
    stop would have written Canceled, and neither reaches the roll-up at all.
    What stopped an individual attack does not change whether the JOB ran its
    course.
    """
    job, rows, _ = _seed(task_count=2)
    update_job_task_status(rows[0].id, "Canceled")
    update_job_task_status(rows[1].id, "Canceled")
    assert Jobs.query.get(job.id).status == "Completed"


def test_a_partly_cancelled_job_is_completed(app, db_session):
    job, rows, _ = _seed(task_count=2)
    update_job_task_status(rows[0].id, "Completed")
    update_job_task_status(rows[1].id, "Canceled")

    assert Jobs.query.get(job.id).status == "Completed"


def test_a_job_with_an_expired_task_is_completed(app, db_session):
    """The case the new status exists for: one attack hit max_runtime_tasks.

    The task is Expired, the job finished inside its own cap, so the job is
    Completed -- and the expired task is still on the record, which is the point
    of giving it a status of its own rather than reusing Canceled.
    """
    job, rows, _ = _seed(task_count=2)
    update_job_task_status(rows[0].id, "Completed")
    update_job_task_status(rows[1].id, "Expired")

    assert Jobs.query.get(job.id).status == "Completed"
    assert JobTasks.query.get(rows[1].id).status == "Expired"


def test_a_not_started_row_is_queued_rather_than_ignored(app, db_session):
    """A task assigned to a running job must run, not be silently skipped.

    'Not Started' is invisible to the dispatch query (status == 'Queued'), so
    before this it neither ran nor blocked completion: the job rolled up to
    Completed with the task still sitting there.
    """
    job, rows, _ = _seed(task_count=2)
    late = JobTasks(job_id=job.id, task_id=rows[0].task_id, status="Not Started")
    db.session.add(late)
    db.session.commit()

    update_job_task_status(rows[0].id, "Completed")
    update_job_task_status(rows[1].id, "Completed")

    assert Jobs.query.get(job.id).status == "Running", "must not complete over an un-run task"
    healed = JobTasks.query.get(late.id)
    assert healed.status == "Queued", "the late row must be queued so dispatch sees it"
    assert healed.command, "and it needs a command to run"

    update_job_task_status(healed.id, "Completed")
    assert Jobs.query.get(job.id).status == "Completed"


def test_completion_fires_exactly_once_under_concurrent_callers(app, db_session):
    """Two agents completing the last tasks at once must not double-fire."""
    job, rows, hf = _seed(task_count=1)
    update_job_task_status(rows[0].id, "Completed")

    runtime_after_first = Hashfiles.query.get(hf.id).runtime
    ended_after_first = Jobs.query.get(job.id).ended_at
    assert Jobs.query.get(job.id).status == "Completed"

    # A second, racing finalisation of the same job.
    assert finalize_job_if_complete(job.id) is False
    assert Hashfiles.query.get(hf.id).runtime == runtime_after_first
    assert Jobs.query.get(job.id).ended_at == ended_after_first


def test_notifications_survive_completion_and_resend_on_requeue(app, db_session):
    """Rows are marked sent, not deleted, so the setup outlives the run."""
    from hashview.utils.utils import build_job_task_commands

    job, rows, _ = _seed(task_count=1)
    update_job_task_status(rows[0].id, "Completed")

    note = JobNotifications.query.filter_by(job_id=job.id).one()
    assert note.sent_at is not None, "delivered rows are stamped, not destroyed"

    # Re-queue the job: the notification arms again.
    build_job_task_commands(job)
    db.session.commit()
    assert JobNotifications.query.get(note.id).sent_at is None


def test_a_canceled_job_is_not_rewritten_by_a_late_completion(app, db_session):
    """An agent still finishing when the operator stopped the job must not
    resurrect it as Completed."""
    job, rows, _ = _seed(task_count=1)
    job.status = "Canceled"
    job.ended_at = utcnow()
    db.session.commit()
    stopped_at = Jobs.query.get(job.id).ended_at

    update_job_task_status(rows[0].id, "Completed")

    refreshed = Jobs.query.get(job.id)
    assert refreshed.status == "Canceled"
    assert refreshed.ended_at == stopped_at


def test_a_goal_met_cancellation_completes_rather_than_incompletes(app, db_session):
    """Cancellation is how SUCCESS looks for a one-and-done job (issue #220).

    api.routes._cancel_job_active_tasks cancels the remaining tasks precisely
    because the job achieved what it was asked to. Those rows must not drag the
    roll-up to Incomplete, so the caller states the intent instead of the
    finaliser guessing at it from hashfile state -- which would misreport a job
    the operator stopped on a hashfile some other job had already finished.
    """
    job, rows, _ = _seed(task_count=2)
    update_job_task_status(rows[0].id, "Completed")
    update_job_task_status(rows[1].id, "Canceled", finalize=False)

    assert finalize_job_if_complete(job.id, goal_met=True) is True
    assert Jobs.query.get(job.id).status == "Completed"


def test_the_same_shape_without_goal_met_is_also_completed(app, db_session):
    """goal_met no longer changes the OUTCOME, and that is deliberate.

    It used to be the only thing separating "cancelled because we succeeded"
    from "cancelled for any other reason". Now every all-terminal row set rolls
    up to Completed, so this is no longer a control on the outcome -- it is a
    guard that the two paths have not diverged. goal_met survives because the
    caller still uses it to say WHY the job ended, which the notification wording
    reads.
    """
    job, rows, _ = _seed(task_count=2)
    update_job_task_status(rows[0].id, "Completed")
    update_job_task_status(rows[1].id, "Canceled", finalize=False)

    assert finalize_job_if_complete(job.id) is True
    assert Jobs.query.get(job.id).status == "Completed"
