"""The JOB_RUNTIME sweep: expire jobs past max_runtime_jobs without being asked.

The cap used to be evaluated in exactly one place -- inside the agent heartbeat,
against the single job that heartbeat was about to be handed work for. That is
fine while a job has agents on it and pathological when it does not:

    Job A (priority 3) is running. Job B (priority 5) is queued. As A's chunks
    finish, every agent is handed B's work instead. A now has no agents, so no
    heartbeat ever reaches A's branch of the check, so A blows its runtime cap
    in silence -- still 'Running', still on the dashboard, still counted as
    active -- until B finishes hours later and the next agent to check in
    happens to look at A and expires it on the way past.

A sweep is the fix because it does not depend on anyone asking. These tests pin
that, and pin the thing a sweep makes newly possible to get wrong: two callers
(the sweep and a heartbeat) expiring the same job at the same moment.
"""
import logging
from datetime import datetime, timedelta

from hashview.models import (
    Agents,
    Customers,
    Jobs,
    JobTaskLedger,
    JobTasks,
    Settings,
    Tasks,
    Users,
    db,
)
from hashview.scheduler import _job_runtime_check_inner
from hashview.utils.utils import expire_job_over_runtime

_LOG = logging.getLogger("test-job-runtime")


def _owner(email="cap@example.com"):
    user = Users(first_name="C", last_name="P", email_address=email,
                 password="x" * 60, admin=True)
    db.session.add(user)
    db.session.commit()
    return user


def _settings(max_runtime_jobs=1):
    s = Settings.query.first() or Settings(retention_period=30, max_runtime_tasks=0,
                                           max_runtime_jobs=0)
    s.max_runtime_jobs = max_runtime_jobs
    s.max_runtime_tasks = 0
    db.session.add(s)
    db.session.commit()
    return s


def _job(owner, hours_ago=5, status="Running", name="capped", with_row=True):
    customer = Customers.query.first() or Customers(name="Cap Customer")
    db.session.add(customer)
    db.session.commit()
    started = None if hours_ago is None else datetime.now() - timedelta(hours=hours_ago)
    job = Jobs(name=name, status=status, customer_id=customer.id, owner_id=owner.id,
               priority=3, started_at=started)
    task = Tasks(name=f"{name}-task", owner_id=owner.id, hc_attackmode=3,
                 hc_mask="?d?d?d?d")
    db.session.add_all([job, task])
    db.session.commit()
    row = None
    if with_row:
        ledger = JobTaskLedger(job_id=job.id, task_id=task.id, position=0,
                               state="Ready", keyspace=1000, keyspace_pos=100,
                               chunkable=True)
        db.session.add(ledger)
        db.session.commit()
        row = JobTasks(job_id=job.id, task_id=task.id, status="Running",
                       priority=3, ledger_id=ledger.id, started_at=started)
        db.session.add(row)
        db.session.commit()
    return job, task, row


# --- the scenario the sweep exists for ---------------------------------------

def test_a_job_nobody_is_asking_about_is_expired(app):
    """No agent, no heartbeat, no check -- until now.

    Note there is no client and no agent in this test at all. That is the point:
    the old enforcement could not fire without one.
    """
    owner = _owner()
    _settings(max_runtime_jobs=1)
    job, _task, row = _job(owner, hours_ago=5)

    assert _job_runtime_check_inner(db, _LOG) == 1

    assert Jobs.query.get(job.id).status == "Expired"
    assert JobTasks.query.get(row.id).status == "Expired", (
        "the job's live rows must be expired too, or it never settles")
    assert Jobs.query.get(job.id).ended_at is not None


def test_the_attack_is_closed_so_nothing_is_minted_afterwards(app):
    # Cancelling rows without closing the ledger is the infinite-mint bug: the
    # next heartbeat issues slice N+1, the cap cancels it, N+2 is issued...
    owner = _owner()
    _settings(max_runtime_jobs=1)
    job, _task, _row = _job(owner, hours_ago=5)

    _job_runtime_check_inner(db, _LOG)

    ledger = JobTaskLedger.query.filter_by(job_id=job.id).one()
    assert ledger.state == "Closed"
    assert ledger.closed_reason == "job_runtime_cap"


def test_a_job_inside_its_cap_is_untouched(app):
    owner = _owner()
    _settings(max_runtime_jobs=8)
    job, _task, row = _job(owner, hours_ago=5)

    assert _job_runtime_check_inner(db, _LOG) == 0

    assert Jobs.query.get(job.id).status == "Running"
    assert JobTasks.query.get(row.id).status == "Running"


def test_a_job_that_never_started_is_not_expired(app):
    # The cap is on RUNTIME. A queued job that has never been handed to an agent
    # has no clock running, and expiring it for sitting in the queue would make
    # the queue itself lossy.
    owner = _owner()
    _settings(max_runtime_jobs=1)
    job, _task, _row = _job(owner, hours_ago=None, status="Queued")

    assert _job_runtime_check_inner(db, _LOG) == 0
    assert Jobs.query.get(job.id).status == "Queued"


def test_a_never_started_job_is_refused_by_the_helper_too(app):
    """Tested against the helper directly, not through the sweep.

    The sweep narrows its candidates with started_at IS NOT NULL, so going
    through it can never reach this branch -- and the heartbeat does not narrow
    anything, it passes whatever job the row belongs to. Without the guard that
    is None + timedelta, which is a TypeError inside a scheduled job.
    """
    owner = _owner()
    _settings(max_runtime_jobs=1)
    job, _task, _row = _job(owner, hours_ago=None, status="Queued")

    assert expire_job_over_runtime(job, 1) is False
    assert Jobs.query.get(job.id).status == "Queued"


def test_the_cap_being_disabled_disables_the_sweep(app):
    owner = _owner()
    _settings(max_runtime_jobs=0)          # 0 = infinite, per the settings form
    job, _task, _row = _job(owner, hours_ago=500)

    assert _job_runtime_check_inner(db, _LOG) == 0
    assert Jobs.query.get(job.id).status == "Running"


def test_an_already_finished_job_is_left_alone(app):
    # Completed/Canceled/Expired jobs keep their recorded outcome. A sweep that
    # rewrote them would relabel history every minute.
    owner = _owner()
    _settings(max_runtime_jobs=1)
    for index, status in enumerate(("Completed", "Canceled", "Expired")):
        job, _t, _r = _job(owner, hours_ago=9, status=status, name=f"done{index}")
        assert _job_runtime_check_inner(db, _LOG) == 0
        assert Jobs.query.get(job.id).status == status


# --- the thing a second caller makes possible to get wrong ---------------------

def test_expiring_twice_does_not_happen(app):
    """Sweep, then sweep again: the second run must find nothing.

    The claim is a conditional UPDATE on ('Queued', 'Running') precisely so a
    heartbeat racing the sweep -- or the two scheduler instances the debug
    reloader creates -- cannot both stamp ended_at and both write an audit entry.
    """
    owner = _owner()
    _settings(max_runtime_jobs=1)
    job, _task, _row = _job(owner, hours_ago=5)

    assert _job_runtime_check_inner(db, _LOG) == 1
    ended_at = Jobs.query.get(job.id).ended_at

    assert _job_runtime_check_inner(db, _LOG) == 0
    assert Jobs.query.get(job.id).ended_at == ended_at, (
        "a second sweep re-stamped ended_at, so the two callers can double-fire")


def test_a_caller_holding_a_stale_job_cannot_expire_it_twice(app):
    """The race itself, not just the sequential case.

    A second sweep sees nothing because the candidate query already filters
    Expired jobs out -- which means that query, not the claim, is what the test
    above exercises. The real race is a caller that read the job while it was
    still Running and acts on it after someone else expired it, which is exactly
    what a heartbeat arriving mid-sweep looks like. Reproduced here with a
    detached copy carrying the pre-expiry status.
    """
    owner = _owner()
    _settings(max_runtime_jobs=1)
    job, _task, _row = _job(owner, hours_ago=5)

    stale = Jobs.query.get(job.id)
    assert expire_job_over_runtime(stale, 1) is True
    ended_at = Jobs.query.get(job.id).ended_at

    # A caller still holding the job as it looked before that: same row, status
    # not yet refreshed. Detached so re-setting it cannot be flushed back.
    stale = Jobs.query.get(job.id)
    db.session.expunge(stale)
    stale.status = "Running"

    assert expire_job_over_runtime(stale, 1) is False, (
        "an unconditional UPDATE would let both callers expire the same job")
    assert Jobs.query.get(job.id).ended_at == ended_at


def test_the_cap_beats_the_completion_roll_up(app):
    """A capped job must read Expired, never Completed.

    close_ledger terminates the rows and then rolls the job up, and with every
    row terminal that roll-up's answer is 'Completed'. Claim the job first and
    the roll-up is a no-op; claim it afterwards and a job killed by the cap is
    recorded as having finished normally -- which is not a cosmetic difference,
    because Completed fires the job's completion notifications.
    """
    owner = _owner()
    _settings(max_runtime_jobs=1)
    job, _task, _row = _job(owner, hours_ago=5)

    _job_runtime_check_inner(db, _LOG)

    assert Jobs.query.get(job.id).status == "Expired"


def test_one_unexpirable_job_does_not_strand_the_rest(app, monkeypatch):
    # A sweep that aborts on the first bad row leaves every later job unchecked,
    # which is the failure mode it was written to remove.
    from hashview.utils import utils as utils_mod

    owner = _owner()
    _settings(max_runtime_jobs=1)
    first, _t1, _r1 = _job(owner, hours_ago=5, name="boom")
    second, _t2, _r2 = _job(owner, hours_ago=5, name="fine")

    real = utils_mod.expire_job_over_runtime

    def flaky(job, cap, now=None):
        if job.id == first.id:
            raise RuntimeError("something went wrong expiring this one")
        return real(job, cap, now=now)

    monkeypatch.setattr(utils_mod, "expire_job_over_runtime", flaky)

    assert _job_runtime_check_inner(db, _LOG) == 1
    assert Jobs.query.get(second.id).status == "Expired"
    assert Jobs.query.get(first.id).status == "Running"


# --- wiring -------------------------------------------------------------------

def test_the_sweep_is_registered_every_minute(app):
    """Registered through the one helper both entry points call, so it cannot be
    present in create_app and missing from hashview.py (the drift that once left
    AGENT_HEALTH unregistered).

    One minute, not five: this sweep is the only thing that makes an over-cap
    job visible at all, so its cadence is the latency of noticing.
    """
    from hashview.scheduler import register_default_jobs, scheduler

    register_default_jobs(app)
    jobs = {j.id: j for j in scheduler.get_jobs()}
    assert "JOB_RUNTIME" in jobs
    assert jobs["JOB_RUNTIME"].trigger.interval == timedelta(minutes=1)


def test_the_heartbeat_and_the_sweep_share_one_implementation(app):
    """Not a style point. Two copies of this drift, and the drift is silent:
    whichever copy forgets close_ledger leaves the attack mintable forever, and
    whichever one claims the job after closing its ledger records a capped job as
    Completed."""
    import inspect

    from hashview.api import routes as api_routes
    from hashview.scheduler import _job_runtime_check_inner as sweep
    from hashview.utils import utils as utils_mod

    # The heartbeat binds it at import; same object, not a same-named copy.
    assert api_routes.expire_job_over_runtime is utils_mod.expire_job_over_runtime
    # The sweep resolves it at call time (the scheduler imports lazily), so the
    # binding is checked in its source instead.
    assert "expire_job_over_runtime" in inspect.getsource(sweep)
    assert "from hashview.utils.utils import expire_job_over_runtime" in inspect.getsource(sweep)


def test_an_agentless_job_is_expired_without_a_heartbeat(app):
    # The scenario end to end: an agent exists but is busy elsewhere and never
    # checks in against this job.
    owner = _owner()
    _settings(max_runtime_jobs=2)
    db.session.add(Agents(name="busy-elsewhere", src_ip="127.0.0.1",
                          uuid="z" * 32, status="Working"))
    db.session.commit()
    job, _task, _row = _job(owner, hours_ago=6)

    _job_runtime_check_inner(db, _LOG)

    assert Jobs.query.get(job.id).status == "Expired"
