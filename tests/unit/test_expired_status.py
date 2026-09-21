"""'Expired' distinguishes "a runtime cap stopped this" from "a person did".

Both used to be 'Canceled', so an operator looking at a stopped job could not
tell whether someone had intervened or the job had simply run out of its
allotted time -- and the two call for completely different responses.

The related rule: a job that reaches the end of its queue is Completed, whatever
stopped its individual attacks. A job that was itself cut short is stamped
directly (Expired by the job cap, Canceled by an operator) and never reaches the
roll-up, so 'Incomplete' now means only "created but never queued".
"""

from datetime import datetime, timedelta

import pytest

from hashview.models import Jobs, JobTasks, Settings, Tasks, Users
from hashview.models import db as _db
from hashview.utils.utils import (
    JOBTASK_ACTIVE_STATUSES,
    JOBTASK_TERMINAL_STATUSES,
    close_ledger,
    update_job_task_status,
)
from tests.unit.helpers import make_customer

pytestmark = pytest.mark.security


def _owner():
    user = Users(first_name='Ex', last_name='Pired', admin=True,
                 email_address='expired@example.test', password='x' * 60)
    _db.session.add(user)
    _db.session.commit()
    return user


def _job_with_running_task(owner, hours_ago=5):
    customer = make_customer(name='Expiry Customer')
    job = Jobs(name='capped', status='Running', customer_id=customer.id,
               owner_id=owner.id, priority=3,
               started_at=datetime.now() - timedelta(hours=hours_ago))
    task = Tasks(name='long-task', owner_id=owner.id, hc_attackmode=3,
                 hc_mask='?d?d?d?d')
    _db.session.add_all([job, task])
    _db.session.commit()
    row = JobTasks(job_id=job.id, task_id=task.id, status='Running',
                   started_at=datetime.now() - timedelta(hours=hours_ago))
    _db.session.add(row)
    _db.session.commit()
    return job, task, row


# --- the vocabulary itself ----------------------------------------------------

def test_expired_is_terminal_and_never_active():
    """Putting Expired in the active set would hang every job forever.

    finalize_job_if_complete waits for the active set to empty; an Expired row
    is finished, and nothing will ever move it on.
    """
    assert 'Expired' in JOBTASK_TERMINAL_STATUSES
    assert 'Expired' not in JOBTASK_ACTIVE_STATUSES


def test_the_status_fits_its_column():
    assert len('Expired') <= Jobs.__table__.columns['status'].type.length
    assert len('Expired') <= JobTasks.__table__.columns['status'].type.length


# --- who writes it ------------------------------------------------------------

def test_the_task_runtime_cap_writes_expired(app, db_session):
    """max_runtime_tasks: the task is Expired, not Canceled."""
    from hashview.api.routes import _cancel_task_group

    owner = _owner()
    _db.session.add(Settings(retention_period=30, max_runtime_jobs=0,
                             max_runtime_tasks=1))
    _db.session.commit()
    job, task, row = _job_with_running_task(owner)

    _cancel_task_group(job.id, task.id)

    assert JobTasks.query.get(row.id).status == 'Expired'


def test_an_operator_stop_still_writes_canceled(app, db_session):
    """The distinction only means something if the other path is unchanged.

    close_ledger picks the terminal status from the REASON it is given, so this
    is the test that stops a cap reason and a person reason collapsing back
    together.
    """
    owner = _owner()
    job, task, row = _job_with_running_task(owner)

    close_ledger(job.id, 'canceled', task_id=task.id)

    assert JobTasks.query.get(row.id).status == 'Canceled'


@pytest.mark.parametrize('reason,expected', [
    ('runtime_cap', 'Expired'),
    ('job_runtime_cap', 'Expired'),
    ('canceled', 'Canceled'),
    ('job_stopped', 'Canceled'),
    ('recovered', 'Canceled'),
])
def test_every_close_reason_maps_to_the_right_terminal_status(app, db_session,
                                                              reason, expected):
    """One table, every caller. A new reason must choose deliberately."""
    owner = _owner()
    job, task, row = _job_with_running_task(owner)

    close_ledger(job.id, reason, task_id=task.id)

    assert JobTasks.query.get(row.id).status == expected


# --- what it means for the job ------------------------------------------------

def test_an_expired_task_releases_its_agent(app, db_session):
    """Terminal cleanup must cover Expired, or the row keeps its agent forever.

    An Expired row that keeps agent_id set is still found by the heartbeat's
    "what is this agent running?" lookup, so the cap re-fires on every beat and
    the agent keeps a stale hashcat status on the fleet view.
    """
    from hashview.models import Agents

    owner = _owner()
    agent = Agents(name='rig', src_ip='127.0.0.1', uuid='a' * 32,
                   status='Working', hc_status='{"progress": "half"}')
    _db.session.add(agent)
    _db.session.commit()
    job, task, row = _job_with_running_task(owner)
    row.agent_id = agent.id
    _db.session.commit()

    update_job_task_status(row.id, 'Expired')

    assert JobTasks.query.get(row.id).agent_id is None
    assert Agents.query.get(agent.id).hc_status == ''


def test_a_job_with_an_expired_task_still_completes(app, db_session):
    """The rule the operator asked for: the job ran its course."""
    owner = _owner()
    job, task, row = _job_with_running_task(owner)
    second = JobTasks(job_id=job.id, task_id=task.id, status='Running')
    _db.session.add(second)
    _db.session.commit()

    update_job_task_status(row.id, 'Expired', finalize=False)
    update_job_task_status(second.id, 'Completed')

    assert Jobs.query.get(job.id).status == 'Completed'
    assert JobTasks.query.get(row.id).status == 'Expired', (
        'the expired task must keep its own status on the record')


def test_the_job_runtime_cap_expires_the_job_and_its_tasks(app, db_session,
                                                           client):
    """max_runtime_jobs: the JOB is Expired, and so are its live tasks.

    Driven through the heartbeat rather than by calling the helper, because the
    ordering matters: the rows are stamped with finalize=False so the last one
    cannot roll the job up to Completed a moment before the cap overwrites it.
    """
    from hashview.models import Agents

    owner = _owner()
    _db.session.add(Settings(retention_period=30, max_runtime_jobs=1,
                             max_runtime_tasks=0))
    agent = Agents(name='rig', src_ip='127.0.0.1', uuid='b' * 32,
                   status='Authorized')
    _db.session.add(agent)
    _db.session.commit()
    job, task, row = _job_with_running_task(owner, hours_ago=3)
    row.agent_id = agent.id
    _db.session.commit()

    client.set_cookie('uuid', 'b' * 32, domain='localhost.test')
    client.set_cookie('name', 'rig', domain='localhost.test')
    client.set_cookie('agent_version', '0.8.3', domain='localhost.test')
    client.post('/v1/agents/heartbeat', json={'agent_status': 'Working'})

    assert Jobs.query.get(job.id).status == 'Expired', (
        'a job past max_runtime_jobs must be Expired, not Canceled'
    )
    assert JobTasks.query.get(row.id).status == 'Expired'


# --- how it shows up ----------------------------------------------------------

# The dashboard precedence cases live in test_dashboard_chunk_groups.py,
# alongside the nine that already pin that ladder, rather than in a second
# harness here.

def test_an_expired_job_offers_info_analytics_and_restart(app, client):
    """Requirement 3, plus the control it would otherwise silently lose.

    Incomplete keeps hiding Info and Analytics -- it now means only "never
    queued", which has nothing to show. Expired ran, so it shows both, and it
    gets the Restart button 'Canceled' already had (without it a capped job
    could only be re-run through the Edit wizard).
    """
    from hashview.models import Hashfiles
    from tests.unit.helpers import login, make_admin

    with app.app_context():
        admin = make_admin()
        login(client, admin)
        customer = make_customer(name='Badge Customer')
        hashfile = Hashfiles(name='hf.txt', customer_id=customer.id,
                             owner_id=admin.id)
        _db.session.add(hashfile)
        _db.session.commit()
        expired = Jobs(name='expired-job', status='Expired', priority=3,
                       customer_id=customer.id, owner_id=admin.id,
                       hashfile_id=hashfile.id)
        incomplete = Jobs(name='incomplete-job', status='Incomplete', priority=3,
                          customer_id=customer.id, owner_id=admin.id,
                          hashfile_id=hashfile.id)
        _db.session.add_all([expired, incomplete])
        _db.session.commit()

        body = client.get('/jobs', follow_redirects=True).get_data(as_text=True)

        assert f"getElementById('info-{expired.id}')" in body, (
            'an Expired job has no Info button')
        assert f"getElementById('info-{incomplete.id}')" not in body, (
            'an Incomplete job should still hide Info')
        assert 'EXPIRED' in body, 'no status badge rendered for Expired'
        assert f"jobs_start/{expired.id}" in body.replace('/jobs/start/', 'jobs_start/'), (
            'an Expired job has no Restart control')
