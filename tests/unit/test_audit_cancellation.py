"""Cancelling a job or task must leave an audit record — by hand or by cap.

Before this, exactly one of the many cancellation paths wrote to audit.log
(POST /v1/jobs/stop). Stopping the same job from the web UI, cancelling a task
from the dashboard, or having either killed by a runtime cap all left the row
marked 'Canceled' with nothing to say who or what did it, or why.

The automatic cases matter most: they fire inside an agent's heartbeat, so a
request context EXISTS but resolve_actor() returns (None, None) — the `uuid`
cookie on a heartbeat is an agent uuid and matches no user's api_key. Logged
without an explicit actor they would read as anonymous user actions, which is
worse than not logging them. Every automatic test below therefore asserts the
actor is 'system', not merely that an entry appeared.
"""

import json
import os
from datetime import datetime, timedelta

import pytest

from hashview.models import Agents, Jobs, JobTasks, Settings, Tasks, Users
from hashview.models import db as _db
from hashview.utils.audit import AUDIT_FILE, configure_audit_logging, logs_dir

pytestmark = pytest.mark.security


@pytest.fixture()
def audit_app(app, tmp_path):
    app.config["HASHVIEW_LOGS_DIR"] = str(tmp_path / "logs")
    configure_audit_logging(app)
    return app


def _events(app, name=None):
    path = os.path.join(logs_dir(app), AUDIT_FILE)
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as fh:
        rows = [json.loads(line) for line in fh if line.strip()]
    return [r for r in rows if name is None or r["event"] == name]


def _admin():
    user = Users(first_name="Cancel", last_name="Admin", admin=True,
                 email_address="cancel-admin@example.test", password="x" * 60)
    _db.session.add(user)
    _db.session.commit()
    return user


def _login(client, user):
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True


def _running_job(owner, *, started_hours_ago=0):
    from tests.unit.helpers import make_customer

    customer = make_customer(name="Cancel Customer")
    job = Jobs(name="cancel-me", status="Running", customer_id=customer.id,
               owner_id=owner.id, priority=3,
               started_at=datetime.now() - timedelta(hours=started_hours_ago))
    task = Tasks(name="cancel-task", owner_id=owner.id, hc_attackmode=3,
                 hc_mask="?d?d?d?d")
    _db.session.add_all([job, task])
    _db.session.commit()
    job_task = JobTasks(job_id=job.id, task_id=task.id, status="Running",
                        started_at=datetime.now() - timedelta(hours=started_hours_ago))
    _db.session.add(job_task)
    _db.session.commit()
    return job, task, job_task


# --- user-initiated ---------------------------------------------------------

def test_stopping_a_job_from_the_web_ui_is_audited(audit_app, client):
    """The API twin already logged job.stop; the UI logged nothing at all."""
    with audit_app.app_context():
        admin = _admin()
        _login(client, admin)
        job, _task, _jt = _running_job(admin)

        client.post(f"/jobs/stop/{job.id}", follow_redirects=True)

        assert Jobs.query.get(job.id).status == "Canceled"
        events = _events(audit_app, "job.stop")
        assert events, "stopping a job from the UI wrote no audit entry"
        assert f"job:{job.id}" in events[-1]["target"]
        assert events[-1]["actor"] == admin.email_address


def test_cancelling_a_task_from_the_dashboard_is_audited(audit_app, client):
    with audit_app.app_context():
        admin = _admin()
        _login(client, admin)
        job, task, _jt = _running_job(admin)

        client.get(f"/job_task/stop_task/{job.id}/{task.id}", follow_redirects=True)

        events = _events(audit_app, "task.cancel")
        assert events, "cancelling a task wrote no audit entry"
        entry = events[-1]
        assert f"job:{job.id}" in entry["target"]
        assert f"task:{task.id}" in entry["target"], (
            "the target must name the job AND the task: a task belongs to many "
            f"jobs, so {entry['target']!r} would not say which run stopped")
        assert entry["actor"] == admin.email_address


def test_cancelling_a_single_chunk_is_audited(audit_app, client):
    """The per-row stop route, which takes the no-ledger fallback branch here."""
    with audit_app.app_context():
        admin = _admin()
        _login(client, admin)
        job, task, job_task = _running_job(admin)

        client.get(f"/job_task/stop/{job_task.id}", follow_redirects=True)

        events = _events(audit_app, "task.cancel")
        assert events, "the fallback (no-ledger) branch wrote no audit entry"
        assert f"job:{job.id}" in events[-1]["target"]


def test_an_unauthorized_stop_is_not_audited_as_a_cancellation(audit_app, client):
    """A refused action must not appear as one that happened."""
    with audit_app.app_context():
        owner = _admin()
        job, task, _jt = _running_job(owner)
        intruder = Users(first_name="Not", last_name="Owner", admin=False,
                         email_address="intruder@example.test", password="x" * 60)
        _db.session.add(intruder)
        _db.session.commit()
        _login(client, intruder)

        client.get(f"/job_task/stop_task/{job.id}/{task.id}", follow_redirects=True)

        assert not _events(audit_app, "task.cancel"), (
            "a stop the app refused was recorded as a cancellation")


# --- automatic (runtime caps) ----------------------------------------------

def _agent_and_settings(max_runtime_tasks=0, max_runtime_jobs=0):
    settings = Settings(retention_period=30, max_runtime_jobs=max_runtime_jobs,
                        max_runtime_tasks=max_runtime_tasks)
    agent = Agents(name="rig", src_ip="127.0.0.1", uuid="a" * 32,
                   status="Authorized")
    _db.session.add_all([settings, agent])
    _db.session.commit()
    return agent


def test_task_runtime_cap_is_audited_as_a_system_action(audit_app):
    """max_runtime_tasks. Actor must be 'system', never an anonymous user."""
    from hashview.api.routes import _cancel_task_group

    with audit_app.app_context():
        owner = _admin()
        _agent_and_settings(max_runtime_tasks=2)
        job, task, _jt = _running_job(owner, started_hours_ago=5)

        _cancel_task_group(job.id, task.id)

        events = _events(audit_app, "task.auto_cancel")
        assert events, "a task killed by max_runtime_tasks wrote no audit entry"
        entry = events[-1]
        assert entry["actor"] == "system", (
            f"automatic cancellation logged actor {entry['actor']!r}; a heartbeat "
            "has a request context but no user, so it must say system")
        assert f"task:{task.id}" in entry["target"]
        assert "max_runtime_tasks" in (entry["detail"] or ""), (
            "the entry must say which cap fired, or it cannot be acted on")


def test_job_runtime_cap_is_audited_as_a_system_action(audit_app):
    """max_runtime_jobs."""
    from hashview.api.routes import _audit_auto_cancel

    with audit_app.app_context():
        owner = _admin()
        _agent_and_settings(max_runtime_jobs=3)
        job, _task, _jt = _running_job(owner, started_hours_ago=9)

        _audit_auto_cancel("job.auto_cancel", job.id, cap="max_runtime_jobs")

        events = _events(audit_app, "job.auto_cancel")
        assert events, "a job killed by max_runtime_jobs wrote no audit entry"
        entry = events[-1]
        assert entry["actor"] == "system"
        assert f"job:{job.id}" in entry["target"]
        assert "max_runtime_jobs" in (entry["detail"] or "")


def test_auditing_never_blocks_the_cap_from_being_enforced(audit_app, monkeypatch):
    """Enforcement must survive a broken audit write.

    The cap is a safety mechanism; a failure to record it must not become a
    failure to apply it.
    """
    from hashview.api import routes as api_routes

    with audit_app.app_context():
        owner = _admin()
        _agent_and_settings(max_runtime_tasks=1)
        job, task, job_task = _running_job(owner, started_hours_ago=4)

        def _boom(*args, **kwargs):
            raise RuntimeError("audit sink is down")

        monkeypatch.setattr(api_routes, "log_event", _boom)
        api_routes._cancel_task_group(job.id, task.id)

        assert JobTasks.query.get(job_task.id).status == "Canceled", (
            "the runtime cap was not applied because auditing raised")
