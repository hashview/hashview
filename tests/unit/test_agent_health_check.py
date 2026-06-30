"""Agent-health scheduler: one-shot offline alert + recovery alert, and the
configurable agent-timeout cutoff. Uses the in-memory SQLite app from
tests/unit/conftest.py; notify_admins is monkeypatched (it's imported inside the
inner job, so patching it on hashview.utils.utils is picked up at call time)."""
import logging
from datetime import datetime, timedelta

import pytest

from hashview.models import Agents, Settings, db
from hashview.scheduler import _agent_health_check_inner
from hashview.utils import utils as utils_mod

_LOG = logging.getLogger("test-agent-health")


def _settings(timeout=10):
    s = Settings.query.first() or Settings(retention_period=1, max_runtime_jobs=0, max_runtime_tasks=0)
    s.agent_timeout_minutes = timeout
    db.session.add(s)
    db.session.commit()
    return s


def _agent(name, minutes_ago=None, offline_notified=False):
    last = None if minutes_ago is None else datetime.utcnow() - timedelta(minutes=minutes_ago)
    a = Agents(name=name, src_ip="127.0.0.1", uuid="u-" + name, status="Idle",
               last_checkin=last, offline_notified=offline_notified)
    db.session.add(a)
    db.session.commit()
    return a


@pytest.mark.security
def test_offline_alert_fires_once(app, monkeypatch):
    _settings(timeout=10)
    a = _agent("rig1", minutes_ago=30)                 # stale -> offline
    calls = []
    monkeypatch.setattr(utils_mod, "notify_admins", lambda subj, msg: calls.append(subj))

    _agent_health_check_inner(db, _LOG)
    assert len(calls) == 1 and calls[0].startswith("Agent offline")
    assert Agents.query.get(a.id).offline_notified is True

    # while it stays offline, a second run must NOT re-notify
    _agent_health_check_inner(db, _LOG)
    assert len(calls) == 1


@pytest.mark.security
def test_recovery_alert_on_checkin(app, monkeypatch):
    _settings(timeout=10)
    a = _agent("rig2", minutes_ago=1, offline_notified=True)   # recent check-in, was flagged offline
    calls = []
    monkeypatch.setattr(utils_mod, "notify_admins", lambda subj, msg: calls.append(subj))

    _agent_health_check_inner(db, _LOG)
    assert len(calls) == 1 and calls[0].startswith("Agent recovered")
    assert Agents.query.get(a.id).offline_notified is False


@pytest.mark.security
def test_never_checked_in_is_ignored(app, monkeypatch):
    _settings(timeout=10)
    _agent("rig3", minutes_ago=None)                   # never checked in -> never "went offline"
    calls = []
    monkeypatch.setattr(utils_mod, "notify_admins", lambda subj, msg: calls.append(subj))

    _agent_health_check_inner(db, _LOG)
    assert calls == []


@pytest.mark.security
def test_within_timeout_no_alert(app, monkeypatch):
    _settings(timeout=60)
    a = _agent("rig4", minutes_ago=5)                  # well within the 60-min window
    calls = []
    monkeypatch.setattr(utils_mod, "notify_admins", lambda subj, msg: calls.append(subj))

    _agent_health_check_inner(db, _LOG)
    assert calls == []
    assert Agents.query.get(a.id).offline_notified is False


@pytest.mark.security
def test_agent_health_check_wrapper_runs_and_notifies(app, monkeypatch):
    """The scheduled entrypoint agent_health_check(app) pushes its own app context
    and runs the check. It must be handed the REAL app object — the scheduler fires
    jobs with no active context, so a current_app proxy would raise here."""
    from hashview.scheduler import agent_health_check
    _settings(timeout=10)
    a = _agent("rigW", minutes_ago=30)
    calls = []
    monkeypatch.setattr(utils_mod, "notify_admins", lambda subj, msg: calls.append(subj))
    agent_health_check(app)
    assert len(calls) == 1 and calls[0].startswith("Agent offline")
    assert Agents.query.get(a.id).offline_notified is True


@pytest.mark.security
def test_offline_and_recovery_write_audit_events(app, monkeypatch):
    """Offline + recovery are recorded in the audit log (agent.offline /
    agent.recovered), so they show up in Settings -> audit log."""
    import hashview.utils.audit as audit_mod
    events = []
    monkeypatch.setattr(audit_mod, "log_event", lambda event, **kw: events.append(event))
    monkeypatch.setattr(utils_mod, "notify_admins", lambda *a, **k: None)
    _settings(timeout=10)
    a = _agent("rigA", minutes_ago=30)

    _agent_health_check_inner(db, _LOG)                  # detected offline
    assert "agent.offline" in events

    a.last_checkin = datetime.utcnow()                   # agent checks back in
    db.session.commit()
    events.clear()
    _agent_health_check_inner(db, _LOG)                  # detected recovery
    assert "agent.recovered" in events


@pytest.mark.security
def test_register_default_jobs_includes_agent_health(app):
    """Regression: both create_app and the hashview.py entry point register jobs
    via this one helper, so AGENT_HEALTH can't be dropped while DATA_RETENTION
    survives (the drift that previously stopped offline alerts from ever firing)."""
    from hashview.scheduler import register_default_jobs, scheduler
    register_default_jobs(app)
    job_ids = {j.id for j in scheduler.get_jobs()}
    assert {"DATA_RETENTION", "AGENT_HEALTH"} <= job_ids


@pytest.mark.security
def test_get_agent_timeout_minutes_reads_setting(app):
    from hashview.utils.utils import get_agent_timeout_minutes
    _settings(timeout=42)
    assert get_agent_timeout_minutes() == 42
