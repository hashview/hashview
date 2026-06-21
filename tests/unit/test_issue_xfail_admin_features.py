"""xfail tests documenting open GitHub issues for admin-facing features.

Each test asserts the DESIRED behavior described in the linked issue and is
marked ``@pytest.mark.xfail(strict=False)`` so it records as XFAIL until the
feature lands (and XPASS once it does) — never as a hard failure or collection
error. They are also ``@pytest.mark.security`` so the parent Playwright autouse
fixtures (which need a live server) are skipped (see tests/unit/conftest.py).

Issues covered:

* #39  — Admin Settings "Database" tab: DB OPTIMIZE action. The encrypted
         export already exists (settings.settings_backup, covered by
         test_db_backup.py); the missing piece is an admin-gated
         ``OPTIMIZE TABLE hashes; OPTIMIZE TABLE hashfile_hashes;`` action.
* #30  — Notify admins when agents stop checking in. ``notify_admins`` exists
         (hashview/utils/utils.py) but nothing detects stale agents.
* #91  — Logging of user activity. Audit logging is broad, but job start/stop
         and wordlist edit emit no ``log_event``.
"""

import inspect
import os
from datetime import datetime, timedelta

import pytest

from hashview.models import (
    Agents,
    Customers,
    JobTasks,
    Jobs,
    Settings,
    Users,
    Wordlists,
)
from hashview.models import db as _db
from hashview.utils.audit import configure_audit_logging, log_event, logs_dir

from .helpers import login, make_admin, make_customer, make_user

pytestmark = pytest.mark.security


# ---------------------------------------------------------------------------
# Shared fixtures / helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def audit_app(app, tmp_path):
    """Re-point the audit/error loggers into tmp_path for this test.

    Mirrors the pattern in test_audit_log.py / test_logs_view.py: set the
    HASHVIEW_LOGS_DIR override and re-run the idempotent configurator so audit
    lines land under tmp_path instead of the repo's real logs dir.
    """
    app.config["HASHVIEW_LOGS_DIR"] = str(tmp_path / "logs")
    configure_audit_logging(app)
    return app


def _audit_events(app):
    """Return the list of event names recorded in the audit log (may be empty)."""
    import json

    path = os.path.join(logs_dir(app), "audit.log")
    if not os.path.exists(path):
        return []
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
    return out


def _seed_job(owner, customer, status="Queued"):
    job = Jobs(name="demo job", status=status, customer_id=customer.id,
               owner_id=owner.id, priority=3)
    _db.session.add(job)
    _db.session.commit()
    task = JobTasks(job_id=job.id, task_id=1, status="Not Started", priority=3)
    _db.session.add(task)
    _db.session.commit()
    return job


# ===========================================================================
# Issue #39 — Admin Settings "Database" tab: DB OPTIMIZE
# ===========================================================================


@pytest.mark.xfail(reason="issue #39: admin DB optimize route not implemented",
                   strict=False)
def test_optimize_route_flashes_success_for_admin(client, app):
    """An admin can trigger DB OPTIMIZE and gets a success flash.

    Desired: a settings route (e.g. /settings/optimize) runs
    ``OPTIMIZE TABLE hashes; OPTIMIZE TABLE hashfile_hashes;`` and flashes
    success. We follow the redirect so the flashed message is rendered.
    """
    _db.session.add(Settings(retention_period=30, max_runtime_jobs=0,
                             max_runtime_tasks=0))
    _db.session.commit()
    admin = make_admin()
    login(client, admin)

    resp = client.post("/settings/optimize", follow_redirects=True)
    assert resp.status_code == 200
    html = resp.get_data(as_text=True).lower()
    assert "optim" in html and ("success" in html or "complete" in html)


@pytest.mark.xfail(reason="issue #39: admin DB optimize route not implemented",
                   strict=False)
def test_optimize_route_is_admin_gated(client, app):
    """A non-admin must NOT be able to run DB OPTIMIZE.

    Desired: the route exists but rejects non-admins (403, or a redirect that
    is not the admin success path). Either way it must not return a plain 200
    success page to a regular user.
    """
    _db.session.add(Settings(retention_period=30, max_runtime_jobs=0,
                             max_runtime_tasks=0))
    _db.session.commit()
    user = make_user()
    login(client, user)

    resp = client.post("/settings/optimize")
    # A 404 here means the route doesn't exist yet (feature missing) — which is
    # the xfail condition; otherwise it must be denied, never a 200 success.
    assert resp.status_code in (403, 401) or 300 <= resp.status_code < 400
    if 300 <= resp.status_code < 400:
        assert "/settings/optimize" not in resp.headers.get("Location", "")


@pytest.mark.xfail(reason="issue #39: optimize helper not implemented in "
                          "hashview.settings.routes", strict=False)
def test_optimize_helper_exists_in_settings_routes():
    """An ``optimize_database``/``optimize_tables`` helper exists in
    hashview.settings.routes that issues the OPTIMIZE TABLE statements."""
    import hashview.settings.routes as sr

    helper = (getattr(sr, "optimize_database", None)
              or getattr(sr, "optimize_tables", None))
    assert helper is not None and callable(helper)
    # It should reference the two tables the issue calls out.
    src = inspect.getsource(helper)
    assert "OPTIMIZE TABLE" in src
    assert "hashes" in src and "hashfile_hashes" in src


# ===========================================================================
# Issue #30 — Notify admins when agents stop checking in
# ===========================================================================


@pytest.mark.xfail(reason="issue #30: stale-agent detection helper not "
                          "implemented", strict=False)
def test_stale_agent_detection_helper_exists():
    """A helper to detect agents that have stopped checking in exists.

    Desired: something like ``hashview.scheduler.check_agent_checkins`` (or an
    equivalently named helper in scheduler/utils) that the scheduler can run.
    """
    import importlib

    found = None
    for modname in ("hashview.scheduler", "hashview.utils.utils"):
        mod = importlib.import_module(modname)
        for name in ("check_agent_checkins", "notify_stale_agents",
                     "detect_stale_agents", "check_stale_agents",
                     "agent_checkin_monitor"):
            cand = getattr(mod, name, None)
            if callable(cand):
                found = cand
                break
        if found:
            break
    assert found is not None, "no stale-agent detection helper found"


@pytest.mark.xfail(reason="issue #30: stale agents do not trigger "
                          "notify_admins", strict=False)
def test_stale_agent_detection_notifies_admins(app, monkeypatch):
    """Running stale-agent detection fires notify_admins for an Agent whose
    last_checkin is old.

    Desired: with an admin user present and an Agent that last checked in well
    beyond any reasonable threshold, the detection helper calls
    ``notify_admins(subject, message)`` at least once.
    """
    import importlib

    make_admin()
    stale = Agents(
        name="gpu-rig-01",
        src_ip="10.0.0.9",
        uuid="a" * 36,
        status="Idle",
        last_checkin=datetime.utcnow() - timedelta(hours=12),
    )
    _db.session.add(stale)
    _db.session.commit()

    calls = []

    # Patch notify_admins everywhere it might be referenced.
    def _spy(subject, message):
        calls.append((subject, message))

    import hashview.utils.utils as uu
    monkeypatch.setattr(uu, "notify_admins", _spy, raising=False)

    found = None
    for modname in ("hashview.scheduler", "hashview.utils.utils"):
        mod = importlib.import_module(modname)
        monkeypatch.setattr(mod, "notify_admins", _spy, raising=False)
        for name in ("check_agent_checkins", "notify_stale_agents",
                     "detect_stale_agents", "check_stale_agents",
                     "agent_checkin_monitor"):
            cand = getattr(mod, name, None)
            if callable(cand):
                found = cand

    assert found is not None, "no stale-agent detection helper to run"
    # Call with the app where the signature allows it; otherwise call bare.
    try:
        found(app)
    except TypeError:
        found()

    assert calls, "stale agent should have triggered notify_admins"


# ===========================================================================
# Issue #91 — Logging of user activity (job start/stop, wordlist edit)
# ===========================================================================


@pytest.mark.xfail(reason="issue #91: job start is not audited (no job.start "
                          "log_event)", strict=False)
def test_job_start_is_audited(client, audit_app):
    """Starting a job writes a job.start audit line."""
    admin = make_admin()
    customer = make_customer()
    job = _seed_job(admin, customer, status="Ready")
    login(client, admin)

    resp = client.get(f"/jobs/start/{job.id}")
    assert resp.status_code in (200, 301, 302)

    starts = [e for e in _audit_events(audit_app) if e.get("event") == "job.start"]
    assert starts, "expected a job.start audit line after starting a job"


@pytest.mark.xfail(reason="issue #91: job stop is not audited (no job.stop/"
                          "job.cancel log_event)", strict=False)
def test_job_stop_is_audited(client, audit_app):
    """Stopping a running job writes a job.stop (or job.cancel) audit line."""
    admin = make_admin()
    customer = make_customer()
    job = _seed_job(admin, customer, status="Running")
    login(client, admin)

    resp = client.get(f"/jobs/stop/{job.id}")
    assert resp.status_code in (200, 301, 302)

    stops = [e for e in _audit_events(audit_app)
             if e.get("event") in ("job.stop", "job.cancel")]
    assert stops, "expected a job.stop/job.cancel audit line after stopping a job"


@pytest.mark.xfail(reason="issue #91: wordlist edit is not audited (only "
                          "create/delete emit log_event)", strict=False)
def test_wordlist_edit_is_audited(client, audit_app):
    """Editing/updating a wordlist writes a wordlist.edit audit line.

    Only wordlist create/delete currently emit log_event; the update path
    (/wordlists/update/<id>) emits nothing. We drive it against a static
    wordlist so the route takes the no-op branch (no file I/O, never errors)
    yet should still record the edit attempt.
    """
    admin = make_admin()
    wl = Wordlists(name="rockyou", owner_id=admin.id, type="static",
                   path="/tmp/does-not-matter.txt", size=0, byte_size=0,
                   checksum="0" * 64)
    _db.session.add(wl)
    _db.session.commit()
    login(client, admin)

    resp = client.get(f"/wordlists/update/{wl.id}")
    assert resp.status_code in (200, 301, 302)

    edits = [e for e in _audit_events(audit_app)
             if e.get("event") == "wordlist.edit"]
    assert edits, "expected a wordlist.edit audit line after updating a wordlist"
