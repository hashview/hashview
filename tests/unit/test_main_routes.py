"""Regression tests for main routes (function-coverage batch: main)."""

from datetime import datetime, timedelta
from unittest import mock

import hashview.main.routes as main_routes
from hashview.models import (
    Hashes,
    HashfileHashes,
    Jobs,
    JobTasks,
    db,
)
from tests.unit.helpers import login, make_admin, make_customer, make_user


def test_home_renders_with_recovery_feed(app, client):
    # Seeding a cracked hash with a username drives the recovery-feed loop,
    # which exercises the nested _hexdec helper.
    admin = make_admin()
    login(client, admin)
    h = Hashes(sub_ciphertext="0" * 8, ciphertext="abc", hash_type=1000,
               cracked=True, plaintext="Summer2024",
               recovered_at=datetime(2024, 1, 2), recovered_by=admin.id)
    db.session.add(h)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=1, username="alice"))
    db.session.commit()
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"Summer2024" in resp.data


def _seed_recovered(admin, *, delta, plaintext, username):
    """A cracked hash recovered `delta` ago, wired into the recovery feed."""
    h = Hashes(sub_ciphertext="0" * 8, ciphertext=plaintext[::-1], hash_type=1000,
               cracked=True, plaintext=plaintext,
               recovered_at=datetime.now() - delta, recovered_by=admin.id)
    db.session.add(h)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=1, username=username))
    db.session.commit()
    return h


def test_recovery_feed_time_is_relative(app, client):
    """The feed's Time column shows 'N <unit> ago' (seconds/minutes/hours under
    24h, days beyond) instead of a wall-clock time."""
    admin = make_admin()
    login(client, admin)
    _seed_recovered(admin, delta=timedelta(hours=2, minutes=5), plaintext="RecentPw", username="bob")
    _seed_recovered(admin, delta=timedelta(days=3), plaintext="OldPw", username="carol")
    body = client.get("/").get_data(as_text=True)
    assert "2 hours ago" in body
    assert "3 days ago" in body


def test_relative_time_units_and_pluralization():
    now = datetime.now()
    rt = main_routes._relative_time
    assert rt(now - timedelta(seconds=1)) == "1 second ago"
    assert rt(now - timedelta(seconds=30)) == "30 seconds ago"
    assert rt(now - timedelta(minutes=1)) == "1 minute ago"
    assert rt(now - timedelta(hours=5)) == "5 hours ago"
    assert rt(now - timedelta(hours=23, minutes=59)) == "23 hours ago"
    assert rt(now - timedelta(days=1)) == "1 day ago"
    assert rt(now - timedelta(days=10)) == "10 days ago"
    assert rt(None) == "—"


def _fixed_now(month, day, year=2026):
    class _D(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(year, month, day, 12, 0, 0)
    return _D


def test_dashboard_flourish_autoplays_once_on_april_first(app, client):
    """The dashboard flourish auto-runs only on April 1 (server time) and only
    once per user per year (a cookie records that it has run)."""
    admin = make_admin()
    login(client, admin)

    # A normal day: no autoplay.
    with mock.patch.object(main_routes, "datetime", _fixed_now(3, 15)):
        assert b"HV_DASH_AUTOPLAY" not in client.get("/").data

    # April 1, first visit: autoplay + a cookie is set.
    with mock.patch.object(main_routes, "datetime", _fixed_now(4, 1)):
        resp = client.get("/")
        assert b"HV_DASH_AUTOPLAY = true" in resp.data
        assert "hv_dash=2026" in resp.headers.get("Set-Cookie", "")
        # Second visit the same day (cookie now present): no repeat.
        assert b"HV_DASH_AUTOPLAY" not in client.get("/").data


def test_profile_api_key_copy_shows_feedback(app, client):
    """Issue #303: the account-settings API-key Copy button gives a momentary
    'Copied!' confirmation (Clipboard API with a legacy fallback)."""
    admin = make_admin()
    login(client, admin)
    body = client.get("/").get_data(as_text=True)
    assert 'onclick="hvApiCopy(this)"' in body        # button hands itself to the handler
    assert 'function hvApiCopy(btn)' in body
    assert '✓ Copied!' in body                        # momentary confirmation text
    assert 'navigator.clipboard.writeText' in body    # Clipboard API path
    assert "document.execCommand('copy')" in body     # legacy fallback
    # After Generate, the layout reopens the account modal + reveals the new key.
    assert 'apikey_generated' in body


def test_stop_job_task_cancels(app, client):
    from hashview.models import Hashfiles
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    hf = Hashfiles(name="hf", customer_id=cust.id, owner_id=admin.id, runtime=0)
    db.session.add(hf)
    db.session.commit()
    job = Jobs(name="j", status="Running", customer_id=cust.id, owner_id=admin.id,
               hashfile_id=hf.id)
    db.session.add(job)
    db.session.commit()
    # update_job_task_status accrues runtime from started_at -> now, so a
    # running task needs a started_at.
    jt = JobTasks(job_id=job.id, task_id=1, status="Running", priority=3,
                  started_at=datetime.utcnow())
    db.session.add(jt)
    db.session.commit()
    resp = client.get(f"/job_task/stop/{jt.id}", follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert JobTasks.query.get(jt.id).status == "Canceled"


def test_stop_task_cancels_all_chunks(app, client):
    """/job_task/stop_task cancels every still-active chunk of a (job, task)."""
    from hashview.models import Hashfiles
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    hf = Hashfiles(name="hf", customer_id=cust.id, owner_id=admin.id, runtime=0)
    db.session.add(hf)
    db.session.commit()
    job = Jobs(name="j", status="Running", customer_id=cust.id, owner_id=admin.id,
               hashfile_id=hf.id)
    db.session.add(job)
    db.session.commit()
    # Two chunks of the SAME task plus a finished one that must be left alone.
    running = JobTasks(job_id=job.id, task_id=7, status="Running", priority=3,
                       started_at=datetime.utcnow())
    queued = JobTasks(job_id=job.id, task_id=7, status="Queued", priority=3)
    completed = JobTasks(job_id=job.id, task_id=7, status="Completed", priority=3)
    db.session.add_all([running, queued, completed])
    db.session.commit()

    resp = client.get(f"/job_task/stop_task/{job.id}/7", follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert JobTasks.query.get(running.id).status == "Canceled"
    assert JobTasks.query.get(queued.id).status == "Canceled"
    # A chunk that already finished is not reopened/recanceled.
    assert JobTasks.query.get(completed.id).status == "Completed"


def test_stop_task_missing_job_redirects(app, client):
    """/job_task/stop_task for a nonexistent job flashes and redirects home."""
    admin = make_admin()
    login(client, admin)
    resp = client.get("/job_task/stop_task/424242/1", follow_redirects=False)
    assert resp.status_code in (301, 302)


def test_stop_task_non_owner_non_admin_does_not_cancel(app, client):
    """A non-owner non-admin user can't stop someone else's task."""
    owner = make_admin()
    cust = make_customer()
    job = Jobs(name="j", status="Running", customer_id=cust.id, owner_id=owner.id)
    db.session.add(job)
    db.session.commit()
    jt = JobTasks(job_id=job.id, task_id=9, status="Running", priority=3,
                  started_at=datetime.utcnow())
    db.session.add(jt)
    db.session.commit()

    intruder = make_user()
    login(client, intruder)
    resp = client.get(f"/job_task/stop_task/{job.id}/9", follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert JobTasks.query.get(jt.id).status == "Running"   # left untouched


def test_dashboard_recovery_fragment(app, client):
    # /dashboard/recovery returns just the live-feed table fragment (polled ~5s).
    admin = make_admin()
    login(client, admin)
    h = Hashes(sub_ciphertext="0" * 8, ciphertext="abc", hash_type=1000,
               cracked=True, plaintext="Winter2025",
               recovered_at=datetime(2024, 1, 3), recovered_by=admin.id)
    db.session.add(h)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=1, username="bob"))
    db.session.commit()
    resp = client.get("/dashboard/recovery")
    assert resp.status_code == 200
    assert b"Winter2025" in resp.data
    assert b"bob" in resp.data
    # It's a fragment, not a full page (no layout chrome).
    assert b"<html" not in resp.data


def test_dashboard_jobs_fragment(app, client):
    # /dashboard/jobs returns the running-job + queue markup fragment (polled ~20s).
    from hashview.models import Hashfiles
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    hf = Hashfiles(name="hf", customer_id=cust.id, owner_id=admin.id, runtime=0)
    db.session.add(hf)
    db.session.commit()
    job = Jobs(name="Quarterly Audit", status="Running", customer_id=cust.id,
               owner_id=admin.id, hashfile_id=hf.id)
    db.session.add(job)
    db.session.commit()
    resp = client.get("/dashboard/jobs")
    assert resp.status_code == 200
    assert b"Quarterly Audit" in resp.data
    assert b"running jobs" in resp.data
    assert b'data-job-id="%d"' % job.id in resp.data


def test_dashboard_summary_json(app, client):
    # /dashboard/summary returns rendered KPI html + 7-day chart series (polled ~15s).
    admin = make_admin()
    login(client, admin)
    resp = client.get("/dashboard/summary")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "ok"
    assert len(data["chart"]["labels"]) == 7
    assert len(data["chart"]["values"]) == 7
    assert data["kpis_html"]
    assert "kpi" in data["kpis_html"]


def test_dashboard_fleet_fragment(app, client):
    # /dashboard/fleet returns the agent-fleet modal contents (polled while open).
    from hashview.models import Agents
    admin = make_admin()
    login(client, admin)
    db.session.add(Agents(name="cracker01", src_ip="10.0.0.5", uuid="u-123",
                          status="Idle"))
    db.session.commit()
    resp = client.get("/dashboard/fleet")
    assert resp.status_code == 200
    assert b"cracker01" in resp.data
    # A fresh agent with no recent check-in renders an OFFLINE state badge.
    assert b"OFFLINE" in resp.data
    assert b"<html" not in resp.data


def test_dashboard_endpoints_require_login(app, client):
    for path in ("/dashboard/jobs", "/dashboard/recovery", "/dashboard/summary",
                 "/dashboard/fleet"):
        resp = client.get(path)
        assert resp.status_code in (301, 302, 401), path
