"""End-to-end integration test for the PUBLIC data-retention entry point.

The existing scheduler tests (test_scheduler_branches.py,
test_scheduler_retention_inner.py) drive the *inner*
``_data_retention_cleanup_inner`` directly (with mocks), so the real public
``data_retention_cleanup(app)`` path -- which opens its own app context, pulls
``db`` from hashview.models, grabs the mailer from ``app.extensions['mail']``,
and wires up ``app.logger`` -- is never integration-tested against a real DB.

This module fills that gap: it seeds a real DB through the test ``app`` fixture,
calls the PUBLIC entry (NOT the inner, NOT mocked), and asserts the resulting DB
state. ``data_retention_cleanup`` swallows all exceptions (logs failure, never
raises), so a broken run wouldn't surface as an exception -- old data simply
wouldn't be deleted. The state assertions below therefore double as proof that
the full inner actually ran to completion via the public path.
"""

import os
import time
from datetime import datetime, timedelta

from hashview.models import (
    Customers,
    Hashes,
    HashfileHashes,
    Hashfiles,
    HashNotifications,
    JobNotifications,
    Jobs,
    JobTasks,
    Settings,
    Tasks,
    Users,
    db,
)
from hashview.scheduler import data_retention_cleanup

RETENTION_DAYS = 30


def _point_tmp_at(app, tmp_path):
    """Redirect the control/tmp sweep at an isolated temp dir.

    The public entry runs the real tmp sweep (``Path(current_app.root_path,
    'control', 'tmp')``). Repointing ``root_path`` keeps the test off the real
    hashview/control/tmp tree while still exercising the genuine sweep code via
    the public path. Returns the stand-in control/tmp dir.
    """
    app.root_path = str(tmp_path)
    tmp_dir = tmp_path / "control" / "tmp"
    os.makedirs(tmp_dir)
    return tmp_dir


def _seed_common():
    """Settings(id=1), an owner user, and a customer. Returns (admin, customer)."""
    db.session.add(Settings(id=1, retention_period=RETENTION_DAYS,
                            max_runtime_jobs=0, max_runtime_tasks=0))
    admin = Users(first_name="Ad", last_name="Min",
                  email_address="admin@example.com", password="x" * 60, admin=True)
    cust = Customers(name="Acme")
    db.session.add_all([admin, cust])
    db.session.commit()
    return admin, cust


def test_public_entry_purges_aged_and_keeps_recent(app, tmp_path, monkeypatch):
    """Drive the REAL data_retention_cleanup(app) end-to-end against the test DB.

    Seeds data straddling the retention boundary: an OLD job + an OLD hashfile
    (each with dependent rows) that must be purged, and a RECENT job + RECENT
    hashfile (each with dependent rows) that must survive. Since the public entry
    swallows exceptions, surviving old data would silently signal a failed run --
    so these assertions are what prove the full inner ran successfully.
    """
    _point_tmp_at(app, tmp_path)
    admin, cust = _seed_common()

    old = datetime.utcnow() - timedelta(days=RETENTION_DAYS + 60)
    now = datetime.utcnow()

    # --- OLD job (well past retention) with a task + notification ---
    old_job = Jobs(name="old-job", status="Completed", customer_id=cust.id,
                   owner_id=admin.id, created_at=old)
    db.session.add(old_job)
    db.session.commit()
    old_task = Tasks(name="old-task", owner_id=admin.id, hc_attackmode=0,
                     loopback=False)
    db.session.add(old_task)
    db.session.commit()
    db.session.add_all([
        JobTasks(job_id=old_job.id, task_id=old_task.id, status="Completed"),
        JobNotifications(owner_id=admin.id, job_id=old_job.id, method="email"),
    ])
    db.session.commit()

    # --- RECENT job (now) with a task + notification ---
    new_job = Jobs(name="new-job", status="Completed", customer_id=cust.id,
                   owner_id=admin.id, created_at=now)
    db.session.add(new_job)
    db.session.commit()
    new_task = Tasks(name="new-task", owner_id=admin.id, hc_attackmode=0,
                     loopback=False)
    db.session.add(new_task)
    db.session.commit()
    db.session.add_all([
        JobTasks(job_id=new_job.id, task_id=new_task.id, status="Not Started"),
        JobNotifications(owner_id=admin.id, job_id=new_job.id, method="email"),
    ])
    db.session.commit()

    # --- OLD hashfile with an uncracked, unshared hash + notification ---
    old_hf = Hashfiles(name="old.txt", customer_id=cust.id, owner_id=admin.id,
                       uploaded_at=old)
    db.session.add(old_hf)
    db.session.commit()
    old_hash = Hashes(sub_ciphertext="a" * 32, ciphertext="aaaa", hash_type=1000,
                      cracked=False)
    db.session.add(old_hash)
    db.session.commit()
    db.session.add_all([
        HashfileHashes(hash_id=old_hash.id, hashfile_id=old_hf.id),
        HashNotifications(owner_id=admin.id, hash_id=old_hash.id, method="email"),
    ])
    db.session.commit()

    # --- RECENT hashfile with an uncracked hash + notification ---
    new_hf = Hashfiles(name="new.txt", customer_id=cust.id, owner_id=admin.id,
                       uploaded_at=now)
    db.session.add(new_hf)
    db.session.commit()
    new_hash = Hashes(sub_ciphertext="b" * 32, ciphertext="bbbb", hash_type=1000,
                      cracked=False)
    db.session.add(new_hash)
    db.session.commit()
    db.session.add_all([
        HashfileHashes(hash_id=new_hash.id, hashfile_id=new_hf.id),
        HashNotifications(owner_id=admin.id, hash_id=new_hash.id, method="email"),
    ])
    db.session.commit()

    ids = dict(
        old_job=old_job.id, new_job=new_job.id,
        old_hf=old_hf.id, new_hf=new_hf.id,
        old_hash=old_hash.id, new_hash=new_hash.id,
    )

    # PUBLIC entry point -- opens its own app_context, not mocked, not the inner.
    data_retention_cleanup(app)
    db.session.expire_all()

    # OLD job + dependents purged
    assert Jobs.query.get(ids["old_job"]) is None
    assert JobTasks.query.filter_by(job_id=ids["old_job"]).count() == 0
    assert JobNotifications.query.filter_by(job_id=ids["old_job"]).count() == 0

    # OLD hashfile + dependents purged (uncracked + unshared hash goes too)
    assert Hashfiles.query.get(ids["old_hf"]) is None
    assert HashfileHashes.query.filter_by(hashfile_id=ids["old_hf"]).count() == 0
    assert Hashes.query.get(ids["old_hash"]) is None
    assert HashNotifications.query.filter_by(hash_id=ids["old_hash"]).count() == 0

    # RECENT job + dependents remain
    assert Jobs.query.get(ids["new_job"]) is not None
    assert JobTasks.query.filter_by(job_id=ids["new_job"]).count() == 1
    assert JobNotifications.query.filter_by(job_id=ids["new_job"]).count() == 1

    # RECENT hashfile + dependents remain
    assert Hashfiles.query.get(ids["new_hf"]) is not None
    assert HashfileHashes.query.filter_by(hashfile_id=ids["new_hf"]).count() == 1
    assert Hashes.query.get(ids["new_hash"]) is not None
    assert HashNotifications.query.filter_by(hash_id=ids["new_hash"]).count() == 1


def test_public_entry_runs_tmp_sweep(app, tmp_path, monkeypatch):
    """The public entry also runs the control/tmp sweep: a stale file is removed,
    a fresh file and .gitignore are kept. root_path is repointed at an isolated
    temp dir so this never touches the real hashview/control/tmp tree.
    """
    tmp_dir = _point_tmp_at(app, tmp_path)
    _seed_common()

    stale_mtime = time.time() - (RETENTION_DAYS + 10) * 86400

    stale = tmp_dir / "stale-upload"
    stale.write_text("old")
    os.utime(stale, (stale_mtime, stale_mtime))

    fresh = tmp_dir / "fresh-upload"
    fresh.write_text("recent")  # mtime = now -> within retention window

    gitignore = tmp_dir / ".gitignore"
    gitignore.write_text("*")
    os.utime(gitignore, (stale_mtime, stale_mtime))  # aged but always kept

    data_retention_cleanup(app)

    assert not stale.exists()    # past retention window -> removed
    assert fresh.exists()        # within window -> kept
    assert gitignore.exists()    # always kept
