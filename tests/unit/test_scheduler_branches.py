"""Branch-coverage tests for hashview.scheduler.

Targets the one remaining uncovered line in hashview/scheduler.py:

  Line 34 — ``return None`` (the success path of try_send_email).

The outer wrapper and all inner-loop branches are already covered by
test_scheduler_retention.py / test_scheduler_retention_inner.py; the tests
here focus on the pieces those files leave out, and add a few complementary
scenarios to lock in correctness of the shared-hash deduplication guard and the
HashNotifications cascade.
"""

import os
import time
from datetime import datetime, timedelta
from unittest.mock import MagicMock

import pytest

from hashview.models import (
    Customers,
    Hashes,
    HashfileHashes,
    HashNotifications,
    Hashfiles,
    JobNotifications,
    Jobs,
    JobTasks,
    Settings,
    Tasks,
    Users,
    db,
)
from hashview.scheduler import _data_retention_cleanup_inner, try_send_email


# ---------------------------------------------------------------------------
# Helpers (mirrors the pattern in test_scheduler_retention_inner.py)
# ---------------------------------------------------------------------------

def _admin(email="admin@branch.test"):
    u = Users(
        first_name="Branch",
        last_name="Admin",
        email_address=email,
        password="x" * 60,
        admin=True,
    )
    db.session.add(u)
    db.session.commit()
    return u


def _settings(retention_period=30):
    s = Settings(retention_period=retention_period, max_runtime_jobs=0, max_runtime_tasks=0)
    db.session.add(s)
    db.session.commit()
    return s


def _setup_tmp(tmp_path, monkeypatch):
    """chdir to tmp_path with a stand-in control/tmp so the cleanup never
    touches the real tree."""
    monkeypatch.chdir(tmp_path)
    tmp_dir = tmp_path / "hashview" / "control" / "tmp"
    os.makedirs(tmp_dir)
    return tmp_dir


def _run_inner(app):
    _data_retention_cleanup_inner(db, app.extensions["mail"], app.logger)


def _make_task(owner_id, name="branch-task"):
    task = Tasks(name=name, owner_id=owner_id, wl_id=None, rule_id=None,
                 hc_attackmode=0, loopback=False)
    db.session.add(task)
    db.session.commit()
    return task


# ---------------------------------------------------------------------------
# try_send_email — direct unit tests
# ---------------------------------------------------------------------------

def test_try_send_email_success_returns_none(app):
    """Line 34: the happy path returns None when mail send succeeds.

    We use a MagicMock mailer (send() does nothing) so the call always
    completes without raising, hitting the ``return None`` success branch.
    """
    user = Users(
        first_name="Happy",
        last_name="Path",
        email_address="happy@branch.test",
        password="x" * 60,
        admin=False,
    )
    db.session.add(user)
    db.session.commit()

    mailer = MagicMock()
    mailer.send.return_value = None  # succeeds silently

    result = try_send_email(user, "Subject", "Body text", mailer)
    assert result is None, (
        "try_send_email should return None on success, got: %r" % result
    )


def test_try_send_email_failure_returns_error_string(app):
    """try_send_email returns an error string (not None) when send raises."""
    with app.app_context():
        mailer = MagicMock()
        mailer.send.side_effect = RuntimeError("connection refused")

        user = Users(
            first_name="Fail",
            last_name="Path",
            email_address="fail@branch.test",
            password="x" * 60,
            admin=False,
        )
        db.session.add(user)
        db.session.commit()

        result = try_send_email(user, "Subject", "Body", mailer)
        assert isinstance(result, str)
        assert result  # non-empty error string


def test_try_send_email_bad_user_attribute_returns_error_string(app):
    """try_send_email returns an error string when the user object is missing
    email_address (AttributeError bubbles into the except branch)."""
    with app.app_context():
        mailer = MagicMock()
        bad_user = object()  # has no .email_address attribute

        result = try_send_email(bad_user, "Subject", "Body", mailer)
        assert isinstance(result, str)
        assert result


# ---------------------------------------------------------------------------
# Shared-hash deduplication guard (hashfile_cnt < 2)
# ---------------------------------------------------------------------------

def test_inner_spares_shared_hash(app, tmp_path, monkeypatch):
    """A hash linked to TWO hashfiles must NOT be deleted when the first
    (aged) hashfile is purged — the hashfile_cnt guard keeps it alive."""
    _setup_tmp(tmp_path, monkeypatch)
    _settings(retention_period=30)
    admin = _admin("shared@branch.test")
    cust = Customers(name="SharedCo")
    db.session.add(cust)
    db.session.commit()

    aged = datetime.utcnow() - timedelta(days=90)

    hf_old = Hashfiles(name="old.txt", customer_id=cust.id, owner_id=admin.id,
                       uploaded_at=aged)
    hf_new = Hashfiles(name="new.txt", customer_id=cust.id, owner_id=admin.id,
                       uploaded_at=datetime.utcnow())
    db.session.add_all([hf_old, hf_new])
    db.session.commit()

    h = Hashes(sub_ciphertext="cc" * 16, ciphertext="dd" * 16, hash_type=1000, cracked=False)
    db.session.add(h)
    db.session.commit()

    # Link the same hash to BOTH hashfiles
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf_old.id))
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf_new.id))
    db.session.commit()
    hash_id = h.id

    _run_inner(app)
    db.session.expire_all()

    # The aged hashfile is gone …
    assert Hashfiles.query.get(hf_old.id) is None
    # … but the hash itself survives because it is still referenced by hf_new.
    assert Hashes.query.get(hash_id) is not None


def test_inner_deletes_unshared_hash(app, tmp_path, monkeypatch):
    """A hash linked to only ONE (aged) hashfile must be deleted along with it."""
    _setup_tmp(tmp_path, monkeypatch)
    _settings(retention_period=30)
    admin = _admin("unshared@branch.test")
    cust = Customers(name="UnsharedCo")
    db.session.add(cust)
    db.session.commit()

    aged = datetime.utcnow() - timedelta(days=90)

    hf = Hashfiles(name="solo.txt", customer_id=cust.id, owner_id=admin.id,
                   uploaded_at=aged)
    db.session.add(hf)
    db.session.commit()

    h = Hashes(sub_ciphertext="ee" * 16, ciphertext="ff" * 16, hash_type=1000, cracked=False)
    db.session.add(h)
    db.session.commit()

    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    db.session.commit()
    hash_id, hf_id = h.id, hf.id

    _run_inner(app)
    db.session.expire_all()

    assert Hashfiles.query.get(hf_id) is None
    assert Hashes.query.get(hash_id) is None  # unshared -> purged


# ---------------------------------------------------------------------------
# HashNotifications cascade
# ---------------------------------------------------------------------------

def test_inner_purges_hash_notifications_with_unshared_hash(app, tmp_path, monkeypatch):
    """HashNotifications tied to a deleted hash are removed in the same pass."""
    _setup_tmp(tmp_path, monkeypatch)
    _settings(retention_period=30)
    admin = _admin("hashnotif@branch.test")
    cust = Customers(name="NotifCo")
    db.session.add(cust)
    db.session.commit()

    aged = datetime.utcnow() - timedelta(days=90)

    hf = Hashfiles(name="notif.txt", customer_id=cust.id, owner_id=admin.id,
                   uploaded_at=aged)
    db.session.add(hf)
    db.session.commit()

    h = Hashes(sub_ciphertext="11" * 16, ciphertext="22" * 16, hash_type=1000, cracked=False)
    db.session.add(h)
    db.session.commit()

    hfh = HashfileHashes(hash_id=h.id, hashfile_id=hf.id)
    db.session.add(hfh)
    db.session.commit()

    notif = HashNotifications(owner_id=admin.id, hash_id=h.id, method="email")
    db.session.add(notif)
    db.session.commit()
    notif_id, hash_id, hf_id = notif.id, h.id, hf.id

    _run_inner(app)
    db.session.expire_all()

    assert Hashfiles.query.get(hf_id) is None
    assert Hashes.query.get(hash_id) is None
    assert HashNotifications.query.get(notif_id) is None


# ---------------------------------------------------------------------------
# Cracked-hash sparing
# ---------------------------------------------------------------------------

def test_inner_spares_cracked_hash(app, tmp_path, monkeypatch):
    """A *cracked* hash must NOT be deleted even when its hashfile is aged out
    (the inner loop only deletes hashes where cracked=0)."""
    _setup_tmp(tmp_path, monkeypatch)
    _settings(retention_period=30)
    admin = _admin("cracked@branch.test")
    cust = Customers(name="CrackedCo")
    db.session.add(cust)
    db.session.commit()

    aged = datetime.utcnow() - timedelta(days=90)

    hf = Hashfiles(name="cracked.txt", customer_id=cust.id, owner_id=admin.id,
                   uploaded_at=aged)
    db.session.add(hf)
    db.session.commit()

    h = Hashes(sub_ciphertext="aa" * 16, ciphertext="bb" * 16, hash_type=1000,
               cracked=True)
    db.session.add(h)
    db.session.commit()

    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    db.session.commit()
    hash_id, hf_id = h.id, hf.id

    _run_inner(app)
    db.session.expire_all()

    assert Hashfiles.query.get(hf_id) is None  # hashfile deleted …
    assert Hashes.query.get(hash_id) is not None  # … but cracked hash kept


# ---------------------------------------------------------------------------
# Aged-job → JobTasks / JobNotifications cascade via the direct-job branch
# ---------------------------------------------------------------------------

def test_inner_cascade_job_tasks_and_notifications_direct_job_branch(app, tmp_path, monkeypatch):
    """The direct-job retention branch deletes JobTasks and JobNotifications."""
    _setup_tmp(tmp_path, monkeypatch)
    _settings(retention_period=30)
    admin = _admin("cascade@branch.test")
    cust = Customers(name="CascadeCo")
    db.session.add(cust)
    db.session.commit()

    aged = datetime.utcnow() - timedelta(days=90)
    job = Jobs(name="cascade-old-job", status="Completed", customer_id=cust.id,
               owner_id=admin.id, created_at=aged)
    db.session.add(job)
    db.session.commit()

    task = _make_task(admin.id, name="cascade-task")
    db.session.add(JobTasks(job_id=job.id, task_id=task.id, status="Not Started"))
    db.session.add(JobNotifications(owner_id=admin.id, job_id=job.id, method="email"))
    db.session.commit()
    job_id = job.id

    _run_inner(app)
    db.session.expire_all()

    assert Jobs.query.get(job_id) is None
    assert JobTasks.query.filter_by(job_id=job_id).count() == 0
    assert JobNotifications.query.filter_by(job_id=job_id).count() == 0


# ---------------------------------------------------------------------------
# Temp-file reaping — fresh .sql.gz.enc is kept (within 1-hour window)
# ---------------------------------------------------------------------------

def test_inner_keeps_recent_backup(app, tmp_path, monkeypatch):
    """A .sql.gz.enc created less than an hour ago must NOT be reaped."""
    tmp_dir = _setup_tmp(tmp_path, monkeypatch)
    _settings(retention_period=30)

    recent_backup = tmp_dir / "recent.sql.gz.enc"
    recent_backup.write_text("data")
    # 30 minutes old — inside the 1-hour backup window
    thirty_min_ago = time.time() - 1800
    os.utime(recent_backup, (thirty_min_ago, thirty_min_ago))

    _run_inner(app)

    assert recent_backup.exists(), "Recent .sql.gz.enc must not be reaped before 1 hour"


# ---------------------------------------------------------------------------
# Temp-file reaping — fresh regular file is kept
# ---------------------------------------------------------------------------

def test_inner_keeps_recent_tmp_file(app, tmp_path, monkeypatch):
    """A recently-uploaded temp file (within retention window) is left alone."""
    tmp_dir = _setup_tmp(tmp_path, monkeypatch)
    _settings(retention_period=30)

    fresh_file = tmp_dir / "recent-upload.bin"
    fresh_file.write_text("payload")
    # 1 day old — well within the 30-day retention window
    one_day_ago = time.time() - 86400
    os.utime(fresh_file, (one_day_ago, one_day_ago))

    _run_inner(app)

    assert fresh_file.exists(), "File within retention window must not be reaped"
