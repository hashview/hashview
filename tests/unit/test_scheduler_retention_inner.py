"""Direct tests for hashview.scheduler._data_retention_cleanup_inner.

The outer data_retention_cleanup wrapper swallows exceptions; these tests call
the inner function directly so failures surface, and pin the three behaviors:
aged rows are purged, the retention_period setting is honored, and a run with
nothing aged is a no-op (including the control/tmp file reaping rules).
"""

import os
import time
from datetime import datetime, timedelta

import pytest

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
from hashview.scheduler import _data_retention_cleanup_inner


def _admin():
    u = Users(first_name="Ad", last_name="Min", email_address="admin@example.com",
              password="x" * 60, admin=True)
    db.session.add(u)
    db.session.commit()
    return u


def _make_task(owner_id, name="task-retention"):
    task = Tasks(name=name, owner_id=owner_id, wl_id=None, rule_id=None,
                 hc_attackmode=0, loopback=False)
    db.session.add(task)
    db.session.commit()
    return task


def _settings(retention_period=30):
    s = Settings(retention_period=retention_period, max_runtime_jobs=0,
                 max_runtime_tasks=0)
    db.session.add(s)
    db.session.commit()
    return s


def _setup_tmp(app, tmp_path, monkeypatch):
    """The cleanup reaps <current_app.root_path>/control/tmp; point root_path at a
    temp dir with a control/tmp stand-in so the test never touches the real
    control/tmp."""
    monkeypatch.setattr(app, "root_path", str(tmp_path))
    tmp_dir = tmp_path / "control" / "tmp"
    os.makedirs(tmp_dir)
    return tmp_dir


def _run_inner(app):
    _data_retention_cleanup_inner(db, app.extensions["mail"], app.logger)


def test_inner_purges_aged_job_and_hashfile_rows(app, tmp_path, monkeypatch):
    _setup_tmp(app, tmp_path, monkeypatch)
    _settings(retention_period=30)
    admin = _admin()
    cust = Customers(name="Acme")
    db.session.add(cust)
    db.session.commit()

    aged = datetime.utcnow() - timedelta(days=90)

    # aged job with a job task + job notification
    job = Jobs(name="old-job", status="Completed", customer_id=cust.id,
               owner_id=admin.id, created_at=aged)
    db.session.add(job)
    db.session.commit()
    task = _make_task(admin.id, name="task-aged-job")
    db.session.add(JobTasks(job_id=job.id, task_id=task.id, status="Not Started"))
    db.session.add(JobNotifications(owner_id=admin.id, job_id=job.id, method="email"))

    # aged hashfile with an uncracked, unshared hash
    hashfile = Hashfiles(name="old.txt", customer_id=cust.id, owner_id=admin.id,
                         uploaded_at=aged)
    db.session.add(hashfile)
    db.session.commit()
    h = Hashes(sub_ciphertext="a" * 32, ciphertext="b" * 32, hash_type=1000,
               cracked=False)
    db.session.add(h)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hashfile.id))
    db.session.commit()
    job_id, hashfile_id, hash_id = job.id, hashfile.id, h.id

    _run_inner(app)
    db.session.expire_all()

    assert Jobs.query.get(job_id) is None
    assert JobTasks.query.filter_by(job_id=job_id).count() == 0
    assert JobNotifications.query.filter_by(job_id=job_id).count() == 0
    assert Hashfiles.query.get(hashfile_id) is None
    assert HashfileHashes.query.filter_by(hashfile_id=hashfile_id).count() == 0
    assert Hashes.query.get(hash_id) is None  # uncracked + unshared -> purged


def test_inner_respects_retention_period_setting(app, tmp_path, monkeypatch):
    _setup_tmp(app, tmp_path, monkeypatch)
    _settings(retention_period=100)  # window wider than the rows' age
    admin = _admin()
    cust = Customers(name="Acme")
    db.session.add(cust)
    db.session.commit()

    aged_90 = datetime.utcnow() - timedelta(days=90)
    job = Jobs(name="90day-job", status="Completed", customer_id=cust.id,
               owner_id=admin.id, created_at=aged_90)
    hashfile = Hashfiles(name="90day.txt", customer_id=cust.id,
                         owner_id=admin.id, uploaded_at=aged_90)
    db.session.add_all([job, hashfile])
    db.session.commit()
    job_id, hashfile_id = job.id, hashfile.id

    _run_inner(app)
    db.session.expire_all()

    # 90 days old but the retention window is 100 days -> kept
    assert Jobs.query.get(job_id) is not None
    assert Hashfiles.query.get(hashfile_id) is not None


def test_inner_noop_when_nothing_aged(app, tmp_path, monkeypatch):
    tmp_dir = _setup_tmp(app, tmp_path, monkeypatch)
    _settings(retention_period=30)
    admin = _admin()
    cust = Customers(name="Acme")
    db.session.add(cust)
    db.session.commit()

    job = Jobs(name="fresh-job", status="Completed", customer_id=cust.id,
               owner_id=admin.id, created_at=datetime.utcnow())
    hashfile = Hashfiles(name="fresh.txt", customer_id=cust.id,
                         owner_id=admin.id, uploaded_at=datetime.utcnow())
    db.session.add_all([job, hashfile])
    db.session.commit()
    job_id, hashfile_id = job.id, hashfile.id

    fresh_file = tmp_dir / "fresh-upload"
    fresh_file.write_text("data")

    _run_inner(app)
    db.session.expire_all()

    assert Jobs.query.get(job_id) is not None
    assert Hashfiles.query.get(hashfile_id) is not None
    assert fresh_file.exists()  # within retention window -> left alone


def test_inner_reaps_tmp_files_by_age_and_keeps_gitignore(app, tmp_path, monkeypatch):
    tmp_dir = _setup_tmp(app, tmp_path, monkeypatch)
    _settings(retention_period=30)

    old_file = tmp_dir / "stale-upload"
    old_file.write_text("old")
    stale = time.time() - 40 * 86400
    os.utime(old_file, (stale, stale))

    gitignore = tmp_dir / ".gitignore"
    gitignore.write_text("*")
    os.utime(gitignore, (stale, stale))

    # one-time DB backups are reaped after an hour regardless of the
    # (day-granular) retention period
    backup = tmp_dir / "backup.sql.gz.enc"
    backup.write_text("enc")
    two_hours_ago = time.time() - 7200
    os.utime(backup, (two_hours_ago, two_hours_ago))

    # a backup younger than an hour must NOT be reaped (pins the other side of
    # the backup_limit boundary so an inverted/off-by-one comparison is caught)
    fresh_backup = tmp_dir / "fresh-backup.sql.gz.enc"
    fresh_backup.write_text("enc")
    half_hour_ago = time.time() - 1800
    os.utime(fresh_backup, (half_hour_ago, half_hour_ago))

    _run_inner(app)

    assert not old_file.exists()       # past retention window -> removed
    assert gitignore.exists()          # always kept
    assert not backup.exists()         # backups reaped within the hour
    assert fresh_backup.exists()       # backup younger than an hour -> kept


def test_inner_reaps_tmp_regardless_of_cwd(app, tmp_path, monkeypatch):
    """Regression for #226: the sweep locates control/tmp via current_app.root_path,
    so it reaps aged files even when the process working directory is elsewhere.

    The old CWD-relative path ('hashview/control/tmp') resolved to nothing when
    CWD wasn't the repo root, so the sweep silently removed nothing. chdir to an
    unrelated directory here so this fails against that old behavior from any CWD.
    """
    tmp_dir = _setup_tmp(app, tmp_path, monkeypatch)
    elsewhere = tmp_path / "elsewhere"
    os.makedirs(elsewhere)
    monkeypatch.chdir(elsewhere)
    _settings(retention_period=30)

    stale_file = tmp_dir / "stale-upload"
    stale_file.write_text("old")
    stale = time.time() - 40 * 86400
    os.utime(stale_file, (stale, stale))

    _run_inner(app)

    assert not stale_file.exists()  # reaped despite CWD != repo root


def test_inner_purges_job_referencing_aged_hashfile(app, tmp_path, monkeypatch):
    # A *fresh* job that references an aged hashfile is deleted along with it.
    _setup_tmp(app, tmp_path, monkeypatch)
    _settings(retention_period=30)
    admin = _admin()
    cust = Customers(name="Acme")
    db.session.add(cust)
    db.session.commit()

    hashfile = Hashfiles(name="aged.txt", customer_id=cust.id, owner_id=admin.id,
                         uploaded_at=datetime.utcnow() - timedelta(days=90))
    db.session.add(hashfile)
    db.session.commit()
    job = Jobs(name="fresh-but-doomed", status="Completed", customer_id=cust.id,
               owner_id=admin.id, created_at=datetime.utcnow(),
               hashfile_id=hashfile.id)
    db.session.add(job)
    db.session.commit()
    task = _make_task(admin.id, name="task-doomed-job")
    db.session.add(JobTasks(job_id=job.id, task_id=task.id, status="Not Started"))
    db.session.add(JobNotifications(owner_id=admin.id, job_id=job.id, method="email"))
    db.session.commit()
    job_id, hashfile_id = job.id, hashfile.id

    _run_inner(app)
    db.session.expire_all()

    assert Hashfiles.query.get(hashfile_id) is None
    assert Jobs.query.get(job_id) is None  # cascaded via the hashfile branch
    assert JobTasks.query.filter_by(job_id=job_id).count() == 0
    assert JobNotifications.query.filter_by(job_id=job_id).count() == 0


@pytest.mark.xfail(strict=True, reason=(
    "BUG: server retention sweep only reaps control/tmp; control/hashes and "
    "control/outfiles accumulate uploaded hashes and cracked output indefinitely, "
    "even after the DB rows are purged. Remove this marker once scheduler.py reaps "
    "those dirs too."))
def test_inner_reaps_hashes_and_outfiles_dirs(app, tmp_path, monkeypatch):
    """Server retention must reap aged files in control/hashes and control/outfiles,
    not just control/tmp. Those dirs hold uploaded hashes (hashfile_*.txt) and cracked
    output (hc_cracked_*.txt, hc_potfile_*.pot); leaving them on disk after the DB rows
    are purged is a data-retention hole."""
    monkeypatch.setattr(app, "root_path", str(tmp_path))
    dirs = {}
    for name in ("tmp", "hashes", "outfiles"):
        d = tmp_path / "control" / name
        os.makedirs(d)
        dirs[name] = d
    _settings(retention_period=30)

    stale = time.time() - 40 * 86400
    aged, fresh = {}, {}
    for name, d in dirs.items():
        a = d / f"aged-{name}"
        a.write_text("secret")
        os.utime(a, (stale, stale))
        aged[name] = a
        f = d / f"fresh-{name}"  # within retention window -> must survive
        f.write_text("recent")
        fresh[name] = f

    _run_inner(app)

    for name in dirs:
        assert not aged[name].exists(), f"aged file in control/{name} should be reaped"
        assert fresh[name].exists(), f"fresh file in control/{name} should be kept"


@pytest.mark.xfail(strict=True, reason=(
    "BUG: the whole sweep is one try/except, so the first un-processable aged row "
    "(here an orphaned owner_id -> AttributeError building the email at "
    "scheduler.py:72) aborts retention of every later row. Remove this marker once "
    "the sweep is per-item resilient."))
def test_inner_continues_after_an_unprocessable_job(app, tmp_path, monkeypatch):
    """One un-processable aged job (e.g. an orphaned owner_id whose user was deleted)
    must not abort retention of every other aged job. Pins per-item resilience: the
    sweep no longer bails on the first failing row."""
    _setup_tmp(app, tmp_path, monkeypatch)
    _settings(retention_period=30)
    admin = _admin()
    cust = Customers(name="Acme")
    db.session.add(cust)
    db.session.commit()

    aged = datetime.utcnow() - timedelta(days=90)
    # owner_id references a user that doesn't exist; building the deletion email
    # dereferences None and raises, the way an orphaned job would in production.
    bad = Jobs(name="orphaned", status="Completed", customer_id=cust.id,
               owner_id=999999, created_at=aged)
    good = Jobs(name="deletable", status="Completed", customer_id=cust.id,
                owner_id=admin.id, created_at=aged)
    db.session.add_all([bad, good])
    db.session.commit()
    good_id = good.id

    _run_inner(app)
    db.session.expire_all()

    assert Jobs.query.get(good_id) is None  # not blocked by the bad job


def test_outer_wrapper_swallows_failures(app, tmp_path, monkeypatch):
    # No Settings row -> the inner function raises; the scheduled-job wrapper
    # must swallow it (log + continue) rather than crash the scheduler thread.
    from hashview.scheduler import data_retention_cleanup
    _setup_tmp(app, tmp_path, monkeypatch)
    data_retention_cleanup(app)  # must not raise


def test_inner_bulk_deletes_orphans_keeps_cracked_and_shared(app, tmp_path, monkeypatch):
    """The set-based hashfile deletion purges only uncracked hashes exclusive to
    the aged hashfile. Cracked recoveries (kept for reporting) and hashes shared
    with a surviving hashfile are preserved, their notifications too, and the
    owner is emailed exactly once -- after the delete has committed."""
    _setup_tmp(app, tmp_path, monkeypatch)
    _settings(retention_period=30)
    admin = _admin()
    cust = Customers(name="Acme")
    db.session.add(cust)
    db.session.commit()

    aged = datetime.utcnow() - timedelta(days=90)
    aged_hf = Hashfiles(name="aged.txt", customer_id=cust.id, owner_id=admin.id,
                        uploaded_at=aged)
    keep_hf = Hashfiles(name="keep.txt", customer_id=cust.id, owner_id=admin.id,
                        uploaded_at=datetime.utcnow())  # fresh -> survives
    db.session.add_all([aged_hf, keep_hf])
    db.session.commit()

    h_orphan = Hashes(sub_ciphertext="1" * 32, ciphertext="o", hash_type=1000,
                      cracked=False)   # uncracked, only in aged_hf -> purged
    h_cracked = Hashes(sub_ciphertext="2" * 32, ciphertext="c", hash_type=1000,
                       cracked=True)   # cracked -> kept
    h_shared = Hashes(sub_ciphertext="3" * 32, ciphertext="s", hash_type=1000,
                      cracked=False)   # uncracked but shared with keep_hf -> kept
    db.session.add_all([h_orphan, h_cracked, h_shared])
    db.session.commit()

    db.session.add_all([
        HashfileHashes(hash_id=h_orphan.id, hashfile_id=aged_hf.id),
        HashfileHashes(hash_id=h_cracked.id, hashfile_id=aged_hf.id),
        HashfileHashes(hash_id=h_shared.id, hashfile_id=aged_hf.id),
        HashfileHashes(hash_id=h_shared.id, hashfile_id=keep_hf.id),
        # notification on the orphan should go; on the shared hash should stay
        HashNotifications(owner_id=admin.id, hash_id=h_orphan.id, method="email"),
        HashNotifications(owner_id=admin.id, hash_id=h_shared.id, method="email"),
    ])
    db.session.commit()

    aged_hf_id, keep_hf_id = aged_hf.id, keep_hf.id
    o_id, c_id, s_id = h_orphan.id, h_cracked.id, h_shared.id

    # Capture emails by intercepting try_send_email (the unit-test env has no
    # MAIL_DEFAULT_SENDER, so real sends raise and never reach the outbox).
    # Record, per call, whether the hashfile still existed at send time so we can
    # prove the "removed" email fires AFTER the delete commits. An assert here
    # would be swallowed by the per-hashfile except, so snapshot and check below.
    sent = []

    def _record_email(user, subject, body, mailer=None):
        present = Hashfiles.query.filter_by(name="aged.txt").first() is not None
        sent.append((subject, present))
        return None

    monkeypatch.setattr("hashview.scheduler.try_send_email", _record_email)

    _run_inner(app)
    db.session.expire_all()

    # aged hashfile + all of its associations are gone
    assert Hashfiles.query.get(aged_hf_id) is None
    assert HashfileHashes.query.filter_by(hashfile_id=aged_hf_id).count() == 0
    # surviving hashfile + its (shared) association untouched
    assert Hashfiles.query.get(keep_hf_id) is not None
    assert HashfileHashes.query.filter_by(hashfile_id=keep_hf_id).count() == 1
    # uncracked orphan hash + its notification purged
    assert Hashes.query.get(o_id) is None
    assert HashNotifications.query.filter_by(hash_id=o_id).count() == 0
    # cracked recovery kept; shared hash + its notification kept
    assert Hashes.query.get(c_id) is not None
    assert Hashes.query.get(s_id) is not None
    assert HashNotifications.query.filter_by(hash_id=s_id).count() == 1
    # emailed exactly once for the removed hashfile, and only after it was gone
    removed = [(subj, present) for (subj, present) in sent
               if "removed an old Hashfile" in subj]
    assert len(removed) == 1
    assert "aged.txt" in removed[0][0]
    assert removed[0][1] is False  # hashfile already deleted when the email fired


def test_inner_isolates_per_hashfile_failure(app, tmp_path, monkeypatch):
    """A failure deleting one aged hashfile is rolled back, logged, and skipped;
    the next aged hashfile is still processed, and no "removed" email goes out
    for the failed one (so it can no longer re-spam the owner every hour)."""
    import logging

    import sqlalchemy.orm as sa_orm

    _setup_tmp(app, tmp_path, monkeypatch)
    _settings(retention_period=30)
    admin = _admin()
    cust = Customers(name="Acme")
    db.session.add(cust)
    db.session.commit()

    aged = datetime.utcnow() - timedelta(days=90)
    hf_bad = Hashfiles(name="bad.txt", customer_id=cust.id, owner_id=admin.id,
                       uploaded_at=aged)   # processed first -> made to fail
    hf_good = Hashfiles(name="good.txt", customer_id=cust.id, owner_id=admin.id,
                        uploaded_at=aged)  # processed after -> must still delete
    db.session.add_all([hf_bad, hf_good])
    db.session.commit()
    h_bad = Hashes(sub_ciphertext="4" * 32, ciphertext="x", hash_type=1000,
                   cracked=False)
    h_good = Hashes(sub_ciphertext="5" * 32, ciphertext="y", hash_type=1000,
                    cracked=False)
    db.session.add_all([h_bad, h_good])
    db.session.commit()
    db.session.add_all([
        HashfileHashes(hash_id=h_bad.id, hashfile_id=hf_bad.id),
        HashfileHashes(hash_id=h_good.id, hashfile_id=hf_good.id),
    ])
    db.session.commit()
    bad_id, good_id = hf_bad.id, hf_good.id

    # aliased() is called once per hashfile, before that hashfile's delete is
    # committed -> raising on the first call fails the first hashfile cleanly
    # (nothing deleted yet) and leaves the second to succeed.
    real_aliased = sa_orm.aliased
    state = {"n": 0}

    def flaky_aliased(*a, **k):
        state["n"] += 1
        if state["n"] == 1:
            raise RuntimeError("boom")
        return real_aliased(*a, **k)

    monkeypatch.setattr(sa_orm, "aliased", flaky_aliased)

    # record which hashfiles get a "removed" email (env-independent, see the
    # other test for why we don't go through Flask-Mail's outbox)
    sent = []

    def _record_email(user, subject, body, mailer=None):
        sent.append(subject)
        return None

    monkeypatch.setattr("hashview.scheduler.try_send_email", _record_email)

    # capture the log directly off app.logger (propagation-independent)
    records = []

    class _Cap(logging.Handler):
        def emit(self, rec):
            records.append(rec)

    handler = _Cap()
    app.logger.addHandler(handler)
    try:
        _run_inner(app)   # must NOT raise despite the first hashfile failing
    finally:
        app.logger.removeHandler(handler)
    db.session.expire_all()

    # first hashfile rolled back -> still present (and not emailed)
    assert Hashfiles.query.get(bad_id) is not None
    # second hashfile processed normally -> deleted
    assert Hashfiles.query.get(good_id) is None
    # only the successful deletion is emailed
    removed = [s for s in sent if "removed an old Hashfile" in s]
    assert len(removed) == 1 and "good.txt" in removed[0]
    assert not any("bad.txt" in s for s in removed)
    # the failure was logged (it is no longer silent)
    assert any("failed to delete hashfile" in r.getMessage() for r in records)
