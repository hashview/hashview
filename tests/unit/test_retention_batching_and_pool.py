"""Tests for the batched retention purge and the connection-pool diagnostics.

Both exist because of one production incident: the hourly retention job deleted a
whole hashfile in a single transaction, its locks blocked everything else, and
every blocked request parked a pooled connection until the 15-connection pool was
empty and requests started failing in before_request with

    QueuePool limit of size 5 overflow 10 reached, connection timed out

So the properties under test are about *lock duration* and *diagnosability*, not
about what gets deleted -- the deletion semantics are pinned by
tests/unit/test_scheduler_retention_inner.py and must not move.
"""

import contextlib
import logging
from datetime import datetime, timedelta

import pytest

from hashview.models import (
    Customers,
    Hashes,
    HashfileHashes,
    Hashfiles,
    HashNotifications,
    Settings,
    Users,
    db,
)
from hashview.scheduler import (
    _delete_exclusive_hashes,
    _delete_hashfile_links,
)


@contextlib.contextmanager
def _captured_error_log():
    """Capture hashview.error records WITHOUT writing to the real error.log.

    tests/unit/conftest.py's control_dirs fixture creates the real
    hashview/control/logs, and configure_audit_logging attaches rotating file
    handlers to it -- so a test that fires the 500 hook appends to the operator's
    live forensic log. Merely adding a capture handler leaves the file handlers in
    place; the logger's handlers are swapped out wholesale and restored instead.
    """
    from hashview.utils.audit import ERROR_LOGGER

    logger = logging.getLogger(ERROR_LOGGER)
    saved = logger.handlers[:]
    captured = {}

    class _Grab(logging.Handler):
        def emit(self, record):
            captured.update(getattr(record, "audit", {}))

    logger.handlers = [_Grab()]
    try:
        yield captured
    finally:
        logger.handlers = saved


def _admin():
    user = Users(first_name="Ad", last_name="Min", email_address="admin@example.com",
                 password="x" * 60, admin=True)
    db.session.add(user)
    db.session.commit()
    return user


def _hashfile(owner_id, customer_id, name="hf.txt", aged=True):
    when = datetime.utcnow() - timedelta(days=90 if aged else 0)
    hf = Hashfiles(name=name, customer_id=customer_id, owner_id=owner_id, uploaded_at=when)
    db.session.add(hf)
    db.session.commit()
    return hf


def _seed(hashfile_id, count, cracked=False, start=0):
    """`count` hashes, each linked once to `hashfile_id`. Returns their ids."""
    rows = [Hashes(sub_ciphertext=f"{i + start:032d}", ciphertext=f"ct{i + start}",
                   hash_type=1000, cracked=cracked) for i in range(count)]
    db.session.add_all(rows)
    db.session.commit()
    ids = [h.id for h in rows]
    db.session.add_all([HashfileHashes(hash_id=i, hashfile_id=hashfile_id) for i in ids])
    db.session.commit()
    return ids


@pytest.fixture()
def scene(app):
    _settings = Settings(retention_period=30, max_runtime_jobs=0, max_runtime_tasks=0)
    db.session.add(_settings)
    cust = Customers(name="Acme")
    db.session.add(cust)
    db.session.commit()
    admin = _admin()
    return admin, cust


#############################################
# Lock duration: one commit per batch, not per hashfile
#############################################

def test_links_are_deleted_in_committed_batches(scene, monkeypatch):
    """The whole point of the change: a hashfile's links leave in several short
    transactions instead of one long one."""
    from hashview import scheduler

    admin, cust = scene
    hf = _hashfile(admin.id, cust.id)
    _seed(hf.id, 25)
    monkeypatch.setattr(scheduler, "_RETENTION_DELETE_BATCH", 5)

    commits = []
    real_commit = db.session.commit
    monkeypatch.setattr(db.session, "commit", lambda: (commits.append(1), real_commit())[1])

    removed = _delete_hashfile_links(db, hf.id, __import__("logging").getLogger("t"))

    assert removed == 25
    assert HashfileHashes.query.filter_by(hashfile_id=hf.id).count() == 0
    # 25 rows / batch of 5 = 5 commits. The old code committed once for the lot,
    # so anything <= 1 means the batching is gone.
    assert len(commits) == 5


def test_link_batch_size_bounds_each_statement(scene, monkeypatch):
    """Each DELETE must carry at most one batch of ids -- that bound is what caps
    how long locks are held, so it is asserted on the emitted SQL."""
    from sqlalchemy import event

    from hashview import scheduler

    admin, cust = scene
    hf = _hashfile(admin.id, cust.id)
    _seed(hf.id, 12)
    monkeypatch.setattr(scheduler, "_RETENTION_DELETE_BATCH", 4)

    deletes = []

    def record(conn, cursor, statement, parameters, context, executemany):
        flat = " ".join(statement.split()).upper()
        if flat.startswith("DELETE FROM HASHFILE_HASHES"):
            deletes.append(flat.count("?") or flat.count("%S"))

    event.listen(db.engine, "before_cursor_execute", record)
    try:
        _delete_hashfile_links(db, hf.id, __import__("logging").getLogger("t"))
    finally:
        event.remove(db.engine, "before_cursor_execute", record)

    assert deletes, "no DELETE against hashfile_hashes was emitted"
    assert max(deletes) <= 4, deletes
    assert len(deletes) == 3          # 12 rows / 4


def test_link_deletion_stops_instead_of_spinning(scene, monkeypatch):
    """If the SELECT sees rows the DELETE cannot match, the loop must exit. A
    naive while-loop would spin forever holding a connection -- the exact failure
    mode this change exists to prevent."""
    from hashview import scheduler

    admin, cust = scene
    hf = _hashfile(admin.id, cust.id)
    _seed(hf.id, 10)
    monkeypatch.setattr(scheduler, "_RETENTION_DELETE_BATCH", 5)

    # Every DELETE is a no-op while the rows stay put. The budget turns an
    # unguarded loop into an immediate failure rather than a hang -- a spinning
    # test would just time out in CI with nothing to read.
    class _Noop:
        calls = 0

        def delete(self, **kwargs):
            type(self).calls += 1
            if type(self).calls > 20:
                raise AssertionError(
                    f"link deletion looped {type(self).calls} times without deleting "
                    "anything -- the no-op DELETE guard is gone")
            return 0

    class _Q:
        def filter(self, *a, **k):
            return _Noop()

    monkeypatch.setattr(HashfileHashes, "query", _Q())

    removed = _delete_hashfile_links(db, hf.id, __import__("logging").getLogger("t"))
    assert removed == 0
    assert _Noop.calls == 1, "should give up after the first fruitless batch"


#############################################
# Resumability: an interrupted purge keeps its committed progress
#############################################

def test_interrupted_purge_keeps_progress_and_finishes_next_run(scene, monkeypatch):
    """Committed batches must survive an interruption, and the hashfile row must
    still be there so the next hourly run can finish it. The old single
    transaction rolled the whole hour's work back and re-emailed the owner."""
    from hashview import scheduler

    admin, cust = scene
    hf = _hashfile(admin.id, cust.id)
    _seed(hf.id, 20)
    hf_id = hf.id
    monkeypatch.setattr(scheduler, "_RETENTION_DELETE_BATCH", 5)

    calls = {"n": 0}
    real_commit = db.session.commit

    def fail_on_third():
        calls["n"] += 1
        if calls["n"] == 3:
            raise RuntimeError("simulated interruption")
        return real_commit()

    monkeypatch.setattr(db.session, "commit", fail_on_third)
    with pytest.raises(RuntimeError):
        _delete_hashfile_links(db, hf_id, __import__("logging").getLogger("t"))
    monkeypatch.setattr(db.session, "commit", real_commit)
    db.session.rollback()

    remaining = HashfileHashes.query.filter_by(hashfile_id=hf_id).count()
    assert 0 < remaining < 20                  # progress kept, work outstanding
    assert Hashfiles.query.get(hf_id) is not None   # hashfile still there to retry

    # the next run finishes the job
    assert _delete_hashfile_links(db, hf_id, __import__("logging").getLogger("t")) == remaining
    assert HashfileHashes.query.filter_by(hashfile_id=hf_id).count() == 0


def test_candidate_scan_is_committed_before_the_batches_start(app, tmp_path, monkeypatch):
    """The SELECT that collects the candidate hash ids opens a transaction. It has
    to be committed before the delete batches run, or MySQL's REPEATABLE-READ
    snapshot is pinned for the whole purge and phase two re-checks pre-purge data
    -- happily deleting a hash that has since been re-shared or cracked.

    SQLite has no such snapshot, so removing the commit breaks nothing there. The
    invariant is therefore pinned on the order of statements the run emits.
    """
    import os

    from sqlalchemy import event

    from hashview.models import Settings as _S
    from hashview.scheduler import _data_retention_cleanup_inner

    monkeypatch.setattr(app, "root_path", str(tmp_path))
    os.makedirs(tmp_path / "control" / "tmp")
    db.session.add(_S(retention_period=30, max_runtime_jobs=0, max_runtime_tasks=0))
    cust = Customers(name="Acme")
    db.session.add(cust)
    db.session.commit()
    admin = _admin()
    hf = _hashfile(admin.id, cust.id, name="aged.txt")
    _seed(hf.id, 6)
    monkeypatch.setattr("hashview.scheduler.try_send_email",
                        lambda user, subject, body, mailer=None: None)

    timeline = []

    def on_statement(conn, cursor, statement, parameters, context, executemany):
        flat = " ".join(statement.split()).upper()
        if "HASHFILE_HASHES" in flat:
            timeline.append("SELECT_CANDIDATES" if "NOT (EXISTS" in flat
                             else flat.split()[0])

    def on_commit(session):
        timeline.append("COMMIT")

    event.listen(db.engine, "before_cursor_execute", on_statement)
    event.listen(db.session, "after_commit", on_commit)
    try:
        _data_retention_cleanup_inner(db, app.extensions["mail"], app.logger)
    finally:
        event.remove(db.engine, "before_cursor_execute", on_statement)
        event.remove(db.session, "after_commit", on_commit)

    assert "SELECT_CANDIDATES" in timeline, timeline
    scan = timeline.index("SELECT_CANDIDATES")
    deletes = [i for i, e in enumerate(timeline) if e == "DELETE"]
    assert deletes, timeline
    assert "COMMIT" in timeline[scan:deletes[0]], (
        f"no COMMIT between the candidate scan and the first batch delete: {timeline}")


#############################################
# Phase 2 re-checks the row, never trusts the stale id list
#############################################

def test_hash_relinked_between_phases_is_kept(scene):
    """The candidate ids are collected before the links are deleted. If an import
    links one of those hashes to another hashfile in between, deleting it blind
    would strand that hashfile's rows -- so the row is re-checked."""
    admin, cust = scene
    aged = _hashfile(admin.id, cust.id, name="aged.txt")
    other = _hashfile(admin.id, cust.id, name="other.txt", aged=False)
    ids = _seed(aged.id, 3)

    # aged's own links are gone (phase 1 already ran) ...
    HashfileHashes.query.filter_by(hashfile_id=aged.id).delete(synchronize_session=False)
    db.session.commit()
    # ... but one hash has since been linked elsewhere
    db.session.add(HashfileHashes(hash_id=ids[1], hashfile_id=other.id))
    db.session.commit()

    removed = _delete_exclusive_hashes(db, ids, __import__("logging").getLogger("t"))

    assert removed == 2
    assert Hashes.query.get(ids[1]) is not None        # re-shared -> kept
    assert Hashes.query.get(ids[0]) is None
    assert Hashes.query.get(ids[2]) is None


def test_hash_cracked_between_phases_is_kept(scene):
    """Same window, the other way: an agent recovers one of the candidates. A
    cracked hash is a reportable result and must never be purged."""
    admin, cust = scene
    aged = _hashfile(admin.id, cust.id)
    ids = _seed(aged.id, 3)
    HashfileHashes.query.filter_by(hashfile_id=aged.id).delete(synchronize_session=False)
    db.session.commit()

    Hashes.query.filter_by(id=ids[0]).update({"cracked": True, "plaintext": "pw"})
    db.session.commit()

    removed = _delete_exclusive_hashes(db, ids, __import__("logging").getLogger("t"))

    assert removed == 2
    assert Hashes.query.get(ids[0]) is not None
    assert Hashes.query.get(ids[0]).plaintext == "pw"


def test_notifications_only_go_with_hashes_that_are_actually_deleted(scene):
    """Notifications are removed for the hashes being deleted and no others --
    deleting them for the whole candidate chunk would strip notifications off
    hashes the re-check then keeps."""
    admin, cust = scene
    aged = _hashfile(admin.id, cust.id, name="aged.txt")
    other = _hashfile(admin.id, cust.id, name="other.txt", aged=False)
    ids = _seed(aged.id, 2)
    HashfileHashes.query.filter_by(hashfile_id=aged.id).delete(synchronize_session=False)
    db.session.commit()
    db.session.add_all([
        HashfileHashes(hash_id=ids[0], hashfile_id=other.id),      # ids[0] survives
        HashNotifications(owner_id=admin.id, hash_id=ids[0], method="email"),
        HashNotifications(owner_id=admin.id, hash_id=ids[1], method="email"),
    ])
    db.session.commit()

    _delete_exclusive_hashes(db, ids, __import__("logging").getLogger("t"))

    assert HashNotifications.query.filter_by(hash_id=ids[0]).count() == 1   # kept
    assert HashNotifications.query.filter_by(hash_id=ids[1]).count() == 0   # went


def test_hashes_are_deleted_in_committed_batches(scene, monkeypatch):
    from hashview import scheduler

    admin, cust = scene
    aged = _hashfile(admin.id, cust.id)
    ids = _seed(aged.id, 15)
    HashfileHashes.query.filter_by(hashfile_id=aged.id).delete(synchronize_session=False)
    db.session.commit()
    monkeypatch.setattr(scheduler, "_RETENTION_DELETE_BATCH", 5)

    commits = []
    real_commit = db.session.commit
    monkeypatch.setattr(db.session, "commit", lambda: (commits.append(1), real_commit())[1])

    assert _delete_exclusive_hashes(db, ids, __import__("logging").getLogger("t")) == 15
    assert len(commits) == 3
    assert Hashes.query.count() == 0


def test_empty_candidate_list_is_a_noop(scene):
    assert _delete_exclusive_hashes(db, [], __import__("logging").getLogger("t")) == 0


#############################################
# Pool diagnostics
#############################################

def test_pool_snapshot_reports_the_pool_and_never_raises(app):
    from hashview.utils.audit import pool_snapshot

    snapshot = pool_snapshot()
    assert snapshot is not None
    assert "impl" in snapshot
    # Only the counters the pool implementation actually exposes are included --
    # SQLite's SingletonThreadPool has none of the QueuePool ones.
    for key, value in snapshot.items():
        if key != "impl":
            assert isinstance(value, int | float), (key, value)


def test_pool_snapshot_returns_none_outside_an_app_context():
    """It is called from an exception handler, so it has to degrade rather than
    raise a second exception."""
    from hashview.utils.audit import pool_snapshot

    assert pool_snapshot() is None


def test_connection_errors_are_classified_for_pool_reporting():
    from sqlalchemy.exc import OperationalError
    from sqlalchemy.exc import TimeoutError as SATimeoutError

    from hashview.utils.audit import _is_connection_error

    assert _is_connection_error(SATimeoutError("pool exhausted", None, None)) is True
    assert _is_connection_error(OperationalError("gone away", None, None)) is True
    assert _is_connection_error(ValueError("not a db problem")) is False
    assert _is_connection_error(RuntimeError("nor this")) is False


def test_pool_counters_are_logged_with_a_checkout_timeout(app, monkeypatch):
    """The incident's own log line said the pool was full but not whether the
    connections were in use. A TimeoutError now carries the counters."""
    from sqlalchemy.exc import TimeoutError as SATimeoutError

    from hashview.utils.audit import _on_request_exception

    with _captured_error_log() as captured:
        with app.test_request_context("/dashboard/recovery"):
            _on_request_exception(app, SATimeoutError("QueuePool limit", None, None))

    assert captured.get("event") == "server.error"
    assert "QueuePool limit" in captured.get("detail", "")
    assert "pool" in captured, "a checkout timeout must record the pool counters"
    assert "impl" in captured["pool"]


def test_unrelated_errors_do_not_carry_pool_counters(app):
    """Only connection errors get the extra field, so ordinary 500s stay clean."""
    from hashview.utils.audit import _on_request_exception

    with _captured_error_log() as captured:
        with app.test_request_context("/dashboard"):
            _on_request_exception(app, ValueError("template blew up"))

    assert captured.get("event") == "server.error"
    assert "pool" not in captured


def test_data_retention_cleanup_logs_pool_state_on_success(app, caplog):
    """The outer job wrapper -- the one actually scheduled hourly -- must log the
    pool snapshot every time it finishes, not just when
    _data_retention_cleanup_inner is called directly (as the tests above do)."""
    import logging

    from hashview.scheduler import data_retention_cleanup

    with caplog.at_level(logging.INFO, logger=app.logger.name):
        data_retention_cleanup(app)

    assert any("DataRetentionCleanup pool state" in r.message for r in caplog.records), (
        [r.message for r in caplog.records])


def test_data_retention_cleanup_logs_pool_state_even_after_a_failure(app, monkeypatch, caplog):
    """The pool snapshot is the diagnostic for exactly the case where something
    went wrong, so it has to run from `finally`, not just the success branch."""
    import logging

    from hashview import scheduler

    def _boom(db, mailer, logger):
        raise RuntimeError("simulated retention failure")

    monkeypatch.setattr(scheduler, "_data_retention_cleanup_inner", _boom)

    with caplog.at_level(logging.INFO, logger=app.logger.name):
        scheduler.data_retention_cleanup(app)

    messages = [r.message for r in caplog.records]
    assert any("Result(Failure)" in m for m in messages), messages
    assert any("DataRetentionCleanup pool state" in m for m in messages), messages


#############################################
# Pool configuration
#############################################

def _fresh_config_module(tmp_path, monkeypatch, database_overrides=None):
    """Import ``hashview.config`` from scratch against a throwaway config.conf.

    hashview.config reads 'hashview/config.conf' (relative to cwd) at class-body
    execution time, and bare-indexes ``file_config['SERVER']['SERVER_NAME']`` --
    so importing the real module KeyErrors on a fresh checkout that has no
    config.conf on disk (it's gitignored; see
    test_form_memory_limit_413.py::test_max_form_memory_size_defaults_to_flask_default_when_absent
    and test_issue_xfail_misc.py::test_db_password_with_percent_is_parsed for the
    same constraint). Nothing else in the unit suite imports hashview.config --
    create_app() only does so when ``testing`` is falsy -- so this module has
    never been imported by the time these tests run, and there is no cached
    sys.modules entry to fall back on.

    This writes a complete, throwaway config.conf into an isolated cwd and
    imports the module fresh, so the test is self-contained instead of
    depending on (or corrupting) whatever config.conf happens to exist on the
    machine running it.
    """
    import configparser
    import sys

    config_dir = tmp_path / "hashview"
    config_dir.mkdir()
    parser = configparser.ConfigParser()
    parser.read_dict({
        "SERVER": {"SERVER_NAME": "example.com:5000"},
        "database": {
            "username": "hashview", "password": "hashview", "host": "localhost",
            **(database_overrides or {}),
        },
        "SMTP": {
            "server": "smtp.example.com", "port": "25", "use_tls": "False",
            "username": "", "password": "", "default_sender": "hashview@example.com",
        },
    })
    with open(config_dir / "config.conf", "w") as f:
        parser.write(f)

    monkeypatch.chdir(tmp_path)
    monkeypatch.delitem(sys.modules, "hashview.config", raising=False)
    import hashview.config as fresh_config
    monkeypatch.delitem(sys.modules, "hashview.config", raising=False)
    return fresh_config


def test_engine_options_pin_the_pool_deliberately(tmp_path, monkeypatch):
    """The defaults SQLAlchemy would otherwise pick (5 + 10) are what the incident
    ran out of, so the values are asserted rather than left implicit."""
    options = _fresh_config_module(tmp_path, monkeypatch).Config.SQLALCHEMY_ENGINE_OPTIONS
    assert options["pool_size"] >= 10
    assert options["max_overflow"] >= 20
    assert options["pool_pre_ping"] is True
    # pool_recycle must retire a connection before MySQL's wait_timeout (28800)
    # does, or the pool hands out sockets the server has already closed.
    assert 0 < options["pool_recycle"] < 28800
    # A blocked query holds its connection for up to innodb_lock_wait_timeout, so
    # pool_timeout is stated explicitly to make that relationship reviewable.
    assert options["pool_timeout"] > 0
    # Total connections must stay well under MySQL's default max_connections (151)
    # so other clients, and a second Hashview process, can still connect.
    assert options["pool_size"] + options["max_overflow"] <= 60


def test_engine_options_are_tunable_via_config_conf(tmp_path, monkeypatch):
    """An operator running many agents plus many operators can raise pool_size /
    max_overflow via config.conf -- see config.conf.example's [database]
    pool_size / max_overflow comment. Unset, they must still fall back to
    10 / 20 (pinned above), not KeyError on an older config.conf that predates
    the keys."""
    options = _fresh_config_module(
        tmp_path, monkeypatch,
        database_overrides={"pool_size": "15", "max_overflow": "40"},
    ).Config.SQLALCHEMY_ENGINE_OPTIONS
    assert options["pool_size"] == 15
    assert options["max_overflow"] == 40
