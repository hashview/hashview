"""Catalog-health scheduler: one-shot missing-file alert + restore alert (#383).

Uses the in-memory SQLite app from tests/unit/conftest.py. notify_admins is
monkeypatched on hashview.utils.utils -- it's imported INSIDE the inner job, so
the patch is picked up at call time. The unit app sets
HASHVIEW_DISABLE_SCHEDULER, so nothing fires on a timer; these call the inner
(and once the wrapper) directly.
"""
import logging
import os

import pytest

from hashview.models import Rules, Tasks, Wordlists, db
from hashview.scheduler import (
    _catalog_health_check_inner,
    catalog_health_check,
    register_default_jobs,
    scheduler,
)
from hashview.utils import audit as audit_mod
from hashview.utils import utils as utils_mod
from tests.unit.helpers import (
    make_admin,
    make_rule_with_file,
    make_wordlist_with_file,
)

_LOG = logging.getLogger("test-catalog-health")


def _capture(monkeypatch):
    """Collect (subject, body) for every admin notification the sweep sends."""
    calls = []
    monkeypatch.setattr(utils_mod, "notify_admins",
                        lambda subj, msg: calls.append((subj, msg)))
    return calls


def _gone_rule(owner_id, tmp_path, name="gone.rule", notified=False):
    rule = Rules(name=name, owner_id=owner_id, path=str(tmp_path / name),
                 size=1, checksum="c" * 64, file_missing_notified=notified)
    db.session.add(rule)
    db.session.commit()
    return rule


def _gone_wordlist(owner_id, tmp_path, name="gone.gz", notified=False,
                   wl_type="static"):
    wl = Wordlists(name=name, owner_id=owner_id, type=wl_type,
                   path=str(tmp_path / name), size=1, byte_size=1,
                   checksum="c" * 64, file_missing_notified=notified)
    db.session.add(wl)
    db.session.commit()
    return wl


# ------------------------------------------------------------- the latch

@pytest.mark.security
def test_missing_file_alert_fires_once(app, monkeypatch, tmp_path):
    admin = make_admin()
    wl = _gone_wordlist(admin.id, tmp_path)
    calls = _capture(monkeypatch)

    _catalog_health_check_inner(db, _LOG)
    assert len(calls) == 1
    assert calls[0][0] == "Hashview: 1 catalog file missing on disk"
    assert Wordlists.query.get(wl.id).file_missing_notified is True

    # while the file stays gone, a second sweep must NOT re-notify
    _catalog_health_check_inner(db, _LOG)
    assert len(calls) == 1


@pytest.mark.security
def test_restored_alert_on_file_return_and_latch_clears(app, monkeypatch):
    admin = make_admin()
    wl = make_wordlist_with_file(admin.id, name="back.gz")
    wl.file_missing_notified = True                 # pretend we alerted earlier
    db.session.commit()
    calls = _capture(monkeypatch)

    _catalog_health_check_inner(db, _LOG)
    assert len(calls) == 1
    assert calls[0][0] == "Hashview: 1 catalog file restored"
    assert Wordlists.query.get(wl.id).file_missing_notified is False

    _catalog_health_check_inner(db, _LOG)           # nothing left to say
    assert len(calls) == 1


@pytest.mark.security
def test_quiet_sweep_sends_nothing(app, monkeypatch):
    admin = make_admin()
    make_rule_with_file(admin.id)
    make_wordlist_with_file(admin.id)
    calls = _capture(monkeypatch)

    _catalog_health_check_inner(db, _LOG)
    assert calls == []


# --------------------------------------------------- dynamic lists never alarm

@pytest.mark.security
def test_dynamic_wordlist_never_alerts(app, monkeypatch, tmp_path):
    """Absent AND zero-byte: both are the expected state for a dynamic list."""
    admin = make_admin()
    absent = _gone_wordlist(admin.id, tmp_path, name="dyn-absent.txt",
                            wl_type="dynamic")
    empty = make_wordlist_with_file(admin.id, name="dyn-empty", content=b"",
                                    wl_type="dynamic")
    assert os.path.getsize(empty.path) == 0
    calls = _capture(monkeypatch)

    _catalog_health_check_inner(db, _LOG)
    assert calls == []
    assert Wordlists.query.get(absent.id).file_missing_notified is False
    assert Wordlists.query.get(empty.id).file_missing_notified is False


# ----------------------------------------------------------- the aggregation

@pytest.mark.security
def test_alert_is_aggregated_into_one_notification(app, monkeypatch, tmp_path):
    """notify_admins reaches a Pushover phone push; N rows must not mean N pushes."""
    admin = make_admin()
    r1 = _gone_rule(admin.id, tmp_path, name="one.rule")
    r2 = _gone_rule(admin.id, tmp_path, name="two.rule")
    wl = _gone_wordlist(admin.id, tmp_path, name="three.gz")
    calls = _capture(monkeypatch)

    _catalog_health_check_inner(db, _LOG)
    assert len(calls) == 1
    subject, body = calls[0]
    assert subject == "Hashview: 3 catalog files missing on disk"
    for row in (r1, r2, wl):
        assert row.name in body


@pytest.mark.security
def test_alert_names_referencing_tasks_including_wl_id_2(app, monkeypatch, tmp_path):
    """Which tasks reference the row is what decides re-upload vs delete -- and a
    combinator task's SECOND wordlist is a real reference."""
    admin = make_admin()
    rule = _gone_rule(admin.id, tmp_path)
    wl = _gone_wordlist(admin.id, tmp_path)
    t1 = Tasks(name="uses-rule", hc_attackmode=0, owner_id=admin.id, rule_id=rule.id)
    t2 = Tasks(name="combinator", hc_attackmode=1, owner_id=admin.id, wl_id_2=wl.id)
    db.session.add_all([t1, t2])
    db.session.commit()
    calls = _capture(monkeypatch)

    _catalog_health_check_inner(db, _LOG)
    body = calls[0][1]
    assert f"used by 1 task(s): {t1.id}" in body
    assert f"used by 1 task(s): {t2.id}" in body


@pytest.mark.security
def test_unreferenced_row_says_so(app, monkeypatch, tmp_path):
    admin = make_admin()
    _gone_rule(admin.id, tmp_path)
    calls = _capture(monkeypatch)

    _catalog_health_check_inner(db, _LOG)
    assert "not referenced by any task" in calls[0][1]


# ------------------------------------------------------------- the audit trail

@pytest.mark.security
def test_audit_events_written(app, monkeypatch, tmp_path):
    """Per row, not aggregated: the Logs viewer parses `target` into entity/id."""
    admin = make_admin()
    gone = _gone_rule(admin.id, tmp_path)
    back = make_wordlist_with_file(admin.id, name="back.gz")
    back.file_missing_notified = True
    db.session.commit()
    _capture(monkeypatch)
    events = []
    monkeypatch.setattr(audit_mod, "log_event",
                        lambda ev, **kw: events.append((ev, kw.get("target"))))

    _catalog_health_check_inner(db, _LOG)
    names = [e[0] for e in events]
    assert "rule.file_missing" in names
    assert "wordlist.file_restored" in names
    assert any(t.startswith(f"rule:{gone.id} ") for _, t in events)


# ------------------------------------------------------------ circuit breaker

@pytest.mark.security
def test_skips_when_control_dir_absent(app, monkeypatch, tmp_path):
    """An unmounted volume must not flag the whole catalog and latch every row."""
    admin = make_admin()
    rule = make_rule_with_file(admin.id)
    wl = make_wordlist_with_file(admin.id)
    calls = _capture(monkeypatch)
    monkeypatch.setattr(app, "root_path", str(tmp_path))   # no control/ under it

    _catalog_health_check_inner(db, _LOG)
    assert calls == []
    assert Rules.query.get(rule.id).file_missing_notified is False
    assert Wordlists.query.get(wl.id).file_missing_notified is False


# ------------------------------------------------------- wrapper + registration

@pytest.mark.security
def test_wrapper_runs_under_app_context(app, monkeypatch, tmp_path):
    """The job takes the real app object, not the current_app proxy -- it runs in
    a context-less background thread."""
    admin = make_admin()
    _gone_rule(admin.id, tmp_path)
    calls = _capture(monkeypatch)

    catalog_health_check(app)
    assert len(calls) == 1


@pytest.mark.security
def test_register_default_jobs_includes_catalog_health(app):
    """register_default_jobs opens with remove_all_jobs(), so it is the only
    legal place to register -- this is the guard against that drift."""
    scheduler.init_app(app)
    register_default_jobs(app)
    ids = {j.id for j in scheduler.get_jobs()}
    assert {"DATA_RETENTION", "AGENT_HEALTH", "CATALOG_HEALTH"} <= ids
