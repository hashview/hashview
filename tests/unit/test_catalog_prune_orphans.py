"""CATALOG_HEALTH orphan prune: delete stranded rows nothing references (#494).

A rule/wordlist row whose file is gone and that no task uses is debris -- it is
excluded from new tasks, the agent skips its download, and /v1/<kind>/<id>
404s. Restoring it needs a file that may no longer exist; deleting it by hand is
a per-row hunt nobody performs. The sweep removes it instead.

The two safety rails these lock down:

  * NEVER on the first sweep that notices. The prune only touches rows whose
    ``file_missing_notified`` was already True on entry -- i.e. the admins were
    told, by name, in an earlier sweep at least an hour ago. Without that a
    transient condition the circuit breaker misses (a permissions blip, a
    half-mounted volume) destroys rows before any human sees the alert.
  * NEVER a referenced row. A task reference means the operator has to choose
    between restore and delete; deleting the task's rule for them would destroy
    Hashes.task_id attribution.

Same fixtures and monkeypatch discipline as test_catalog_health_check.py:
notify_admins is patched on hashview.utils.utils because the sweep imports it at
call time.
"""
import logging

import pytest

from hashview.models import Rules, Settings, Tasks, Wordlists, db
from hashview.scheduler import _catalog_health_check_inner
from hashview.utils import audit as audit_mod
from hashview.utils import utils as utils_mod
from tests.unit.helpers import make_admin, make_rule_with_file, make_wordlist_with_file

_LOG = logging.getLogger("test-catalog-prune")


def _capture(monkeypatch):
    calls = []
    monkeypatch.setattr(utils_mod, "notify_admins",
                        lambda subj, msg: calls.append((subj, msg)))
    return calls


def _settings(prune=True):
    settings = Settings.query.first()
    if settings is None:
        settings = Settings(retention_period=30, max_runtime_jobs=0, max_runtime_tasks=0)
        db.session.add(settings)
    settings.catalog_prune_orphans = prune
    db.session.commit()
    return settings


def _gone_rule(owner_id, tmp_path, name="orphan.rule", notified=True):
    rule = Rules(name=name, owner_id=owner_id, path=str(tmp_path / name),
                 size=1, checksum="c" * 64, file_missing_notified=notified)
    db.session.add(rule)
    db.session.commit()
    return rule


def _gone_wordlist(owner_id, tmp_path, name="orphan.gz", notified=True,
                   wl_type="static"):
    wl = Wordlists(name=name, owner_id=owner_id, type=wl_type,
                   path=str(tmp_path / name), size=1, byte_size=1,
                   checksum="c" * 64, file_missing_notified=notified)
    db.session.add(wl)
    db.session.commit()
    return wl


def _trustworthy_disk(owner_id):
    """One healthy row of each kind.

    The prune refuses to touch a kind with nothing on disk at all (that shape is
    a lost mount, not a lost file), so every test that expects a deletion has to
    put the catalog in the state where deleting is the right answer.
    """
    make_rule_with_file(owner_id, name="anchor-rule")
    make_wordlist_with_file(owner_id, name="anchor.gz")


def _task(**kwargs):
    task = Tasks(name="t", hc_attackmode=0, hc_mask="", owner_id=1, **kwargs)
    db.session.add(task)
    db.session.commit()
    return task


# --------------------------------------------------------------- the happy path

@pytest.mark.security
def test_previously_reported_unreferenced_rows_are_deleted(app, monkeypatch, tmp_path):
    _settings()
    admin = make_admin()
    _trustworthy_disk(admin.id)
    rule = _gone_rule(admin.id, tmp_path)
    wl = _gone_wordlist(admin.id, tmp_path)
    calls = _capture(monkeypatch)

    _catalog_health_check_inner(db, _LOG)

    assert Rules.query.get(rule.id) is None
    assert Wordlists.query.get(wl.id) is None
    subjects = [s for s, _ in calls]
    assert any("removed" in s for s in subjects)
    body = next(b for s, b in calls if "removed" in s)
    assert "orphan.rule" in body and "orphan.gz" in body


@pytest.mark.security
def test_prune_is_its_own_notification(app, monkeypatch, tmp_path):
    """Not folded into the missing-file alert: the two call for different action
    (go fix something, vs. nothing to do), and a merged Pushover title reads
    badly. Mirrors how the restored alert is already split out."""
    _settings()
    admin = make_admin()
    _trustworthy_disk(admin.id)
    _gone_rule(admin.id, tmp_path, name="fresh.rule", notified=False)   # newly noticed
    _gone_rule(admin.id, tmp_path, name="old.rule")                     # already told
    calls = _capture(monkeypatch)

    _catalog_health_check_inner(db, _LOG)

    assert len(calls) == 2
    missing = next(b for s, b in calls if "missing" in s)
    removed = next(b for s, b in calls if "removed" in s)
    assert "fresh.rule" in missing and "old.rule" not in missing
    assert "old.rule" in removed and "fresh.rule" not in removed


# -------------------------------------------------------------- the safety rails

@pytest.mark.security
def test_never_prunes_on_the_sweep_that_first_notices(app, monkeypatch, tmp_path):
    """The alert comes first, always. A row the admins have not been told about
    survives this sweep and is only eligible on the next one."""
    _settings()
    admin = make_admin()
    _trustworthy_disk(admin.id)
    rule = _gone_rule(admin.id, tmp_path, notified=False)
    _capture(monkeypatch)

    _catalog_health_check_inner(db, _LOG)
    survivor = Rules.query.get(rule.id)
    assert survivor is not None
    assert survivor.file_missing_notified is True          # told now

    _catalog_health_check_inner(db, _LOG)                  # the next hour
    assert Rules.query.get(rule.id) is None


@pytest.mark.security
def test_a_referenced_row_is_never_pruned(app, monkeypatch, tmp_path):
    _settings()
    admin = make_admin()
    _trustworthy_disk(admin.id)
    rule = _gone_rule(admin.id, tmp_path)
    wl = _gone_wordlist(admin.id, tmp_path)
    _task(rule_id=rule.id)
    _task(wl_id=wl.id)
    calls = _capture(monkeypatch)

    _catalog_health_check_inner(db, _LOG)

    assert Rules.query.get(rule.id) is not None
    assert Wordlists.query.get(wl.id) is not None
    # And it stays quiet about them: these rows were latched in an earlier sweep,
    # so re-alerting every hour on a condition only a human can resolve would be
    # the pager storm the one-shot latch exists to prevent.
    assert calls == []


@pytest.mark.security
def test_wl_id_2_counts_as_a_reference(app, monkeypatch, tmp_path):
    """A combinator task's second wordlist is a real reference -- the same trap
    the delete guard had to be fixed for (663b6eb)."""
    _settings()
    admin = make_admin()
    _trustworthy_disk(admin.id)
    wl = _gone_wordlist(admin.id, tmp_path)
    _task(wl_id=999, wl_id_2=wl.id)
    _capture(monkeypatch)

    _catalog_health_check_inner(db, _LOG)
    assert Wordlists.query.get(wl.id) is not None


@pytest.mark.security
def test_a_present_file_is_never_pruned(app, monkeypatch, tmp_path):
    """A stale latch on a row whose file came back is a restore, not a prune."""
    _settings()
    admin = make_admin()
    rule = make_rule_with_file(admin.id)
    rule.file_missing_notified = True
    wl = make_wordlist_with_file(admin.id, name="present.gz")
    wl.file_missing_notified = True
    db.session.commit()
    _capture(monkeypatch)

    _catalog_health_check_inner(db, _LOG)

    assert Rules.query.get(rule.id) is not None
    assert Wordlists.query.get(wl.id).file_missing_notified is False


@pytest.mark.security
def test_dynamic_wordlists_are_never_pruned(app, monkeypatch, tmp_path):
    """Its file is a regenerable cache, so 'missing' says nothing about health."""
    _settings()
    admin = make_admin()
    _trustworthy_disk(admin.id)
    wl = _gone_wordlist(admin.id, tmp_path, wl_type="dynamic")
    _capture(monkeypatch)

    _catalog_health_check_inner(db, _LOG)
    assert Wordlists.query.get(wl.id) is not None


@pytest.mark.security
def test_the_switch_disarms_it(app, monkeypatch, tmp_path):
    _settings(prune=False)
    admin = make_admin()
    _trustworthy_disk(admin.id)
    rule = _gone_rule(admin.id, tmp_path)
    calls = _capture(monkeypatch)

    _catalog_health_check_inner(db, _LOG)

    assert Rules.query.get(rule.id) is not None
    assert calls == []                       # already latched: nothing new to say


@pytest.mark.security
def test_no_settings_row_does_not_crash_the_sweep(app, monkeypatch, tmp_path):
    """setup.py seeds Settings, but the sweep must not be the thing that explodes
    on a half-initialised install."""
    for row in Settings.query.all():
        db.session.delete(row)
    db.session.commit()
    admin = make_admin()
    _trustworthy_disk(admin.id)
    rule = _gone_rule(admin.id, tmp_path)
    _capture(monkeypatch)

    _catalog_health_check_inner(db, _LOG)
    assert Rules.query.get(rule.id) is not None      # no row == not armed


@pytest.mark.security
def test_a_wholesale_empty_control_dir_is_not_a_catalog_of_orphans(app, monkeypatch, tmp_path):
    """The case the isdir breaker does NOT catch: the directory is there and
    empty. A fresh named volume, a bind-mount typo, a restore that brought the
    database back but not the files — all leave every row stranded at once.

    Before the prune that was fully recoverable: alert, latch, un-latch on
    remount. With a prune it would be one hour from "wrong volume attached" to
    "the catalog is gone", and remounting the right volume brings back files
    whose rows no longer exist. So: if not a single row of a kind resolves on
    disk, distrust the disk rather than the catalog.
    """
    _settings()
    admin = make_admin()
    doomed = [_gone_rule(admin.id, tmp_path, name=f"r{i}.rule") for i in range(3)]
    calls = _capture(monkeypatch)

    _catalog_health_check_inner(db, _LOG)

    for rule in doomed:
        assert Rules.query.get(rule.id) is not None
    assert calls == []


@pytest.mark.security
def test_one_healthy_row_is_enough_to_trust_the_disk(app, monkeypatch, tmp_path):
    """The flip side: a genuinely deleted file sits beside files that are fine,
    which is what a per-file deletion looks like."""
    _settings()
    admin = make_admin()
    make_rule_with_file(admin.id, name="healthy")
    rule = _gone_rule(admin.id, tmp_path)
    _capture(monkeypatch)

    _catalog_health_check_inner(db, _LOG)
    assert Rules.query.get(rule.id) is None


@pytest.mark.security
def test_the_two_kinds_are_judged_separately(app, monkeypatch, tmp_path):
    """control/rules and control/wordlists are separate mounts on plenty of
    installs, so an empty one must not veto the prune on the healthy other."""
    _settings()
    admin = make_admin()
    make_wordlist_with_file(admin.id, name="healthy.gz")
    wl = _gone_wordlist(admin.id, tmp_path)
    rule = _gone_rule(admin.id, tmp_path)          # no rule resolves at all
    _capture(monkeypatch)

    _catalog_health_check_inner(db, _LOG)
    assert Wordlists.query.get(wl.id) is None      # wordlists are trustworthy
    assert Rules.query.get(rule.id) is not None    # rules are not


@pytest.mark.security
def test_a_dynamic_wordlist_does_not_vouch_for_the_disk(app, monkeypatch, tmp_path):
    """Its file is never read, so its 'presence' says nothing about the mount."""
    _settings()
    admin = make_admin()
    _gone_wordlist(admin.id, tmp_path, name="dyn.gz", wl_type="dynamic")
    wl = _gone_wordlist(admin.id, tmp_path)
    _capture(monkeypatch)

    _catalog_health_check_inner(db, _LOG)
    assert Wordlists.query.get(wl.id) is not None


@pytest.mark.security
def test_circuit_breaker_still_wins(app, monkeypatch, tmp_path):
    """An unmounted control volume makes every row look stranded. Deleting the
    whole catalog is precisely the disaster the breaker exists to prevent."""
    _settings()
    admin = make_admin()
    rule = make_rule_with_file(admin.id)
    rule.file_missing_notified = True
    db.session.commit()
    calls = _capture(monkeypatch)
    monkeypatch.setattr(app, "root_path", str(tmp_path))    # no control/ under it

    _catalog_health_check_inner(db, _LOG)

    assert Rules.query.get(rule.id) is not None
    assert calls == []


# -------------------------------------------------------------- the audit trail

@pytest.mark.security
def test_audit_event_per_pruned_row(app, monkeypatch, tmp_path):
    """The row is about to stop existing; the log line is the only record left,
    so it carries the task count that justified the deletion."""
    _settings()
    admin = make_admin()
    _trustworthy_disk(admin.id)
    rule = _gone_rule(admin.id, tmp_path)
    _capture(monkeypatch)
    events = []
    monkeypatch.setattr(audit_mod, "log_event",
                        lambda ev, **kw: events.append((ev, kw.get("target"), kw.get("detail"))))

    _catalog_health_check_inner(db, _LOG)

    pruned = [e for e in events if e[0] == "rule.pruned"]
    assert len(pruned) == 1
    assert pruned[0][1].startswith(f"rule:{rule.id} ")
    assert "orphan.rule" in pruned[0][2]


@pytest.mark.security
def test_a_failing_transport_does_not_leave_the_rows_half_deleted(app, monkeypatch, tmp_path):
    """notify_admins fans out to email/Pushover/Slack and only email swallows its
    own errors. A raise must not skip the delete the alert describes -- the row
    is gone either way, and an un-notified prune is recoverable from the audit
    log, while a notified-but-not-deleted one repeats forever."""
    _settings()
    admin = make_admin()
    _trustworthy_disk(admin.id)
    rule = _gone_rule(admin.id, tmp_path)

    def boom(subj, msg):
        raise RuntimeError("pushover timeout")

    monkeypatch.setattr(utils_mod, "notify_admins", boom)

    _catalog_health_check_inner(db, _LOG)
    assert Rules.query.get(rule.id) is None
