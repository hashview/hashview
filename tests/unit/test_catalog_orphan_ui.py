"""The listings say a stranded, unused row is about to be removed (#494).

The sweep deletes these on its own. An operator who opens /rules or /wordlists
between the alert and the prune has to be able to see which rows are on their
way out — a row that vanishes overnight with no warning on the page that showed
it is indistinguishable from data loss.

The wording follows the switch: armed, it says the entry will be removed;
disarmed, the same row is merely flagged as safe to delete by hand.
"""

from hashview.models import Rules, Settings, Tasks, Wordlists, db
from tests.unit.helpers import login, make_admin, make_rule_with_file


def _settings(prune=True):
    settings = Settings.query.first()
    if settings is None:
        settings = Settings(retention_period=30, max_runtime_jobs=0, max_runtime_tasks=0)
        db.session.add(settings)
    settings.catalog_prune_orphans = prune
    db.session.commit()
    return settings


def _gone_rule(owner_id, tmp_path, name="orphan-rule"):
    rule = Rules(name=name, owner_id=owner_id, path=str(tmp_path / "gone.rule"),
                 size=7, checksum="c" * 64)
    db.session.add(rule)
    db.session.commit()
    return rule


def _gone_wordlist(owner_id, tmp_path, name="orphan-wordlist"):
    wl = Wordlists(name=name, owner_id=owner_id, type="static",
                   path=str(tmp_path / "gone.gz"), size=9, byte_size=11,
                   checksum="c" * 64)
    db.session.add(wl)
    db.session.commit()
    return wl


def _task(**kwargs):
    task = Tasks(name="t", hc_attackmode="dictionary", hc_mask="", owner_id=1, **kwargs)
    db.session.add(task)
    db.session.commit()
    return task


def test_rules_list_marks_an_unused_missing_rule(app, client, tmp_path):
    _settings()
    admin = make_admin()
    login(client, admin)
    _gone_rule(admin.id, tmp_path)

    html = client.get("/rules").get_data(as_text=True)
    assert "FILE MISSING" in html
    assert "UNUSED" in html


def test_a_referenced_missing_rule_is_not_marked_unused(app, client, tmp_path):
    """It is not going anywhere: the prune never touches a referenced row."""
    _settings()
    admin = make_admin()
    login(client, admin)
    rule = _gone_rule(admin.id, tmp_path)
    _task(rule_id=rule.id)

    html = client.get("/rules").get_data(as_text=True)
    assert "FILE MISSING" in html
    assert "UNUSED" not in html


def test_a_present_rule_is_never_marked_unused(app, client):
    """Plenty of healthy rules have no tasks yet; that is not a defect."""
    _settings()
    admin = make_admin()
    login(client, admin)
    make_rule_with_file(admin.id, name="healthy-rule")

    html = client.get("/rules").get_data(as_text=True)
    assert "UNUSED" not in html


def test_wordlists_list_marks_an_unused_missing_wordlist(app, client, tmp_path):
    _settings()
    admin = make_admin()
    login(client, admin)
    _gone_wordlist(admin.id, tmp_path)

    html = client.get("/wordlists").get_data(as_text=True)
    assert "UNUSED" in html


def test_the_page_says_it_will_be_removed_when_the_prune_is_armed(app, client, tmp_path):
    _settings(prune=True)
    admin = make_admin()
    login(client, admin)
    _gone_rule(admin.id, tmp_path)

    html = client.get("/rules").get_data(as_text=True)
    assert "removed automatically" in html


def test_the_page_does_not_promise_removal_when_disarmed(app, client, tmp_path):
    _settings(prune=False)
    admin = make_admin()
    login(client, admin)
    _gone_rule(admin.id, tmp_path)

    html = client.get("/rules").get_data(as_text=True)
    assert "UNUSED" in html                     # still worth pointing at
    assert "removed automatically" not in html  # nothing is going to remove it
