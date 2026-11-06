"""Unit tests for Settings -> Data management: manual catalog prune (#502).

Manual prune of stranded catalog entries (rules/wordlists whose file is gone
AND which no task references) via POST /settings/prune_catalog/<kind>.

Unlike the scheduled sweep, the manual path is NOT gated on:
- catalog_prune_armed: the toggle arms the *automatic* sweep; operators who
  switch it off still have a cleanup path.
- file_missing_notified: the latch exists so a *scheduler* never destroys rows
  before a human sees an alert; the by-hand path is under direct control.

Both omissions are deliberate and are tested (#502). The empty-control-directory
rail (when no row of the kind resolves on disk and there are candidates) is kept
to avoid destroying the entire catalog on mount/restore mishaps.

Uses the in-memory SQLite app from tests/unit/conftest.py. Flash messages are
read from the session. CSRF is validated via CatalogPruneForm.validate_on_submit().
"""

import re

import pytest
from sqlalchemy.exc import SQLAlchemyError

from hashview.models import Rules, Settings, Tasks, Wordlists, db
from hashview.utils import utils as utils_mod
from tests.unit.helpers import (
    login,
    make_admin,
    make_rule_with_file,
    make_user,
    make_wordlist_with_file,
)


def _gone_rule(owner_id, tmp_path, name="orphan.rule", notified=True):
    """A Rules row whose file is gone (missing on disk)."""
    rule = Rules(name=name, owner_id=owner_id, path=str(tmp_path / name),
                 size=1, checksum="c" * 64, file_missing_notified=notified)
    db.session.add(rule)
    db.session.commit()
    return rule


def _gone_wordlist(owner_id, tmp_path, name="orphan.gz", notified=True,
                   wl_type="static"):
    """A Wordlists row whose file is gone (missing on disk)."""
    wl = Wordlists(name=name, owner_id=owner_id, type=wl_type,
                   path=str(tmp_path / name), size=1, byte_size=1,
                   checksum="c" * 64, file_missing_notified=notified)
    db.session.add(wl)
    db.session.commit()
    return wl


def _trustworthy_disk(owner_id):
    """Place at least one healthy row of each kind on disk.

    The prune refuses when no row of a kind resolves on disk (that shape
    suggests a lost mount, not a lost file), so every test expecting a delete
    must put the catalog in the state where deleting is the right answer.
    """
    make_rule_with_file(owner_id, name="anchor-rule")
    make_wordlist_with_file(owner_id, name="anchor.gz")


def _task(**kwargs):
    """Make and return a Tasks row."""
    task = Tasks(name="t", hc_attackmode=0, hc_mask="", owner_id=1, **kwargs)
    db.session.add(task)
    db.session.commit()
    return task


def _settings(prune=True):
    """Get or create a Settings row with the given prune flag."""
    settings = Settings.query.first()
    if settings is None:
        settings = Settings(retention_period=30, max_runtime_jobs=0, max_runtime_tasks=0)
        db.session.add(settings)
    settings.catalog_prune_orphans = prune
    db.session.commit()
    return settings


# --------- 0. Helper rejects an unknown kind ---------------------------------
# Pure helper-level test: calls prune_orphaned_catalog() directly, no client,
# login, or route involved.

@pytest.mark.security
def test_prune_orphaned_catalog_rejects_unknown_kind(app):
    """prune_orphaned_catalog() raises ValueError for a kind other than
    'rules'/'wordlists' -- the docstring calls this the security boundary,
    since the route's own kind check must not be the only thing enforcing it.
    """
    with pytest.raises(ValueError):
        utils_mod.prune_orphaned_catalog('masks')


@pytest.mark.security
def test_failed_commit_leaves_no_audit_trail(app, monkeypatch, tmp_path):
    """A failed try_commit() must not leave rule.pruned audit lines for rows
    that are still in the DB (#502 re-review): log_event is captured-then-
    deferred until after the commit succeeds, so a rolled-back batch logs
    nothing.
    """
    admin = make_admin()
    _trustworthy_disk(admin.id)
    rule = _gone_rule(admin.id, tmp_path, name="orphan.rule")

    events = []
    monkeypatch.setattr(utils_mod, "log_event",
                       lambda event, **kw: events.append((event, kw)))
    # Force the real try_commit()'s failure path (rollback + False), rather
    # than faking try_commit itself, so the delete is genuinely undone --
    # a bare lambda-returns-False would leave the pending delete flushed
    # with nothing to roll it back.
    def _raise_commit(*a, **kw):
        raise SQLAlchemyError("simulated commit failure")
    monkeypatch.setattr(utils_mod.db.session, "commit", _raise_commit)

    removed_count, refusal_reason = utils_mod.prune_orphaned_catalog('rules')

    assert removed_count == 0
    assert refusal_reason is not None
    assert 'commit' in refusal_reason.lower()

    # No audit event was emitted for a delete that didn't actually happen.
    assert events == []

    # The row is still present -- the commit failure rolled the delete back.
    assert Rules.query.get(rule.id) is not None


# --------- 1. Stranded rule row is deleted; audit event logged; flash set ----------

@pytest.mark.security
def test_orphaned_rule_deleted(app, client, monkeypatch, tmp_path):
    """A stranded, unreferenced rule row is deleted with an audit event."""
    admin = make_admin()
    login(client, admin)
    _trustworthy_disk(admin.id)
    rule = _gone_rule(admin.id, tmp_path, name="orphan.rule")

    # Capture audit events.
    events = []
    monkeypatch.setattr(utils_mod, "log_event",
                       lambda event, **kw: events.append((event, kw)))

    resp = client.post("/settings/prune_catalog/rules")
    assert resp.status_code == 302

    # Rule is gone from the database.
    assert Rules.query.get(rule.id) is None

    # Audit event was logged.
    assert len(events) == 1
    event_name, event_kw = events[0]
    assert event_name == 'rule.pruned'
    assert f'rule:{rule.id}' in event_kw['target']
    assert 'orphan.rule' in event_kw['target']
    assert f'path={rule.path}' in event_kw.get('detail', '')
    assert 'manual=1' in event_kw.get('detail', '')

    # Success flash.
    with client.session_transaction() as sess:
        flashes = sess.get("_flashes", [])
    assert any(cat == "success" and msg == "Removed 1 stranded rule entry from the catalog."
               for cat, msg in flashes)


# --------- 2. Stranded wordlist row is deleted --------------------------------

@pytest.mark.security
def test_orphaned_wordlist_deleted(app, client, monkeypatch, tmp_path):
    """A stranded, unreferenced wordlist row is deleted with an audit event."""
    admin = make_admin()
    login(client, admin)
    _trustworthy_disk(admin.id)
    wl = _gone_wordlist(admin.id, tmp_path, name="orphan.gz")

    # Capture audit events.
    events = []
    monkeypatch.setattr(utils_mod, "log_event",
                       lambda event, **kw: events.append((event, kw)))

    resp = client.post("/settings/prune_catalog/wordlists")
    assert resp.status_code == 302

    # Wordlist is gone.
    assert Wordlists.query.get(wl.id) is None

    # Audit event logged.
    assert len(events) == 1
    event_name, event_kw = events[0]
    assert event_name == 'wordlist.pruned'
    assert f'wordlist:{wl.id}' in event_kw['target']
    assert 'orphan.gz' in event_kw['target']
    assert f'path={wl.path}' in event_kw.get('detail', '')
    assert 'manual=1' in event_kw.get('detail', '')

    # Success flash.
    with client.session_transaction() as sess:
        flashes = sess.get("_flashes", [])
    assert any(cat == "success" and msg == "Removed 1 stranded wordlist entry from the catalog."
               for cat, msg in flashes)


# --------- 3. Stranded row referenced by wl_id is NOT deleted ----------------

@pytest.mark.security
def test_stranded_wordlist_referenced_by_wl_id_not_deleted(app, client, tmp_path):
    """A stranded wordlist referenced via Tasks.wl_id is NOT deleted."""
    admin = make_admin()
    login(client, admin)
    _trustworthy_disk(admin.id)
    wl = _gone_wordlist(admin.id, tmp_path, name="orphan.gz")

    # Reference the wordlist via wl_id.
    _task(wl_id=wl.id)

    resp = client.post("/settings/prune_catalog/wordlists")
    assert resp.status_code == 302

    # Wordlist is still there.
    assert Wordlists.query.get(wl.id) is not None

    # Info flash is set (no candidates were deleted).
    with client.session_transaction() as sess:
        flashes = sess.get("_flashes", [])
    assert any(cat == "info" and msg == "No stranded wordlist entries to remove."
               for cat, msg in flashes)


# --------- 4. Stranded row referenced by wl_id_2 is NOT deleted ----------------

@pytest.mark.security
def test_stranded_wordlist_referenced_by_wl_id_2_not_deleted(app, client, tmp_path):
    """A stranded wordlist referenced only via Tasks.wl_id_2 is NOT deleted.

    This is the reference the wordlist delete guard was once buggy about (#494).
    """
    admin = make_admin()
    login(client, admin)
    _trustworthy_disk(admin.id)
    wl = _gone_wordlist(admin.id, tmp_path, name="orphan.gz")

    # Reference the wordlist via wl_id_2 only.
    _task(wl_id_2=wl.id)

    resp = client.post("/settings/prune_catalog/wordlists")
    assert resp.status_code == 302

    # Wordlist is still there.
    assert Wordlists.query.get(wl.id) is not None

    # Info flash is set (no candidates were deleted).
    with client.session_transaction() as sess:
        flashes = sess.get("_flashes", [])
    assert any(cat == "info" and msg == "No stranded wordlist entries to remove."
               for cat, msg in flashes)


# --------- 5. Row whose file exists on disk is NOT deleted --------------------

@pytest.mark.security
def test_healthy_rule_not_deleted(app, client, tmp_path):
    """A row whose file exists on disk is NOT deleted."""
    admin = make_admin()
    login(client, admin)
    _trustworthy_disk(admin.id)

    # Make a healthy rule (file exists on disk).
    healthy = make_rule_with_file(admin.id, name="healthy-rule")
    # Make a stranded rule (file is gone) that will be deleted.
    stranded = _gone_rule(admin.id, tmp_path, name="stranded.rule")

    resp = client.post("/settings/prune_catalog/rules")
    assert resp.status_code == 302

    # Healthy rule is still there.
    assert Rules.query.get(healthy.id) is not None
    # Stranded rule was deleted.
    assert Rules.query.get(stranded.id) is None


# --------- 6a. Prune runs even when catalog_prune_orphans is False -----------

@pytest.mark.security
def test_prune_ignores_catalog_prune_orphans_flag(app, client, tmp_path):
    """Manual prune runs and deletes even when catalog_prune_orphans is False.

    The flag arms the *automatic* sweep. The by-hand path is under direct
    operator control and should not be gated on it (#502).
    """
    admin = make_admin()
    login(client, admin)
    _settings(prune=False)  # Sweep is disabled.
    _trustworthy_disk(admin.id)
    rule = _gone_rule(admin.id, tmp_path, name="orphan.rule")

    resp = client.post("/settings/prune_catalog/rules")
    assert resp.status_code == 302

    # Rule was deleted despite catalog_prune_orphans being False.
    assert Rules.query.get(rule.id) is None


# --------- 6b. Prune runs even when file_missing_notified is False -----------

@pytest.mark.security
def test_prune_ignores_file_missing_notified_flag(app, client, tmp_path):
    """Manual prune deletes even when file_missing_notified is False on all rows.

    The latch exists so a *scheduler* never destroys rows before a human sees
    an alert. The by-hand path is under direct control and should not be gated
    on it (#502).
    """
    admin = make_admin()
    login(client, admin)
    _trustworthy_disk(admin.id)
    rule = _gone_rule(admin.id, tmp_path, name="orphan.rule", notified=False)

    resp = client.post("/settings/prune_catalog/rules")
    assert resp.status_code == 302

    # Rule was deleted despite file_missing_notified being False.
    assert Rules.query.get(rule.id) is None


# --------- 7. Empty-control-directory rail: refuse when no file resolves -----

@pytest.mark.security
def test_empty_control_directory_rail_rules(app, client, tmp_path):
    """When no rule file resolves on disk and there are candidates, refuse."""
    admin = make_admin()
    login(client, admin)
    # Deliberately do NOT place a healthy rule on disk.
    rule = _gone_rule(admin.id, tmp_path, name="orphan.rule")

    resp = client.post("/settings/prune_catalog/rules")
    assert resp.status_code == 302

    # Rule was NOT deleted.
    assert Rules.query.get(rule.id) is not None

    # Danger flash was set, naming the control dir and the Rules page.
    with client.session_transaction() as sess:
        flashes = sess.get("_flashes", [])
    assert any(cat == "danger" and "control/rules may be unmounted or empty" in msg
               and "Rules page" in msg
               for cat, msg in flashes)


@pytest.mark.security
def test_empty_control_directory_rail_wordlists(app, client, tmp_path):
    """When no wordlist file resolves on disk and there are candidates, refuse."""
    admin = make_admin()
    login(client, admin)
    # Deliberately do NOT place a healthy wordlist on disk.
    wl = _gone_wordlist(admin.id, tmp_path, name="orphan.gz")

    resp = client.post("/settings/prune_catalog/wordlists")
    assert resp.status_code == 302

    # Wordlist was NOT deleted.
    assert Wordlists.query.get(wl.id) is not None

    # Danger flash was set, naming the control dir and the Wordlists page.
    with client.session_transaction() as sess:
        flashes = sess.get("_flashes", [])
    assert any(cat == "danger" and "control/wordlists may be unmounted or empty" in msg
               and "Wordlists page" in msg
               for cat, msg in flashes)


# --------- 8. Non-admin gets 403 and nothing is deleted -----------------------

@pytest.mark.security
def test_non_admin_gets_403(app, client, tmp_path):
    """Non-admin POST is rejected with 403 and nothing is deleted."""
    admin = make_admin()
    user = make_user()
    login(client, user)
    _trustworthy_disk(admin.id)
    rule = _gone_rule(admin.id, tmp_path, name="orphan.rule")

    resp = client.post("/settings/prune_catalog/rules")
    assert resp.status_code == 403

    # Rule untouched.
    assert Rules.query.get(rule.id) is not None


# --------- 9. POST without CSRF token is rejected with 400 ---------------------

@pytest.mark.security
def test_post_without_csrf_token_rejected(app, client, tmp_path):
    """POST without a valid CSRF token is rejected (400) and nothing is deleted.

    CSRF is validated via CatalogPruneForm.validate_on_submit(). By default
    CSRF is disabled in conftest, so we enable it for this test.
    """
    admin = make_admin()
    login(client, admin)
    _trustworthy_disk(admin.id)
    rule = _gone_rule(admin.id, tmp_path, name="orphan.rule")

    # Enable CSRF for this test.
    app.config['WTF_CSRF_ENABLED'] = True

    try:
        # POST without a CSRF token (no form data means no token).
        resp = client.post("/settings/prune_catalog/rules")
        assert resp.status_code == 400

        # Rule untouched.
        assert Rules.query.get(rule.id) is not None
    finally:
        app.config['WTF_CSRF_ENABLED'] = False


# --------- 10. Unknown kind returns 404 ----------------------------------------

@pytest.mark.security
def test_unknown_kind_returns_404(app, client):
    """An unknown ``kind`` parameter returns 404."""
    admin = make_admin()
    login(client, admin)

    resp = client.post("/settings/prune_catalog/masks")
    assert resp.status_code == 404


# --------- 11. UI: settings page renders both buttons with correct counts ----

def test_settings_page_renders_prune_buttons_with_counts(app, client, tmp_path):
    """The settings page renders both prune buttons with the correct orphan counts tied to their rows."""
    admin = make_admin()
    login(client, admin)
    _settings()  # Use helper to create Settings row.

    # Populate: 2 stranded rules, 3 stranded wordlists, 1 healthy rule, 1 healthy wordlist.
    _trustworthy_disk(admin.id)
    _gone_rule(admin.id, tmp_path, name="orphan1.rule")
    _gone_rule(admin.id, tmp_path, name="orphan2.rule")
    _gone_wordlist(admin.id, tmp_path, name="orphan1.gz")
    _gone_wordlist(admin.id, tmp_path, name="orphan2.gz")
    _gone_wordlist(admin.id, tmp_path, name="orphan3.gz")

    html = client.get("/settings").get_data(as_text=True)

    # Extract wordlist section: from "Prune stranded wordlists" to next </form>.
    wl_match = re.search(r'Prune stranded wordlists.*?</form>', html, re.DOTALL)
    assert wl_match, "Wordlist prune section not found"
    wl_section = wl_match.group(0)
    # Verify count is in wordlist section and button is enabled.
    assert "currently 3" in wl_section
    assert "<button" in wl_section and "disabled" not in wl_section  # enabled

    # Extract rules section: from "Prune stranded rules" to next </form>.
    rules_match = re.search(r'Prune stranded rules.*?</form>', html, re.DOTALL)
    assert rules_match, "Rules prune section not found"
    rules_section = rules_match.group(0)
    # Verify count is in rules section and button is enabled.
    assert "currently 2" in rules_section
    assert "<button" in rules_section and "disabled" not in rules_section  # enabled


def test_settings_page_disables_prune_button_when_count_is_zero(app, client):
    """The prune button is disabled when there are no stranded entries, and enabled when nonzero."""
    admin = make_admin()
    login(client, admin)
    _settings()  # Use helper.

    html = client.get("/settings").get_data(as_text=True)

    # Extract wordlist section and assert it's disabled (count=0).
    wl_match = re.search(r'Prune stranded wordlists.*?</form>', html, re.DOTALL)
    assert wl_match
    wl_section = wl_match.group(0)
    assert "currently 0" in wl_section
    assert re.search(r'<button[^>]*disabled', wl_section), "Wordlist button should be disabled"

    # Extract rules section and assert it's disabled (count=0).
    rules_match = re.search(r'Prune stranded rules.*?</form>', html, re.DOTALL)
    assert rules_match
    rules_section = rules_match.group(0)
    assert "currently 0" in rules_section
    assert re.search(r'<button[^>]*disabled', rules_section), "Rules button should be disabled"


def test_settings_page_prune_form_carries_csrf_token(app, client):
    """The rendered prune forms include CSRF tokens, validated end-to-end."""
    admin = make_admin()
    login(client, admin)
    _settings()  # Use helper.

    # Enable CSRF for this test.
    app.config['WTF_CSRF_ENABLED'] = True

    try:
        html = client.get("/settings").get_data(as_text=True)

        # Extract wordlist form and assert csrf_token is inside it.
        wl_match = re.search(
            r'action="/settings/prune_catalog/wordlists"[^>]*>.*?</form>',
            html, re.DOTALL
        )
        assert wl_match, "Wordlist prune form not found"
        wl_form = wl_match.group(0)
        assert 'name="csrf_token"' in wl_form, "CSRF token not in wordlist form"

        # Extract rules form and assert csrf_token is inside it.
        rules_match = re.search(
            r'action="/settings/prune_catalog/rules"[^>]*>.*?</form>',
            html, re.DOTALL
        )
        assert rules_match, "Rules prune form not found"
        rules_form = rules_match.group(0)
        assert 'name="csrf_token"' in rules_form, "CSRF token not in rules form"

        # Round-trip test: extract tokens, POST back, confirm 302 (valid CSRF).
        # Extract csrf_token value from wordlist form.
        csrf_match = re.search(r'<input[^>]*name="csrf_token"[^>]*value="([^"]*)"', wl_form)
        assert csrf_match, "Could not extract CSRF token value"
        csrf_token = csrf_match.group(1)

        # POST with the extracted token; should redirect (302) if valid.
        resp = client.post(
            "/settings/prune_catalog/wordlists",
            data={'csrf_token': csrf_token}
        )
        assert resp.status_code == 302, "CSRF validation failed; token rejected"
    finally:
        app.config['WTF_CSRF_ENABLED'] = False
