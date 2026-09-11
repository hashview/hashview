"""Operator-facing surfacing of a catalog row whose file is gone (#383).

Covers the listings (badge, disabled download, info-modal size) and the task
pickers (excluded when adding, preserved and labelled when editing).
"""

import pytest

from hashview.models import Rules, Tasks, Wordlists, db
from tests.unit.helpers import (
    login,
    make_admin,
    make_rule_with_file,
    make_wordlist_with_file,
)


def _gone_rule(owner_id, tmp_path, name="gone-rule"):
    rule = Rules(name=name, owner_id=owner_id, path=str(tmp_path / "gone.rule"),
                 size=7, checksum="c" * 64)
    db.session.add(rule)
    db.session.commit()
    return rule


def _gone_wordlist(owner_id, tmp_path, name="gone-wordlist", wl_type="static"):
    wl = Wordlists(name=name, owner_id=owner_id, type=wl_type,
                   path=str(tmp_path / "gone.gz"), size=9, byte_size=11,
                   checksum="c" * 64)
    db.session.add(wl)
    db.session.commit()
    return wl


# ------------------------------------------------------------------- listings

def test_rules_list_badges_a_missing_rule_without_hiding_it(app, client, tmp_path):
    """Badged, not hidden: an operator has to be able to see and act on it."""
    admin = make_admin()
    login(client, admin)
    rule = _gone_rule(admin.id, tmp_path)

    html = client.get("/rules").get_data(as_text=True)
    assert rule.name in html
    assert "FILE MISSING" in html
    assert "1 missing on disk" in html


def test_rules_list_does_not_badge_a_present_rule(app, client):
    admin = make_admin()
    login(client, admin)
    make_rule_with_file(admin.id, name="healthy-rule")

    html = client.get("/rules").get_data(as_text=True)
    assert "healthy-rule" in html
    assert "FILE MISSING" not in html


def test_rules_list_disables_download_for_a_missing_rule(app, client, tmp_path):
    admin = make_admin()
    login(client, admin)
    gone = _gone_rule(admin.id, tmp_path)
    present = make_rule_with_file(admin.id, name="healthy-rule")

    html = client.get("/rules").get_data(as_text=True)
    assert f"/rules/download/{gone.id}" not in html
    assert f"/rules/download/{present.id}" in html
    assert "cursor:not-allowed" in html
    # View/Edit stays available: it is the in-place restore path.
    assert f"/rules/edit/{gone.id}" in html


def test_rules_info_modal_reports_size_on_disk(app, client, tmp_path):
    """The modal used to hard-code an em dash; it now tells the truth."""
    admin = make_admin()
    login(client, admin)
    make_rule_with_file(admin.id, name="healthy-rule", content=b"$1\n" * 100)
    _gone_rule(admin.id, tmp_path)

    html = client.get("/rules").get_data(as_text=True)
    assert "file missing" in html          # the gone row
    assert "MISSING" in html               # the File-on-disk kv badge
    assert "Bytes" in html                 # the healthy row's real on-disk size


def test_wordlists_list_badges_a_missing_static_wordlist(app, client, tmp_path):
    admin = make_admin()
    login(client, admin)
    wl = _gone_wordlist(admin.id, tmp_path)

    html = client.get("/wordlists").get_data(as_text=True)
    assert wl.name in html
    assert "FILE MISSING" in html
    assert f"/wordlists/download/{wl.id}" not in html


def test_wordlists_list_never_badges_a_dynamic_wordlist(app, client, tmp_path):
    """A dynamic list's file is regenerated per download, so its absence is not
    a fault -- badging it would false-alarm on every install."""
    admin = make_admin()
    login(client, admin)
    _gone_wordlist(admin.id, tmp_path, name="(DYNAMIC) All Customers",
                   wl_type="dynamic")

    html = client.get("/wordlists").get_data(as_text=True)
    assert "(DYNAMIC) All Customers" in html
    assert "FILE MISSING" not in html


def test_missing_row_info_modal_warns_when_tasks_reference_it(app, client, tmp_path):
    admin = make_admin()
    login(client, admin)
    rule = _gone_rule(admin.id, tmp_path)
    db.session.add(Tasks(name="blocked-task", hc_attackmode=0, owner_id=admin.id,
                         rule_id=rule.id))
    db.session.commit()

    html = client.get("/rules").get_data(as_text=True)
    assert "cannot run until it is restored" in html


# -------------------------------------------------------------------- pickers

def test_tasks_add_choices_exclude_a_missing_wordlist(app, client, tmp_path):
    admin = make_admin()
    login(client, admin)
    gone = _gone_wordlist(admin.id, tmp_path)
    present = make_wordlist_with_file(admin.id, name="healthy-wl")

    # Scope to the wordlist select: value="N" also appears in the attack-mode one.
    html = client.get("/tasks/add").get_data(as_text=True)
    wl_select = html.split('name="wl_id"')[1].split("</select>")[0]
    assert f'value="{present.id}"' in wl_select
    assert f'value="{gone.id}"' not in wl_select


def test_tasks_add_choices_exclude_a_missing_rule_but_keep_none(app, client, tmp_path):
    admin = make_admin()
    login(client, admin)
    gone = _gone_rule(admin.id, tmp_path)
    present = make_rule_with_file(admin.id, name="healthy-rule")

    html = client.get("/tasks/add").get_data(as_text=True)
    assert "healthy-rule" in html
    assert gone.name not in html
    assert 'value="None"' in html
    assert present.id


@pytest.mark.security
def test_tasks_add_rejects_a_missing_wordlist_posted_directly(app, client, tmp_path):
    """The route is the enforcement, not the template: a hand-crafted POST must
    not be able to build a task that can never run."""
    admin = make_admin()
    login(client, admin)
    gone = _gone_wordlist(admin.id, tmp_path)

    client.post("/tasks/add", data={"name": "sneaky", "hc_attackmode": "0",
                                    "wl_id": str(gone.id), "rule_id": "None"},
                follow_redirects=True)
    assert Tasks.query.filter_by(name="sneaky").first() is None


@pytest.mark.security
def test_tasks_add_rejects_a_missing_rule_posted_directly(app, client, tmp_path):
    admin = make_admin()
    login(client, admin)
    wl = make_wordlist_with_file(admin.id)
    gone = _gone_rule(admin.id, tmp_path)

    client.post("/tasks/add", data={"name": "sneaky-rule", "hc_attackmode": "0",
                                    "wl_id": str(wl.id), "rule_id": str(gone.id)},
                follow_redirects=True)
    assert Tasks.query.filter_by(name="sneaky-rule").first() is None


def test_task_edit_keeps_and_labels_a_missing_current_wordlist(app, client, tmp_path):
    """Excluding it here would leave the select on selectedIndex -1, and the
    task could never be saved again."""
    admin = make_admin()
    login(client, admin)
    gone = _gone_wordlist(admin.id, tmp_path)
    task = Tasks(name="stranded", hc_attackmode=0, owner_id=admin.id, wl_id=gone.id)
    db.session.add(task)
    db.session.commit()

    html = client.get(f"/tasks/edit/{task.id}").get_data(as_text=True)
    assert f'value="{gone.id}"' in html
    assert "FILE MISSING" in html


def test_task_edit_resave_preserves_a_missing_wl_id(app, client, tmp_path):
    admin = make_admin()
    login(client, admin)
    gone = _gone_wordlist(admin.id, tmp_path)
    # The hidden wl_id_2 select still submits whatever it happens to show, which
    # for a mode-0 task is the first offered (i.e. present) wordlist.
    other = make_wordlist_with_file(admin.id, name="healthy-wl")
    task = Tasks(name="stranded", hc_attackmode=0, owner_id=admin.id, wl_id=gone.id)
    db.session.add(task)
    db.session.commit()

    resp = client.post(f"/tasks/edit/{task.id}", data={
        "name": "stranded-renamed", "hc_attackmode": "0",
        "wl_id": str(gone.id), "wl_id_2": str(other.id), "rule_id": "None"})
    assert resp.status_code in (301, 302)
    edited = Tasks.query.get(task.id)
    assert edited.name == "stranded-renamed"
    assert edited.wl_id == gone.id


def test_task_edit_combinator_keeps_a_missing_wl_id_2(app, client, tmp_path):
    """wl_id_2 was never prepended at all, and the wl_id prepend was gated on
    attackmode 0 -- so a combinator task would have become un-saveable."""
    admin = make_admin()
    login(client, admin)
    present = make_wordlist_with_file(admin.id, name="healthy-wl")
    gone = _gone_wordlist(admin.id, tmp_path)
    task = Tasks(name="combi", hc_attackmode=1, owner_id=admin.id,
                 wl_id=present.id, wl_id_2=gone.id)
    db.session.add(task)
    db.session.commit()

    html = client.get(f"/tasks/edit/{task.id}").get_data(as_text=True)
    assert f'value="{gone.id}"' in html

    resp = client.post(f"/tasks/edit/{task.id}", data={
        "name": "combi", "hc_attackmode": "1",
        "wl_id": str(present.id), "wl_id_2": str(gone.id), "rule_id": "None"})
    assert resp.status_code in (301, 302)
    assert Tasks.query.get(task.id).wl_id_2 == gone.id


def test_edit_modal_offers_the_missing_option_but_the_add_modal_does_not(app, client, tmp_path):
    """One shared macro renders both; keep_missing is what separates them."""
    admin = make_admin()
    login(client, admin)
    _gone_wordlist(admin.id, tmp_path)
    make_wordlist_with_file(admin.id, name="healthy-wl")

    html = client.get("/tasks").get_data(as_text=True)
    etk = html.split('id="etk-wl"')[1].split("</select>")[0]
    atk = html.split('id="atk-wl"')[1].split("</select>")[0]
    assert 'data-missing="1"' in etk
    assert 'data-missing="1"' not in atk


def test_tasks_list_badges_a_task_whose_file_is_missing(app, client, tmp_path):
    """Answers "which of my tasks are broken?" without opening anything."""
    admin = make_admin()
    login(client, admin)
    gone = _gone_wordlist(admin.id, tmp_path)
    db.session.add(Tasks(name="broken-task", hc_attackmode=0, owner_id=admin.id,
                         wl_id=gone.id))
    db.session.commit()

    html = client.get("/tasks").get_data(as_text=True)
    assert "broken-task" in html
    assert "FILE MISSING" in html
    # the info modal must still name the wordlist rather than reading "none"
    assert gone.name in html


# ------------------------------------------------------------- POST /v1/tasks

def _api_admin():
    admin = make_admin(email="api-admin@example.com")
    admin.api_key = "api-key-catalog"
    db.session.commit()
    return admin


@pytest.mark.security
def test_api_add_task_rejects_a_missing_wordlist_file(app, client, tmp_path):
    """The API has no picker to grey out, so the refusal is the only warning.
    Body-only 400, matching every sibling refusal in this handler."""
    admin = _api_admin()
    gone = _gone_wordlist(admin.id, tmp_path)
    client.set_cookie("uuid", admin.api_key, domain="localhost.test")

    resp = client.post("/v1/tasks/add", json={"name": "api-task", "wl_id": gone.id,
                                              "hc_attackmode": 0})
    body = resp.get_json()
    assert body["status"] == 400
    assert "missing on disk" in body["msg"]
    assert Tasks.query.filter_by(name="api-task").first() is None


@pytest.mark.security
def test_api_add_task_rejects_a_missing_rule_file(app, client, tmp_path):
    admin = _api_admin()
    wl = make_wordlist_with_file(admin.id)
    gone = _gone_rule(admin.id, tmp_path)
    client.set_cookie("uuid", admin.api_key, domain="localhost.test")

    resp = client.post("/v1/tasks/add", json={"name": "api-task-rule", "wl_id": wl.id,
                                              "rule_id": gone.id, "hc_attackmode": 0})
    body = resp.get_json()
    assert body["status"] == 400
    assert "missing on disk" in body["msg"]
    assert Tasks.query.filter_by(name="api-task-rule").first() is None


def test_api_add_task_accepts_present_files(app, client):
    admin = _api_admin()
    wl = make_wordlist_with_file(admin.id)
    rule = make_rule_with_file(admin.id)
    client.set_cookie("uuid", admin.api_key, domain="localhost.test")

    resp = client.post("/v1/tasks/add", json={"name": "api-task-ok", "wl_id": wl.id,
                                              "rule_id": rule.id, "hc_attackmode": 0})
    assert resp.get_json()["status"] == 200
    assert Tasks.query.filter_by(name="api-task-ok").first() is not None
