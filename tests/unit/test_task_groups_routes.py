"""Regression tests for task_groups routes + form (function-coverage batch)."""

import json

import pytest
from wtforms.validators import ValidationError

from hashview.models import TaskGroups, Tasks, db
from hashview.task_groups.forms import TaskGroupsForm
from tests.unit.helpers import login, make_admin, make_user


def _task(owner, name="t"):
    t = Tasks(name=name, hc_attackmode=0, owner_id=owner.id)
    db.session.add(t)
    db.session.commit()
    return t


def _group(owner, task_ids, name="grp"):
    tg = TaskGroups(name=name, owner_id=owner.id, tasks=str(list(task_ids)))
    db.session.add(tg)
    db.session.commit()
    return tg


def test_task_groups_list_renders(app, client):
    admin = make_admin()
    login(client, admin)
    t = _task(admin, "memberA")
    _group(admin, [t.id], name="GroupShown")
    resp = client.get("/task_groups")
    assert resp.status_code == 200
    assert b"GroupShown" in resp.data


def test_task_groups_add_with_task_ids_creates_group(app, client):
    admin = make_admin()
    login(client, admin)
    t1, t2 = _task(admin, "a"), _task(admin, "b")
    resp = client.post("/task_groups/add", data={
        "name": "NewGroup", "task_ids": f"{t1.id},{t2.id}", "submit": "Create",
    }, follow_redirects=False)
    assert resp.status_code in (301, 302)
    tg = TaskGroups.query.filter_by(name="NewGroup").first()
    assert tg is not None
    assert json.loads(tg.tasks) == [t1.id, t2.id]


def test_assigned_tasks_renders(app, client):
    admin = make_admin()
    login(client, admin)
    t = _task(admin, "m")
    tg = _group(admin, [t.id])
    resp = client.get(f"/task_groups/assigned_tasks/{tg.id}")
    assert resp.status_code == 200


def test_assigned_tasks_add_task_appends(app, client):
    admin = make_admin()
    login(client, admin)
    t1, t2 = _task(admin, "a"), _task(admin, "b")
    tg = _group(admin, [t1.id])
    resp = client.get(f"/task_groups/assigned_tasks/{tg.id}/add_task/{t2.id}",
                      follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert json.loads(TaskGroups.query.get(tg.id).tasks) == [t1.id, t2.id]


def test_assigned_tasks_promote_task_moves_up(app, client):
    admin = make_admin()
    login(client, admin)
    t1, t2 = _task(admin, "a"), _task(admin, "b")
    tg = _group(admin, [t1.id, t2.id])
    resp = client.get(f"/task_groups/assigned_tasks/{tg.id}/promote_task/{t2.id}",
                      follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert json.loads(TaskGroups.query.get(tg.id).tasks) == [t2.id, t1.id]


def test_assigned_tasks_promote_top_is_noop(app, client):
    admin = make_admin()
    login(client, admin)
    t1, t2 = _task(admin, "a"), _task(admin, "b")
    tg = _group(admin, [t1.id, t2.id])
    client.get(f"/task_groups/assigned_tasks/{tg.id}/promote_task/{t1.id}",
               follow_redirects=False)
    assert json.loads(TaskGroups.query.get(tg.id).tasks) == [t1.id, t2.id]


def test_assigned_tasks_demote_task_moves_down(app, client):
    admin = make_admin()
    login(client, admin)
    t1, t2 = _task(admin, "a"), _task(admin, "b")
    tg = _group(admin, [t1.id, t2.id])
    resp = client.get(f"/task_groups/assigned_tasks/{tg.id}/demote_task/{t1.id}",
                      follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert json.loads(TaskGroups.query.get(tg.id).tasks) == [t2.id, t1.id]


def test_validate_name_rejects_duplicate_group(app):
    admin = make_admin()
    _group(admin, [], name="TakenName")   # a task GROUP, not a task
    form = TaskGroupsForm()

    class _Field:
        data = "TakenName"

    with pytest.raises(ValidationError):
        form.validate_name(_Field())


# --- edit route ------------------------------------------------------------


def test_task_groups_edit_renames_and_reorders(app, client):
    admin = make_admin()
    login(client, admin)
    t1, t2 = _task(admin, "a"), _task(admin, "b")
    tg = _group(admin, [t1.id, t2.id], name="OldName")
    resp = client.post("/task_groups/edit", data={
        "group_id": tg.id, "name": "NewName",
        "task_ids": f"{t2.id},{t1.id}", "submit": "Create",
    }, follow_redirects=False)
    assert resp.status_code in (301, 302)
    updated = TaskGroups.query.get(tg.id)
    assert updated.name == "NewName"
    assert json.loads(updated.tasks) == [t2.id, t1.id]


def test_task_groups_edit_drops_invalid_and_duplicate_ids(app, client):
    admin = make_admin()
    login(client, admin)
    t1 = _task(admin, "a")
    tg = _group(admin, [t1.id])
    resp = client.post("/task_groups/edit", data={
        "group_id": tg.id, "name": "G",
        "task_ids": f"{t1.id},abc,{t1.id},999999", "submit": "Create",
    }, follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert json.loads(TaskGroups.query.get(tg.id).tasks) == [t1.id]


def test_task_groups_edit_missing_group_flashes_warning(app, client):
    admin = make_admin()
    login(client, admin)
    before = TaskGroups.query.count()
    resp = client.post("/task_groups/edit", data={
        "group_id": 999999, "name": "G", "task_ids": "", "submit": "Create",
    }, follow_redirects=True)
    assert b"Task Group not found" in resp.data
    assert TaskGroups.query.count() == before


def test_task_groups_edit_non_owner_non_admin_403(app, client):
    admin = make_admin()
    other = make_user(email="other@example.com")
    t1 = _task(admin, "a")
    tg = _group(admin, [t1.id], name="AdminGroup")
    login(client, other)
    resp = client.post("/task_groups/edit", data={
        "group_id": tg.id, "name": "Hijacked",
        "task_ids": f"{t1.id}", "submit": "Create",
    }, follow_redirects=False)
    assert resp.status_code == 403
    assert TaskGroups.query.get(tg.id).name == "AdminGroup"


def test_task_groups_edit_invalid_shows_error_in_modal(app, client):
    admin = make_admin()
    login(client, admin)
    t1 = _task(admin, "a")
    tg = _group(admin, [t1.id], name="Keep")
    resp = client.post("/task_groups/edit", data={
        "group_id": tg.id, "name": "",
        "task_ids": f"{t1.id}", "submit": "Create",
    }, follow_redirects=True)
    # Error is surfaced inside the reopened Edit-group modal, not flashed; the
    # group keeps its old name.
    assert b"This field is required" in resp.data
    assert TaskGroups.query.get(tg.id).name == "Keep"


# --- remove_task route -----------------------------------------------------


def test_task_groups_remove_task_not_in_group_flashes_warning(app, client):
    admin = make_admin()
    login(client, admin)
    t1, t2 = _task(admin, "a"), _task(admin, "b")
    tg = _group(admin, [t1.id])
    resp = client.get(
        f"/task_groups/assigned_tasks/{tg.id}/remove_task/{t2.id}",
        follow_redirects=True)
    assert b"no longer in this group" in resp.data
    assert json.loads(TaskGroups.query.get(tg.id).tasks) == [t1.id]


def test_task_groups_remove_task_missing_group_flashes_warning(app, client):
    admin = make_admin()
    login(client, admin)
    resp = client.get(
        "/task_groups/assigned_tasks/999999/remove_task/1",
        follow_redirects=True)
    assert b"Task Group not found" in resp.data


# --- delete route ----------------------------------------------------------


def test_task_groups_delete_happy_path(app, client):
    admin = make_admin()
    login(client, admin)
    t1 = _task(admin, "a")
    tg = _group(admin, [t1.id])
    tg_id = tg.id
    resp = client.post(f"/task_groups/delete/{tg_id}", follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert TaskGroups.query.get(tg_id) is None


def test_task_groups_delete_missing_group_flashes_warning(app, client):
    admin = make_admin()
    login(client, admin)
    resp = client.post("/task_groups/delete/999999", follow_redirects=True)
    assert b"Task Group not found" in resp.data


def test_task_groups_delete_non_owner_non_admin_403(app, client):
    admin = make_admin()
    other = make_user(email="other@example.com")
    t1 = _task(admin, "a")
    tg = _group(admin, [t1.id])
    tg_id = tg.id
    login(client, other)
    resp = client.post(f"/task_groups/delete/{tg_id}", follow_redirects=False)
    assert resp.status_code == 403
    assert TaskGroups.query.get(tg_id) is not None
