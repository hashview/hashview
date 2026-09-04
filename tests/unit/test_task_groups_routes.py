"""Regression tests for task_groups routes + form (function-coverage batch)."""

import json

import pytest
from wtforms.validators import ValidationError

from hashview.models import TaskGroups, Tasks, db
from hashview.task_groups.forms import TaskGroupsForm
from hashview.utils.utils import MAX_TASKS_PER_GROUP
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


# --- MAX_TASKS_PER_GROUP cap (web UI) --------------------------------------


def _bulk_tasks(owner, n):
    """Create n Tasks rows cheaply and return their ids in insertion order.

    Real rows are unavoidable for the UI cap tests: task_groups_add/edit
    silently drop ids that aren't in the Tasks table, so a fabricated payload
    would collapse to an empty list and could never reach the cap.
    """
    db.session.bulk_insert_mappings(
        Tasks,
        [{"name": f"bulk{i}", "hc_attackmode": 0, "owner_id": owner.id, "loopback": False}
         for i in range(n)],
    )
    db.session.commit()
    return [row[0] for row in db.session.query(Tasks.id).order_by(Tasks.id).all()]


def test_task_groups_add_over_limit_shows_error_and_creates_nothing(app, client):
    admin = make_admin()
    login(client, admin)
    ids = _bulk_tasks(admin, MAX_TASKS_PER_GROUP + 1)
    resp = client.post("/task_groups/add", data={
        "name": "Over", "task_ids": ",".join(str(i) for i in ids),
        "from_modal": "1", "submit": "Create",
    }, follow_redirects=True)
    assert resp.status_code == 200
    assert b"can hold at most 10,000 tasks" in resp.data
    assert b"new-group-modal" in resp.data          # reopened, error inside it
    assert TaskGroups.query.filter_by(name="Over").first() is None


def test_task_groups_add_over_limit_keeps_the_session_cookie_small(app, client):
    # The error round-trips through session['task_groups_form_err'], which is a
    # signed *cookie*: a cap-sized CSV is ~60 KB and a browser silently drops an
    # over-sized cookie, logging the user out. The name is kept, the oversized
    # selection is not, and the cookie stays inside the 4093-byte browser limit.
    admin = make_admin()
    login(client, admin)
    ids = _bulk_tasks(admin, MAX_TASKS_PER_GROUP + 1)
    csv = ",".join(str(i) for i in ids)
    # follow_redirects=False: task_groups_list pops the key, so it is gone once
    # the redirect is followed.
    resp = client.post("/task_groups/add", data={
        "name": "Over", "task_ids": csv, "from_modal": "1", "submit": "Create",
    }, follow_redirects=False)
    with client.session_transaction() as sess:
        err = sess["task_groups_form_err"]
    assert err["modal"] == "new-group-modal"
    assert err["values"]["name"] == "Over"
    assert err["values"]["task_ids"] == ""
    for header in resp.headers.getlist("Set-Cookie"):
        if header.startswith("session="):
            assert len(header) < 4093, f"session cookie would be dropped: {len(header)} bytes"


def test_task_groups_add_failure_round_trips_a_normal_selection(app, client):
    # The size guard above must not cost the common case: a duplicate-name
    # rejection still reopens the modal with the selection intact.
    admin = make_admin()
    login(client, admin)
    t1, t2 = _task(admin, "a"), _task(admin, "b")
    _group(admin, [t1.id], name="Taken")
    csv = f"{t1.id},{t2.id}"
    client.post("/task_groups/add", data={
        "name": "Taken", "task_ids": csv, "from_modal": "1", "submit": "Create",
    }, follow_redirects=False)
    with client.session_transaction() as sess:
        err = sess["task_groups_form_err"]
    assert err["values"]["task_ids"] == csv
    assert "That task group name is taken." in " ".join(err["errors"])


def test_task_groups_add_at_limit_creates_group(app, client):
    admin = make_admin()
    login(client, admin)
    ids = _bulk_tasks(admin, MAX_TASKS_PER_GROUP)
    resp = client.post("/task_groups/add", data={
        "name": "AtLimit", "task_ids": ",".join(str(i) for i in ids),
        "from_modal": "1", "submit": "Create",
    }, follow_redirects=False)
    assert resp.status_code in (301, 302)
    tg = TaskGroups.query.filter_by(name="AtLimit").first()
    assert tg is not None
    assert len(json.loads(tg.tasks)) == MAX_TASKS_PER_GROUP


def test_task_groups_edit_over_limit_leaves_group_unchanged(app, client):
    admin = make_admin()
    login(client, admin)
    t1 = _task(admin, "keeper")
    tg = _group(admin, [t1.id], name="OldName")
    ids = _bulk_tasks(admin, MAX_TASKS_PER_GROUP + 1)
    resp = client.post("/task_groups/edit", data={
        "group_id": tg.id, "name": "NewName",
        "task_ids": ",".join(str(i) for i in ids), "submit": "Create",
    }, follow_redirects=True)
    assert b"can hold at most 10,000 tasks" in resp.data
    # The check runs before either attribute is assigned, so neither moved.
    updated = TaskGroups.query.get(tg.id)
    assert updated.name == "OldName"
    assert json.loads(updated.tasks) == [t1.id]


def test_assigned_tasks_add_task_at_cap_is_rejected(app, client):
    # The legacy single-task route is the only incremental growth path, so
    # without this the cap would be walkable one click at a time.
    admin = make_admin()
    login(client, admin)
    t1 = _task(admin, "newcomer")
    existing = list(range(500000, 500000 + MAX_TASKS_PER_GROUP))
    tg = _group(admin, existing, name="Full")
    resp = client.get(f"/task_groups/assigned_tasks/{tg.id}/add_task/{t1.id}",
                      follow_redirects=True)
    assert resp.status_code == 200
    assert b"already holds the maximum of 10,000 tasks" in resp.data
    assert json.loads(TaskGroups.query.get(tg.id).tasks) == existing
