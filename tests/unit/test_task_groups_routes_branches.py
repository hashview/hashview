"""Comprehensive branch-coverage tests for hashview/task_groups/routes.py.

Covers:
- task_groups_list (GET, with/without tasks, with recovered-password data)
- task_groups_add (GET, POST with task_ids, POST legacy flow)
- task_groups_edit (POST not-found, POST authz, POST success, POST form-invalid)
- task_groups_assigned_tasks (GET)
- task_groups_assigned_tasks_add_task (GET)
- task_groups_assigned_tasks_remove_task (not-found, already-removed, success,
  commit-failure via monkeypatching)
- task_groups_assigned_tasks_promote_task (already-first, middle element)
- task_groups_assigned_tasks_demote_task (already-last, middle element)
- task_groups_delete (not-found, authz, success, non-owner/non-admin abort)
"""

import json

import pytest

from hashview.models import Hashes, TaskGroups, Tasks, Users, db


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _admin(email="tga_admin@example.com"):
    u = Users(first_name="TG", last_name="Admin", email_address=email,
              password="x" * 60, admin=True)
    db.session.add(u)
    db.session.commit()
    return u


def _nonadmin(email="tga_user@example.com"):
    u = Users(first_name="TG", last_name="User", email_address=email,
              password="x" * 60, admin=False)
    db.session.add(u)
    db.session.commit()
    return u


def _login(client, user):
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True


def _make_task(owner_id, name="tg-task"):
    t = Tasks(name=name, owner_id=owner_id, hc_attackmode=0, loopback=False)
    db.session.add(t)
    db.session.commit()
    return t


def _make_group(owner_id, name="tg-group", tasks=None):
    """tasks should be a Python list of ints; stored as str(list)."""
    tg = TaskGroups(name=name, owner_id=owner_id,
                    tasks=str(tasks if tasks is not None else []))
    db.session.add(tg)
    db.session.commit()
    return tg


# ---------------------------------------------------------------------------
# task_groups_list
# ---------------------------------------------------------------------------

def test_task_groups_list_empty(app, client):
    admin = _admin()
    _login(client, admin)

    resp = client.get("/task_groups")
    assert resp.status_code == 200


def test_task_groups_list_with_group_and_tasks(app, client):
    admin = _admin()
    _login(client, admin)
    t1 = _make_task(admin.id, name="tg-list-t1")
    t2 = _make_task(admin.id, name="tg-list-t2")
    _make_group(admin.id, name="my-group", tasks=[t1.id, t2.id])

    resp = client.get("/task_groups")
    assert resp.status_code == 200
    assert b"my-group" in resp.data


def test_task_groups_list_with_recovered_hashes(app, client):
    """Lines that compute recovered_by_task / group_hits are exercised."""
    admin = _admin()
    _login(client, admin)
    t = _make_task(admin.id, name="tg-recovered-task")
    _make_group(admin.id, name="recovered-group", tasks=[t.id])
    h = Hashes(sub_ciphertext="abc", ciphertext="abcdef", hash_type=0,
               cracked=True, task_id=t.id)
    db.session.add(h)
    db.session.commit()

    resp = client.get("/task_groups")
    assert resp.status_code == 200


def test_task_groups_list_group_bad_json(app, client):
    """Branch: tasks JSON parse error falls back to empty list."""
    admin = _admin()
    _login(client, admin)
    tg = TaskGroups(name="bad-json-group", owner_id=admin.id, tasks="not-json!!!")
    db.session.add(tg)
    db.session.commit()

    resp = client.get("/task_groups")
    assert resp.status_code == 200


def test_task_groups_list_tasks_field_empty(app, client):
    """Branch: group.tasks is empty string -> ids == []."""
    admin = _admin()
    _login(client, admin)
    tg = TaskGroups(name="empty-tasks-group", owner_id=admin.id, tasks="")
    db.session.add(tg)
    db.session.commit()

    resp = client.get("/task_groups")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# task_groups_add  (GET)
# ---------------------------------------------------------------------------

def test_task_groups_add_get(app, client):
    admin = _admin()
    _login(client, admin)

    resp = client.get("/task_groups/add")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# task_groups_add  (POST with task_ids — modal path)
# ---------------------------------------------------------------------------

def test_task_groups_add_post_with_task_ids(app, client):
    admin = _admin()
    _login(client, admin)
    t1 = _make_task(admin.id, name="add-modal-t1")
    t2 = _make_task(admin.id, name="add-modal-t2")

    resp = client.post("/task_groups/add", data={
        "name": "modal-group",
        "task_ids": f"{t1.id},{t2.id}",
    }, follow_redirects=False)
    assert resp.status_code in (301, 302)
    tg = TaskGroups.query.filter_by(name="modal-group").first()
    assert tg is not None


def test_task_groups_add_post_task_ids_deduplication(app, client):
    """Duplicate ids in task_ids are silently dropped."""
    import ast
    admin = _admin()
    _login(client, admin)
    t = _make_task(admin.id, name="add-dedup-t1")

    client.post("/task_groups/add", data={
        "name": "dedup-group",
        "task_ids": f"{t.id},{t.id}",
    }, follow_redirects=False)
    tg = TaskGroups.query.filter_by(name="dedup-group").first()
    assert tg is not None
    # ast.literal_eval is safe for Python list literals produced by str(list)
    stored = ast.literal_eval(tg.tasks)
    assert stored.count(t.id) == 1


def test_task_groups_add_post_task_ids_invalid_skipped(app, client):
    """Non-numeric and non-existent ids in task_ids are ignored."""
    import ast
    admin = _admin()
    _login(client, admin)

    client.post("/task_groups/add", data={
        "name": "skip-group",
        "task_ids": "notanumber,99999",
    }, follow_redirects=False)
    tg = TaskGroups.query.filter_by(name="skip-group").first()
    assert tg is not None
    # ast.literal_eval is safe for Python list literals produced by str(list)
    assert ast.literal_eval(tg.tasks) == []


# ---------------------------------------------------------------------------
# task_groups_add  (POST legacy path — no task_ids field)
# ---------------------------------------------------------------------------

def test_task_groups_add_post_legacy_no_task_ids(app, client):
    """Without task_ids the route creates empty group and redirects to assigned."""
    admin = _admin()
    _login(client, admin)

    resp = client.post("/task_groups/add", data={
        "name": "legacy-group",
    }, follow_redirects=False)
    # redirect goes to the assigned_tasks sub-path
    assert resp.status_code in (301, 302)
    tg = TaskGroups.query.filter_by(name="legacy-group").first()
    assert tg is not None
    assert resp.headers["Location"].endswith(f"assigned_tasks/{tg.id}")


# ---------------------------------------------------------------------------
# task_groups_edit
# ---------------------------------------------------------------------------

def test_task_groups_edit_not_found(app, client):
    admin = _admin()
    _login(client, admin)

    resp = client.post("/task_groups/edit", data={
        "group_id": "99999",
        "name": "whatever",
        "task_ids": "",
    }, follow_redirects=True)
    assert b"not found" in resp.data.lower()


def test_task_groups_edit_non_owner_non_admin_aborts(app, client):
    admin = _admin()
    user = _nonadmin()
    tg = _make_group(admin.id, name="owned-by-admin-edit")
    _login(client, user)

    resp = client.post("/task_groups/edit", data={
        "group_id": str(tg.id),
        "name": "hijacked",
        "task_ids": "",
    }, follow_redirects=False)
    assert resp.status_code == 403


def test_task_groups_edit_owner_success(app, client):
    user = _nonadmin()
    _login(client, user)
    t1 = _make_task(user.id, name="edit-task-1")
    t2 = _make_task(user.id, name="edit-task-2")
    tg = _make_group(user.id, name="to-edit", tasks=[t1.id])

    resp = client.post("/task_groups/edit", data={
        "group_id": str(tg.id),
        "name": "edited-name",
        "task_ids": f"{t1.id},{t2.id}",
    }, follow_redirects=False)
    assert resp.status_code in (301, 302)
    db.session.refresh(tg)
    assert tg.name == "edited-name"


def test_task_groups_edit_admin_can_edit_any_group(app, client):
    admin = _admin()
    user = _nonadmin()
    tg = _make_group(user.id, name="user-owned-edit")
    _login(client, admin)

    resp = client.post("/task_groups/edit", data={
        "group_id": str(tg.id),
        "name": "admin-renamed",
        "task_ids": "",
    }, follow_redirects=False)
    assert resp.status_code in (301, 302)
    db.session.refresh(tg)
    assert tg.name == "admin-renamed"


def test_task_groups_edit_form_invalid(app, client):
    """Missing name field → form fails validation → danger flash."""
    admin = _admin()
    _login(client, admin)
    tg = _make_group(admin.id, name="form-invalid-group")

    resp = client.post("/task_groups/edit", data={
        "group_id": str(tg.id),
        # name omitted — DataRequired will reject
        "task_ids": "",
    }, follow_redirects=True)
    assert b"Could not update task group" in resp.data


# ---------------------------------------------------------------------------
# task_groups_assigned_tasks  (GET)
# ---------------------------------------------------------------------------

def test_task_groups_assigned_tasks_get(app, client):
    admin = _admin()
    _login(client, admin)
    t = _make_task(admin.id, name="assigned-t1")
    tg = _make_group(admin.id, name="assigned-group", tasks=[t.id])

    resp = client.get(f"/task_groups/assigned_tasks/{tg.id}")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# task_groups_assigned_tasks_add_task
# ---------------------------------------------------------------------------

def test_assigned_tasks_add_task(app, client):
    admin = _admin()
    _login(client, admin)
    t1 = _make_task(admin.id, name="add-to-group-t1")
    t2 = _make_task(admin.id, name="add-to-group-t2")
    tg = _make_group(admin.id, name="add-task-group", tasks=[t1.id])

    resp = client.get(f"/task_groups/assigned_tasks/{tg.id}/add_task/{t2.id}",
                      follow_redirects=False)
    assert resp.status_code in (301, 302)
    db.session.refresh(tg)
    stored = json.loads(tg.tasks.replace("'", '"'))
    assert t2.id in stored


# ---------------------------------------------------------------------------
# task_groups_assigned_tasks_remove_task
# ---------------------------------------------------------------------------

def test_assigned_tasks_remove_task_not_found_group(app, client):
    admin = _admin()
    _login(client, admin)

    resp = client.get("/task_groups/assigned_tasks/99999/remove_task/1",
                      follow_redirects=True)
    assert b"not found" in resp.data.lower()


def test_assigned_tasks_remove_task_not_in_group(app, client):
    """task_id is not in the group's tasks list → 'already been removed' flash."""
    admin = _admin()
    _login(client, admin)
    t1 = _make_task(admin.id, name="rm-t1-present")
    t2 = _make_task(admin.id, name="rm-t2-absent")
    tg = _make_group(admin.id, name="rm-group", tasks=[t1.id])

    resp = client.get(f"/task_groups/assigned_tasks/{tg.id}/remove_task/{t2.id}",
                      follow_redirects=True)
    assert b"already been removed" in resp.data


def test_assigned_tasks_remove_task_success(app, client):
    admin = _admin()
    _login(client, admin)
    t = _make_task(admin.id, name="rm-success-t1")
    tg = _make_group(admin.id, name="rm-success-group", tasks=[t.id])

    resp = client.get(f"/task_groups/assigned_tasks/{tg.id}/remove_task/{t.id}",
                      follow_redirects=False)
    assert resp.status_code in (301, 302)
    db.session.refresh(tg)
    stored_raw = tg.tasks.replace("'", '"')
    stored = json.loads(stored_raw)
    assert t.id not in stored


def test_assigned_tasks_remove_task_commit_failure(app, client, monkeypatch):
    """try_commit returns False → danger flash is shown."""
    admin = _admin()
    _login(client, admin)
    t = _make_task(admin.id, name="rm-fail-t1")
    tg = _make_group(admin.id, name="rm-fail-group", tasks=[t.id])

    import hashview.task_groups.routes as tg_routes
    monkeypatch.setattr(tg_routes, "try_commit", lambda *_a, **_kw: False)

    resp = client.get(f"/task_groups/assigned_tasks/{tg.id}/remove_task/{t.id}",
                      follow_redirects=True)
    assert b"Could not remove" in resp.data


# ---------------------------------------------------------------------------
# task_groups_assigned_tasks_promote_task
# ---------------------------------------------------------------------------

def test_assigned_tasks_promote_already_first(app, client):
    """Promoting the first item is a no-op redirect."""
    admin = _admin()
    _login(client, admin)
    t1 = _make_task(admin.id, name="promote-t1")
    t2 = _make_task(admin.id, name="promote-t2")
    tg = _make_group(admin.id, name="promote-group", tasks=[t1.id, t2.id])

    resp = client.get(
        f"/task_groups/assigned_tasks/{tg.id}/promote_task/{t1.id}",
        follow_redirects=False,
    )
    assert resp.status_code in (301, 302)
    db.session.refresh(tg)
    # order unchanged
    import ast; stored = ast.literal_eval(tg.tasks)  # safe: str(list) literals only
    assert stored[0] == t1.id


def test_assigned_tasks_promote_middle_element(app, client):
    """Promoting t2 from position 1 moves it before t1."""
    admin = _admin()
    _login(client, admin)
    t1 = _make_task(admin.id, name="promote-mid-t1")
    t2 = _make_task(admin.id, name="promote-mid-t2")
    t3 = _make_task(admin.id, name="promote-mid-t3")
    tg = _make_group(admin.id, name="promote-mid-group", tasks=[t1.id, t2.id, t3.id])

    resp = client.get(
        f"/task_groups/assigned_tasks/{tg.id}/promote_task/{t2.id}",
        follow_redirects=False,
    )
    assert resp.status_code in (301, 302)
    db.session.refresh(tg)
    import ast; stored = ast.literal_eval(tg.tasks)  # safe: str(list) literals only
    assert stored.index(t2.id) < stored.index(t1.id)


def test_assigned_tasks_promote_last_element(app, client):
    """Promoting the last element in a 3-item list exercises the while-loop
    else branch (line 177: element at index+1 is not the target, so current
    element is appended as-is before the swap happens on the next iteration)."""
    admin = _admin()
    _login(client, admin)
    t1 = _make_task(admin.id, name="promote-last-t1")
    t2 = _make_task(admin.id, name="promote-last-t2")
    t3 = _make_task(admin.id, name="promote-last-t3")
    # [t1, t2, t3] — promote t3: index=0 sees t2!=t3 -> line 177 appends t1,
    # then index=1 sees t3==t3 -> swap t3 before t2.
    tg = _make_group(admin.id, name="promote-last-group", tasks=[t1.id, t2.id, t3.id])

    resp = client.get(
        f"/task_groups/assigned_tasks/{tg.id}/promote_task/{t3.id}",
        follow_redirects=False,
    )
    assert resp.status_code in (301, 302)
    db.session.refresh(tg)
    # ast.literal_eval is safe for Python list literals stored by str()
    import ast
    stored = ast.literal_eval(tg.tasks)
    assert stored.index(t3.id) < stored.index(t2.id)


# ---------------------------------------------------------------------------
# task_groups_assigned_tasks_demote_task
# ---------------------------------------------------------------------------

def test_assigned_tasks_demote_already_last(app, client):
    """Demoting the last item is a no-op redirect."""
    admin = _admin()
    _login(client, admin)
    t1 = _make_task(admin.id, name="demote-t1")
    t2 = _make_task(admin.id, name="demote-t2")
    tg = _make_group(admin.id, name="demote-group", tasks=[t1.id, t2.id])

    resp = client.get(
        f"/task_groups/assigned_tasks/{tg.id}/demote_task/{t2.id}",
        follow_redirects=False,
    )
    assert resp.status_code in (301, 302)
    db.session.refresh(tg)
    import ast; stored = ast.literal_eval(tg.tasks)  # safe: str(list) literals only
    assert stored[-1] == t2.id


def test_assigned_tasks_demote_first_element(app, client):
    """Demoting t1 from position 0 moves it after t2."""
    admin = _admin()
    _login(client, admin)
    t1 = _make_task(admin.id, name="demote-first-t1")
    t2 = _make_task(admin.id, name="demote-first-t2")
    t3 = _make_task(admin.id, name="demote-first-t3")
    tg = _make_group(admin.id, name="demote-first-group", tasks=[t1.id, t2.id, t3.id])

    resp = client.get(
        f"/task_groups/assigned_tasks/{tg.id}/demote_task/{t1.id}",
        follow_redirects=False,
    )
    assert resp.status_code in (301, 302)
    db.session.refresh(tg)
    import ast; stored = ast.literal_eval(tg.tasks)  # safe: str(list) literals only
    assert stored.index(t1.id) > stored.index(t2.id)


def test_assigned_tasks_demote_middle_element(app, client):
    """Demoting t2 from position 1 moves it after t3."""
    admin = _admin()
    _login(client, admin)
    t1 = _make_task(admin.id, name="demote-mid-t1")
    t2 = _make_task(admin.id, name="demote-mid-t2")
    t3 = _make_task(admin.id, name="demote-mid-t3")
    tg = _make_group(admin.id, name="demote-mid-group", tasks=[t1.id, t2.id, t3.id])

    resp = client.get(
        f"/task_groups/assigned_tasks/{tg.id}/demote_task/{t2.id}",
        follow_redirects=False,
    )
    assert resp.status_code in (301, 302)
    db.session.refresh(tg)
    import ast; stored = ast.literal_eval(tg.tasks)  # safe: str(list) literals only
    assert stored.index(t2.id) > stored.index(t3.id)


# ---------------------------------------------------------------------------
# task_groups_delete
# ---------------------------------------------------------------------------

def test_task_groups_delete_not_found(app, client):
    admin = _admin()
    _login(client, admin)

    resp = client.post("/task_groups/delete/99999", follow_redirects=True)
    assert b"not found" in resp.data.lower()


def test_task_groups_delete_non_owner_non_admin_aborts(app, client):
    admin = _admin()
    user = _nonadmin()
    tg = _make_group(admin.id, name="delete-authz-group")
    _login(client, user)

    resp = client.post(f"/task_groups/delete/{tg.id}", follow_redirects=False)
    assert resp.status_code == 403


def test_task_groups_delete_owner_success(app, client):
    user = _nonadmin()
    _login(client, user)
    tg = _make_group(user.id, name="delete-owner-group")
    tg_id = tg.id

    resp = client.post(f"/task_groups/delete/{tg_id}", follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert TaskGroups.query.get(tg_id) is None


def test_task_groups_delete_admin_can_delete_any(app, client):
    admin = _admin()
    user = _nonadmin()
    tg = _make_group(user.id, name="delete-admin-any-group")
    tg_id = tg.id
    _login(client, admin)

    resp = client.post(f"/task_groups/delete/{tg_id}", follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert TaskGroups.query.get(tg_id) is None


def test_task_groups_delete_commit_failure(app, client, monkeypatch):
    """try_commit returns False → danger flash, group NOT deleted."""
    admin = _admin()
    _login(client, admin)
    tg = _make_group(admin.id, name="delete-fail-group")
    tg_id = tg.id

    import hashview.task_groups.routes as tg_routes
    monkeypatch.setattr(tg_routes, "try_commit", lambda *_a, **_kw: False)

    resp = client.post(f"/task_groups/delete/{tg_id}", follow_redirects=True)
    assert b"could not be deleted" in resp.data.lower()
