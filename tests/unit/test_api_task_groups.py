"""Unit tests for the /v1/task_groups routes in hashview/api/routes.py.

Covers: GET /v1/task_groups, POST /v1/task_groups/add,
POST /v1/task_groups/<id>/tasks, DELETE /v1/task_groups/<id>.

Follows the conventions in tests/unit/test_api_endpoints.py: local fixtures
(not tests/unit/helpers.py::make_admin, which doesn't set api_key), the
@pytest.mark.security marker, and cookie auth via client.set_cookie(...,
domain="localhost.test").
"""

import json
from unittest import mock

import pytest

from hashview.api import routes as api_routes
from hashview.models import Agents, TaskGroups, Tasks, Users
from hashview.models import db as _db
from hashview.utils.utils import MAX_TASKS_PER_GROUP

# ---------------------------------------------------------------------------
# Local fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def admin_user(app):
    user = Users(
        first_name="Admin",
        last_name="User",
        email_address="admin@example.test",
        password="hashed-pw",
        admin=True,
        api_key="user-api-key-admin",
    )
    _db.session.add(user)
    _db.session.commit()
    return user


@pytest.fixture()
def owner_user(app):
    user = Users(
        first_name="Owner",
        last_name="User",
        email_address="owner@example.test",
        password="hashed-pw",
        admin=False,
        api_key="user-api-key-owner",
    )
    _db.session.add(user)
    _db.session.commit()
    return user


@pytest.fixture()
def other_user(app):
    user = Users(
        first_name="Other",
        last_name="User",
        email_address="other@example.test",
        password="hashed-pw",
        admin=False,
        api_key="user-api-key-other",
    )
    _db.session.add(user)
    _db.session.commit()
    return user


@pytest.fixture()
def authorized_agent(app):
    agent = Agents(
        name="agent-1",
        src_ip="127.0.0.1",
        uuid="agent-uuid-ok",
        status="Authorized",
    )
    _db.session.add(agent)
    _db.session.commit()
    return agent


def _json_body(resp):
    """Return parsed JSON body from a Flask test response."""
    return json.loads(resp.get_data(as_text=True))


def _task(owner, name="t"):
    t = Tasks(name=name, hc_attackmode=0, owner_id=owner.id)
    _db.session.add(t)
    _db.session.commit()
    return t


def _group(owner, task_ids, name="grp"):
    tg = TaskGroups(name=name, owner_id=owner.id, tasks=json.dumps(list(task_ids)))
    _db.session.add(tg)
    _db.session.commit()
    return tg


# ---------------------------------------------------------------------------
# GET /v1/task_groups
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_list_no_cookie_redirects_to_not_authorized(client):
    resp = client.get("/v1/task_groups")
    assert 300 <= resp.status_code < 400
    assert "/v1/not_authorized" in resp.headers.get("Location", "")


@pytest.mark.security
def test_list_agent_cookie_rejected(client, authorized_agent):
    client.set_cookie("uuid", authorized_agent.uuid, domain="localhost.test")
    resp = client.get("/v1/task_groups")
    assert 300 <= resp.status_code < 400
    assert "/v1/not_authorized" in resp.headers.get("Location", "")


@pytest.mark.security
def test_list_returns_parsed_task_lists(client, admin_user):
    t1 = _task(admin_user, "a")
    t2 = _task(admin_user, "b")
    _group(admin_user, [t1.id, t2.id], name="G1")

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.get("/v1/task_groups")

    assert resp.status_code == 200
    body = _json_body(resp)
    assert body["status"] == 200
    groups = body["task_groups"]
    assert len(groups) == 1
    assert groups[0]["tasks"] == [t1.id, t2.id]
    assert all(isinstance(x, int) for x in groups[0]["tasks"])


@pytest.mark.security
def test_list_malformed_tasks_json_degrades_to_empty_list(client, admin_user):
    tg = TaskGroups(name="Bad", owner_id=admin_user.id, tasks="not json")
    _db.session.add(tg)
    _db.session.commit()

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.get("/v1/task_groups")

    assert resp.status_code == 200
    body = _json_body(resp)
    assert body["status"] == 200
    row = next(g for g in body["task_groups"] if g["name"] == "Bad")
    assert row["tasks"] == []


# ---------------------------------------------------------------------------
# POST /v1/task_groups/add
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_add_no_cookie_redirects_to_not_authorized(client):
    resp = client.post(
        "/v1/task_groups/add",
        data=json.dumps({"name": "G"}),
        content_type="application/json",
    )
    assert 300 <= resp.status_code < 400
    assert "/v1/not_authorized" in resp.headers.get("Location", "")


@pytest.mark.security
def test_add_agent_cookie_rejected(client, authorized_agent):
    client.set_cookie("uuid", authorized_agent.uuid, domain="localhost.test")
    resp = client.post(
        "/v1/task_groups/add",
        data=json.dumps({"name": "G"}),
        content_type="application/json",
    )
    assert 300 <= resp.status_code < 400
    assert "/v1/not_authorized" in resp.headers.get("Location", "")


@pytest.mark.security
def test_add_cookie_no_user_returns_403(client):
    # A cookie with no matching Users row can never pass is_authorized(user=True,
    # ...) in practice (it runs the identical Users.query.filter_by(api_key=...)
    # lookup), so this downstream 403 branch is only reachable by isolating it
    # from the auth gate — patch is_authorized to simulate the gate passing.
    with mock.patch.object(api_routes, "is_authorized", return_value=True):
        client.set_cookie("uuid", "not-a-real-key", domain="localhost.test")
        resp = client.post(
            "/v1/task_groups/add",
            data=json.dumps({"name": "G"}),
            content_type="application/json",
        )
    body = _json_body(resp)
    assert body["status"] == 403
    assert body["msg"] == "User not found"


@pytest.mark.security
def test_add_missing_body_returns_400(client, admin_user):
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post("/v1/task_groups/add", data="", content_type="application/json")
    body = _json_body(resp)
    assert body["status"] == 400
    assert body["msg"] == "Missing task group data in request body"


@pytest.mark.security
def test_add_blank_name_returns_400(client, admin_user):
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/task_groups/add",
        data=json.dumps({"name": "   "}),
        content_type="application/json",
    )
    body = _json_body(resp)
    assert body["status"] == 400
    assert body["msg"] == "Task group name is required"


@pytest.mark.security
def test_add_duplicate_name_returns_400(client, admin_user):
    _group(admin_user, [], name="Dup")
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/task_groups/add",
        data=json.dumps({"name": "Dup"}),
        content_type="application/json",
    )
    body = _json_body(resp)
    assert body["status"] == 400
    assert body["msg"] == "A task group with that name already exists"


@pytest.mark.security
def test_add_duplicate_name_via_race_returns_400(client, admin_user, monkeypatch):
    """Test that IntegrityError from a race past the pre-check is handled.

    The application-level pre-check (TaskGroups.query.filter_by(name).first())
    is a TOCTOU race: two requests can both pass the check, then only one can
    actually commit. This test monkeypatches the pre-check to return None,
    allowing two adds with the same name to get to db.session.commit(). The
    first commit succeeds; the second hits the database unique constraint and
    must return a 400, not a 500.
    """
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")

    # Monkeypatch TaskGroups.query.filter_by(name=...).first() to return None,
    # bypassing the pre-check. This simulates the TOCTOU race.
    original_filter_by = TaskGroups.query.filter_by

    def mock_filter_by(**kwargs):
        query_obj = original_filter_by(**kwargs)

        def mock_first():
            return None  # Always bypass the pre-check

        query_obj.first = mock_first
        return query_obj

    monkeypatch.setattr(TaskGroups.query, 'filter_by', mock_filter_by)

    # First request with name="RaceName" should succeed (no duplicate yet).
    resp1 = client.post(
        "/v1/task_groups/add",
        data=json.dumps({"name": "RaceName"}),
        content_type="application/json",
    )
    body1 = _json_body(resp1)
    assert body1["status"] == 200

    # Second request with same name should fail with IntegrityError -> 400,
    # not 500.
    resp2 = client.post(
        "/v1/task_groups/add",
        data=json.dumps({"name": "RaceName"}),
        content_type="application/json",
    )
    body2 = _json_body(resp2)
    assert body2["status"] == 400
    assert body2["msg"] == "A task group with that name already exists"


@pytest.mark.security
def test_add_tasks_not_a_list_returns_400(client, admin_user):
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/task_groups/add",
        data=json.dumps({"name": "G", "tasks": "not-a-list"}),
        content_type="application/json",
    )
    body = _json_body(resp)
    assert body["status"] == 400
    assert body["msg"] == "tasks must be a list of task ids"


@pytest.mark.security
def test_add_invalid_task_id_returns_400(client, admin_user):
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/task_groups/add",
        data=json.dumps({"name": "G", "tasks": ["abc"]}),
        content_type="application/json",
    )
    body = _json_body(resp)
    assert body["status"] == 400
    assert body["msg"] == "Invalid task id: 'abc'"


@pytest.mark.security
def test_add_success_creates_group_with_deduped_ordered_tasks(client, admin_user):
    t1 = _task(admin_user, "a")
    t2 = _task(admin_user, "b")
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/task_groups/add",
        data=json.dumps({"name": "NewGroup", "tasks": [t1.id, t2.id, t1.id]}),
        content_type="application/json",
    )
    assert resp.status_code == 200
    body = _json_body(resp)
    assert body["status"] == 200
    assert body["type"] == "message"
    assert body["msg"] == "Task group added"
    tg_id = body["task_group_id"]
    assert isinstance(tg_id, int)

    stored = TaskGroups.query.get(tg_id)
    assert json.loads(stored.tasks) == [t1.id, t2.id]


@pytest.mark.security
def test_add_default_tasks_is_empty_list(client, admin_user):
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/task_groups/add",
        data=json.dumps({"name": "NoTasks"}),
        content_type="application/json",
    )
    body = _json_body(resp)
    assert body["status"] == 200
    stored = TaskGroups.query.get(body["task_group_id"])
    assert json.loads(stored.tasks) == []


# ---------------------------------------------------------------------------
# POST /v1/task_groups/<id>/tasks
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_set_tasks_no_cookie_redirects(client, owner_user):
    tg = _group(owner_user, [], name="G")
    resp = client.post(
        f"/v1/task_groups/{tg.id}/tasks",
        data=json.dumps({"tasks": []}),
        content_type="application/json",
    )
    assert 300 <= resp.status_code < 400
    assert "/v1/not_authorized" in resp.headers.get("Location", "")


@pytest.mark.security
def test_set_tasks_agent_cookie_rejected(client, owner_user, authorized_agent):
    tg = _group(owner_user, [], name="G")
    client.set_cookie("uuid", authorized_agent.uuid, domain="localhost.test")
    resp = client.post(
        f"/v1/task_groups/{tg.id}/tasks",
        data=json.dumps({"tasks": []}),
        content_type="application/json",
    )
    assert 300 <= resp.status_code < 400
    assert "/v1/not_authorized" in resp.headers.get("Location", "")


@pytest.mark.security
def test_set_tasks_cookie_no_user_returns_403(client, owner_user):
    tg = _group(owner_user, [], name="G")
    with mock.patch.object(api_routes, "is_authorized", return_value=True):
        client.set_cookie("uuid", "not-a-real-key", domain="localhost.test")
        resp = client.post(
            f"/v1/task_groups/{tg.id}/tasks",
            data=json.dumps({"tasks": []}),
            content_type="application/json",
        )
    body = _json_body(resp)
    assert body["status"] == 403
    assert body["msg"] == "User not found"


@pytest.mark.security
def test_set_tasks_missing_group_returns_real_404(client, owner_user):
    client.set_cookie("uuid", owner_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/task_groups/999999/tasks",
        data=json.dumps({"tasks": []}),
        content_type="application/json",
    )
    assert resp.status_code == 404
    body = _json_body(resp)
    assert body == {"status": 404, "type": "Error", "msg": "Task group not found"}


@pytest.mark.security
def test_set_tasks_non_owner_non_admin_returns_body_403(client, owner_user, other_user):
    tg = _group(owner_user, [], name="G")
    client.set_cookie("uuid", other_user.api_key, domain="localhost.test")
    resp = client.post(
        f"/v1/task_groups/{tg.id}/tasks",
        data=json.dumps({"tasks": []}),
        content_type="application/json",
    )
    assert resp.status_code == 200
    body = _json_body(resp)
    assert body["status"] == 403
    assert body["msg"] == "You do not have rights to modify this task group"


@pytest.mark.security
def test_set_tasks_missing_body_returns_400(client, owner_user):
    tg = _group(owner_user, [], name="G")
    client.set_cookie("uuid", owner_user.api_key, domain="localhost.test")
    resp = client.post(f"/v1/task_groups/{tg.id}/tasks", data="", content_type="application/json")
    body = _json_body(resp)
    assert body["status"] == 400
    assert body["msg"] == "Missing task group data in request body"


@pytest.mark.security
def test_set_tasks_not_a_list_returns_400(client, owner_user):
    tg = _group(owner_user, [], name="G")
    client.set_cookie("uuid", owner_user.api_key, domain="localhost.test")
    resp = client.post(
        f"/v1/task_groups/{tg.id}/tasks",
        data=json.dumps({"tasks": "nope"}),
        content_type="application/json",
    )
    body = _json_body(resp)
    assert body["status"] == 400
    assert body["msg"] == "tasks must be a list of task ids"


@pytest.mark.security
def test_set_tasks_missing_tasks_key_returns_400(client, owner_user):
    tg = _group(owner_user, [], name="G")
    client.set_cookie("uuid", owner_user.api_key, domain="localhost.test")
    # A body of {} is falsy in Python, so it would hit the "missing body"
    # branch instead of the "tasks must be a list" branch; use a non-empty
    # body that simply omits the "tasks" key.
    resp = client.post(
        f"/v1/task_groups/{tg.id}/tasks",
        data=json.dumps({"mode": "replace"}),
        content_type="application/json",
    )
    body = _json_body(resp)
    assert body["status"] == 400
    assert body["msg"] == "tasks must be a list of task ids"


@pytest.mark.security
def test_set_tasks_invalid_mode_returns_400(client, owner_user):
    tg = _group(owner_user, [], name="G")
    client.set_cookie("uuid", owner_user.api_key, domain="localhost.test")
    resp = client.post(
        f"/v1/task_groups/{tg.id}/tasks",
        data=json.dumps({"tasks": [], "mode": "bogus"}),
        content_type="application/json",
    )
    body = _json_body(resp)
    assert body["status"] == 400
    assert body["msg"] == "mode must be 'replace' or 'append'"


@pytest.mark.security
def test_set_tasks_invalid_task_id_returns_400(client, owner_user):
    tg = _group(owner_user, [], name="G")
    client.set_cookie("uuid", owner_user.api_key, domain="localhost.test")
    resp = client.post(
        f"/v1/task_groups/{tg.id}/tasks",
        data=json.dumps({"tasks": ["abc"]}),
        content_type="application/json",
    )
    body = _json_body(resp)
    assert body["status"] == 400
    assert body["msg"] == "Invalid task id: 'abc'"


@pytest.mark.security
def test_set_tasks_replace_mode_discards_existing(client, owner_user):
    t1 = _task(owner_user, "a")
    t2 = _task(owner_user, "b")
    t3 = _task(owner_user, "c")
    tg = _group(owner_user, [t1.id, t2.id], name="G")

    client.set_cookie("uuid", owner_user.api_key, domain="localhost.test")
    resp = client.post(
        f"/v1/task_groups/{tg.id}/tasks",
        data=json.dumps({"tasks": [t3.id], "mode": "replace"}),
        content_type="application/json",
    )
    assert resp.status_code == 200
    body = _json_body(resp)
    assert body["status"] == 200
    assert body["type"] == "message"
    assert body["msg"] == "Task group updated"
    assert body["task_group_id"] == tg.id
    assert body["tasks"] == [t3.id]
    assert json.loads(TaskGroups.query.get(tg.id).tasks) == [t3.id]


@pytest.mark.security
def test_set_tasks_replace_is_default_mode(client, owner_user):
    t1 = _task(owner_user, "a")
    t2 = _task(owner_user, "b")
    tg = _group(owner_user, [t1.id], name="G")

    client.set_cookie("uuid", owner_user.api_key, domain="localhost.test")
    resp = client.post(
        f"/v1/task_groups/{tg.id}/tasks",
        data=json.dumps({"tasks": [t2.id]}),
        content_type="application/json",
    )
    body = _json_body(resp)
    assert body["tasks"] == [t2.id]
    assert json.loads(TaskGroups.query.get(tg.id).tasks) == [t2.id]


@pytest.mark.security
def test_set_tasks_append_mode_preserves_existing_and_dedupes(client, owner_user):
    t1 = _task(owner_user, "a")
    t2 = _task(owner_user, "b")
    t3 = _task(owner_user, "c")
    tg = _group(owner_user, [t1.id, t2.id], name="G")

    client.set_cookie("uuid", owner_user.api_key, domain="localhost.test")
    resp = client.post(
        f"/v1/task_groups/{tg.id}/tasks",
        data=json.dumps({"tasks": [t2.id, t3.id], "mode": "append"}),
        content_type="application/json",
    )
    assert resp.status_code == 200
    body = _json_body(resp)
    assert body["tasks"] == [t1.id, t2.id, t3.id]
    assert json.loads(TaskGroups.query.get(tg.id).tasks) == [t1.id, t2.id, t3.id]


@pytest.mark.security
def test_set_tasks_append_mode_malformed_existing_json_falls_back_to_empty(client, owner_user):
    t1 = _task(owner_user, "a")
    tg = TaskGroups(name="G", owner_id=owner_user.id, tasks="not json")
    _db.session.add(tg)
    _db.session.commit()

    client.set_cookie("uuid", owner_user.api_key, domain="localhost.test")
    resp = client.post(
        f"/v1/task_groups/{tg.id}/tasks",
        data=json.dumps({"tasks": [t1.id], "mode": "append"}),
        content_type="application/json",
    )
    assert resp.status_code == 200
    body = _json_body(resp)
    assert body["tasks"] == [t1.id]
    assert json.loads(TaskGroups.query.get(tg.id).tasks) == [t1.id]


@pytest.mark.security
def test_set_tasks_admin_can_update_others_group(client, owner_user, admin_user):
    t1 = _task(owner_user, "a")
    tg = _group(owner_user, [], name="G")

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        f"/v1/task_groups/{tg.id}/tasks",
        data=json.dumps({"tasks": [t1.id]}),
        content_type="application/json",
    )
    assert resp.status_code == 200
    body = _json_body(resp)
    assert body["status"] == 200
    assert json.loads(TaskGroups.query.get(tg.id).tasks) == [t1.id]


# ---------------------------------------------------------------------------
# DELETE /v1/task_groups/<id>
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_delete_no_cookie_redirects(client, owner_user):
    tg = _group(owner_user, [], name="G")
    resp = client.delete(f"/v1/task_groups/{tg.id}")
    assert 300 <= resp.status_code < 400
    assert "/v1/not_authorized" in resp.headers.get("Location", "")


@pytest.mark.security
def test_delete_agent_cookie_rejected(client, owner_user, authorized_agent):
    tg = _group(owner_user, [], name="G")
    client.set_cookie("uuid", authorized_agent.uuid, domain="localhost.test")
    resp = client.delete(f"/v1/task_groups/{tg.id}")
    assert 300 <= resp.status_code < 400
    assert "/v1/not_authorized" in resp.headers.get("Location", "")


@pytest.mark.security
def test_delete_cookie_no_user_returns_403(client, owner_user):
    tg = _group(owner_user, [], name="G")
    with mock.patch.object(api_routes, "is_authorized", return_value=True):
        client.set_cookie("uuid", "not-a-real-key", domain="localhost.test")
        resp = client.delete(f"/v1/task_groups/{tg.id}")
    body = _json_body(resp)
    assert body["status"] == 403
    assert body["msg"] == "User not found"


@pytest.mark.security
def test_delete_missing_group_returns_real_404(client, owner_user):
    client.set_cookie("uuid", owner_user.api_key, domain="localhost.test")
    resp = client.delete("/v1/task_groups/999999")
    assert resp.status_code == 404
    body = _json_body(resp)
    assert body == {"status": 404, "type": "Error", "msg": "Task group not found"}


@pytest.mark.security
def test_delete_non_owner_non_admin_returns_body_403(client, owner_user, other_user):
    tg = _group(owner_user, [], name="G")
    client.set_cookie("uuid", other_user.api_key, domain="localhost.test")
    resp = client.delete(f"/v1/task_groups/{tg.id}")
    assert resp.status_code == 200
    body = _json_body(resp)
    assert body["status"] == 403
    assert body["msg"] == "You do not have rights to delete this task group"
    assert TaskGroups.query.get(tg.id) is not None


@pytest.mark.security
def test_delete_admin_can_delete_others_group(client, owner_user, admin_user):
    tg = _group(owner_user, [], name="G")
    tg_id = tg.id
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.delete(f"/v1/task_groups/{tg_id}")
    assert resp.status_code == 200
    body = _json_body(resp)
    assert body["status"] == 200
    assert TaskGroups.query.get(tg_id) is None


@pytest.mark.security
def test_delete_success(client, owner_user):
    tg = _group(owner_user, [], name="G")
    tg_id = tg.id
    client.set_cookie("uuid", owner_user.api_key, domain="localhost.test")
    resp = client.delete(f"/v1/task_groups/{tg_id}")
    assert resp.status_code == 200
    body = _json_body(resp)
    assert body["status"] == 200
    assert body["type"] == "message"
    assert body["msg"] == "Task group deleted"
    assert body["task_group_id"] == tg_id
    assert TaskGroups.query.get(tg_id) is None


# ---------------------------------------------------------------------------
# Storage-format regression: TaskGroups.tasks used to be String(256), which
# truncated JSON for groups with enough task ids. Verify the widened TEXT
# column round-trips a large id list without truncation, end to end through
# the add + list routes.
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_add_and_list_large_task_list_is_not_truncated(client, admin_user):
    tasks = [_task(admin_user, f"t{i}") for i in range(120)]
    task_ids = [t.id for t in tasks]
    # Sanity: the serialized ids alone must exceed the old String(256) limit.
    assert len(json.dumps(task_ids)) > 256

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/task_groups/add",
        data=json.dumps({"name": "BigGroup", "tasks": task_ids}),
        content_type="application/json",
    )
    assert resp.status_code == 200
    body = _json_body(resp)
    assert body["status"] == 200
    tg_id = body["task_group_id"]

    stored = TaskGroups.query.get(tg_id)
    assert json.loads(stored.tasks) == task_ids

    list_resp = client.get("/v1/task_groups")
    list_body = _json_body(list_resp)
    row = next(g for g in list_body["task_groups"] if g["id"] == tg_id)
    assert row["tasks"] == task_ids


# ---------------------------------------------------------------------------
# MAX_TASKS_PER_GROUP cap (both write endpoints)
# ---------------------------------------------------------------------------


def _bulk_tasks(owner, n):
    """Create n Tasks rows cheaply and return their ids in insertion order.

    bulk_insert_mappings skips the ORM, so `loopback` (nullable=False with a
    Python-side default) has to be passed explicitly, and the PKs are not
    written back — hence the id read-back. Committing n rows one at a time
    instead costs ~50x more for the cap-sized cases.
    """
    before = {row[0] for row in _db.session.query(Tasks.id).all()}
    _db.session.bulk_insert_mappings(
        Tasks,
        [{"name": f"bulk{i}", "hc_attackmode": 0, "owner_id": owner.id, "loopback": False}
         for i in range(n)],
    )
    _db.session.commit()
    return [row[0] for row in _db.session.query(Tasks.id).order_by(Tasks.id).all()
            if row[0] not in before]


def test_max_tasks_per_group_is_10000():
    """Pin the product limit so it cannot drift silently."""
    assert MAX_TASKS_PER_GROUP == 10000


@pytest.mark.security
def test_add_over_limit_rejected_before_task_id_validation(client, admin_user):
    # No Tasks rows exist at all: the cap has to fire on the raw submitted
    # length, before the ids are checked against the table. If the order ever
    # flips, the caller gets "Invalid task id" and never learns the real
    # problem — and this test would need 10,001 real rows to say anything.
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/task_groups/add",
        data=json.dumps({"name": "Over", "tasks": list(range(1, MAX_TASKS_PER_GROUP + 2))}),
        content_type="application/json",
    )
    body = _json_body(resp)
    assert body["status"] == 400
    assert body["msg"] == (
        f"A task group can hold at most {MAX_TASKS_PER_GROUP} tasks "
        f"({MAX_TASKS_PER_GROUP + 1} submitted)"
    )
    assert "Invalid task id" not in body["msg"]
    assert TaskGroups.query.filter_by(name="Over").first() is None


@pytest.mark.security
def test_add_at_limit_is_accepted(client, admin_user):
    ids = _bulk_tasks(admin_user, MAX_TASKS_PER_GROUP)
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/task_groups/add",
        data=json.dumps({"name": "AtLimit", "tasks": ids}),
        content_type="application/json",
    )
    body = _json_body(resp)
    assert body["status"] == 200
    stored = json.loads(TaskGroups.query.get(body["task_group_id"]).tasks)
    assert len(stored) == MAX_TASKS_PER_GROUP


@pytest.mark.security
def test_set_tasks_replace_over_limit_leaves_row_unchanged(client, owner_user):
    t1 = _task(owner_user, "a")
    tg = _group(owner_user, [t1.id], name="G")

    client.set_cookie("uuid", owner_user.api_key, domain="localhost.test")
    resp = client.post(
        f"/v1/task_groups/{tg.id}/tasks",
        data=json.dumps({
            "tasks": list(range(1, MAX_TASKS_PER_GROUP + 2)),
            "mode": "replace",
        }),
        content_type="application/json",
    )
    body = _json_body(resp)
    assert body["status"] == 400
    assert f"at most {MAX_TASKS_PER_GROUP} tasks" in body["msg"]
    assert json.loads(TaskGroups.query.get(tg.id).tasks) == [t1.id]


@pytest.mark.security
def test_set_tasks_append_crossing_cap_returns_400(client, owner_user):
    # The combined-list case: only 2 ids are submitted, so an input-length
    # check alone would let this through. append never revalidates the stored
    # membership, so the cap has to be on the resulting list.
    t1 = _task(owner_user, "a")
    t2 = _task(owner_user, "b")
    existing = list(range(500000, 500000 + MAX_TASKS_PER_GROUP - 1))   # 9,999 entries
    tg = _group(owner_user, existing, name="G")

    client.set_cookie("uuid", owner_user.api_key, domain="localhost.test")
    resp = client.post(
        f"/v1/task_groups/{tg.id}/tasks",
        data=json.dumps({"tasks": [t1.id, t2.id], "mode": "append"}),
        content_type="application/json",
    )
    body = _json_body(resp)
    assert body["status"] == 400
    assert body["msg"] == (
        f"A task group can hold at most {MAX_TASKS_PER_GROUP} tasks "
        f"({MAX_TASKS_PER_GROUP + 1} after this change)"
    )
    assert json.loads(TaskGroups.query.get(tg.id).tasks) == existing


@pytest.mark.security
def test_set_tasks_append_up_to_limit_is_accepted(client, owner_user):
    t1 = _task(owner_user, "a")
    existing = list(range(500000, 500000 + MAX_TASKS_PER_GROUP - 1))   # 9,999 entries
    tg = _group(owner_user, existing, name="G")

    client.set_cookie("uuid", owner_user.api_key, domain="localhost.test")
    resp = client.post(
        f"/v1/task_groups/{tg.id}/tasks",
        data=json.dumps({"tasks": [t1.id], "mode": "append"}),
        content_type="application/json",
    )
    body = _json_body(resp)
    assert body["status"] == 200
    assert len(json.loads(TaskGroups.query.get(tg.id).tasks)) == MAX_TASKS_PER_GROUP


@pytest.mark.security
def test_set_tasks_append_duplicate_at_cap_is_accepted(client, owner_user):
    # A full group re-appending an id it already holds must NOT be rejected:
    # the merge dedupes, so the resulting length is unchanged. Guards against
    # a naive len(existing) + len(ordered) check.
    t1 = _task(owner_user, "a")
    existing = [t1.id] + list(range(500000, 500000 + MAX_TASKS_PER_GROUP - 1))
    assert len(existing) == MAX_TASKS_PER_GROUP
    tg = _group(owner_user, existing, name="G")

    client.set_cookie("uuid", owner_user.api_key, domain="localhost.test")
    resp = client.post(
        f"/v1/task_groups/{tg.id}/tasks",
        data=json.dumps({"tasks": [t1.id], "mode": "append"}),
        content_type="application/json",
    )
    body = _json_body(resp)
    assert body["status"] == 200
    assert json.loads(TaskGroups.query.get(tg.id).tasks) == existing
