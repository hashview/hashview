"""Regression tests for issue #440: /v1 JSON-body endpoints and non-object bodies.

``request.get_json(silent=True)`` parses any valid JSON, so a top-level array,
string or number reached handlers that then called ``.get()`` or indexed it
like a dict. A non-empty array is truthy and passed the ``if not data`` guard,
so the handler raised and Flask answered with an HTML 500 page instead of the
API's ``{status, type, msg}`` envelope. Agent routes that only checked
``'key' in data`` were reachable the same way with ``["key"]`` or a string
containing the key.

Every /v1 endpoint that reads a JSON body must treat a valid-but-non-object
body exactly like a missing one.
"""

import json

import pytest

import hashview
from hashview.models import Agents, TaskGroups, Users
from hashview.models import db as _db

DOMAIN = "localhost.test"

# Bodies that are valid JSON but not an object. Each one is truthy, so the old
# ``if not data`` guard let it through.
NON_OBJECT_BODIES = [
    pytest.param([1, 2], id="array"),
    pytest.param("text", id="string"),
    pytest.param(42, id="number"),
]


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
def agent(app):
    agent = Agents(
        name="agent-1",
        src_ip="127.0.0.1",
        uuid="agent-uuid-ok",
        status="Authorized",
    )
    _db.session.add(agent)
    _db.session.commit()
    return agent


def _post(client, url, body):
    return client.post(url, data=json.dumps(body), content_type="application/json")


def _envelope(resp):
    # An unhandled exception would surface as an HTML 500 (or propagate under
    # TESTING); the API contract is a JSON envelope.
    assert resp.status_code == 200
    assert resp.is_json, resp.get_data(as_text=True)[:200]
    return resp.get_json()


USER_ENDPOINTS = [
    ("/v1/tasks/add", 400),
    ("/v1/jobs/add", 400),
    ("/v1/customers/add", 400),
    ("/v1/task_groups/add", 400),
    ("/v1/task_groups/{group_id}/tasks", 400),
    # /v1/search has always answered a missing body with status 500.
    ("/v1/search", 500),
]


@pytest.mark.parametrize("body", NON_OBJECT_BODIES)
@pytest.mark.parametrize(("url", "expected_status"), USER_ENDPOINTS)
def test_user_endpoint_rejects_non_object_body(client, admin_user, url, expected_status, body):
    group = TaskGroups(name="grp", owner_id=admin_user.id, tasks="[]")
    _db.session.add(group)
    _db.session.commit()
    client.set_cookie("uuid", admin_user.api_key, domain=DOMAIN)

    payload = _envelope(_post(client, url.format(group_id=group.id), body))

    assert payload["status"] == expected_status
    assert payload["type"] == "Error" or expected_status == 500


# A list holding the required key names passes the old ``'key' in data`` checks.
AGENT_ENDPOINTS = [
    ("/v1/agents/heartbeat", ["agent_status"]),
    ("/v1/agents/benchmark", ["benchmark_results"]),
    ("/v1/jobtask/keyspace", ["ledger_id", "keyspace"]),
    ("/v1/uploadCrackFile/1", ["file"]),
    ("/v1/jobtask/status", ["job_task_id", "task_status"]),
]


@pytest.mark.parametrize(("url", "body"), AGENT_ENDPOINTS)
def test_agent_endpoint_rejects_non_object_body(client, agent, url, body):
    client.set_cookie("uuid", agent.uuid, domain=DOMAIN)
    client.set_cookie("agent_version", hashview.__version__, domain=DOMAIN)

    payload = _envelope(_post(client, url, body))

    assert payload["status"] == 400
    assert payload["type"] == "Error"


@pytest.mark.parametrize("url", [u for u, _ in AGENT_ENDPOINTS])
@pytest.mark.parametrize("body", NON_OBJECT_BODIES)
def test_agent_endpoint_rejects_scalar_and_array_bodies(client, agent, url, body):
    client.set_cookie("uuid", agent.uuid, domain=DOMAIN)
    client.set_cookie("agent_version", hashview.__version__, domain=DOMAIN)

    payload = _envelope(_post(client, url, body))

    assert payload["status"] == 400
    assert payload["type"] == "Error"


@pytest.mark.parametrize("body", NON_OBJECT_BODIES)
def test_error_report_with_non_object_body_is_accepted(client, agent, body, monkeypatch):
    sent = []
    monkeypatch.setattr(
        "hashview.api.routes.notify_admins", lambda subject, message: sent.append(message)
    )
    client.set_cookie("uuid", agent.uuid, domain=DOMAIN)

    payload = _envelope(_post(client, "/v1/error", body))

    assert payload["status"] == 200
    # Same as an empty or missing body: no error text to forward.
    assert sent == [None]
