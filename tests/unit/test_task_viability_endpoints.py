"""Tests for the task-viability read endpoints: GET /v1/tasks and
GET /v1/agents/benchmark. Auth/fixture style mirrors test_api_routes_regression.py
(the 'uuid' cookie maps to Users.api_key; see is_authorized)."""

import json

import pytest

from hashview.models import AgentBenchmarks, Rules, Tasks, Users, Wordlists
from hashview.models import db as _db

DOMAIN = "localhost.test"


@pytest.fixture()
def admin_user(app):
    u = Users(first_name="Ad", last_name="Min", email_address="admin@vt.test",
              password="x" * 60, admin=True, api_key="user-api-key-admin")
    _db.session.add(u)
    _db.session.commit()
    return u


def _auth(client, value):
    client.set_cookie("uuid", value, domain=DOMAIN)


def _body(resp):
    return json.loads(resp.get_data(as_text=True))


def _task(owner_id, name="t1", wl_id=None, rule_id=None, attackmode=0):
    t = Tasks(name=name, hc_attackmode=attackmode, owner_id=owner_id,
              wl_id=wl_id, rule_id=rule_id)
    _db.session.add(t)
    _db.session.commit()
    return t


def test_get_tasks_requires_auth(client):
    """No/invalid uuid cookie -> redirect to /v1/not_authorized (not a 200 body)."""
    resp = client.get("/v1/tasks", follow_redirects=False)
    assert resp.status_code == 302
    assert "/v1/not_authorized" in resp.headers["Location"]


def test_get_tasks_lists_all(client, admin_user):
    """Authorized -> status 200 and every task serialized with its ids."""
    _task(admin_user.id, name="rockyou + best64", wl_id=6, rule_id=1)
    _task(admin_user.id, name="rockyou (plain)", wl_id=6, rule_id=None)

    _auth(client, admin_user.api_key)
    resp = client.get("/v1/tasks")
    assert resp.status_code == 200
    body = _body(resp)

    assert body["status"] == 200
    names = {t["name"] for t in body["tasks"]}
    assert {"rockyou + best64", "rockyou (plain)"} <= names
    withrule = next(t for t in body["tasks"] if t["name"] == "rockyou + best64")
    assert withrule["wl_id"] == 6 and withrule["rule_id"] == 1


def _bench(agent_id, hash_type, speed):
    b = AgentBenchmarks(agent_id=agent_id, hash_type=hash_type, speed=speed)
    _db.session.add(b)
    _db.session.commit()
    return b


def test_get_benchmark_requires_auth(client):
    resp = client.get("/v1/agents/benchmark", follow_redirects=False)
    assert resp.status_code == 302
    assert "/v1/not_authorized" in resp.headers["Location"]


def test_get_benchmark_performance_is_slowest_per_hash(client, admin_user):
    """Two agents benchmarked mode 1000; the map reports the SLOWEST (min) speed."""
    _bench(agent_id=1, hash_type=1000, speed=100_000_000_000)
    _bench(agent_id=2, hash_type=1000, speed=60_000_000_000)   # slower rig
    _bench(agent_id=1, hash_type=3200, speed=20_000)

    _auth(client, admin_user.api_key)
    body = _body(client.get("/v1/agents/benchmark"))

    assert body["status"] == 200
    # JSON object keys are strings.
    assert body["performance"]["1000"] == 60_000_000_000
    assert body["performance"]["3200"] == 20_000


def test_get_benchmark_single_hash_and_missing(client, admin_user):
    _bench(agent_id=1, hash_type=1000, speed=60_000_000_000)
    _auth(client, admin_user.api_key)

    hit = _body(client.get("/v1/agents/benchmark?hash_type=1000"))
    assert hit["hash_type"] == 1000 and hit["speed"] == 60_000_000_000

    miss = _body(client.get("/v1/agents/benchmark?hash_type=9999"))
    assert miss["hash_type"] == 9999 and miss["speed"] is None


def test_get_benchmark_empty_table(client, admin_user):
    _auth(client, admin_user.api_key)
    body = _body(client.get("/v1/agents/benchmark"))
    assert body["status"] == 200 and body["performance"] == {}
