"""Regression tests for issue #218.

Several API handlers dereferenced query results without a ``None`` check, so an
unknown/missing id produced an ``AttributeError`` (or a ``KeyError`` for a body
without the expected key). Flask turned those unhandled exceptions into an
opaque HTTP 500 instead of a clean 4xx. Each handler below now guards its
lookups and returns a proper 404 (or a handled "Invalid Search").

Endpoints covered:
  * GET  /v1/getHashType/<hashfile_id>   -> 404 for an unknown hashfile
  * GET  /v1/jobTasks/<job_task_id>      -> no 500 for a user caller (no Agents row)
  * POST /v1/uploadCrackFile/<job_task_id> -> 404 for an unknown job task
  * POST /v1/search                      -> handled response when 'hash' is absent
"""

import json

import pytest

from hashview.models import (
    db,
    Agents,
    Customers,
    HashfileHashes,
    Hashes,
    Hashfiles,
    Users,
)


@pytest.fixture()
def admin_user(app):
    with app.app_context():
        user = Users(
            first_name="Admin",
            last_name="User",
            email_address="admin@example.test",
            password="hashed-pw",
            admin=True,
            api_key="user-api-key-admin",
        )
        db.session.add(user)
        db.session.commit()
        return {"api_key": user.api_key}


@pytest.fixture()
def agent_a(app):
    with app.app_context():
        agent = Agents(
            name="agent-a", src_ip="127.0.0.1", uuid="agent-uuid-a", status="Authorized"
        )
        db.session.add(agent)
        db.session.commit()
        return {"uuid": agent.uuid}


@pytest.fixture()
def hashfile_with_hash(app, admin_user):
    """A hashfile holding a single hash, plus the junction row that links them."""
    with app.app_context():
        customer = Customers(name="Acme")
        user = Users.query.filter_by(api_key=admin_user["api_key"]).first()
        db.session.add(customer)
        db.session.commit()

        hashfile = Hashfiles(name="hf", customer_id=customer.id, owner_id=user.id)
        db.session.add(hashfile)
        db.session.commit()

        h = Hashes(sub_ciphertext="a", ciphertext="aa", hash_type=1000, cracked=False)
        db.session.add(h)
        db.session.commit()
        db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hashfile.id))
        db.session.commit()

        return {"hashfile_id": hashfile.id}


def test_get_hashtype_unknown_hashfile_returns_404(client, admin_user):
    client.set_cookie("uuid", admin_user["api_key"])
    resp = client.get("/v1/getHashType/999999")
    assert resp.status_code == 404


def test_get_hashtype_known_hashfile_returns_hash_type(client, admin_user, hashfile_with_hash):
    client.set_cookie("uuid", admin_user["api_key"])
    resp = client.get("/v1/getHashType/{}".format(hashfile_with_hash["hashfile_id"]))
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["hash_type"] == 1000


def test_jobtasks_assignment_user_caller_does_not_500(client, admin_user):
    # The route allows user=True, agent=True, but only an agent has an Agents
    # row; a user caller must not hit agent.id on None.
    client.set_cookie("uuid", admin_user["api_key"])
    resp = client.get("/v1/jobTasks/1")
    assert resp.status_code in (200, 404)


def test_uploadcrackfile_unknown_jobtask_returns_404(client, agent_a, monkeypatch):
    client.set_cookie("uuid", agent_a["uuid"])
    # Neutralise the unrelated agent-heartbeat write: update_heartbeat persists a
    # strftime string into the DateTime last_checkin column, which the in-memory
    # SQLite test backend rejects (production MySQL accepts it). It is orthogonal
    # to the missing job-task lookup guard exercised here.
    monkeypatch.setattr("hashview.api.routes.update_heartbeat", lambda uuid: None)
    resp = client.post(
        "/v1/uploadCrackFile/999999",
        data=json.dumps({"file": ""}),
        content_type="application/json",
    )
    assert resp.status_code == 404


def test_search_missing_hash_key_is_handled(client, admin_user):
    client.set_cookie("uuid", admin_user["api_key"])
    resp = client.post(
        "/v1/search",
        data=json.dumps({"not_hash": "x"}),
        content_type="application/json",
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert "Invalid" in str(body.get("msg", ""))
