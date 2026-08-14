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
    Agents,
    Customers,
    Hashes,
    HashfileHashes,
    Hashfiles,
    Users,
    db,
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
    client.set_cookie("uuid", admin_user["api_key"], domain="localhost.test")
    resp = client.get("/v1/getHashType/999999")
    assert resp.status_code == 404


def test_get_hashtype_known_hashfile_returns_hash_type(client, admin_user, hashfile_with_hash):
    client.set_cookie("uuid", admin_user["api_key"], domain="localhost.test")
    resp = client.get("/v1/getHashType/{}".format(hashfile_with_hash["hashfile_id"]))
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["hash_type"] == 1000


def test_jobtasks_assignment_user_caller_returns_404(client, admin_user):
    # The route allows user=True, agent=True, but only an agent has an Agents
    # row; a user caller must not hit agent.id on None. Asserting the exact
    # status (not "not a 500") is what actually pins the new guard -- the old
    # code raised AttributeError here, which Flask turned into a 500.
    client.set_cookie("uuid", admin_user["api_key"], domain="localhost.test")
    resp = client.get("/v1/jobTasks/1")
    assert resp.status_code == 404
    assert "not found" in str(resp.get_json().get("msg", "")).lower()


def test_jobtasks_assignment_agent_caller_succeeds(client, agent_a, monkeypatch):
    """The guard must not break the caller it exists for: a real agent with no
    assignment still gets a 200 with a null job_task."""
    monkeypatch.setattr("hashview.api.routes.update_heartbeat", lambda uuid: None)
    client.set_cookie("uuid", agent_a["uuid"], domain="localhost.test")
    resp = client.get("/v1/jobTasks/1")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == 200


def test_uploadcrackfile_unknown_jobtask_returns_404(client, agent_a, monkeypatch):
    client.set_cookie("uuid", agent_a["uuid"], domain="localhost.test")
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
    client.set_cookie("uuid", admin_user["api_key"], domain="localhost.test")
    resp = client.post(
        "/v1/search",
        data=json.dumps({"not_hash": "x"}),
        content_type="application/json",
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert "Invalid" in str(body.get("msg", ""))


@pytest.mark.parametrize("payload", [{"hash": ""}, {"hash": None}])
def test_search_falsy_hash_value_is_handled(client, admin_user, payload):
    """``search_json['hash']`` -> ``.get('hash')`` also has to survive a key
    that's present but empty, which is what an empty search box submits."""
    client.set_cookie("uuid", admin_user["api_key"], domain="localhost.test")
    resp = client.post(
        "/v1/search", data=json.dumps(payload), content_type="application/json"
    )
    assert resp.status_code == 200
    assert "Invalid" in str(resp.get_json().get("msg", ""))


# --------------------------------------------------------------------------- #
# uploadCrackFile walks job_task -> job -> hashfile -> hashfilehashes -> hash. #
# Each hop got a guard; each hop is reachable with an orphaned row (job_id,    #
# hashfile_id and hash_id are plain integer columns, not enforced FKs, and     #
# deletes have historically left orphans behind).                             #
# --------------------------------------------------------------------------- #


@pytest.fixture()
def no_heartbeat(monkeypatch):
    """update_heartbeat persists a strftime string into the DateTime
    last_checkin column, which in-memory SQLite rejects (production MySQL
    accepts it). Orthogonal to the lookup guards under test."""
    monkeypatch.setattr("hashview.api.routes.update_heartbeat", lambda uuid: None)


def _upload(client, job_task_id):
    return client.post(
        f"/v1/uploadCrackFile/{job_task_id}",
        data=json.dumps({"file": ""}),
        content_type="application/json",
    )


def _job_task(app, **fields):
    from hashview.models import JobTasks

    with app.app_context():
        job_task = JobTasks(status="Running", priority=3, task_id=1, **fields)
        db.session.add(job_task)
        db.session.commit()
        return job_task.id


def test_uploadcrackfile_orphaned_job_returns_404(client, app, agent_a, no_heartbeat):
    """A job_task whose job row is gone."""
    client.set_cookie("uuid", agent_a["uuid"], domain="localhost.test")
    job_task_id = _job_task(app, job_id=999999)

    resp = _upload(client, job_task_id)

    assert resp.status_code == 404
    assert resp.get_json()["msg"] == "Job not found"


def test_uploadcrackfile_orphaned_hashfile_returns_404(
    client, app, agent_a, admin_user, no_heartbeat
):
    """A job pointing at a hashfile row that no longer exists."""
    from hashview.models import Jobs

    with app.app_context():
        customer = Customers(name="Acme")
        user = Users.query.filter_by(api_key=admin_user["api_key"]).first()
        db.session.add(customer)
        db.session.commit()
        job = Jobs(
            name="j",
            status="Running",
            hashfile_id=999999,
            customer_id=customer.id,
            owner_id=user.id,
        )
        db.session.add(job)
        db.session.commit()
        job_id = job.id

    client.set_cookie("uuid", agent_a["uuid"], domain="localhost.test")
    resp = _upload(client, _job_task(app, job_id=job_id))

    assert resp.status_code == 404
    assert resp.get_json()["msg"] == "Hashfile not found"


def test_uploadcrackfile_hashfile_with_no_hashes_returns_404(
    client, app, agent_a, admin_user, no_heartbeat
):
    """A hashfile that exists but holds no HashfileHashes rows -- the case that
    dereferenced ``hashfilehashes.hash_id`` on None."""
    from hashview.models import Jobs

    with app.app_context():
        customer = Customers(name="Acme")
        user = Users.query.filter_by(api_key=admin_user["api_key"]).first()
        db.session.add(customer)
        db.session.commit()
        hashfile = Hashfiles(name="empty", customer_id=customer.id, owner_id=user.id)
        db.session.add(hashfile)
        db.session.commit()
        job = Jobs(
            name="j",
            status="Running",
            hashfile_id=hashfile.id,
            customer_id=customer.id,
            owner_id=user.id,
        )
        db.session.add(job)
        db.session.commit()
        job_id = job.id

    client.set_cookie("uuid", agent_a["uuid"], domain="localhost.test")
    resp = _upload(client, _job_task(app, job_id=job_id))

    assert resp.status_code == 404
    assert resp.get_json()["msg"] == "Hashfile hashes not found"


def test_uploadcrackfile_orphaned_hash_returns_404(
    client, app, agent_a, admin_user, no_heartbeat
):
    """A HashfileHashes row whose Hashes row is gone."""
    from hashview.models import Jobs

    with app.app_context():
        customer = Customers(name="Acme")
        user = Users.query.filter_by(api_key=admin_user["api_key"]).first()
        db.session.add(customer)
        db.session.commit()
        hashfile = Hashfiles(name="orphan", customer_id=customer.id, owner_id=user.id)
        db.session.add(hashfile)
        db.session.commit()
        db.session.add(HashfileHashes(hash_id=999999, hashfile_id=hashfile.id))
        job = Jobs(
            name="j",
            status="Running",
            hashfile_id=hashfile.id,
            customer_id=customer.id,
            owner_id=user.id,
        )
        db.session.add(job)
        db.session.commit()
        job_id = job.id

    client.set_cookie("uuid", agent_a["uuid"], domain="localhost.test")
    resp = _upload(client, _job_task(app, job_id=job_id))

    assert resp.status_code == 404
    assert resp.get_json()["msg"] == "Hash not found"


def test_gethashtype_orphaned_hash_returns_404(client, app, admin_user):
    """getHashType has the same second hop: the hashfile has a junction row but
    the Hashes row it names is missing."""
    with app.app_context():
        customer = Customers(name="Acme")
        user = Users.query.filter_by(api_key=admin_user["api_key"]).first()
        db.session.add(customer)
        db.session.commit()
        hashfile = Hashfiles(name="hf", customer_id=customer.id, owner_id=user.id)
        db.session.add(hashfile)
        db.session.commit()
        db.session.add(HashfileHashes(hash_id=999999, hashfile_id=hashfile.id))
        db.session.commit()
        hashfile_id = hashfile.id

    client.set_cookie("uuid", admin_user["api_key"], domain="localhost.test")
    resp = client.get(f"/v1/getHashType/{hashfile_id}")

    assert resp.status_code == 404
    assert resp.get_json()["msg"] == "Hash not found"
