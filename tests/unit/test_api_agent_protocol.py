"""Regression tests for agent-facing v1 API protocol endpoints
(function-coverage batch: api).

Auth recap (see hashview/api/routes.py is_authorized): the 'uuid' cookie maps
to Users.api_key (user routes) or Agents.uuid with an active status (agent
routes). Cookie domain must equal the test SERVER_NAME (localhost.test).
"""

import json

import hashview
from hashview.models import (
    Agents,
    Customers,
    Hashes,
    HashfileHashes,
    Hashfiles,
    JobTasks,
    Jobs,
    Settings,
    Tasks,
    Users,
    db,
)

DOMAIN = "localhost.test"


def _agent(uuid="agent-uuid", status="Idle"):
    a = Agents(name="a1", src_ip="127.0.0.1", uuid=uuid, status=status)
    db.session.add(a)
    db.session.commit()
    return a


def _user(api_key="user-key"):
    u = Users(first_name="U", last_name="Sr", email_address="u@e.com",
              password="x" * 60, admin=True, api_key=api_key)
    db.session.add(u)
    db.session.commit()
    return u


def _body(resp):
    return json.loads(resp.get_data(as_text=True))


# --- pure / static responses ------------------------------------------------

def test_version_check():
    from hashview.api.routes import versionCheck
    assert versionCheck(None) is False
    assert versionCheck("0.0.1") is False           # older than current
    assert versionCheck(hashview.__version__) is True


def test_unauthorized_envelope(app, client):
    body = _body(client.get("/v1/not_authorized"))
    assert body["status"] == 200
    assert body["type"] == "Error"
    assert "not authorized" in body["msg"].lower()


def test_upgrade_required_envelope(app, client):
    body = _body(client.get("/v1/upgrade_required"))
    assert body["status"] == 426
    assert "update your agent" in body["msg"].lower()


# --- heartbeat --------------------------------------------------------------

def _set_agent_cookies(client, uuid):
    client.set_cookie("uuid", uuid, domain=DOMAIN)
    client.set_cookie("agent_version", hashview.__version__, domain=DOMAIN)


def test_heartbeat_old_version_redirects_to_upgrade(app, client):
    client.set_cookie("uuid", "x", domain=DOMAIN)
    client.set_cookie("agent_version", "0.0.1", domain=DOMAIN)
    resp = client.post("/v1/agents/heartbeat", json={"agent_status": "Idle", "hc_status": ""})
    assert 300 <= resp.status_code < 400
    assert "upgrade_required" in resp.headers.get("Location", "")


def test_heartbeat_new_agent_is_registered_pending(app, client):
    db.session.add(Settings(max_runtime_tasks=0, max_runtime_jobs=0))
    db.session.commit()
    _set_agent_cookies(client, "brand-new-uuid")
    client.set_cookie("name", "fresh-agent", domain=DOMAIN)
    resp = client.post("/v1/agents/heartbeat", json={"agent_status": "Idle", "hc_status": ""})
    body = _body(resp)
    assert body["msg"] == "Go Away"
    agent = Agents.query.filter_by(uuid="brand-new-uuid").first()
    assert agent is not None and agent.status == "Pending"


def test_heartbeat_idle_agent_gets_queued_task(app, client):
    db.session.add(Settings(max_runtime_tasks=0, max_runtime_jobs=0))
    db.session.commit()
    agent = _agent(uuid="idle-agent", status="Idle")
    jt = JobTasks(job_id=1, task_id=1, status="Queued", priority=3)
    db.session.add(jt)
    db.session.commit()
    _set_agent_cookies(client, "idle-agent")
    resp = client.post("/v1/agents/heartbeat", json={"agent_status": "Idle", "hc_status": ""})
    body = _body(resp)
    assert body["msg"] == "START"
    assert body["job_task_id"] == jt.id
    assert JobTasks.query.get(jt.id).agent_id == agent.id


# --- read endpoints ---------------------------------------------------------

def test_get_update_wordlist_returns_ok(app, client, monkeypatch):
    _user()
    # patch the heavy regeneration helper at its use site in the route module
    monkeypatch.setattr("hashview.api.routes.update_dynamic_wordlist",
                        lambda wid, jid: None)
    client.set_cookie("uuid", "user-key", domain=DOMAIN)
    resp = client.get("/v1/updateWordlist/1")
    assert _body(resp)["status"] == 200


def test_get_queue_assignment_returns_assigned_task(app, client):
    agent = _agent(uuid="qa-agent", status="Working")
    jt = JobTasks(job_id=1, task_id=2, status="Running", priority=3, agent_id=agent.id)
    db.session.add(jt)
    db.session.commit()
    client.set_cookie("uuid", "qa-agent", domain=DOMAIN)
    resp = client.get(f"/v1/jobTasks/{jt.id}")
    body = _body(resp)
    assert body["status"] == 200
    assert json.loads(body["job_task"])["task_id"] == 2


def test_get_job_returns_job_json(app, client):
    _user()
    cust = Customers(name="C")
    db.session.add(cust)
    db.session.commit()
    job = Jobs(name="apijob", status="Ready", customer_id=cust.id, owner_id=1)
    db.session.add(job)
    db.session.commit()
    client.set_cookie("uuid", "user-key", domain=DOMAIN)
    resp = client.get(f"/v1/jobs/{job.id}")
    body = _body(resp)
    assert body["status"] == 200
    assert json.loads(body["job"])["name"] == "apijob"


def test_get_task_returns_task_json(app, client):
    user = _user()
    task = Tasks(name="apitask", owner_id=user.id, hc_attackmode=0)
    db.session.add(task)
    db.session.commit()
    client.set_cookie("uuid", "user-key", domain=DOMAIN)
    resp = client.get(f"/v1/tasks/{task.id}")
    body = _body(resp)
    assert body["status"] == 200
    assert json.loads(body["task"])["name"] == "apitask"


def test_get_hashtype_returns_mode(app, client):
    _user()
    hf = Hashfiles(name="hf", customer_id=1, owner_id=1)
    db.session.add(hf)
    db.session.commit()
    h = Hashes(sub_ciphertext="0" * 8, ciphertext="abc", hash_type=1000, cracked=False)
    db.session.add(h)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    db.session.commit()
    client.set_cookie("uuid", "user-key", domain=DOMAIN)
    resp = client.get(f"/v1/getHashType/{hf.id}")
    body = _body(resp)
    assert body["status"] == 200
    assert body["hash_type"] == 1000


def test_get_hashfile_serves_uncracked_ciphertext(app, client):
    _user()
    hf = Hashfiles(name="hf", customer_id=1, owner_id=1)
    db.session.add(hf)
    db.session.commit()
    h = Hashes(sub_ciphertext="0" * 8, ciphertext="UNCRACKEDHASH", hash_type=0, cracked=False)
    db.session.add(h)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    db.session.commit()
    client.set_cookie("uuid", "user-key", domain=DOMAIN)
    resp = client.get(f"/v1/hashfiles/{hf.id}")
    assert resp.status_code == 200
    assert b"UNCRACKEDHASH" in resp.data


# --- upload endpoints -------------------------------------------------------

def test_post_hashfile_upload_invalid_customer(app, client):
    _user()
    client.set_cookie("uuid", "user-key", domain=DOMAIN)
    resp = client.post("/v1/hashfiles/upload/99999/5/0/myfile",
                       data="deadbeef", content_type="text/plain")
    body = _body(resp)
    assert body["status"] == 400
    assert "customer" in body["msg"].lower()


def test_post_hashfile_upload_creates_hashfile(app, client):
    user = _user()
    cust = Customers(name="UpCo")
    db.session.add(cust)
    db.session.commit()
    client.set_cookie("uuid", "user-key", domain=DOMAIN)
    # file_format 5 = hash_only, hash_type 0 (raw MD5-style accepted by validator)
    resp = client.post(f"/v1/hashfiles/upload/{cust.id}/5/0/myfile",
                       data="5f4dcc3b5aa765d61d8327deb882cf99",
                       content_type="text/plain")
    body = _body(resp)
    assert body["status"] == 200
    assert body["msg"] == "Hashfile added"
    assert Hashfiles.query.get(body["hashfile_id"]) is not None


# --- privilege boundaries ---------------------------------------------------

def test_user_only_route_rejects_agent(app, client):
    _agent(uuid="agentx", status="Idle")
    client.set_cookie("uuid", "agentx", domain=DOMAIN)
    resp = client.post("/v1/hashfiles/upload/1/5/0/f", data="x", content_type="text/plain")
    assert 300 <= resp.status_code < 400
    assert "not_authorized" in resp.headers.get("Location", "")


def test_agent_only_route_rejects_user(app, client):
    _user()
    client.set_cookie("uuid", "user-key", domain=DOMAIN)
    resp = client.post("/v1/uploadCrackFile/1", json={"file": ""})
    assert 300 <= resp.status_code < 400
    assert "not_authorized" in resp.headers.get("Location", "")
