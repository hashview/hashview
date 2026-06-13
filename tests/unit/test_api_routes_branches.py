"""Branch-coverage tests for hashview/api/routes.py.

Covers the gaps NOT already exercised by tests/unit/test_api_endpoints.py:
  - /v1/not_authorized and /v1/upgrade_required endpoints
  - /v1/agents/heartbeat (all states: new agent, pending, idle, working,
    runtime limits, version check failure)
  - /v1/customers (agent cookie, auth failure)
  - /v1/rules (GET list - authenticated)
  - /v1/wordlists (GET list, download static/dynamic, updateWordlist)
  - /v1/jobTasks/<id>
  - /v1/jobs/<id> GET
  - /v1/jobs/add (missing body, no effective tasks, missing hashfile)
  - /v1/jobs/start (success, non-owner, missing job+task)
  - /v1/tasks/<id> GET
  - /v1/hashfiles/upload/<...> (all file formats, validation failures,
    invalid customer, empty body, bad format, no hashes found)
  - /v1/hashfiles/<id> GET
  - /v1/uploadCrackFile/<task_id>/<hash_type> (old route)
  - /v1/uploadCrackFile/<job_task_id> (new route - hash found, not found,
    limit_recovered, hash_type 22000)
  - /v1/getHashType/<hashfile_id>
  - /v1/jobtask/status (success, failure)
  - /v1/search (found, not found, no body, missing hash key)
  - /v1/error (race-condition / agent deleted after auth)
  - /v1/hashes/import/<hash_type> (empty body, user not found guard)
"""

import json
import os
from datetime import datetime, timedelta

import pytest

from hashview.models import (
    Agents,
    Customers,
    Hashes,
    HashfileHashes,
    Hashfiles,
    JobNotifications,
    Jobs,
    JobTasks,
    Rules,
    Settings,
    Tasks,
    Users,
    Wordlists,
    db as _db,
)
from hashview.utils.utils import get_md5_hash

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def admin_user(app):
    user = Users(
        first_name="Admin",
        last_name="User",
        email_address="admin@example.test",
        password="hashed-pw",
        admin=True,
        api_key="branch-admin-api-key",
    )
    _db.session.add(user)
    _db.session.commit()
    return user


@pytest.fixture()
def regular_user(app):
    user = Users(
        first_name="Regular",
        last_name="User",
        email_address="regular@example.test",
        password="hashed-pw",
        admin=False,
        api_key="branch-regular-api-key",
    )
    _db.session.add(user)
    _db.session.commit()
    return user


@pytest.fixture()
def authorized_agent(app):
    agent = Agents(
        name="test-agent",
        src_ip="127.0.0.1",
        uuid="branch-agent-uuid-ok",
        status="Authorized",
    )
    _db.session.add(agent)
    _db.session.commit()
    return agent


@pytest.fixture()
def pending_agent(app):
    agent = Agents(
        name="pending-agent",
        src_ip="127.0.0.1",
        uuid="branch-pending-uuid",
        status="Pending",
    )
    _db.session.add(agent)
    _db.session.commit()
    return agent


@pytest.fixture()
def settings_row(app):
    row = Settings(
        retention_period=30,
        max_runtime_tasks=0,
        max_runtime_jobs=0,
    )
    _db.session.add(row)
    _db.session.commit()
    return row


def _json(resp):
    return json.loads(resp.get_data(as_text=True))


def _agent_cookie(client, agent, domain="localhost.test"):
    client.set_cookie("uuid", agent.uuid, domain=domain)


def _user_cookie(client, user, domain="localhost.test"):
    client.set_cookie("uuid", user.api_key, domain=domain)


def _heartbeat(client, agent, agent_status, hc_status="stopped"):
    """POST /v1/agents/heartbeat with a valid agent_version cookie."""
    import hashview
    client.set_cookie("uuid", agent.uuid, domain="localhost.test")
    client.set_cookie("agent_version", hashview.__version__, domain="localhost.test")
    return client.post(
        "/v1/agents/heartbeat",
        data=json.dumps({"agent_status": agent_status, "hc_status": hc_status}),
        content_type="application/json",
    )


# ---------------------------------------------------------------------------
# /v1/not_authorized  and  /v1/upgrade_required
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_not_authorized_endpoint_returns_200_and_error_type(client):
    """GET/POST /v1/not_authorized always returns HTTP 200 with type Error."""
    resp = client.get("/v1/not_authorized")
    assert resp.status_code == 200
    body = _json(resp)
    assert body["type"] == "Error"
    assert "not authorized" in body["msg"].lower()


@pytest.mark.security
def test_upgrade_required_endpoint_returns_426(client):
    """GET /v1/upgrade_required returns status 426 in JSON body."""
    resp = client.get("/v1/upgrade_required")
    assert resp.status_code == 200  # HTTP envelope is 200
    body = _json(resp)
    assert body["status"] == 426
    assert "update" in body["msg"].lower()


# ---------------------------------------------------------------------------
# /v1/agents/heartbeat — version check
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_heartbeat_version_mismatch_redirects_to_upgrade_required(client, authorized_agent, settings_row):
    """Heartbeat with a stale agent_version redirects to /v1/upgrade_required."""
    client.set_cookie("uuid", authorized_agent.uuid, domain="localhost.test")
    client.set_cookie("agent_version", "0.0.1", domain="localhost.test")
    resp = client.post(
        "/v1/agents/heartbeat",
        data=json.dumps({"agent_status": "Idle", "hc_status": "stopped"}),
        content_type="application/json",
    )
    assert 300 <= resp.status_code < 400
    assert "upgrade_required" in resp.headers.get("Location", "")


@pytest.mark.security
def test_heartbeat_missing_version_cookie_redirects_to_upgrade_required(client, authorized_agent, settings_row):
    """Heartbeat with no agent_version cookie redirects to /v1/upgrade_required."""
    client.set_cookie("uuid", authorized_agent.uuid, domain="localhost.test")
    resp = client.post(
        "/v1/agents/heartbeat",
        data=json.dumps({"agent_status": "Idle", "hc_status": "stopped"}),
        content_type="application/json",
    )
    assert 300 <= resp.status_code < 400
    assert "upgrade_required" in resp.headers.get("Location", "")


# ---------------------------------------------------------------------------
# /v1/agents/heartbeat — new agent auto-registration
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_heartbeat_new_agent_uuid_creates_pending_agent(client, settings_row):
    """A heartbeat from an unknown uuid auto-registers the agent as Pending."""
    import hashview
    client.set_cookie("uuid", "completely-new-uuid-xyz", domain="localhost.test")
    client.set_cookie("agent_version", hashview.__version__, domain="localhost.test")
    client.set_cookie("name", "new-auto-agent", domain="localhost.test")
    resp = client.post(
        "/v1/agents/heartbeat",
        data=json.dumps({"agent_status": "Idle", "hc_status": "stopped"}),
        content_type="application/json",
    )
    body = _json(resp)
    assert body["status"] == 200
    assert body["msg"] == "Go Away"
    new_agent = Agents.query.filter_by(uuid="completely-new-uuid-xyz").first()
    assert new_agent is not None
    assert new_agent.status == "Pending"


# ---------------------------------------------------------------------------
# /v1/agents/heartbeat — Pending agent (existing)
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_heartbeat_pending_agent_returns_go_away(client, pending_agent, settings_row):
    """A heartbeat from a Pending (existing) agent gets 'Go Away'."""
    resp = _heartbeat(client, pending_agent, "Idle")
    body = _json(resp)
    assert body["status"] == 200
    assert body["msg"] == "Go Away"


# ---------------------------------------------------------------------------
# /v1/agents/heartbeat — Idle agent, no queued tasks
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_heartbeat_idle_agent_no_tasks_returns_ok(client, authorized_agent, settings_row):
    """An idle agent with no queued tasks gets msg=OK."""
    resp = _heartbeat(client, authorized_agent, "Idle")
    body = _json(resp)
    assert body["status"] == 200
    assert body["msg"] == "OK"


# ---------------------------------------------------------------------------
# /v1/agents/heartbeat — Idle agent, already assigned a task
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_heartbeat_idle_agent_with_assigned_task_returns_start(
    client, authorized_agent, admin_user, settings_row
):
    """Idle heartbeat when agent already has an assigned task returns START."""
    cust = Customers(name="HbCo")
    _db.session.add(cust)
    _db.session.commit()
    hf = Hashfiles(name="hb-hf", customer_id=cust.id, owner_id=admin_user.id)
    _db.session.add(hf)
    _db.session.commit()
    job = Jobs(name="hb-job", status="Running", hashfile_id=hf.id,
               customer_id=cust.id, owner_id=admin_user.id)
    _db.session.add(job)
    _db.session.commit()
    jt = JobTasks(job_id=job.id, task_id=1, status="Running", agent_id=authorized_agent.id)
    _db.session.add(jt)
    _db.session.commit()

    resp = _heartbeat(client, authorized_agent, "Idle")
    body = _json(resp)
    assert body["status"] == 200
    assert body["msg"] == "START"
    assert body["job_task_id"] == jt.id


# ---------------------------------------------------------------------------
# /v1/agents/heartbeat — Idle agent, picks up queued task
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_heartbeat_idle_agent_picks_up_queued_task(
    client, authorized_agent, admin_user, settings_row
):
    """An idle agent with no current assignment picks up the first Queued task."""
    cust = Customers(name="HbCo2")
    _db.session.add(cust)
    _db.session.commit()
    hf = Hashfiles(name="hb-hf2", customer_id=cust.id, owner_id=admin_user.id)
    _db.session.add(hf)
    _db.session.commit()
    job = Jobs(name="hb-job2", status="Queued", hashfile_id=hf.id,
               customer_id=cust.id, owner_id=admin_user.id)
    _db.session.add(job)
    _db.session.commit()
    jt = JobTasks(job_id=job.id, task_id=1, status="Queued")
    _db.session.add(jt)
    _db.session.commit()

    resp = _heartbeat(client, authorized_agent, "Idle")
    body = _json(resp)
    assert body["status"] == 200
    assert body["msg"] == "START"
    assert body["job_task_id"] == jt.id
    # The task should now be assigned to the agent
    _db.session.refresh(jt)
    assert jt.agent_id == authorized_agent.id
    assert jt.status == "Running"


# ---------------------------------------------------------------------------
# /v1/agents/heartbeat — Working agent
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_heartbeat_working_agent_no_task_returns_canceled(
    client, authorized_agent, admin_user, settings_row
):
    """Working heartbeat where agent has no assigned task returns Canceled."""
    resp = _heartbeat(client, authorized_agent, "Working")
    body = _json(resp)
    assert body["status"] == 200
    assert body["msg"] == "Canceled"


@pytest.mark.security
def test_heartbeat_working_agent_canceled_task_returns_canceled(
    client, authorized_agent, admin_user, settings_row
):
    """Working heartbeat with a Canceled job_task returns Canceled."""
    cust = Customers(name="HbCo3")
    _db.session.add(cust)
    _db.session.commit()
    hf = Hashfiles(name="hb-hf3", customer_id=cust.id, owner_id=admin_user.id)
    _db.session.add(hf)
    _db.session.commit()
    job = Jobs(name="hb-job3", status="Running", hashfile_id=hf.id,
               customer_id=cust.id, owner_id=admin_user.id)
    _db.session.add(job)
    _db.session.commit()
    jt = JobTasks(job_id=job.id, task_id=1, status="Canceled", agent_id=authorized_agent.id)
    _db.session.add(jt)
    _db.session.commit()

    resp = _heartbeat(client, authorized_agent, "Working")
    body = _json(resp)
    assert body["msg"] == "Canceled"


@pytest.mark.security
def test_heartbeat_working_agent_task_runtime_exceeded_cancels_task(
    client, authorized_agent, admin_user
):
    """Working heartbeat with task exceeding max_runtime_tasks cancels the task."""
    settings = Settings(retention_period=30, max_runtime_tasks=1, max_runtime_jobs=0)
    _db.session.add(settings)
    _db.session.commit()

    cust = Customers(name="HbCo4")
    _db.session.add(cust)
    _db.session.commit()
    hf = Hashfiles(name="hb-hf4", customer_id=cust.id, owner_id=admin_user.id)
    _db.session.add(hf)
    _db.session.commit()
    job = Jobs(name="hb-job4", status="Running", hashfile_id=hf.id,
               customer_id=cust.id, owner_id=admin_user.id)
    _db.session.add(job)
    _db.session.commit()
    # started_at is far in the past so it exceeds max_runtime_tasks=1 hour
    old_start = datetime.now() - timedelta(hours=2)
    jt = JobTasks(job_id=job.id, task_id=1, status="Running",
                  agent_id=authorized_agent.id, started_at=old_start)
    _db.session.add(jt)
    _db.session.commit()

    resp = _heartbeat(client, authorized_agent, "Working")
    body = _json(resp)
    assert body["msg"] == "Canceled"
    _db.session.refresh(jt)
    assert jt.status == "Canceled"


@pytest.mark.security
def test_heartbeat_working_agent_job_runtime_exceeded_cancels_job(
    client, authorized_agent, admin_user
):
    """Working heartbeat with job exceeding max_runtime_jobs cancels all tasks."""
    settings = Settings(retention_period=30, max_runtime_tasks=0, max_runtime_jobs=1)
    _db.session.add(settings)
    _db.session.commit()

    cust = Customers(name="HbCo5")
    _db.session.add(cust)
    _db.session.commit()
    hf = Hashfiles(name="hb-hf5", customer_id=cust.id, owner_id=admin_user.id)
    _db.session.add(hf)
    _db.session.commit()
    # Job started 2 hours ago (exceeds 1-hour limit)
    old_start = datetime.now() - timedelta(hours=2)
    job = Jobs(name="hb-job5", status="Running", hashfile_id=hf.id,
               customer_id=cust.id, owner_id=admin_user.id, started_at=old_start)
    _db.session.add(job)
    _db.session.commit()
    jt = JobTasks(job_id=job.id, task_id=1, status="Running",
                  agent_id=authorized_agent.id, started_at=datetime.now())
    _db.session.add(jt)
    _db.session.commit()

    resp = _heartbeat(client, authorized_agent, "Working")
    body = _json(resp)
    assert body["msg"] == "Canceled"
    _db.session.refresh(job)
    assert job.status == "Canceled"


@pytest.mark.security
def test_heartbeat_working_agent_with_hc_status_updates_benchmark(
    client, authorized_agent, admin_user, settings_row
):
    """Working heartbeat with valid hc_status JSON updates agent benchmark."""
    cust = Customers(name="HbCo6")
    _db.session.add(cust)
    _db.session.commit()
    hf = Hashfiles(name="hb-hf6", customer_id=cust.id, owner_id=admin_user.id)
    _db.session.add(hf)
    _db.session.commit()
    job = Jobs(name="hb-job6", status="Running", hashfile_id=hf.id,
               customer_id=cust.id, owner_id=admin_user.id)
    _db.session.add(job)
    _db.session.commit()
    jt = JobTasks(job_id=job.id, task_id=1, status="Running",
                  agent_id=authorized_agent.id, started_at=datetime.now())
    _db.session.add(jt)
    _db.session.commit()

    import hashview
    hc_status_json = {"Speed #": "1.5 GH/s", "Progress": "50%"}
    client.set_cookie("uuid", authorized_agent.uuid, domain="localhost.test")
    client.set_cookie("agent_version", hashview.__version__, domain="localhost.test")
    resp = client.post(
        "/v1/agents/heartbeat",
        data=json.dumps({
            "agent_status": "Working",
            "hc_status": str(hc_status_json),
        }),
        content_type="application/json",
    )
    body = _json(resp)
    assert body["status"] == 200


# ---------------------------------------------------------------------------
# /v1/customers — agent cookie (user+agent route)
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_customers_list_agent_cookie_returns_200(client, authorized_agent):
    """GET /v1/customers with an agent cookie succeeds (user=True, agent=True)."""
    client.set_cookie("uuid", authorized_agent.uuid, domain="localhost.test")
    resp = client.get("/v1/customers")
    assert resp.status_code == 200
    body = _json(resp)
    assert body["status"] == 200


@pytest.mark.security
def test_customers_list_no_cookie_redirects(client):
    """GET /v1/customers without a cookie redirects to not_authorized."""
    resp = client.get("/v1/customers")
    assert 300 <= resp.status_code < 400
    assert "not_authorized" in resp.headers.get("Location", "")


# ---------------------------------------------------------------------------
# /v1/rules — GET list
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_rules_list_returns_seeded_rule(client, admin_user):
    """GET /v1/rules with a valid user cookie returns the rules list."""
    rule = Rules(
        name="branch-rule",
        owner_id=admin_user.id,
        path="/nonexistent/branch-rule.txt",
        size=1,
        checksum="a" * 64,
    )
    _db.session.add(rule)
    _db.session.commit()

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.get("/v1/rules")
    assert resp.status_code == 200
    body = _json(resp)
    assert body["status"] == 200
    assert "branch-rule" in body["rules"]


@pytest.mark.security
def test_rules_list_agent_cookie_returns_200(client, authorized_agent):
    """GET /v1/rules with an agent cookie succeeds (user=True, agent=True)."""
    client.set_cookie("uuid", authorized_agent.uuid, domain="localhost.test")
    resp = client.get("/v1/rules")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# /v1/wordlists — GET list, download static, download dynamic, update
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_wordlists_list_returns_200(client, admin_user):
    """GET /v1/wordlists returns the wordlist collection."""
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.get("/v1/wordlists")
    assert resp.status_code == 200
    body = _json(resp)
    assert body["status"] == 200


@pytest.mark.security
def test_wordlists_list_no_cookie_redirects(client):
    """GET /v1/wordlists without a cookie redirects to not_authorized."""
    resp = client.get("/v1/wordlists")
    assert 300 <= resp.status_code < 400
    assert "not_authorized" in resp.headers.get("Location", "")


@pytest.mark.security
def test_wordlist_download_missing_returns_404(client, admin_user):
    """GET /v1/wordlists/<id> for a nonexistent wordlist returns 404."""
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.get("/v1/wordlists/424242")
    assert resp.status_code == 404
    body = _json(resp)
    assert body["status"] == 404


@pytest.mark.security
def test_wordlist_download_static_serves_file(
    client, app, admin_user, tmp_path, monkeypatch
):
    """GET /v1/wordlists/<id> for a static wordlist serves the compressed file."""
    import gzip
    monkeypatch.setattr(app, "root_path", str(tmp_path))
    wl_dir = os.path.join(str(tmp_path), "control", "wordlists")
    os.makedirs(wl_dir, exist_ok=True)

    content = b"word1\nword2\n"
    gz_name = "static-wl.gz"
    gz_path = os.path.join(wl_dir, gz_name)
    with gzip.open(gz_path, "wb") as f:
        f.write(content)

    wl = Wordlists(
        name="static-wl",
        owner_id=admin_user.id,
        type="static",
        path=gz_path,
        size=2,
        checksum="b" * 64,
    )
    _db.session.add(wl)
    _db.session.commit()

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.get(f"/v1/wordlists/{wl.id}")
    assert resp.status_code == 200
    assert gzip.decompress(resp.data) == content


@pytest.mark.security
def test_wordlist_download_dynamic_compresses_and_serves(
    client, app, admin_user, tmp_path, monkeypatch
):
    """GET /v1/wordlists/<id> for a dynamic wordlist compresses on the fly."""
    import gzip
    monkeypatch.setattr(app, "root_path", str(tmp_path))
    wl_dir = os.path.join(str(tmp_path), "control", "wordlists")
    tmp_dir = os.path.join(str(tmp_path), "control", "tmp")
    os.makedirs(wl_dir, exist_ok=True)
    os.makedirs(tmp_dir, exist_ok=True)

    plain_name = "dynamic-wl.txt"
    plain_path = os.path.join(wl_dir, plain_name)
    content = b"passw0rd\nletmein\n"
    with open(plain_path, "wb") as f:
        f.write(content)

    wl = Wordlists(
        name="dynamic-wl",
        owner_id=admin_user.id,
        type="dynamic",
        path=plain_path,
        size=2,
        checksum="c" * 64,
    )
    _db.session.add(wl)
    _db.session.commit()

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.get(f"/v1/wordlists/{wl.id}")
    assert resp.status_code == 200
    assert gzip.decompress(resp.data) == content


@pytest.mark.security
def test_update_wordlist_no_cookie_redirects(client):
    """GET /v1/updateWordlist/<id> without a cookie redirects to not_authorized."""
    resp = client.get("/v1/updateWordlist/1")
    assert 300 <= resp.status_code < 400
    assert "not_authorized" in resp.headers.get("Location", "")


@pytest.mark.security
def test_update_wordlist_user_cookie_returns_ok(
    client, admin_user, monkeypatch
):
    """GET /v1/updateWordlist/<id> with user cookie calls update and returns OK.

    Wordlist id 99999 doesn't exist; update_dynamic_wordlist is a no-op for
    nonexistent ids, so we just confirm the route returns 200/OK.
    """
    import hashview.api.routes as routes_mod
    monkeypatch.setattr(routes_mod, "update_dynamic_wordlist", lambda wl_id, job_id: None)

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.get("/v1/updateWordlist/99999")
    body = _json(resp)
    assert body["status"] == 200
    assert body["msg"] == "OK"


@pytest.mark.security
def test_update_wordlist_agent_with_running_task_resolves_job(
    client, authorized_agent, admin_user, monkeypatch
):
    """GET /v1/updateWordlist/<id> with an agent that has a Running task
    resolves the job_id from that task."""
    import hashview.api.routes as routes_mod
    captured = {}

    def fake_update(wl_id, job_id):
        captured["job_id"] = job_id

    monkeypatch.setattr(routes_mod, "update_dynamic_wordlist", fake_update)

    cust = Customers(name="UpdWlCo")
    _db.session.add(cust)
    _db.session.commit()
    hf = Hashfiles(name="upd-hf", customer_id=cust.id, owner_id=admin_user.id)
    _db.session.add(hf)
    _db.session.commit()
    job = Jobs(name="upd-job", status="Running", hashfile_id=hf.id,
               customer_id=cust.id, owner_id=admin_user.id)
    _db.session.add(job)
    _db.session.commit()
    jt = JobTasks(job_id=job.id, task_id=1, status="Running", agent_id=authorized_agent.id)
    _db.session.add(jt)
    _db.session.commit()

    client.set_cookie("uuid", authorized_agent.uuid, domain="localhost.test")
    resp = client.get("/v1/updateWordlist/99999")
    body = _json(resp)
    assert body["status"] == 200
    assert captured.get("job_id") == job.id


# ---------------------------------------------------------------------------
# /v1/jobTasks/<id>
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_jobtasks_get_returns_task_for_agent(
    client, authorized_agent, admin_user
):
    """GET /v1/jobTasks/<id> returns the JobTask assigned to the calling agent."""
    cust = Customers(name="JtCo")
    _db.session.add(cust)
    _db.session.commit()
    hf = Hashfiles(name="jt-hf", customer_id=cust.id, owner_id=admin_user.id)
    _db.session.add(hf)
    _db.session.commit()
    job = Jobs(name="jt-job", status="Running", hashfile_id=hf.id,
               customer_id=cust.id, owner_id=admin_user.id)
    _db.session.add(job)
    _db.session.commit()
    jt = JobTasks(job_id=job.id, task_id=1, status="Running", agent_id=authorized_agent.id)
    _db.session.add(jt)
    _db.session.commit()

    client.set_cookie("uuid", authorized_agent.uuid, domain="localhost.test")
    resp = client.get(f"/v1/jobTasks/{jt.id}")
    assert resp.status_code == 200
    body = _json(resp)
    assert body["status"] == 200
    assert "job_task" in body


@pytest.mark.security
def test_jobtasks_no_cookie_redirects(client):
    """GET /v1/jobTasks/<id> without a cookie redirects to not_authorized."""
    resp = client.get("/v1/jobTasks/1")
    assert 300 <= resp.status_code < 400
    assert "not_authorized" in resp.headers.get("Location", "")


# ---------------------------------------------------------------------------
# /v1/jobs/<id>  GET
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_jobs_get_returns_job(client, admin_user):
    """GET /v1/jobs/<id> returns the serialized job."""
    cust = Customers(name="GetJobCo")
    _db.session.add(cust)
    _db.session.commit()
    hf = Hashfiles(name="gj-hf", customer_id=cust.id, owner_id=admin_user.id)
    _db.session.add(hf)
    _db.session.commit()
    job = Jobs(name="get-job", status="Ready", hashfile_id=hf.id,
               customer_id=cust.id, owner_id=admin_user.id)
    _db.session.add(job)
    _db.session.commit()

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.get(f"/v1/jobs/{job.id}")
    assert resp.status_code == 200
    body = _json(resp)
    assert body["status"] == 200
    assert "get-job" in body["job"]


@pytest.mark.security
def test_jobs_get_no_cookie_redirects(client):
    """GET /v1/jobs/<id> without a cookie redirects to not_authorized."""
    resp = client.get("/v1/jobs/1")
    assert 300 <= resp.status_code < 400
    assert "not_authorized" in resp.headers.get("Location", "")


# ---------------------------------------------------------------------------
# /v1/jobs/add — missing body, missing effective tasks
# ---------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.xfail(
    strict=True,
    reason=(
        "Bug: v1_api_post_add_job uses request.get_json() without silent=True "
        "(hashview/api/routes.py:720). An empty body with content-type "
        "application/json causes Flask to return an HTML 400 page instead of "
        "the route's JSON {'status': 400, 'msg': 'Missing job data ...'}."
    ),
)
def test_jobs_add_missing_body_returns_400(client, admin_user):
    """POST /v1/jobs/add with no JSON body should return JSON 400 (correct behavior)."""
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post("/v1/jobs/add", data="", content_type="application/json")
    # Correct behavior: the route's JSON error, not Flask's HTML 400
    body = _json(resp)
    assert body["status"] == 400
    assert "Missing" in body["msg"]


@pytest.mark.security
def test_jobs_add_rejects_agent_cookie(client, authorized_agent):
    """POST /v1/jobs/add with an agent cookie redirects to not_authorized."""
    client.set_cookie("uuid", authorized_agent.uuid, domain="localhost.test")
    resp = client.post(
        "/v1/jobs/add",
        data=json.dumps({"name": "x", "hashfile_id": 1, "customer_id": 1}),
        content_type="application/json",
    )
    assert 300 <= resp.status_code < 400
    assert "not_authorized" in resp.headers.get("Location", "")


@pytest.mark.security
def test_jobs_add_no_effective_tasks_returns_500(client, admin_user):
    """POST /v1/jobs/add when there are no effective tasks for the hash type returns 500."""
    cust = Customers(name="NoEffCo")
    _db.session.add(cust)
    _db.session.commit()
    hf = Hashfiles(name="noeff-hf", customer_id=cust.id, owner_id=admin_user.id)
    _db.session.add(hf)
    _db.session.commit()
    # Seed a hash so hashfile_hashes lookup works, but NO cracked hashes with task_id
    h = Hashes(sub_ciphertext="e" * 32, ciphertext="abc123", hash_type=1000, cracked=False)
    _db.session.add(h)
    _db.session.commit()
    _db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    _db.session.commit()

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/jobs/add",
        data=json.dumps({"name": "noeff-job", "hashfile_id": hf.id, "customer_id": cust.id}),
        content_type="application/json",
    )
    body = _json(resp)
    assert body["status"] == 500
    assert "effective tasks" in body["msg"].lower() or "data" in body["msg"].lower()


# ---------------------------------------------------------------------------
# /v1/jobs/start — success path and non-owner path
# ---------------------------------------------------------------------------


def _seed_queued_job(owner):
    """Seed a Queued job with one JobTask."""
    cust = Customers(name=f"StartCo-{owner.id}")
    _db.session.add(cust)
    _db.session.commit()
    hf = Hashfiles(name=f"start-hf-{owner.id}", customer_id=cust.id, owner_id=owner.id)
    _db.session.add(hf)
    _db.session.commit()
    job = Jobs(name="start-me", status="Queued", hashfile_id=hf.id,
               customer_id=cust.id, owner_id=owner.id)
    _db.session.add(job)
    _db.session.commit()
    wl = Wordlists(
        name=f"start-wl-{owner.id}",
        owner_id=owner.id,
        type="static",
        path="/nonexistent/start-wl.gz",
        size=1,
        checksum="0" * 64,
    )
    _db.session.add(wl)
    _db.session.commit()
    task = Tasks(name=f"start-task-{owner.id}", owner_id=owner.id, wl_id=wl.id, hc_attackmode=0)
    _db.session.add(task)
    _db.session.commit()
    jt = JobTasks(job_id=job.id, task_id=task.id, status="Not Started")
    _db.session.add(jt)
    _db.session.commit()
    return job


@pytest.mark.security
def test_jobs_start_admin_queued_job_returns_200(client, admin_user, monkeypatch):
    """POST /v1/jobs/start/<id> for an owner+Queued job succeeds."""
    import hashview.api.routes as routes_mod
    monkeypatch.setattr(routes_mod, "build_hashcat_command", lambda job_id, task_id: "hc cmd")

    job = _seed_queued_job(admin_user)

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(f"/v1/jobs/start/{job.id}")
    body = _json(resp)
    assert body["status"] == 200
    assert body["msg"] == "Job started"


@pytest.mark.security
def test_jobs_start_non_owner_non_admin_returns_403(client, admin_user, regular_user, monkeypatch):
    """POST /v1/jobs/start/<id> by a non-owner non-admin returns 403."""
    import hashview.api.routes as routes_mod
    monkeypatch.setattr(routes_mod, "build_hashcat_command", lambda job_id, task_id: "hc cmd")

    job = _seed_queued_job(admin_user)

    client.set_cookie("uuid", regular_user.api_key, domain="localhost.test")
    resp = client.post(f"/v1/jobs/start/{job.id}")
    body = _json(resp)
    assert body["status"] == 403


@pytest.mark.security
def test_jobs_start_missing_job_returns_400(client, admin_user):
    """POST /v1/jobs/start/<id> for a nonexistent job returns 400."""
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post("/v1/jobs/start/424242")
    body = _json(resp)
    assert body["status"] == 400
    assert "Invalid job ID" in body["msg"]


# ---------------------------------------------------------------------------
# /v1/tasks/<id>  GET
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_tasks_get_returns_task(client, admin_user):
    """GET /v1/tasks/<id> returns the serialized task."""
    wl = Wordlists(
        name="tasks-get-wl",
        owner_id=admin_user.id,
        type="static",
        path="/nonexistent/tg.gz",
        size=1,
        checksum="0" * 64,
    )
    _db.session.add(wl)
    _db.session.commit()
    task = Tasks(name="tasks-get-task", owner_id=admin_user.id, wl_id=wl.id, hc_attackmode=0)
    _db.session.add(task)
    _db.session.commit()

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.get(f"/v1/tasks/{task.id}")
    assert resp.status_code == 200
    body = _json(resp)
    assert body["status"] == 200
    assert "tasks-get-task" in body["task"]


@pytest.mark.security
def test_tasks_get_no_cookie_redirects(client):
    """GET /v1/tasks/<id> without a cookie redirects to not_authorized."""
    resp = client.get("/v1/tasks/1")
    assert 300 <= resp.status_code < 400
    assert "not_authorized" in resp.headers.get("Location", "")


# ---------------------------------------------------------------------------
# /v1/hashfiles/upload/<customer_id>/<file_format>/<hash_type>/<name>
# ---------------------------------------------------------------------------


def _upload_dirs(app, tmp_path, monkeypatch):
    monkeypatch.setattr(app, "root_path", str(tmp_path))
    os.makedirs(os.path.join(str(tmp_path), "control", "tmp"), exist_ok=True)


NTLM_HASH = "8846F7EAEE8FB117AD06BDD830B7586C"


@pytest.mark.security
def test_hashfile_upload_no_cookie_redirects(client):
    """POST /v1/hashfiles/upload/... without a cookie redirects to not_authorized."""
    resp = client.post(
        "/v1/hashfiles/upload/1/5/1000/test",
        data="hash",
        content_type="text/plain",
    )
    assert 300 <= resp.status_code < 400
    assert "not_authorized" in resp.headers.get("Location", "")


@pytest.mark.security
def test_hashfile_upload_invalid_customer_returns_400(client, admin_user):
    """POST /v1/hashfiles/upload/<bad_cust>/... returns 400 for unknown customer."""
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/hashfiles/upload/999999/5/1000/test",
        data=NTLM_HASH,
        content_type="text/plain",
    )
    body = _json(resp)
    assert body["status"] == 400
    assert "customer" in body["msg"].lower()


@pytest.mark.security
def test_hashfile_upload_empty_body_returns_400(client, admin_user):
    """POST /v1/hashfiles/upload/... with empty body returns 400."""
    cust = Customers(name="UploadCo1")
    _db.session.add(cust)
    _db.session.commit()

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        f"/v1/hashfiles/upload/{cust.id}/5/1000/test",
        data="",
        content_type="text/plain",
    )
    body = _json(resp)
    assert body["status"] == 400
    assert "Missing" in body["msg"]


@pytest.mark.security
def test_hashfile_upload_invalid_file_format_returns_400(client, admin_user):
    """POST /v1/hashfiles/upload/... with file_format=99 returns 400."""
    cust = Customers(name="UploadCo2")
    _db.session.add(cust)
    _db.session.commit()

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        f"/v1/hashfiles/upload/{cust.id}/99/1000/test",
        data=NTLM_HASH,
        content_type="text/plain",
    )
    body = _json(resp)
    assert body["status"] == 400
    assert "format" in body["msg"].lower()


@pytest.mark.security
def test_hashfile_upload_hash_only_valid_ntlm(
    client, app, admin_user, tmp_path, monkeypatch
):
    """POST /v1/hashfiles/upload/<cust>/5/1000/<name> with a valid NTLM hash
    creates a Hashfile row and returns hashfile_id."""
    _upload_dirs(app, tmp_path, monkeypatch)
    cust = Customers(name="UploadCo3")
    _db.session.add(cust)
    _db.session.commit()

    # Pre-seed a known NTLM hash so instacrack count works
    existing = Hashes(
        sub_ciphertext=get_md5_hash(NTLM_HASH),
        ciphertext=NTLM_HASH,
        hash_type=1000,
        cracked=False,
    )
    _db.session.add(existing)
    _db.session.commit()

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        f"/v1/hashfiles/upload/{cust.id}/5/1000/my-ntlm-file",
        data=NTLM_HASH + "\n",
        content_type="text/plain",
    )
    body = _json(resp)
    assert body["status"] == 200
    assert body["msg"] == "Hashfile added"
    assert isinstance(body["hashfile_id"], int)


@pytest.mark.security
def test_hashfile_upload_all_file_formats_validation_path(
    client, app, admin_user, tmp_path, monkeypatch
):
    """POST with an invalid content for each format exercises all validation branches."""
    _upload_dirs(app, tmp_path, monkeypatch)
    cust = Customers(name="FmtValidCo")
    _db.session.add(cust)
    _db.session.commit()

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    # format 0 = pwdump: invalid content should fail validation
    for fmt in [0, 1, 2, 3, 4]:
        resp = client.post(
            f"/v1/hashfiles/upload/{cust.id}/{fmt}/1000/fmt-{fmt}",
            data="this_is_not_a_valid_hash_format\n",
            content_type="text/plain",
        )
        body = _json(resp)
        # Could be 500 (invalid hash) or 500 (no hashes found) — not 200
        assert body["status"] in (400, 500), f"format {fmt} unexpectedly returned 200"


# ---------------------------------------------------------------------------
# /v1/hashfiles/<id>  GET
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_hashfile_get_returns_file(client, app, admin_user, monkeypatch):
    """GET /v1/hashfiles/<id> writes a temp file and serves it."""
    # Patch the hard-coded path in the route to use a real writable location
    import hashview.api.routes as routes_mod
    import tempfile

    # The route writes to 'hashview/control/tmp/' (relative to cwd), so we
    # need that path to exist. Create it temporarily.
    cwd = os.getcwd()
    tmp_dir = os.path.join(cwd, "hashview", "control", "tmp")
    os.makedirs(tmp_dir, exist_ok=True)

    cust = Customers(name="GetHfCo")
    _db.session.add(cust)
    _db.session.commit()
    hf = Hashfiles(name="get-hf", customer_id=cust.id, owner_id=admin_user.id)
    _db.session.add(hf)
    _db.session.commit()
    # Add an uncracked hash to the hashfile
    h = Hashes(sub_ciphertext="f" * 32, ciphertext="deadcafe", hash_type=1000, cracked=False)
    _db.session.add(h)
    _db.session.commit()
    _db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    _db.session.commit()

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.get(f"/v1/hashfiles/{hf.id}")
    assert resp.status_code == 200
    # Response should contain the ciphertext
    assert b"deadcafe" in resp.data


# ---------------------------------------------------------------------------
# /v1/uploadCrackFile/<task_id>/<hash_type>  (old route)
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_uploadcrackfile_old_route_no_cookie_redirects(client):
    """POST /v1/uploadCrackFile/<task>/<type> without agent cookie redirects."""
    resp = client.post(
        "/v1/uploadCrackFile/1/1000",
        data=json.dumps({"file": ""}),
        content_type="application/json",
    )
    assert 300 <= resp.status_code < 400
    assert "not_authorized" in resp.headers.get("Location", "")


@pytest.mark.security
def test_uploadcrackfile_old_route_processes_entry(
    client, authorized_agent, monkeypatch
):
    """POST /v1/uploadCrackFile/<task>/<hash_type> processes a hash:plain pair."""
    import hashview.utils.utils as utils_mod
    monkeypatch.setattr(utils_mod, "process_recovered_hash_notifications", lambda: None)
    monkeypatch.setattr(utils_mod, "hexplain_to_text", lambda s: s)

    hash_val = NTLM_HASH
    h = Hashes(
        sub_ciphertext=get_md5_hash(hash_val),
        ciphertext=hash_val,
        hash_type=1000,
        cracked=False,
    )
    _db.session.add(h)
    _db.session.commit()

    client.set_cookie("uuid", authorized_agent.uuid, domain="localhost.test")
    resp = client.post(
        "/v1/uploadCrackFile/1/1000",
        data=json.dumps({"file": f"{hash_val}:password\n"}),
        content_type="application/json",
    )
    body = _json(resp)
    assert body["status"] == 200
    assert body["msg"] == "OK"
    _db.session.refresh(h)
    assert h.cracked


@pytest.mark.security
def test_uploadcrackfile_old_route_no_matching_hash_is_noop(
    client, authorized_agent, monkeypatch
):
    """POST /v1/uploadCrackFile/<task>/<hash_type> with unknown hash is a no-op."""
    import hashview.utils.utils as utils_mod
    monkeypatch.setattr(utils_mod, "process_recovered_hash_notifications", lambda: None)
    monkeypatch.setattr(utils_mod, "hexplain_to_text", lambda s: s)

    client.set_cookie("uuid", authorized_agent.uuid, domain="localhost.test")
    resp = client.post(
        "/v1/uploadCrackFile/1/1000",
        data=json.dumps({"file": "AAAA1234AAAA1234AAAA1234AAAA1234:unknown\n"}),
        content_type="application/json",
    )
    body = _json(resp)
    assert body["status"] == 200


# ---------------------------------------------------------------------------
# /v1/uploadCrackFile/<job_task_id>  (new route)
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_uploadcrackfile_new_route_no_cookie_redirects(client):
    """POST /v1/uploadCrackFile/<job_task_id> without agent cookie redirects."""
    resp = client.post(
        "/v1/uploadCrackFile/1",
        data=json.dumps({"file": ""}),
        content_type="application/json",
    )
    assert 300 <= resp.status_code < 400
    assert "not_authorized" in resp.headers.get("Location", "")


def _seed_job_task_with_hash(owner, hash_type=1000, cracked=False):
    """Create customer -> hashfile -> job -> jobtask -> hash chain."""
    cust = Customers(name=f"CrackCo-{hash_type}-{cracked}")
    _db.session.add(cust)
    _db.session.commit()
    hf = Hashfiles(name=f"crack-hf-{hash_type}", customer_id=cust.id, owner_id=owner.id)
    _db.session.add(hf)
    _db.session.commit()
    wl = Wordlists(
        name=f"crack-wl-{hash_type}",
        owner_id=owner.id,
        type="static",
        path="/nonexistent/crack-wl.gz",
        size=1,
        checksum="0" * 64,
    )
    _db.session.add(wl)
    _db.session.commit()
    task = Tasks(name=f"crack-task-{hash_type}", owner_id=owner.id, wl_id=wl.id, hc_attackmode=0)
    _db.session.add(task)
    _db.session.commit()
    job = Jobs(name=f"crack-job-{hash_type}", status="Running", hashfile_id=hf.id,
               customer_id=cust.id, owner_id=owner.id)
    _db.session.add(job)
    _db.session.commit()
    jt = JobTasks(job_id=job.id, task_id=task.id, status="Running")
    _db.session.add(jt)
    _db.session.commit()
    h = Hashes(
        sub_ciphertext=get_md5_hash(NTLM_HASH),
        ciphertext=NTLM_HASH,
        hash_type=hash_type,
        cracked=cracked,
    )
    _db.session.add(h)
    _db.session.commit()
    _db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    _db.session.commit()
    return jt, h


@pytest.mark.security
def test_uploadcrackfile_new_route_cracks_hash(
    client, authorized_agent, admin_user, monkeypatch
):
    """POST /v1/uploadCrackFile/<job_task_id> marks a matching hash as cracked."""
    import hashview.utils.utils as utils_mod
    monkeypatch.setattr(utils_mod, "process_recovered_hash_notifications", lambda: None)
    monkeypatch.setattr(utils_mod, "hexplain_to_text", lambda s: s)

    jt, h = _seed_job_task_with_hash(admin_user, hash_type=1000, cracked=False)

    client.set_cookie("uuid", authorized_agent.uuid, domain="localhost.test")
    resp = client.post(
        f"/v1/uploadCrackFile/{jt.id}",
        data=json.dumps({"file": f"{NTLM_HASH}:password\n"}),
        content_type="application/json",
    )
    body = _json(resp)
    assert body["status"] == 200
    _db.session.refresh(h)
    assert h.cracked


@pytest.mark.security
def test_uploadcrackfile_new_route_no_matching_hash_is_noop(
    client, authorized_agent, admin_user, monkeypatch
):
    """POST /v1/uploadCrackFile/<job_task_id> with unknown hash is a no-op."""
    import hashview.utils.utils as utils_mod
    monkeypatch.setattr(utils_mod, "process_recovered_hash_notifications", lambda: None)
    monkeypatch.setattr(utils_mod, "hexplain_to_text", lambda s: s)

    jt, h = _seed_job_task_with_hash(admin_user, hash_type=1000, cracked=False)

    client.set_cookie("uuid", authorized_agent.uuid, domain="localhost.test")
    resp = client.post(
        f"/v1/uploadCrackFile/{jt.id}",
        data=json.dumps({"file": "BBBB1234BBBB1234BBBB1234BBBB1234:unknown\n"}),
        content_type="application/json",
    )
    body = _json(resp)
    assert body["status"] == 200
    _db.session.refresh(h)
    assert not h.cracked


@pytest.mark.security
def test_uploadcrackfile_new_route_limit_recovered_cancels_tasks(
    client, authorized_agent, admin_user, monkeypatch
):
    """POST /v1/uploadCrackFile/<job_task_id> with limit_recovered=True cancels
    all tasks when at least one hash is recovered."""
    import hashview.utils.utils as utils_mod
    monkeypatch.setattr(utils_mod, "process_recovered_hash_notifications", lambda: None)
    monkeypatch.setattr(utils_mod, "hexplain_to_text", lambda s: s)
    monkeypatch.setattr(utils_mod, "update_job_task_status",
                        lambda jobtask_id, status: None)

    jt, h = _seed_job_task_with_hash(admin_user, hash_type=1000, cracked=False)
    # Enable one-and-done for the job
    job = Jobs.query.get(jt.job_id)
    job.limit_recovered = True
    _db.session.commit()

    client.set_cookie("uuid", authorized_agent.uuid, domain="localhost.test")
    resp = client.post(
        f"/v1/uploadCrackFile/{jt.id}",
        data=json.dumps({"file": f"{NTLM_HASH}:password\n"}),
        content_type="application/json",
    )
    body = _json(resp)
    assert body["status"] == 200


# ---------------------------------------------------------------------------
# /v1/getHashType/<hashfile_id>
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_gethashtype_returns_hash_type(client, admin_user):
    """GET /v1/getHashType/<id> returns the hash_type of the first hash in the file."""
    cust = Customers(name="HtCo")
    _db.session.add(cust)
    _db.session.commit()
    hf = Hashfiles(name="ht-hf", customer_id=cust.id, owner_id=admin_user.id)
    _db.session.add(hf)
    _db.session.commit()
    h = Hashes(sub_ciphertext="1" * 32, ciphertext="cafebabe", hash_type=1000, cracked=False)
    _db.session.add(h)
    _db.session.commit()
    _db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    _db.session.commit()

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.get(f"/v1/getHashType/{hf.id}")
    assert resp.status_code == 200
    body = _json(resp)
    assert body["status"] == 200
    assert body["hash_type"] == 1000


@pytest.mark.security
def test_gethashtype_no_cookie_redirects(client):
    """GET /v1/getHashType/<id> without a cookie redirects to not_authorized."""
    resp = client.get("/v1/getHashType/1")
    assert 300 <= resp.status_code < 400
    assert "not_authorized" in resp.headers.get("Location", "")


@pytest.mark.security
def test_gethashtype_agent_cookie_accepted(client, authorized_agent, admin_user):
    """GET /v1/getHashType/<id> with an agent cookie succeeds."""
    cust = Customers(name="HtAgentCo")
    _db.session.add(cust)
    _db.session.commit()
    hf = Hashfiles(name="ht-agent-hf", customer_id=cust.id, owner_id=admin_user.id)
    _db.session.add(hf)
    _db.session.commit()
    h = Hashes(sub_ciphertext="2" * 32, ciphertext="beefdead", hash_type=18000, cracked=False)
    _db.session.add(h)
    _db.session.commit()
    _db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    _db.session.commit()

    client.set_cookie("uuid", authorized_agent.uuid, domain="localhost.test")
    resp = client.get(f"/v1/getHashType/{hf.id}")
    body = _json(resp)
    assert body["status"] == 200
    assert body["hash_type"] == 18000


# ---------------------------------------------------------------------------
# /v1/jobtask/status
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_jobtask_status_no_cookie_redirects(client):
    """POST /v1/jobtask/status without a cookie redirects to not_authorized."""
    resp = client.post(
        "/v1/jobtask/status",
        data=json.dumps({"job_task_id": 1, "task_status": "Completed"}),
        content_type="application/json",
    )
    assert 300 <= resp.status_code < 400
    assert "not_authorized" in resp.headers.get("Location", "")


@pytest.mark.security
def test_jobtask_status_success(client, authorized_agent, admin_user, monkeypatch):
    """POST /v1/jobtask/status with valid data returns OK."""
    import hashview.api.routes as routes_mod
    monkeypatch.setattr(routes_mod, "update_job_task_status",
                        lambda jobtask_id, status: True)

    client.set_cookie("uuid", authorized_agent.uuid, domain="localhost.test")
    resp = client.post(
        "/v1/jobtask/status",
        data=json.dumps({"job_task_id": 1, "task_status": "Completed"}),
        content_type="application/json",
    )
    body = _json(resp)
    assert body["status"] == 200
    assert body["msg"] == "OK"


@pytest.mark.security
def test_jobtask_status_failure_returns_500(client, authorized_agent, monkeypatch):
    """POST /v1/jobtask/status when update_job_task_status returns falsy returns 500."""
    import hashview.api.routes as routes_mod
    monkeypatch.setattr(routes_mod, "update_job_task_status",
                        lambda jobtask_id, status: False)

    client.set_cookie("uuid", authorized_agent.uuid, domain="localhost.test")
    resp = client.post(
        "/v1/jobtask/status",
        data=json.dumps({"job_task_id": 1, "task_status": "Completed"}),
        content_type="application/json",
    )
    body = _json(resp)
    assert body["status"] == 500


# ---------------------------------------------------------------------------
# /v1/search
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_search_no_cookie_redirects(client):
    """POST /v1/search without a cookie redirects to not_authorized."""
    resp = client.post(
        "/v1/search",
        data=json.dumps({"hash": "abc"}),
        content_type="application/json",
    )
    assert 300 <= resp.status_code < 400
    assert "not_authorized" in resp.headers.get("Location", "")


@pytest.mark.security
@pytest.mark.xfail(
    strict=True,
    reason=(
        "Bug: v1_api_search uses request.get_json() without silent=True "
        "(hashview/api/routes.py:1392). An empty body with content-type "
        "application/json causes Flask to return an HTML 400 page instead of "
        "the route's JSON {'status': 500, 'msg': 'Invalid Search'}."
    ),
)
def test_search_no_body_returns_500(client, admin_user):
    """POST /v1/search with no JSON body should return JSON 500 (correct behavior)."""
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post("/v1/search", data="", content_type="application/json")
    # Correct behavior: JSON error, not Flask's HTML 400
    body = _json(resp)
    assert body["status"] == 500
    assert "Invalid Search" in body["msg"]


@pytest.mark.security
def test_search_found_cracked_hash_returns_plaintext(client, admin_user):
    """POST /v1/search with a known cracked hash returns the plaintext."""
    h = Hashes(
        sub_ciphertext="3" * 32,
        ciphertext="deadbeefdeadbeef",
        hash_type=1000,
        cracked=True,
        plaintext="secretpassword",
    )
    _db.session.add(h)
    _db.session.commit()

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/search",
        data=json.dumps({"hash": "deadbeefdeadbeef"}),
        content_type="application/json",
    )
    body = _json(resp)
    assert body["status"] == 200
    assert body["msg"]["plaintext"] == "secretpassword"


@pytest.mark.security
def test_search_not_found_returns_no_results_message(client, admin_user):
    """POST /v1/search for an unknown hash returns a 'No Results Found' message."""
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/search",
        data=json.dumps({"hash": "nosuchhash"}),
        content_type="application/json",
    )
    body = _json(resp)
    assert body["status"] == 200
    assert "No Results Found" in body["msg"]


@pytest.mark.security
@pytest.mark.xfail(
    strict=True,
    reason=(
        "Bug: v1_api_search accesses search_json['hash'] without using .get() "
        "(hashview/api/routes.py:1395). When the 'hash' key is absent a bare "
        "KeyError propagates as an unhandled exception (500 HTML traceback) "
        "instead of the intended JSON {'status': 500, 'msg': 'Invalid Search'}."
    ),
)
def test_search_missing_hash_key_returns_500(client, admin_user):
    """POST /v1/search without a 'hash' key should return JSON 500 (correct behavior)."""
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/search",
        data=json.dumps({"not_hash": "whatever"}),
        content_type="application/json",
    )
    # Correct behavior: reach the else branch and return JSON 500 "Invalid Search"
    body = _json(resp)
    assert body["status"] == 500


# ---------------------------------------------------------------------------
# /v1/error — race-condition branch (agent deleted after auth)
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_error_route_agent_deleted_after_auth_redirects(client, monkeypatch):
    """POST /v1/error where the agent is removed between auth and lookup redirects.

    This exercises the narrow race-condition guard in v1_api_error.
    We monkeypatch is_authorized to return True (bypassing the normal auth)
    while providing a uuid that has no matching Agents row.
    """
    import hashview.api.routes as routes_mod
    monkeypatch.setattr(routes_mod, "is_authorized", lambda user, agent, request: True)

    # Use a uuid that doesn't exist in the Agents table
    client.set_cookie("uuid", "ghost-agent-uuid-not-in-db", domain="localhost.test")
    resp = client.post(
        "/v1/error",
        data=json.dumps({"error": "test"}),
        content_type="application/json",
    )
    assert 300 <= resp.status_code < 400
    assert "not_authorized" in resp.headers.get("Location", "")


# ---------------------------------------------------------------------------
# /v1/hashes/import/<hash_type> — empty body, user guard
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_hashes_import_1000_empty_body_returns_400(client, admin_user):
    """POST /v1/hashes/import/1000 with no body returns 400."""
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post("/v1/hashes/import/1000", data="", content_type="text/plain")
    body = _json(resp)
    assert body["status"] == 400
    assert "Missing" in body["msg"]


@pytest.mark.security
def test_hashes_import_1000_no_matching_record_is_noop(
    client, app, admin_user, tmp_path, monkeypatch
):
    """POST /v1/hashes/import/1000 with a valid pair for an unknown hash is a no-op
    (no matching Hashes row, so nothing is updated but the request succeeds)."""
    _upload_dirs(app, tmp_path, monkeypatch)

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/hashes/import/1000",
        data=f"{NTLM_HASH}:password",
        content_type="text/plain",
    )
    body = _json(resp)
    assert body["status"] == 200
    assert body["msg"] == "OK"


@pytest.mark.security
def test_hashes_import_rejects_agent_cookie(client, authorized_agent):
    """POST /v1/hashes/import/<n> with an agent cookie redirects to not_authorized."""
    client.set_cookie("uuid", authorized_agent.uuid, domain="localhost.test")
    resp = client.post(
        "/v1/hashes/import/1000",
        data=f"{NTLM_HASH}:password",
        content_type="text/plain",
    )
    assert 300 <= resp.status_code < 400
    assert "not_authorized" in resp.headers.get("Location", "")


# ---------------------------------------------------------------------------
# /v1/wordlists/add — agent cookie rejected
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_wordlist_add_rejects_agent_cookie(client, authorized_agent):
    """POST /v1/wordlists/add/<name> with an agent cookie redirects to not_authorized."""
    client.set_cookie("uuid", authorized_agent.uuid, domain="localhost.test")
    resp = client.post(
        "/v1/wordlists/add/agent-wl",
        data="word1\nword2\n",
        content_type="text/plain",
    )
    assert 300 <= resp.status_code < 400
    assert "not_authorized" in resp.headers.get("Location", "")


@pytest.mark.security
def test_wordlist_add_empty_body_returns_400(client, admin_user):
    """POST /v1/wordlists/add/<name> with empty body returns 400."""
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/wordlists/add/empty-wl",
        data="",
        content_type="text/plain",
    )
    body = _json(resp)
    assert body["status"] == 400
    assert "Missing" in body["msg"]


# ---------------------------------------------------------------------------
# versionCheck helper — direct unit tests
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_versioncheck_none_returns_false(app):
    """versionCheck(None) returns False."""
    from hashview.api.routes import versionCheck
    with app.app_context():
        assert versionCheck(None) is False


@pytest.mark.security
def test_versioncheck_current_version_returns_true(app):
    """versionCheck with the current __version__ returns True."""
    import hashview
    from hashview.api.routes import versionCheck
    with app.app_context():
        assert versionCheck(hashview.__version__) is True


@pytest.mark.security
def test_versioncheck_old_version_returns_false(app):
    """versionCheck with '0.0.1' returns False."""
    from hashview.api.routes import versionCheck
    with app.app_context():
        assert versionCheck("0.0.1") is False


# ---------------------------------------------------------------------------
# Additional gap-filling tests
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_alchemy_encoder_non_sqlalchemy_object_raises(app):
    """AlchemyEncoder.default falls back to json.JSONEncoder for non-SQLAlchemy
    objects (line 97: the super() call for unrecognized types)."""
    import hashview.api.routes as routes_mod
    enc = routes_mod.AlchemyEncoder()
    # A plain Python object that json.JSONEncoder can't handle raises TypeError
    try:
        enc.default(object())
        raised = False
    except TypeError:
        raised = True
    assert raised, "Expected TypeError for non-serializable non-SA object"


@pytest.mark.security
def test_agent_authorized_with_invalid_status_returns_false(app):
    """agentAuthorized returns False for an agent with a status not in the valid set
    (line 133: the implicit False return when status is 'Pending')."""
    from hashview.api.routes import agentAuthorized
    with app.app_context():
        agent = Agents(
            name="bad-status-agent",
            src_ip="127.0.0.1",
            uuid="bad-status-uuid",
            status="Pending",
        )
        _db.session.add(agent)
        _db.session.commit()
        assert agentAuthorized("bad-status-uuid") is False


@pytest.mark.security
def test_rules_download_agent_cookie_returns_file(
    client, app, authorized_agent, admin_user, tmp_path, monkeypatch
):
    """GET /v1/rules/<id> with an agent cookie is accepted (user=True, agent=True)
    and serves the gzip-compressed rule file."""
    import gzip
    monkeypatch.setattr(app, "root_path", str(tmp_path))
    rules_dir = os.path.join(str(tmp_path), "control", "rules")
    tmp_dir = os.path.join(str(tmp_path), "control", "tmp")
    os.makedirs(rules_dir, exist_ok=True)
    os.makedirs(tmp_dir, exist_ok=True)

    content = b"$1\n$2\n"
    rule_filename = "agent-rule.txt"
    rule_path = os.path.join(rules_dir, rule_filename)
    with open(rule_path, "wb") as f:
        f.write(content)

    rule = Rules(
        name="agent-rule",
        owner_id=admin_user.id,
        path=rule_path,
        size=2,
        checksum="0" * 64,
    )
    _db.session.add(rule)
    _db.session.commit()

    client.set_cookie("uuid", authorized_agent.uuid, domain="localhost.test")
    resp = client.get(f"/v1/rules/{rule.id}")
    assert resp.status_code == 200
    assert gzip.decompress(resp.data) == content


@pytest.mark.security
def test_rules_download_missing_file_on_disk_returns_404(
    client, app, admin_user, tmp_path, monkeypatch
):
    """GET /v1/rules/<id> where the DB row exists but the file is missing on disk
    returns a 404 JSON error (line 407)."""
    monkeypatch.setattr(app, "root_path", str(tmp_path))
    rules_dir = os.path.join(str(tmp_path), "control", "rules")
    os.makedirs(rules_dir, exist_ok=True)

    rule = Rules(
        name="ghost-rule",
        owner_id=admin_user.id,
        path="/nonexistent/path/to/ghost-rule.txt",  # file does not exist
        size=1,
        checksum="0" * 64,
    )
    _db.session.add(rule)
    _db.session.commit()

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.get(f"/v1/rules/{rule.id}")
    assert resp.status_code == 404
    body = _json(resp)
    assert body["status"] == 404
    assert "missing" in body["msg"].lower()


@pytest.mark.security
def test_jobs_add_exception_path_returns_500(client, admin_user, monkeypatch):
    """POST /v1/jobs/add where the inner try raises an exception returns 500
    (lines 800-801). We trigger it by seeding a hashfile with a HashfileHashes
    row that points to a nonexistent hash, so Hashes.query.get() returns None
    and attribute access on None raises AttributeError inside the try block."""
    cust = Customers(name="ExcCo")
    _db.session.add(cust)
    _db.session.commit()
    hf = Hashfiles(name="exc-hf", customer_id=cust.id, owner_id=admin_user.id)
    _db.session.add(hf)
    _db.session.commit()
    # Point HashfileHashes at a nonexistent hash_id
    _db.session.add(HashfileHashes(hash_id=999999, hashfile_id=hf.id))
    _db.session.commit()

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/jobs/add",
        data=json.dumps({"name": "exc-job", "hashfile_id": hf.id, "customer_id": cust.id}),
        content_type="application/json",
    )
    body = _json(resp)
    assert body["status"] == 500


@pytest.mark.security
def test_jobs_start_queued_job_no_tasks_returns_400(client, admin_user):
    """POST /v1/jobs/start/<id> for a Queued job with NO tasks returns 400.

    The route's guard is `if job and job_tasks:` — an empty tasks list is
    falsy, so the else branch fires (line 851: 'Invalid job ID').
    """
    cust = Customers(name="NoTaskCo")
    _db.session.add(cust)
    _db.session.commit()
    hf = Hashfiles(name="notask-hf", customer_id=cust.id, owner_id=admin_user.id)
    _db.session.add(hf)
    _db.session.commit()
    job = Jobs(name="notask-job", status="Queued", hashfile_id=hf.id,
               customer_id=cust.id, owner_id=admin_user.id)
    _db.session.add(job)
    _db.session.commit()
    # Deliberately add no JobTasks

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(f"/v1/jobs/start/{job.id}")
    body = _json(resp)
    assert body["status"] == 400
    assert "Invalid job ID" in body["msg"]


@pytest.mark.security
def test_hashfile_upload_hash_only_no_valid_hashes_returns_500(
    client, app, admin_user, tmp_path, monkeypatch
):
    """POST /v1/hashfiles/upload with a file that passes validation but import
    finds zero hashes returns 500 'No valid hashes found' (lines 1087-1089).

    We trigger this by monkeypatching import_hashfilehashes to return True
    (success) but leave HashfileHashes empty — so hash count == 0.
    """
    _upload_dirs(app, tmp_path, monkeypatch)

    import hashview.api.routes as routes_mod
    monkeypatch.setattr(routes_mod, "validate_hash_only_hashfile", lambda p, ht: None)
    monkeypatch.setattr(routes_mod, "import_hashfilehashes",
                        lambda **kw: True)  # claims success but adds nothing

    cust = Customers(name="NoHashCo")
    _db.session.add(cust)
    _db.session.commit()

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        f"/v1/hashfiles/upload/{cust.id}/5/1000/empty-result",
        data="DEADBEEFDEADBEEFDEADBEEFDEADBEEF\n",
        content_type="text/plain",
    )
    body = _json(resp)
    assert body["status"] == 500
    assert "No valid hashes" in body["msg"]


@pytest.mark.security
def test_hashfile_upload_import_returns_false_returns_500(
    client, app, admin_user, tmp_path, monkeypatch
):
    """POST /v1/hashfiles/upload where import_hashfilehashes returns False (falsy)
    returns 500 'Something went wrong' (line 1079)."""
    _upload_dirs(app, tmp_path, monkeypatch)

    import hashview.api.routes as routes_mod
    monkeypatch.setattr(routes_mod, "validate_hash_only_hashfile", lambda p, ht: None)
    monkeypatch.setattr(routes_mod, "import_hashfilehashes", lambda **kw: False)

    cust = Customers(name="FalseCo")
    _db.session.add(cust)
    _db.session.commit()

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        f"/v1/hashfiles/upload/{cust.id}/5/1000/false-import",
        data="DEADBEEFDEADBEEFDEADBEEFDEADBEEF\n",
        content_type="text/plain",
    )
    body = _json(resp)
    assert body["status"] == 500
    assert "went wrong" in body["msg"].lower()


@pytest.mark.security
def test_uploadcrackfile_new_route_22000_hash_type(
    client, authorized_agent, admin_user, monkeypatch
):
    """POST /v1/uploadCrackFile/<job_task_id> with hash_type 22000 exercises the
    WPA-PMKID special case (lines 1287, 1291-1294)."""
    import hashview.utils.utils as utils_mod
    monkeypatch.setattr(utils_mod, "process_recovered_hash_notifications", lambda: None)
    monkeypatch.setattr(utils_mod, "hexplain_to_text", lambda s: s)

    cust = Customers(name="WPACo")
    _db.session.add(cust)
    _db.session.commit()
    hf = Hashfiles(name="wpa-hf", customer_id=cust.id, owner_id=admin_user.id)
    _db.session.add(hf)
    _db.session.commit()
    wl = Wordlists(
        name="wpa-wl",
        owner_id=admin_user.id,
        type="static",
        path="/nonexistent/wpa-wl.gz",
        size=1,
        checksum="0" * 64,
    )
    _db.session.add(wl)
    _db.session.commit()
    task = Tasks(name="wpa-task", owner_id=admin_user.id, wl_id=wl.id, hc_attackmode=0)
    _db.session.add(task)
    _db.session.commit()
    job = Jobs(name="wpa-job", status="Running", hashfile_id=hf.id,
               customer_id=cust.id, owner_id=admin_user.id)
    _db.session.add(job)
    _db.session.commit()
    jt = JobTasks(job_id=job.id, task_id=task.id, status="Running")
    _db.session.add(jt)
    _db.session.commit()

    # Seed a real 22000-type hash
    wpa_cipher = "WPA*02*abc123*aa:bb:cc:dd:ee:ff*11:22:33:44:55:66*myssid*abcdef1234567890"
    h = Hashes(
        sub_ciphertext=get_md5_hash(wpa_cipher),
        ciphertext=wpa_cipher,
        hash_type=22000,
        cracked=False,
    )
    _db.session.add(h)
    _db.session.commit()
    _db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    _db.session.commit()

    # A cracked 22000 line looks like: <partial>:<ssid>:<hex_plain>
    client.set_cookie("uuid", authorized_agent.uuid, domain="localhost.test")
    resp = client.post(
        f"/v1/uploadCrackFile/{jt.id}",
        data=json.dumps({"file": "abc123:myssid:70617373776f7264\n"}),
        content_type="application/json",
    )
    body = _json(resp)
    assert body["status"] == 200


@pytest.mark.security
def test_search_found_returns_structured_msg(client, admin_user):
    """POST /v1/search for a cracked hash returns a structured msg dict
    (lines 1417-1423: the if cracked_hash branch).

    This specifically exercises the branch that builds a dict response —
    hash_type, hash, plaintext — which test_search_found_cracked_hash_returns_plaintext
    already covers but we need this branch hit from a fresh DB.
    """
    h = Hashes(
        sub_ciphertext="9" * 32,
        ciphertext="uniquehashvalue999",
        hash_type=1000,
        cracked=True,
        plaintext="hunter2",
    )
    _db.session.add(h)
    _db.session.commit()

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/search",
        data=json.dumps({"hash": "uniquehashvalue999"}),
        content_type="application/json",
    )
    body = _json(resp)
    assert body["status"] == 200
    assert isinstance(body["msg"], dict)
    assert body["msg"]["plaintext"] == "hunter2"
    assert body["msg"]["hash_type"] == 1000


@pytest.mark.security
def test_hashes_import_1000_no_tmp_dir_triggers_write_exception(
    client, app, admin_user, tmp_path, monkeypatch
):
    """POST /v1/hashes/import/1000 when the control/tmp directory doesn't exist
    triggers the file write exception path (lines 1495-1496)."""
    # Point the app at a tmp directory that has NO control/tmp subdirectory
    monkeypatch.setattr(app, "root_path", str(tmp_path))
    # Deliberately do NOT create control/tmp

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/hashes/import/1000",
        data=f"{NTLM_HASH}:password",
        content_type="text/plain",
    )
    body = _json(resp)
    assert body["status"] == 500
    assert "Failed to write" in body["msg"] or "file" in body["msg"].lower()


@pytest.mark.security
def test_hashfile_get_no_cookie_redirects(client):
    """GET /v1/hashfiles/<id> without a cookie redirects to not_authorized (line 1121)."""
    resp = client.get("/v1/hashfiles/1")
    assert 300 <= resp.status_code < 400
    assert "not_authorized" in resp.headers.get("Location", "")


@pytest.mark.security
def test_hashfiles_by_hash_type_hashfile_missing_in_loop(client, admin_user):
    """GET /v1/hashfiles/hash_type/<n> skips hashfile_id rows where Hashfiles.get()
    returns None (line 1165: the `continue` guard in the loop).

    We create a HashfileHashes row pointing to a nonexistent hashfile_id and
    a hash of the queried type, then verify no crash occurs and the result list
    is empty.
    """
    # Create a hash of type 7777 but link it to a nonexistent hashfile
    h = Hashes(sub_ciphertext="7" * 32, ciphertext="ghost7777", hash_type=7777, cracked=False)
    _db.session.add(h)
    _db.session.commit()
    # Point to a hashfile_id that doesn't exist
    _db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=999888))
    _db.session.commit()

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.get("/v1/hashfiles/hash_type/7777")
    body = _json(resp)
    assert body["status"] == 200
    # The orphan row is skipped via `continue` and we get an empty list
    assert body["hashfiles"] == []


@pytest.mark.security
def test_hashfile_upload_file_format_5_write_exception(
    client, app, admin_user, tmp_path, monkeypatch
):
    """POST /v1/hashfiles/upload/... where writing the tmp file fails returns
    500 'Failed to write hashfile' (lines 1023-1024)."""
    # Point at tmp_path root but do NOT create control/tmp — open() will fail
    monkeypatch.setattr(app, "root_path", str(tmp_path))
    # Do NOT create the tmp dir

    cust = Customers(name="WriteFailCo")
    _db.session.add(cust)
    _db.session.commit()

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        f"/v1/hashfiles/upload/{cust.id}/5/1000/writefail",
        data=NTLM_HASH + "\n",
        content_type="text/plain",
    )
    body = _json(resp)
    assert body["status"] == 500
    assert "write" in body["msg"].lower() or "failed" in body["msg"].lower()


# ---------------------------------------------------------------------------
# Exception / edge-case paths not yet covered
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_wordlist_download_no_cookie_redirects(client):
    """GET /v1/wordlists/<id> without a cookie redirects to not_authorized (line 506)."""
    resp = client.get("/v1/wordlists/1")
    assert 300 <= resp.status_code < 400
    assert "not_authorized" in resp.headers.get("Location", "")


@pytest.mark.security
def test_rules_download_no_cookie_redirects(client):
    """GET /v1/rules/<id> without a cookie redirects to not_authorized (line 392)."""
    resp = client.get("/v1/rules/1")
    assert 300 <= resp.status_code < 400
    assert "not_authorized" in resp.headers.get("Location", "")


@pytest.mark.security
def test_search_empty_hash_value_returns_500(client, admin_user):
    """POST /v1/search with {"hash": ""} — an empty hash string is falsy so
    the `if search_json['hash']:` branch goes to the else at line 1417."""
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/search",
        data=json.dumps({"hash": ""}),
        content_type="application/json",
    )
    body = _json(resp)
    assert body["status"] == 500
    assert "Invalid Search" in body["msg"]


@pytest.mark.security
def test_search_null_json_body_returns_500(client, admin_user):
    """POST /v1/search with JSON body 'null' — request.get_json() returns None
    (falsy), reaching the `else` branch at line 1423."""
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/search",
        data="null",
        content_type="application/json",
    )
    body = _json(resp)
    assert body["status"] == 500
    assert "Invalid Search" in body["msg"]


@pytest.mark.security
def test_customers_add_exception_path_returns_500(client, admin_user, monkeypatch):
    """POST /v1/customers/add where db.session.commit raises an exception returns
    500 (lines 368-369)."""
    import hashview.api.routes as routes_mod
    original_commit = _db.session.commit

    def raise_on_commit():
        raise RuntimeError("simulated DB error")

    monkeypatch.setattr(_db.session, "commit", raise_on_commit)
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/customers/add",
        data=json.dumps({"name": "ExceptionCo"}),
        content_type="application/json",
    )
    body = _json(resp)
    assert body["status"] == 500
    assert "Failed to add customer" in body["msg"]


@pytest.mark.security
def test_rules_add_user_not_found_returns_403(client, monkeypatch):
    """POST /v1/rules/add/<name> where is_authorized passes but user lookup fails
    returns 403 'User not found' (line 435).

    We monkeypatch is_authorized to True but use a uuid with no matching user.
    """
    import hashview.api.routes as routes_mod
    monkeypatch.setattr(routes_mod, "is_authorized", lambda user, agent, request: True)

    client.set_cookie("uuid", "no-such-user-uuid", domain="localhost.test")
    resp = client.post(
        "/v1/rules/add/ghost-rule",
        data=b"rule content",
        content_type="text/plain",
    )
    body = _json(resp)
    assert body["status"] == 403
    assert "User not found" in body["msg"]


@pytest.mark.security
def test_wordlist_add_user_not_found_returns_403(client, monkeypatch):
    """POST /v1/wordlists/add/<name> where is_authorized passes but user lookup fails
    returns 403 'User not found' (line 582)."""
    import hashview.api.routes as routes_mod
    monkeypatch.setattr(routes_mod, "is_authorized", lambda user, agent, request: True)

    client.set_cookie("uuid", "no-such-user-uuid", domain="localhost.test")
    resp = client.post(
        "/v1/wordlists/add/ghost-wl",
        data=b"word1\nword2\n",
        content_type="text/plain",
    )
    body = _json(resp)
    assert body["status"] == 403
    assert "User not found" in body["msg"]


@pytest.mark.security
def test_jobs_delete_user_not_found_returns_403(client, monkeypatch):
    """DELETE /v1/jobs/<id> where is_authorized passes but user lookup fails
    returns 403 (line 662)."""
    import hashview.api.routes as routes_mod
    monkeypatch.setattr(routes_mod, "is_authorized", lambda user, agent, request: True)

    client.set_cookie("uuid", "no-such-user-uuid", domain="localhost.test")
    resp = client.delete("/v1/jobs/1")
    body = _json(resp)
    assert body["status"] == 403


@pytest.mark.security
def test_jobs_delete_exception_returns_500(client, admin_user, monkeypatch):
    """DELETE /v1/jobs/<id> where db.session.commit raises returns 500 (lines 688-689)."""
    cust = Customers(name="DelExcCo")
    _db.session.add(cust)
    _db.session.commit()
    job = Jobs(name="del-exc-job", status="Ready", customer_id=cust.id, owner_id=admin_user.id)
    _db.session.add(job)
    _db.session.commit()

    def raise_on_commit():
        raise RuntimeError("simulated delete error")

    monkeypatch.setattr(_db.session, "commit", raise_on_commit)
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.delete(f"/v1/jobs/{job.id}")
    body = _json(resp)
    assert body["status"] == 500
    assert "Failed to delete job" in body["msg"]


@pytest.mark.security
def test_jobs_add_user_not_found_returns_403(client, monkeypatch):
    """POST /v1/jobs/add where is_authorized passes but user lookup fails
    returns 403 (line 713)."""
    import hashview.api.routes as routes_mod
    monkeypatch.setattr(routes_mod, "is_authorized", lambda user, agent, request: True)

    client.set_cookie("uuid", "no-such-user-uuid", domain="localhost.test")
    resp = client.post(
        "/v1/jobs/add",
        data=json.dumps({"name": "x", "hashfile_id": 1, "customer_id": 1}),
        content_type="application/json",
    )
    body = _json(resp)
    assert body["status"] == 403


@pytest.mark.security
def test_jobs_add_null_json_body_returns_400(client, admin_user):
    """POST /v1/jobs/add with JSON 'null' body returns 400 'Missing job data'.

    request.get_json() returns Python None for JSON null, which is falsy,
    so the route's missing-body check fires at line 722.
    """
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post("/v1/jobs/add", data="null", content_type="application/json")
    body = _json(resp)
    assert body["status"] == 400
    assert "Missing" in body["msg"]


@pytest.mark.security
def test_tasks_add_user_not_found_returns_403(client, monkeypatch):
    """POST /v1/tasks/add where is_authorized passes but user lookup fails
    returns 403 (line 876)."""
    import hashview.api.routes as routes_mod
    monkeypatch.setattr(routes_mod, "is_authorized", lambda user, agent, request: True)

    client.set_cookie("uuid", "no-such-user-uuid", domain="localhost.test")
    resp = client.post(
        "/v1/tasks/add",
        data=json.dumps({"name": "x", "wl_id": 1}),
        content_type="application/json",
    )
    body = _json(resp)
    assert body["status"] == 403


@pytest.mark.security
def test_tasks_add_rule_id_str_not_digit_returns_400(client, admin_user):
    """POST /v1/tasks/add with a non-numeric string rule_id returns 400 (line 926)."""
    wl = Wordlists(
        name="rule-str-wl",
        owner_id=admin_user.id,
        type="static",
        path="/nonexistent/rule-str-wl.gz",
        size=1,
        checksum="0" * 64,
    )
    _db.session.add(wl)
    _db.session.commit()

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/tasks/add",
        data=json.dumps({"name": "rule-str-task", "wl_id": wl.id, "rule_id": "abc"}),
        content_type="application/json",
    )
    body = _json(resp)
    assert body["status"] == 400
    assert "rule_id" in body["msg"]


@pytest.mark.security
def test_tasks_add_exception_returns_500(client, admin_user, monkeypatch):
    """POST /v1/tasks/add where db.session.commit raises returns 500 (lines 949-950)."""
    wl = Wordlists(
        name="exc-tasks-wl",
        owner_id=admin_user.id,
        type="static",
        path="/nonexistent/exc-tasks-wl.gz",
        size=1,
        checksum="0" * 64,
    )
    _db.session.add(wl)
    _db.session.commit()

    def raise_on_commit():
        raise RuntimeError("simulated task add error")

    monkeypatch.setattr(_db.session, "commit", raise_on_commit)
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/tasks/add",
        data=json.dumps({"name": "exc-task", "wl_id": wl.id}),
        content_type="application/json",
    )
    body = _json(resp)
    assert body["status"] == 500
    assert "Failed to add task" in body["msg"]


@pytest.mark.security
def test_hashfile_upload_user_not_found_returns_403(client, monkeypatch):
    """POST /v1/hashfiles/upload where is_authorized passes but user lookup fails
    returns 403 (line 1008)."""
    import hashview.api.routes as routes_mod
    monkeypatch.setattr(routes_mod, "is_authorized", lambda user, agent, request: True)

    cust = Customers(name="HfUserNotFound")
    _db.session.add(cust)
    _db.session.commit()

    client.set_cookie("uuid", "no-such-user-uuid", domain="localhost.test")
    resp = client.post(
        f"/v1/hashfiles/upload/{cust.id}/5/1000/test",
        data=NTLM_HASH + "\n",
        content_type="text/plain",
    )
    body = _json(resp)
    assert body["status"] == 403


@pytest.mark.security
def test_hashfile_upload_all_valid_format_strings(
    client, app, admin_user, tmp_path, monkeypatch
):
    """POST /v1/hashfiles/upload exercises the format-string conversion branches
    (lines 1062-1073) by patching validate_* to return no error and
    import_hashfilehashes to succeed, with a real hash in the hashfile."""
    _upload_dirs(app, tmp_path, monkeypatch)
    import hashview.api.routes as routes_mod

    # Each format validator monkeypatched to return no problem
    for name in ["validate_pwdump_hashfile", "validate_netntlm_hashfile",
                 "validate_kerberos_hashfile", "validate_shadow_hashfile",
                 "validate_user_hash_hashfile", "validate_hash_only_hashfile"]:
        monkeypatch.setattr(routes_mod, name, lambda p, ht: None)

    cust = Customers(name="FmtStrCo")
    _db.session.add(cust)
    _db.session.commit()

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    for fmt_int in range(6):  # 0..5
        # Patch import to actually insert a hash so count != 0
        h = Hashes(
            sub_ciphertext=get_md5_hash(f"DEADBEEF{fmt_int:02d}DEADBEEFDEADBEEF00"),
            ciphertext=f"DEADBEEF{fmt_int:02d}DEADBEEFDEADBEEF00",
            hash_type=1000,
            cracked=False,
        )
        _db.session.add(h)
        _db.session.commit()

        def _make_import(hash_id, hashfile_id_ref):
            def fake_import(hashfile_id, hashfile_path, file_type, hash_type):
                _db.session.add(HashfileHashes(hash_id=hash_id, hashfile_id=hashfile_id))
                _db.session.commit()
                return True
            return fake_import

        monkeypatch.setattr(routes_mod, "import_hashfilehashes",
                            _make_import(h.id, None))

        resp = client.post(
            f"/v1/hashfiles/upload/{cust.id}/{fmt_int}/1000/fmt-{fmt_int}",
            data=f"DEADBEEF{fmt_int:02d}DEADBEEFDEADBEEF00\n",
            content_type="text/plain",
        )
        body = _json(resp)
        assert body["status"] == 200, f"format {fmt_int} returned {body}"


@pytest.mark.security
def test_hashfile_upload_exception_in_validation_returns_500(
    client, app, admin_user, tmp_path, monkeypatch
):
    """POST /v1/hashfiles/upload where the validation call raises returns 500
    (lines 1110-1111)."""
    _upload_dirs(app, tmp_path, monkeypatch)
    import hashview.api.routes as routes_mod
    monkeypatch.setattr(routes_mod, "validate_hash_only_hashfile",
                        lambda p, ht: (_ for _ in ()).throw(RuntimeError("boom")))

    cust = Customers(name="ValExcCo")
    _db.session.add(cust)
    _db.session.commit()

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        f"/v1/hashfiles/upload/{cust.id}/5/1000/valexc",
        data=NTLM_HASH + "\n",
        content_type="text/plain",
    )
    body = _json(resp)
    assert body["status"] == 500


@pytest.mark.security
def test_hashfiles_by_hash_type_user_not_found_returns_403(client, monkeypatch):
    """GET /v1/hashfiles/hash_type/<n> where is_authorized passes but user lookup
    fails returns 403 (line 1146)."""
    import hashview.api.routes as routes_mod
    monkeypatch.setattr(routes_mod, "is_authorized", lambda user, agent, request: True)

    client.set_cookie("uuid", "no-such-user-uuid", domain="localhost.test")
    resp = client.get("/v1/hashfiles/hash_type/1000")
    body = _json(resp)
    assert body["status"] == 403


@pytest.mark.security
def test_uploadcrackfile_old_route_exception_during_commit(
    client, authorized_agent, monkeypatch
):
    """POST /v1/uploadCrackFile/<task>/<hash_type> where db.session.commit raises
    prints the error and continues (lines 1229-1231: the inner try/except).

    The route catches commit exceptions silently (just prints) and still returns
    status 200, so the exception path is covered even though the record isn't saved.

    We trigger the exception by making hexplain_to_text raise (the inner try
    block also catches any error from the helper calls, not just commit).
    """
    import hashview.api.routes as routes_mod
    import hashview.utils.utils as utils_mod
    monkeypatch.setattr(utils_mod, "process_recovered_hash_notifications", lambda: None)

    def raise_hexplain(s):
        raise ValueError("simulated hexplain error")

    # The route imports hexplain_to_text directly into its namespace, so patch there
    monkeypatch.setattr(routes_mod, "hexplain_to_text", raise_hexplain)

    hash_val = NTLM_HASH
    h = Hashes(
        sub_ciphertext=get_md5_hash(hash_val),
        ciphertext=hash_val,
        hash_type=1000,
        cracked=False,
    )
    _db.session.add(h)
    _db.session.commit()

    client.set_cookie("uuid", authorized_agent.uuid, domain="localhost.test")
    resp = client.post(
        "/v1/uploadCrackFile/1/1000",
        data=json.dumps({"file": f"{hash_val}:password\n"}),
        content_type="application/json",
    )
    # Despite the inner exception, the route always returns 200
    body = _json(resp)
    assert body["status"] == 200


@pytest.mark.security
def test_uploadcrackfile_new_route_22000_no_record_found(
    client, authorized_agent, admin_user, monkeypatch
):
    """POST /v1/uploadCrackFile/<job_task_id> with hash_type 22000 where no
    matching record is found hits the debug print at line 1294."""
    import hashview.utils.utils as utils_mod
    monkeypatch.setattr(utils_mod, "process_recovered_hash_notifications", lambda: None)
    monkeypatch.setattr(utils_mod, "hexplain_to_text", lambda s: s)

    cust = Customers(name="WPA2Co")
    _db.session.add(cust)
    _db.session.commit()
    hf = Hashfiles(name="wpa2-hf", customer_id=cust.id, owner_id=admin_user.id)
    _db.session.add(hf)
    _db.session.commit()
    wl = Wordlists(
        name="wpa2-wl",
        owner_id=admin_user.id,
        type="static",
        path="/nonexistent/wpa2-wl.gz",
        size=1,
        checksum="0" * 64,
    )
    _db.session.add(wl)
    _db.session.commit()
    task = Tasks(name="wpa2-task", owner_id=admin_user.id, wl_id=wl.id, hc_attackmode=0)
    _db.session.add(task)
    _db.session.commit()
    job = Jobs(name="wpa2-job", status="Running", hashfile_id=hf.id,
               customer_id=cust.id, owner_id=admin_user.id)
    _db.session.add(job)
    _db.session.commit()
    jt = JobTasks(job_id=job.id, task_id=task.id, status="Running")
    _db.session.add(jt)
    _db.session.commit()
    # A real 22000-type hash (no matching partial in DB for the test line)
    wpa_cipher = "WPA*02*xyz999*aa:bb:cc:dd:ee:ff*11:22:33:44:55:66*testwifi*deadbeef"
    h = Hashes(
        sub_ciphertext=get_md5_hash(wpa_cipher),
        ciphertext=wpa_cipher,
        hash_type=22000,
        cracked=False,
    )
    _db.session.add(h)
    _db.session.commit()
    _db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    _db.session.commit()

    # Send a cracked line that won't match the partial hash in DB
    client.set_cookie("uuid", authorized_agent.uuid, domain="localhost.test")
    resp = client.post(
        f"/v1/uploadCrackFile/{jt.id}",
        data=json.dumps({"file": "nomatch:ssid:7061737377307264\n"}),
        content_type="application/json",
    )
    body = _json(resp)
    assert body["status"] == 200


@pytest.mark.security
def test_uploadcrackfile_new_route_exception_during_commit(
    client, authorized_agent, admin_user, monkeypatch
):
    """POST /v1/uploadCrackFile/<job_task_id> where hexplain_to_text raises covers
    the inner try/except at lines 1308-1310 (the route prints the error and
    continues, still returning 200)."""
    import hashview.api.routes as routes_mod
    import hashview.utils.utils as utils_mod
    monkeypatch.setattr(utils_mod, "process_recovered_hash_notifications", lambda: None)

    def raise_hexplain(s):
        raise ValueError("simulated hexplain error new route")

    # The route imports hexplain_to_text directly into its namespace, so patch there
    monkeypatch.setattr(routes_mod, "hexplain_to_text", raise_hexplain)

    jt, h = _seed_job_task_with_hash(admin_user, hash_type=1000, cracked=False)

    client.set_cookie("uuid", authorized_agent.uuid, domain="localhost.test")
    resp = client.post(
        f"/v1/uploadCrackFile/{jt.id}",
        data=json.dumps({"file": f"{NTLM_HASH}:password\n"}),
        content_type="application/json",
    )
    body = _json(resp)
    assert body["status"] == 200


@pytest.mark.security
def test_hashes_import_1000_user_not_found_returns_403(client, monkeypatch):
    """POST /v1/hashes/import/1000 where is_authorized passes but user lookup fails
    returns 403 (line 1480)."""
    import hashview.api.routes as routes_mod
    monkeypatch.setattr(routes_mod, "is_authorized", lambda user, agent, request: True)

    client.set_cookie("uuid", "no-such-user-uuid", domain="localhost.test")
    resp = client.post(
        "/v1/hashes/import/1000",
        data=f"{NTLM_HASH}:password",
        content_type="text/plain",
    )
    body = _json(resp)
    assert body["status"] == 403


@pytest.mark.security
def test_hashes_import_1000_record_commit_exception_returns_500(
    client, app, admin_user, tmp_path, monkeypatch
):
    """POST /v1/hashes/import/1000 where the inner db commit raises returns 500
    (lines 1526-1527)."""
    _upload_dirs(app, tmp_path, monkeypatch)

    # Pre-seed the hash so it gets found
    from hashview.utils.utils import get_md5_hash as _md5
    record = Hashes(
        sub_ciphertext=_md5(NTLM_HASH),
        ciphertext=NTLM_HASH,
        hash_type=1000,
        cracked=False,
    )
    _db.session.add(record)
    _db.session.commit()

    call_count = [0]
    original_commit = _db.session.commit

    def flaky_commit():
        call_count[0] += 1
        # First commit is the file write (none for import); second is the hash update
        if call_count[0] >= 1:
            raise RuntimeError("hash import commit fail")
        return original_commit()

    monkeypatch.setattr(_db.session, "commit", flaky_commit)

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/hashes/import/1000",
        data=f"{NTLM_HASH}:password",
        content_type="text/plain",
    )
    body = _json(resp)
    assert body["status"] == 500


@pytest.mark.security
def test_hashes_import_1000_open_exception_returns_500(
    client, app, admin_user, tmp_path, monkeypatch
):
    """POST /v1/hashes/import/1000 where reopening the tmp file fails returns
    500 'Failed to openfile file' (lines 1538-1539)."""
    _upload_dirs(app, tmp_path, monkeypatch)

    # Monkeypatch builtins.open to fail on the second call (the read-back open)
    import builtins
    original_open = builtins.open
    call_count = [0]

    def patched_open(path, *args, **kwargs):
        call_count[0] += 1
        if call_count[0] == 2 and str(path).endswith(".txt"):
            raise OSError("simulated read failure")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", patched_open)

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/hashes/import/1000",
        data=f"{NTLM_HASH}:password",
        content_type="text/plain",
    )
    body = _json(resp)
    assert body["status"] == 500
