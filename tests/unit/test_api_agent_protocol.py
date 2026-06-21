"""Regression tests for agent-facing v1 API protocol endpoints
(function-coverage batch: api).

Auth recap (see hashview/api/routes.py is_authorized): the 'uuid' cookie maps
to Users.api_key (user routes) or Agents.uuid with an active status (agent
routes). Cookie domain must equal the test SERVER_NAME (localhost.test).
"""

import json

import hashview
from hashview.models import (
    AgentBenchmarks,
    Agents,
    Customers,
    Hashes,
    HashfileHashes,
    Hashfiles,
    Jobs,
    JobTasks,
    Rules,
    Settings,
    Tasks,
    Users,
    Wordlists,
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


def test_put_jobtask_crackfile_marks_hash_cracked(app, client, monkeypatch):
    monkeypatch.setattr("hashview.api.routes.process_recovered_hash_notifications",
                        lambda: None)
    agent = _agent(uuid="crack-agent", status="Working")
    # NTLM('password') sub_ciphertext keyed by get_md5_hash(ciphertext)
    from hashview.utils.utils import get_md5_hash
    ntlm = "8846F7EAEE8FB117AD06BDD830B7586C"
    h = Hashes(sub_ciphertext=get_md5_hash(ntlm), ciphertext=ntlm,
               hash_type=1000, cracked=False)
    db.session.add(h)
    db.session.commit()
    client.set_cookie("uuid", "crack-agent", domain=DOMAIN)
    # encoded_plaintext is hex; hexplain_to_text decodes it -> "password"
    hexpw = b"password".hex()
    resp = client.post("/v1/uploadCrackFile/1/1000",
                       json={"file": f"{ntlm}:{hexpw}"})
    body = _body(resp)
    assert body["status"] == 200
    refreshed = Hashes.query.get(h.id)
    assert refreshed.cracked
    assert refreshed.plaintext == "password"


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
    resp = client.post("/v1/uploadCrackFile/1/1000", json={"file": ""})
    assert 300 <= resp.status_code < 400
    assert "not_authorized" in resp.headers.get("Location", "")


# --- per-hashtype benchmarks (chunk sizing) ---------------------------------

def test_benchmark_endpoint_upserts(app, client):
    """POST /v1/agents/benchmark inserts then overwrites one row per hash type."""
    agent = _agent(uuid="bench-agent", status="Idle")
    _set_agent_cookies(client, "bench-agent")

    resp = client.post("/v1/agents/benchmark",
                       json={"benchmark_results": {"1000": 28460000000, "1800": 95000}})
    assert _body(resp)["msg"] == "OK"
    rows = {r.hash_type: r.speed
            for r in AgentBenchmarks.query.filter_by(agent_id=agent.id).all()}
    assert rows == {1000: 28460000000, 1800: 95000}

    # re-running a benchmark upserts (no duplicate row, value replaced)
    resp = client.post("/v1/agents/benchmark",
                       json={"benchmark_results": {"1000": 30000000000}})
    assert _body(resp)["msg"] == "OK"
    assert AgentBenchmarks.query.filter_by(agent_id=agent.id, hash_type=1000).count() == 1
    assert AgentBenchmarks.query.filter_by(
        agent_id=agent.id, hash_type=1000).first().speed == 30000000000


def test_benchmark_endpoint_rejects_user(app, client):
    """/v1/agents/benchmark is agent-only — a user credential is turned away."""
    _user(api_key="user-key")
    client.set_cookie("uuid", "user-key", domain=DOMAIN)
    resp = client.post("/v1/agents/benchmark", json={"benchmark_results": {"1000": 1}})
    assert 300 <= resp.status_code < 400
    assert "not_authorized" in resp.headers.get("Location", "")


def test_benchmark_endpoint_missing_body(app, client):
    _agent(uuid="bench-agent2", status="Idle")
    _set_agent_cookies(client, "bench-agent2")
    resp = client.post("/v1/agents/benchmark", json={})
    body = _body(resp)
    assert body["status"] == 400
    assert "benchmark_results" in body["msg"]


def test_heartbeat_idle_missing_benchmark_returns_benchmark(app, client):
    """Benchmark-first: an idle agent missing a benchmark for an in-use hash type
    is told to BENCHMARK before it is given crack work."""
    db.session.add(Settings(retention_period=30, max_runtime_tasks=0, max_runtime_jobs=0))
    db.session.add(Hashes(sub_ciphertext="0" * 32, ciphertext="AAA",
                          hash_type=1000, cracked=False))
    db.session.commit()
    _agent(uuid="hb-agent", status="Idle")
    _set_agent_cookies(client, "hb-agent")

    body = _body(client.post("/v1/agents/heartbeat",
                             json={"agent_status": "Idle", "hc_status": ""}))
    assert body["msg"] == "BENCHMARK"
    assert body["hash_modes"] == [1000]


def test_heartbeat_idle_with_benchmark_returns_start(app, client):
    """Once the in-use hash types are benchmarked, the idle agent gets work."""
    db.session.add(Settings(retention_period=30, max_runtime_tasks=0, max_runtime_jobs=0))
    db.session.add(Hashes(sub_ciphertext="0" * 32, ciphertext="AAA",
                          hash_type=1000, cracked=False))
    db.session.commit()
    agent = _agent(uuid="hb2-agent", status="Idle")
    db.session.add(AgentBenchmarks(agent_id=agent.id, hash_type=1000, speed=1000))
    jt = JobTasks(job_id=1, task_id=1, status="Queued", priority=3)
    db.session.add(jt)
    db.session.commit()
    _set_agent_cookies(client, "hb2-agent")

    body = _body(client.post("/v1/agents/heartbeat",
                             json={"agent_status": "Idle", "hc_status": ""}))
    assert body["msg"] == "START"
    assert body["job_task_id"] == jt.id


def test_benchmark_report_rechunks_queued_whole_task(app, client):
    """A benchmark report for a hash type that had none re-plans still-queued
    whole tasks of that type into chunks (option 1: re-chunk on first benchmark)."""
    db.session.add(Settings(retention_period=30, max_runtime_tasks=0, max_runtime_jobs=0,
                            enabled_chunking=True, chunk_target_duration=60))
    user = _user(api_key="rc-owner")
    cust = Customers(name="C")
    db.session.add(cust)
    db.session.commit()
    hf = Hashfiles(name="hf", customer_id=cust.id, owner_id=user.id)
    db.session.add(hf)
    db.session.commit()
    h = Hashes(sub_ciphertext="0" * 32, ciphertext="AAA", hash_type=1000, cracked=False)
    db.session.add(h)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    wl = Wordlists(name="wl", owner_id=user.id, type="static",
                   path="control/wordlists/wl.gz", size=1_000_000, checksum="0" * 64)
    db.session.add(wl)
    db.session.commit()
    rule = Rules(name="r", owner_id=user.id, path="control/rules/r.rule",
                 checksum="0" * 64, size=100)
    db.session.add(rule)
    db.session.commit()
    task = Tasks(name="t", owner_id=user.id, hc_attackmode=0, wl_id=wl.id,
                 rule_id=rule.id, loopback=False)
    db.session.add(task)
    db.session.commit()
    job = Jobs(name="j", owner_id=user.id, customer_id=cust.id, hashfile_id=hf.id,
               status="Queued", priority=3)
    db.session.add(job)
    db.session.commit()
    db.session.add(JobTasks(job_id=job.id, task_id=task.id, status="Queued"))
    db.session.commit()
    assert JobTasks.query.filter_by(job_id=job.id).count() == 1   # queued whole

    _agent(uuid="rc-bench", status="Idle")
    _set_agent_cookies(client, "rc-bench")
    # a slow speed so the 1M-word task is worth splitting (fast speeds -> 1 chunk)
    resp = client.post("/v1/agents/benchmark",
                       json={"benchmark_results": {"1000": 1000}})
    assert _body(resp)["msg"] == "OK"
    # the queued whole task was split into chunks by the report
    rows = JobTasks.query.filter_by(job_id=job.id).all()
    assert len(rows) > 1
    assert all(r.chunk_total == len(rows) for r in rows)


def test_dispatch_exhausts_task_chunks_before_next_task(app, client):
    """With 2+ agents, all chunks of a task are handed out before the next task.

    Insert chunks so their raw ids INTERLEAVE the tasks (A1, B1, A2, A3, B2);
    ordering by raw id alone would hand out A1, B1, A2... The grouped ordering must
    instead drain task A (chunks 1,2,3) before task B (chunks 1,2). No Hashes are
    seeded, so benchmark-first stays out of the way.
    """
    db.session.add(Settings(max_runtime_tasks=0, max_runtime_jobs=0))
    db.session.commit()
    rows = [
        dict(task_id=1, chunk_no=1, chunk_total=3),
        dict(task_id=2, chunk_no=1, chunk_total=2),
        dict(task_id=1, chunk_no=2, chunk_total=3),
        dict(task_id=1, chunk_no=3, chunk_total=3),
        dict(task_id=2, chunk_no=2, chunk_total=2),
    ]
    for r in rows:                       # commit individually -> ascending ids in insert order
        db.session.add(JobTasks(job_id=1, status="Queued", priority=3, **r))
        db.session.commit()

    order = []
    for i in range(len(rows)):
        _agent(uuid=f"disp-{i}", status="Idle")
        _set_agent_cookies(client, f"disp-{i}")
        body = _body(client.post("/v1/agents/heartbeat",
                                 json={"agent_status": "Idle", "hc_status": ""}))
        assert body["msg"] == "START"
        jt = JobTasks.query.get(body["job_task_id"])
        order.append((jt.task_id, jt.chunk_no))

    assert order == [(1, 1), (1, 2), (1, 3), (2, 1), (2, 2)]


def test_heartbeat_working_persists_gpu_telemetry(app, client):
    """A Working heartbeat's hc_status device info is parsed and persisted on the
    agent (and retained across idle), populating the agents page GPU/temp columns."""
    db.session.add(Settings(max_runtime_tasks=0, max_runtime_jobs=0))
    db.session.commit()
    agent = _agent(uuid="gpu-agent", status="Working")
    db.session.add(JobTasks(job_id=1, task_id=1, status="Running", priority=3,
                            agent_id=agent.id))
    db.session.commit()
    _set_agent_cookies(client, "gpu-agent")
    hc = {"Speed #": "100 GH/s", "Recovered": "1/9", "Time_Estimated": "x (1h)",
          "GPU_Count": 8, "GPU_Model": "RTX 4090", "Temps": "71,70,72"}
    resp = client.post("/v1/agents/heartbeat",
                       json={"agent_status": "Working", "hc_status": hc})
    assert resp.status_code == 200
    a = Agents.query.get(agent.id)
    assert a.gpu_count == 8
    assert a.gpu_model == "RTX 4090"
    assert a.gpu_temps == "71,70,72"
