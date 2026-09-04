"""Regression tests for issue #447's server-side benchmark bookkeeping.

Covers:
1. slowest_benchmark ignores speed=0 rows (a zero-speed agent must not drag
   the reported minimum -- and therefore chunk sizing -- to a falsy 0).
2. The /v1/agents/benchmark pre-scan does not treat a fresh zero-report as
   "pending work to rechunk" (that was the starvation-loop trigger).
3. The heartbeat's Idle dispatch never hands an agent a task whose hash type
   it has already reported unsupported (speed=0); it is dispatched other
   queued work instead, or 'OK' if nothing else qualifies. A zero-speed row
   also does not cause the agent to be re-asked to BENCHMARK that hash type.

Reuses the agent/heartbeat fixture patterns from test_api_agent_protocol.py
(_agent, _set_agent_cookies, DOMAIN) rather than inventing new ones.
"""

import json

from hashview.models import (
    AgentBenchmarks,
    Agents,
    Customers,
    Hashes,
    HashfileHashes,
    Hashfiles,
    Jobs,
    JobTasks,
    Settings,
    db,
)
from hashview.utils.utils import slowest_benchmark

DOMAIN = "localhost.test"


def _agent(uuid="agent-uuid", status="Idle"):
    a = Agents(name="a1", src_ip="127.0.0.1", uuid=uuid, status=status)
    db.session.add(a)
    db.session.commit()
    return a


def _set_agent_cookies(client, uuid):
    import hashview
    client.set_cookie("uuid", uuid, domain=DOMAIN)
    client.set_cookie("agent_version", hashview.__version__, domain=DOMAIN)


def _body(resp):
    return json.loads(resp.get_data(as_text=True))


def _job_with_hash_type(hash_type, name="j"):
    """A Running job whose hashfile contains a single hash of ``hash_type``,
    so _job_hash_type(job) resolves to it."""
    cust = Customers(name=f"C-{name}")
    db.session.add(cust)
    db.session.commit()
    hf = Hashfiles(name=f"hf-{name}", customer_id=cust.id, owner_id=1)
    db.session.add(hf)
    db.session.commit()
    h = Hashes(sub_ciphertext=f"{hash_type:032X}", ciphertext="AAA",
               hash_type=hash_type, cracked=False)
    db.session.add(h)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    job = Jobs(name=name, status="Running", customer_id=cust.id, owner_id=1,
               priority=3, hashfile_id=hf.id)
    db.session.add(job)
    db.session.commit()
    return job


# --- slowest_benchmark -------------------------------------------------------

def test_slowest_benchmark_none_when_only_zero_speed_row(app, client):
    agent = _agent(uuid="sb-agent")
    db.session.add(AgentBenchmarks(agent_id=agent.id, hash_type=9999, speed=0))
    db.session.commit()
    assert slowest_benchmark(9999) is None


def test_slowest_benchmark_ignores_zero_among_mixed_rows(app, client):
    a1 = _agent(uuid="sb-a1")
    a2 = _agent(uuid="sb-a2")
    a3 = _agent(uuid="sb-a3")
    db.session.add_all([
        AgentBenchmarks(agent_id=a1.id, hash_type=8888, speed=0),
        AgentBenchmarks(agent_id=a2.id, hash_type=8888, speed=500),
        AgentBenchmarks(agent_id=a3.id, hash_type=8888, speed=1000),
    ])
    db.session.commit()
    assert slowest_benchmark(8888) == 500


# --- benchmark pre-scan: zero report is not "pending" ------------------------

def test_zero_speed_benchmark_does_not_trigger_rechunk(app, client, monkeypatch):
    called = []
    monkeypatch.setattr(
        "hashview.api.routes.rechunk_queued_tasks_for_hashtype",
        lambda hash_type: called.append(hash_type))
    agent = _agent(uuid="zero-bench")
    _set_agent_cookies(client, "zero-bench")

    resp = client.post("/v1/agents/benchmark",
                       json={"benchmark_results": {"7777": 0}})
    assert _body(resp)["msg"] == "OK"
    assert called == []                          # never rechunked
    row = AgentBenchmarks.query.filter_by(agent_id=agent.id, hash_type=7777).first()
    assert row is not None and row.speed == 0     # but still recorded (Task 1 contract)


def test_nonzero_first_benchmark_still_triggers_rechunk(app, client, monkeypatch):
    # Sanity check the pre-scan restructure didn't also break the real case.
    called = []
    monkeypatch.setattr(
        "hashview.api.routes.rechunk_queued_tasks_for_hashtype",
        lambda hash_type: called.append(hash_type))
    _agent(uuid="nonzero-bench")
    _set_agent_cookies(client, "nonzero-bench")

    resp = client.post("/v1/agents/benchmark",
                       json={"benchmark_results": {"6666": 5000}})
    assert _body(resp)["msg"] == "OK"
    assert called == [6666]


# --- heartbeat dispatch skips a hash type the agent can't run ---------------

def test_heartbeat_does_not_reask_benchmark_for_zero_speed_mode(app, client):
    # An agent with a recorded (even zero) benchmark for the in-use hash type
    # is not sent back to BENCHMARK for it.
    db.session.add(Settings(retention_period=30, max_runtime_tasks=0, max_runtime_jobs=0))
    db.session.commit()
    _job_with_hash_type(4444, name="zb")
    agent = _agent(uuid="zb-agent", status="Idle")
    db.session.add(AgentBenchmarks(agent_id=agent.id, hash_type=4444, speed=0))
    db.session.commit()
    _set_agent_cookies(client, "zb-agent")

    body = _body(client.post("/v1/agents/heartbeat",
                             json={"agent_status": "Idle", "hc_status": ""}))
    assert body["msg"] != "BENCHMARK"


def test_heartbeat_skips_unsupported_hashtype_dispatches_other_task(app, client):
    # Agent has already reported hash type X (4001) unsupported (speed=0), and
    # has a real benchmark for hash type Y (4002). Queued work exists for BOTH,
    # X first in priority/id order. The agent must be dispatched Y's task, not
    # X's -- and X's task must remain untouched/Queued.
    db.session.add(Settings(retention_period=30, max_runtime_tasks=0, max_runtime_jobs=0))
    db.session.commit()
    job_x = _job_with_hash_type(4001, name="jx")
    job_y = _job_with_hash_type(4002, name="jy")
    agent = _agent(uuid="skip-agent", status="Idle")
    db.session.add_all([
        AgentBenchmarks(agent_id=agent.id, hash_type=4001, speed=0),
        AgentBenchmarks(agent_id=agent.id, hash_type=4002, speed=1000),
    ])
    # X queued first (lower id / higher precedence in the default ordering)
    jt_x = JobTasks(job_id=job_x.id, task_id=1, status="Queued", priority=3)
    db.session.add(jt_x)
    db.session.commit()
    jt_y = JobTasks(job_id=job_y.id, task_id=2, status="Queued", priority=3)
    db.session.add(jt_y)
    db.session.commit()
    _set_agent_cookies(client, "skip-agent")

    body = _body(client.post("/v1/agents/heartbeat",
                             json={"agent_status": "Idle", "hc_status": ""}))
    assert body["msg"] == "START"
    assert body["job_task_id"] == jt_y.id
    assert JobTasks.query.get(jt_x.id).status == "Queued"
    assert JobTasks.query.get(jt_x.id).agent_id is None
    assert JobTasks.query.get(jt_y.id).agent_id == agent.id


def test_heartbeat_all_queued_work_unsupported_returns_ok(app, client):
    # Only queued work is for a hash type the agent has already flagged
    # unsupported -- nothing else qualifies, so it gets OK (not START, not a
    # wasted BENCHMARK re-ask since it already has a benchmark row for it).
    db.session.add(Settings(retention_period=30, max_runtime_tasks=0, max_runtime_jobs=0))
    db.session.commit()
    job_x = _job_with_hash_type(5001, name="onlyx")
    agent = _agent(uuid="onlyx-agent", status="Idle")
    db.session.add(AgentBenchmarks(agent_id=agent.id, hash_type=5001, speed=0))
    jt_x = JobTasks(job_id=job_x.id, task_id=1, status="Queued", priority=3)
    db.session.add(jt_x)
    db.session.commit()
    _set_agent_cookies(client, "onlyx-agent")

    body = _body(client.post("/v1/agents/heartbeat",
                             json={"agent_status": "Idle", "hc_status": ""}))
    assert body["msg"] == "OK"
    assert JobTasks.query.get(jt_x.id).status == "Queued"
    assert JobTasks.query.get(jt_x.id).agent_id is None
