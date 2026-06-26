"""Tests for agent GPU/temp/util telemetry: utils.agent_telemetry + the agents
page and fleet-modal render that consume it."""

from datetime import datetime

import pytest

from hashview.models import (
    AgentBenchmarks,
    Agents,
    Customers,
    Hashes,
    HashfileHashes,
    Hashfiles,
    Jobs,
    JobTasks,
    Tasks,
    db,
)
from hashview.utils.utils import agent_telemetry
from tests.unit.helpers import login, make_admin


def _running_agent_with_task(uuid="ua"):
    """An agent cracking a task. hashtype 1000, benchmark 300 GH/s, current
    270 GH/s -> 90% util; cards 71/70/72 °C; 8× RTX 4090. Returns (agent, task, user)."""
    user = make_admin()
    cust = Customers(name="C")
    db.session.add(cust)
    db.session.commit()
    hf = Hashfiles(name="hf", customer_id=cust.id, owner_id=user.id)
    db.session.add(hf)
    db.session.commit()
    h = Hashes(sub_ciphertext="0" * 32, ciphertext="A", hash_type=1000, cracked=False)
    db.session.add(h)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    db.session.commit()
    job = Jobs(name="Hashmob run", owner_id=user.id, customer_id=cust.id,
               hashfile_id=hf.id, status="Running", priority=3)
    db.session.add(job)
    db.session.commit()
    task = Tasks(name="rockyou + best64", owner_id=user.id, hc_attackmode=0)
    db.session.add(task)
    db.session.commit()
    agent = Agents(name="rig-alpha", src_ip="1.1.1.1", uuid=uuid, status="Working",
                   benchmark="270 GH/s", gpu_count=8, gpu_model="RTX 4090",
                   gpu_temps="71,70,72", last_checkin=datetime.utcnow())
    db.session.add(agent)
    db.session.commit()
    db.session.add(AgentBenchmarks(agent_id=agent.id, hash_type=1000, speed=300_000_000_000))
    db.session.add(JobTasks(job_id=job.id, task_id=task.id, status="Running",
                            chunk_no=1, chunk_total=4, agent_id=agent.id))
    db.session.commit()
    return agent, task, user


# --- agent_telemetry (pure-ish aggregation) --------------------------------

@pytest.mark.security
def test_agent_telemetry_running(app, db_session):
    agent, task, _ = _running_agent_with_task()
    t = agent_telemetry([agent])[agent.id]
    assert t["gpu"] == "8× RTX 4090"
    assert t["temp"] == 72                       # hottest card
    assert t["task"] == "rockyou + best64"
    assert t["hashrate"] == "270 GH/s"
    assert t["util"] == 90                        # 270 of 300 GH/s benchmark


@pytest.mark.security
def test_agent_telemetry_idle_agent(app, db_session):
    make_admin()
    agent = Agents(name="rig-charlie", src_ip="1.1.1.3", uuid="uc", status="Idle",
                   benchmark="200 GH/s", gpu_count=8, gpu_model="RTX 3090", gpu_temps="41")
    db.session.add(agent)
    db.session.commit()
    t = agent_telemetry([agent])[agent.id]
    assert t["gpu"] == "8× RTX 3090"
    assert t["temp"] == 41
    assert t["task"] is None                      # not cracking
    assert t["util"] is None                      # idle -> no utilization
    assert t["hashrate"] is None


@pytest.mark.security
def test_agent_telemetry_no_gpu_info(app, db_session):
    make_admin()
    agent = Agents(name="bare", src_ip="1.1.1.9", uuid="ub", status="Idle")
    db.session.add(agent)
    db.session.commit()
    t = agent_telemetry([agent])[agent.id]
    assert t["gpu"] == "" and t["temp"] is None and t["util"] is None


# --- agents page render -----------------------------------------------------

@pytest.mark.security
def test_agents_page_shows_gpu_temp_util_task(app, client):
    agent, task, user = _running_agent_with_task()
    login(client, user)
    html = client.get("/agents").get_data(as_text=True)
    assert "8× RTX 4090" in html                  # GPU column
    assert "72°C" in html                          # hottest card temp
    assert "90%" in html                           # utilization
    assert "rockyou + best64" in html              # current task
    assert "270 GH/s" in html                      # hashrate
    assert "telemetry pending" not in html         # old placeholder gone


@pytest.mark.security
def test_agents_page_gpu_kpi_sums_gpu_counts(app, client):
    _, _, user = _running_agent_with_task()         # 8 GPUs
    db.session.add(Agents(name="rig-2", src_ip="1.1.1.2", uuid="u2", status="Idle",
                          gpu_count=4, gpu_model="A100", last_checkin=datetime.utcnow()))
    db.session.commit()
    login(client, user)
    html = client.get("/agents").get_data(as_text=True)
    assert "GPUs Active" in html
    assert '<div class="kpi-value">12</div>' in html   # 8 + 4 summed


# --- fleet modal render -----------------------------------------------------

@pytest.mark.security
def test_fleet_modal_shows_util_temp_task_drops_recovered_lastseen(app, client):
    agent, task, user = _running_agent_with_task()
    login(client, user)
    html = client.get("/dashboard/fleet").get_data(as_text=True)
    assert "rig-alpha" in html
    assert ">util<" in html                        # utilization row added
    assert ">temp<" in html                        # temperature row added
    assert "rockyou + best64" in html              # parent task added
    assert ">recovered<" not in html               # dropped
    assert "last seen" not in html                 # dropped
