"""Tests for the dashboard per-task chunk aggregation.

main.routes._job_task_groups collapses a running job's chunk JobTasks into one
parent row per task (counts, derived status, summed rate, recovered, eta, active
chunks). These pin that math and the grouped /dashboard/jobs render.
"""

import json

import pytest

from hashview.main.routes import _agents_ctx, _fmt, _hps, _job_task_groups
from hashview.models import (
    Agents,
    Customers,
    Hashes,
    HashfileHashes,
    Hashfiles,
    Jobs,
    JobTasks,
    Tasks,
    Users,
    db,
)


def _seed_running_job():
    user = Users(first_name="A", last_name="D", email_address="own@e.com",
                 password="x" * 60, admin=True)
    db.session.add(user)
    db.session.commit()
    cust = Customers(name="Acme")
    db.session.add(cust)
    db.session.commit()
    hf = Hashfiles(name="hf", customer_id=cust.id, owner_id=user.id)
    db.session.add(hf)
    db.session.commit()
    job = Jobs(name="Q2 Pentest", owner_id=user.id, customer_id=cust.id,
               hashfile_id=hf.id, status="Running", priority=3)
    db.session.add(job)
    db.session.commit()

    task_a = Tasks(name="rockyou + best64", owner_id=user.id, hc_attackmode=0,
                   wl_id=1, rule_id=1)               # Dict + Rule
    task_b = Tasks(name="NTLM mask", owner_id=user.id, hc_attackmode=3,
                   hc_mask="?d?d?d")                  # Mask, whole (un-chunked)
    db.session.add_all([task_a, task_b])
    db.session.commit()

    # agent running chunk 3 of task A
    agent_a = Agents(name="rig-alpha", src_ip="1.1.1.1", uuid="u-alpha",
                     status="Working", benchmark="100 GH/s",
                     hc_status=json.dumps({"Speed #": "100 GH/s",
                                           "Recovered": "7/100",
                                           "Time_Estimated": "x (41 mins)"}))
    db.session.add(agent_a)
    db.session.commit()
    # 5 chunks: 2 completed, 1 running (chunk 3), 2 queued
    for i, st in enumerate(["Completed", "Completed", "Running", "Queued", "Queued"], start=1):
        db.session.add(JobTasks(job_id=job.id, task_id=task_a.id, status=st,
                                chunk_no=i, chunk_total=5,
                                agent_id=(agent_a.id if st == "Running" else None)))

    # task B: a single whole running JobTask on its own agent
    agent_b = Agents(name="rig-bravo", src_ip="1.1.1.2", uuid="u-bravo",
                     status="Working", benchmark="50 GH/s",
                     hc_status=json.dumps({"Speed #": "50 GH/s",
                                           "Recovered": "3/100",
                                           "Time_Estimated": "y (1h 6m)"}))
    db.session.add(agent_b)
    db.session.commit()
    db.session.add(JobTasks(job_id=job.id, task_id=task_b.id, status="Running",
                            agent_id=agent_b.id))

    # 4 cracked hashes credited to task A
    for i in range(4):
        db.session.add(Hashes(sub_ciphertext=f"{i:032x}", ciphertext=f"c{i}",
                              hash_type=1000, cracked=True, task_id=task_a.id))
    db.session.commit()
    return job, task_a, task_b


def _build(job):
    ac = _agents_ctx()
    return _job_task_groups(
        [job], JobTasks.query.all(),
        {t.id: t for t in Tasks.query.all()},
        {a.id: a for a in ac['agents']},
        ac['recovered_list'], ac['time_estimated_list'],
    )[job.id]


@pytest.mark.security
def test_job_task_groups_rollups(app, db_session):
    job, _, _ = _seed_running_job()
    dash = _build(job)
    assert dash['tasks_total'] == 2          # grouped by task, NOT 6 chunks
    assert dash['tasks_running'] == 2
    assert dash['chunks_total'] == 6
    assert dash['chunks_done'] == 2
    assert dash['chunks_active'] == 2


@pytest.mark.security
def test_job_task_groups_chunked_task(app, db_session):
    job, task_a, _ = _seed_running_job()
    g = {grp['task_id']: grp for grp in _build(job)['groups']}[task_a.id]
    assert g['status'] == 'Running'
    assert (g['total'], g['completed'], g['running'], g['queued']) == (5, 2, 1, 2)
    assert g['is_chunked'] and g['expandable']
    assert g['attack'] == 'Dict + Rule'
    assert g['recovered'] == 4
    assert g['rate'] == _fmt(_hps("100 GH/s"))     # summed over running agents (one)
    assert len(g['active_chunks']) == 1
    chunk = g['active_chunks'][0]
    assert chunk['chunk_no'] == 3 and chunk['agent'] == 'rig-alpha'
    assert g['eta'] == '41 mins'


@pytest.mark.security
def test_job_task_groups_whole_task_not_expandable(app, db_session):
    job, _, task_b = _seed_running_job()
    g = {grp['task_id']: grp for grp in _build(job)['groups']}[task_b.id]
    assert g['total'] == 1
    assert not g['is_chunked']
    assert not g['expandable']               # nothing to drill into
    assert g['attack'] == 'Mask'


@pytest.mark.security
def test_dashboard_jobs_renders_one_row_per_task(app, client):
    from tests.unit.helpers import login, make_admin
    _seed_running_job()
    login(client, make_admin())
    resp = client.get("/dashboard/jobs")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    # one parent row per task (2), not one per chunk (6)
    assert html.count('class="task-row"') == 2
    assert 'chunk-row' in html               # active chunk child rendered
    assert 'active' in html                  # "N active" indicator
    assert 'rockyou + best64' in html


@pytest.mark.security
def test_parent_rate_sums_all_running_chunks(app, db_session):
    """The parent task Rate is the SUM of every running chunk's agent speed."""
    user = Users(first_name="A", last_name="D", email_address="sum@e.com",
                 password="x" * 60, admin=True)
    db.session.add(user)
    db.session.commit()
    cust = Customers(name="C")
    db.session.add(cust)
    db.session.commit()
    hf = Hashfiles(name="h", customer_id=cust.id, owner_id=user.id)
    db.session.add(hf)
    db.session.commit()
    h = Hashes(sub_ciphertext="0" * 32, ciphertext="A", hash_type=1000, cracked=False)
    db.session.add(h)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    db.session.commit()
    job = Jobs(name="j", owner_id=user.id, customer_id=cust.id, hashfile_id=hf.id,
               status="Running", priority=3)
    db.session.add(job)
    db.session.commit()
    task = Tasks(name="t", owner_id=user.id, hc_attackmode=0)
    db.session.add(task)
    db.session.commit()

    def _agent(name, speed, uuid):
        a = Agents(name=name, src_ip="1.1.1.1", uuid=uuid, status="Working",
                   benchmark=speed,
                   hc_status=json.dumps({"Speed #": speed, "Recovered": "1/9",
                                         "Time_Estimated": "x (1h)"}))
        db.session.add(a)
        db.session.commit()
        return a
    a1 = _agent("rig-a", "100 GH/s", "ua")
    a2 = _agent("rig-b", "50 GH/s", "ub")
    db.session.add_all([
        JobTasks(job_id=job.id, task_id=task.id, status="Running", chunk_no=1, chunk_total=3, agent_id=a1.id),
        JobTasks(job_id=job.id, task_id=task.id, status="Running", chunk_no=2, chunk_total=3, agent_id=a2.id),
        JobTasks(job_id=job.id, task_id=task.id, status="Queued", chunk_no=3, chunk_total=3),
    ])
    db.session.commit()

    g = _build(job)["groups"][0]
    assert len(g["active_chunks"]) == 2
    assert g["rate"] == _fmt(_hps("100 GH/s") + _hps("50 GH/s"))   # 150.0 GH/s, NOT 100
    assert g["rate"] == "150.0 GH/s"


@pytest.mark.security
def test_parent_rate_skips_running_chunk_without_speed(app, db_session):
    """A running chunk whose agent has no current speed contributes 0 to the sum
    (documents the only way the parent under-counts: a speedless agent)."""
    user = Users(first_name="A", last_name="D", email_address="ns@e.com",
                 password="x" * 60, admin=True)
    db.session.add(user)
    db.session.commit()
    cust = Customers(name="C")
    db.session.add(cust)
    db.session.commit()
    hf = Hashfiles(name="h", customer_id=cust.id, owner_id=user.id)
    db.session.add(hf)
    db.session.commit()
    job = Jobs(name="j", owner_id=user.id, customer_id=cust.id, hashfile_id=hf.id,
               status="Running", priority=3)
    db.session.add(job)
    db.session.commit()
    task = Tasks(name="t", owner_id=user.id, hc_attackmode=0)
    db.session.add(task)
    db.session.commit()
    a1 = Agents(name="rig-a", src_ip="1.1.1.1", uuid="na1", status="Working", benchmark="100 GH/s")
    a2 = Agents(name="rig-b", src_ip="1.1.1.2", uuid="na2", status="Working", benchmark=None)
    db.session.add_all([a1, a2])
    db.session.commit()
    db.session.add_all([
        JobTasks(job_id=job.id, task_id=task.id, status="Running", chunk_no=1, chunk_total=2, agent_id=a1.id),
        JobTasks(job_id=job.id, task_id=task.id, status="Running", chunk_no=2, chunk_total=2, agent_id=a2.id),
    ])
    db.session.commit()
    g = _build(job)["groups"][0]
    assert g["rate"] == "100.0 GH/s"      # a2 (no speed) adds 0


@pytest.mark.security
def test_hps_parses_tricky_speed_formats():
    """The strict old parser returned 0 for any of these, dropping the chunk's
    rate from the parent sum even though its own row displayed it."""
    assert _hps("284.6 GH/s") == 284.6e9
    assert _hps("284.6 gh/s") == 284.6e9            # lowercase unit
    assert _hps("1,024 MH/s") == 1024e6             # thousands separator
    assert _hps("284.6 GH/s (12.3ms)") == 284.6e9   # trailing text
    assert _hps("512 H/s") == 512
    assert _hps("512") == 512                       # bare number -> H/s
    assert _hps(512) == 512                         # already numeric
    assert _hps("1.5 TH/s") == 1.5e12
    assert _hps(None) == 0.0
    assert _hps("") == 0.0
    assert _hps("n/a") == 0.0


@pytest.mark.security
def test_parent_rate_sums_chunk_with_unusual_speed_format(app, db_session):
    """A running chunk whose agent reports an unusual-but-valid speed (lowercase
    unit) is still summed into the parent rate (regression for the reported bug:
    chunk row showed a rate but the parent only counted the first agent)."""
    user = Users(first_name="A", last_name="D", email_address="fmt@e.com",
                 password="x" * 60, admin=True)
    db.session.add(user)
    db.session.commit()
    cust = Customers(name="C")
    db.session.add(cust)
    db.session.commit()
    hf = Hashfiles(name="h", customer_id=cust.id, owner_id=user.id)
    db.session.add(hf)
    db.session.commit()
    job = Jobs(name="Hashmob + barrage", owner_id=user.id, customer_id=cust.id,
               hashfile_id=hf.id, status="Running", priority=3)
    db.session.add(job)
    db.session.commit()
    task = Tasks(name="t", owner_id=user.id, hc_attackmode=0)
    db.session.add(task)
    db.session.commit()
    a1 = Agents(name="local", src_ip="1.1.1.1", uuid="loc", status="Working",
                benchmark="100.0 GH/s")
    a2 = Agents(name="remote", src_ip="1.1.1.2", uuid="rem", status="Working",
                benchmark="50.0 gh/s")          # lowercase -> old parser dropped it
    db.session.add_all([a1, a2])
    db.session.commit()
    db.session.add_all([
        JobTasks(job_id=job.id, task_id=task.id, status="Running", chunk_no=2, chunk_total=8, agent_id=a1.id),
        JobTasks(job_id=job.id, task_id=task.id, status="Running", chunk_no=8, chunk_total=8, agent_id=a2.id),
    ])
    db.session.commit()
    g = _build(job)["groups"][0]
    assert len(g["active_chunks"]) == 2
    assert g["rate"] == "150.0 GH/s"     # both summed, not just the first (100)
