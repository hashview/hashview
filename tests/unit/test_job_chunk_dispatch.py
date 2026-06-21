"""Dispatch-side tests for build_job_task_commands (hashview.utils.utils).

Covers the fan-out at queue time: a static-wordlist task splits into N chunk
JobTasks when chunking is enabled and a benchmark exists; a dynamic-wordlist task
and a toggle-off job stay whole; and re-queue is idempotent (no re-expansion).
"""

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
    Settings,
    Tasks,
    Users,
    Wordlists,
    db,
)
from hashview.utils.utils import build_job_task_commands, rechunk_queued_tasks_for_hashtype


def _seed(attackmode=0, wl_type="static", wl_size=1_000_000, rule_size=100,
          enabled_chunking=True, benchmark_speed=1000, target=60):
    user = Users(first_name="A", last_name="D", email_address="a@b.com",
                 password="x" * 60, admin=True)
    db.session.add(user)
    db.session.commit()
    db.session.add(Settings(retention_period=30, max_runtime_jobs=0, max_runtime_tasks=0,
                            enabled_chunking=enabled_chunking, chunk_target_duration=target))
    cust = Customers(name="C")
    db.session.add(cust)
    db.session.commit()
    hf = Hashfiles(name="h", customer_id=cust.id, owner_id=user.id)
    db.session.add(hf)
    db.session.commit()
    h = Hashes(sub_ciphertext="0" * 32, ciphertext="AAA", hash_type=1000, cracked=False)
    db.session.add(h)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    db.session.commit()
    wl = Wordlists(name="wl", owner_id=user.id, type=wl_type,
                   path="control/wordlists/wl.gz", size=wl_size, checksum="0" * 64)
    db.session.add(wl)
    db.session.commit()
    from hashview.models import Rules
    rule = Rules(name="r", owner_id=user.id, path="control/rules/r.rule",
                 checksum="0" * 64, size=rule_size)
    db.session.add(rule)
    db.session.commit()
    task = Tasks(name="t", owner_id=user.id, hc_attackmode=attackmode, wl_id=wl.id,
                 rule_id=(rule.id if attackmode == 0 else None), loopback=False)
    db.session.add(task)
    db.session.commit()
    if benchmark_speed is not None:
        agent = Agents(name="ag", src_ip="1.1.1.1", uuid="u1", status="Idle")
        db.session.add(agent)
        db.session.commit()
        db.session.add(AgentBenchmarks(agent_id=agent.id, hash_type=1000,
                                       speed=benchmark_speed))
        db.session.commit()
    job = Jobs(name="j", owner_id=user.id, customer_id=cust.id, hashfile_id=hf.id,
               status="Ready", priority=3)
    db.session.add(job)
    db.session.commit()
    db.session.add(JobTasks(job_id=job.id, task_id=task.id, status="Not Started"))
    db.session.commit()
    return job, task


@pytest.mark.security
def test_static_task_fans_out_into_chunks(app, db_session):
    job, task = _seed()
    build_job_task_commands(job)
    db.session.commit()

    rows = JobTasks.query.filter_by(job_id=job.id).all()
    assert len(rows) > 1, "expected the task to split into multiple chunk JobTasks"
    # every chunk: Queued, has --skip/--limit in its command, chunk_no/total set
    assert all(r.status == "Queued" for r in rows)
    assert all("--skip" in r.command and "--limit" in r.command for r in rows)
    assert all(r.chunk_total == len(rows) for r in rows)
    assert {r.chunk_no for r in rows} == set(range(1, len(rows) + 1))
    # chunks tile the keyspace contiguously (ordered by skip)
    ordered = sorted(rows, key=lambda r: r.chunk_skip)
    skip = 0
    for r in ordered:
        assert r.chunk_skip == skip
        skip += r.chunk_limit
    assert skip == 1_000_000
    # per-chunk file identity: outfile keyed by the chunk's own job_task id
    for r in rows:
        assert f"_{r.id}.txt" in r.command


@pytest.mark.security
def test_dynamic_wordlist_task_stays_whole(app, db_session):
    job, task = _seed(wl_type="dynamic")
    build_job_task_commands(job)
    db.session.commit()
    rows = JobTasks.query.filter_by(job_id=job.id).all()
    assert len(rows) == 1
    assert rows[0].chunk_total is None
    assert "--skip" not in rows[0].command


@pytest.mark.security
def test_toggle_off_stays_whole(app, db_session):
    job, task = _seed(enabled_chunking=False)
    build_job_task_commands(job)
    db.session.commit()
    rows = JobTasks.query.filter_by(job_id=job.id).all()
    assert len(rows) == 1
    assert rows[0].chunk_total is None


@pytest.mark.security
def test_no_benchmark_stays_whole(app, db_session):
    job, task = _seed(benchmark_speed=None)
    build_job_task_commands(job)
    db.session.commit()
    rows = JobTasks.query.filter_by(job_id=job.id).all()
    assert len(rows) == 1
    assert rows[0].chunk_total is None


@pytest.mark.security
def test_requeue_is_idempotent(app, db_session):
    job, task = _seed()
    build_job_task_commands(job)
    db.session.commit()
    first = JobTasks.query.filter_by(job_id=job.id).all()
    first_count = len(first)
    first_ids = {r.id for r in first}
    assert first_count > 1

    # simulate stop -> start: re-run the queue builder
    for r in first:
        r.status = "Canceled"
    db.session.commit()
    build_job_task_commands(job)
    db.session.commit()

    second = JobTasks.query.filter_by(job_id=job.id).all()
    assert len(second) == first_count, "re-queue must not create more chunks"
    assert {r.id for r in second} == first_ids, "re-queue must reuse the same rows"
    assert all(r.status == "Queued" for r in second)


# --- re-chunk on first benchmark (option 1) --------------------------------


def _seed_queued_whole_task(enabled_chunking=True, wl_type="static"):
    """A QUEUED job whose only task is a WHOLE 'Queued' JobTask (as if it was
    queued for a hash type that had no benchmark yet -> ran un-chunked)."""
    from hashview.models import Rules
    user = Users(first_name="A", last_name="D", email_address="rc@b.com",
                 password="x" * 60, admin=True)
    db.session.add(user)
    db.session.commit()
    db.session.add(Settings(retention_period=30, max_runtime_jobs=0, max_runtime_tasks=0,
                            enabled_chunking=enabled_chunking, chunk_target_duration=60))
    cust = Customers(name="C")
    db.session.add(cust)
    db.session.commit()
    hf = Hashfiles(name="h", customer_id=cust.id, owner_id=user.id)
    db.session.add(hf)
    db.session.commit()
    h = Hashes(sub_ciphertext="0" * 32, ciphertext="AAA", hash_type=1000, cracked=False)
    db.session.add(h)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    db.session.commit()
    wl = Wordlists(name="wl", owner_id=user.id, type=wl_type,
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
    return job, task


def _add_benchmark(hash_type=1000, speed=1000, uuid="rc-agent"):
    agent = Agents(name="ag", src_ip="1.1.1.1", uuid=uuid, status="Idle")
    db.session.add(agent)
    db.session.commit()
    db.session.add(AgentBenchmarks(agent_id=agent.id, hash_type=hash_type, speed=speed))
    db.session.commit()
    return agent


@pytest.mark.security
def test_rechunk_splits_queued_whole_task_after_benchmark(app, db_session):
    job, _ = _seed_queued_whole_task()
    assert JobTasks.query.filter_by(job_id=job.id).count() == 1   # ran un-chunked
    _add_benchmark()
    rechunk_queued_tasks_for_hashtype(1000)
    rows = JobTasks.query.filter_by(job_id=job.id).all()
    assert len(rows) > 1                                          # now split
    assert all(r.chunk_total == len(rows) for r in rows)
    assert all(r.status == "Queued" and r.agent_id is None for r in rows)
    assert all("--skip" in r.command for r in rows)


@pytest.mark.security
def test_rechunk_skips_already_assigned_task(app, db_session):
    job, _ = _seed_queued_whole_task()
    jt = JobTasks.query.filter_by(job_id=job.id).first()
    agent = _add_benchmark()
    jt.status = "Running"           # an agent grabbed the whole task first
    jt.agent_id = agent.id
    db.session.commit()
    rechunk_queued_tasks_for_hashtype(1000)
    assert JobTasks.query.filter_by(job_id=job.id).count() == 1   # left alone


@pytest.mark.security
def test_rechunk_noop_when_chunking_disabled(app, db_session):
    job, _ = _seed_queued_whole_task(enabled_chunking=False)
    _add_benchmark()
    rechunk_queued_tasks_for_hashtype(1000)
    assert JobTasks.query.filter_by(job_id=job.id).count() == 1


@pytest.mark.security
def test_rechunk_skips_dynamic_wordlist_task(app, db_session):
    job, _ = _seed_queued_whole_task(wl_type="dynamic")
    _add_benchmark()
    rechunk_queued_tasks_for_hashtype(1000)
    assert JobTasks.query.filter_by(job_id=job.id).count() == 1
