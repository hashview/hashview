"""Tests for the dashboard per-task chunk aggregation.

main.routes._job_task_groups collapses a running job's chunk JobTasks into one
parent row per task (counts, derived status, summed rate, recovered, eta, active
chunks). These pin that math and the grouped /dashboard/jobs render.
"""

import json
import re
from datetime import datetime

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
    Settings,
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
               hashfile_id=hf.id, status="Running", priority=3,
               started_at=datetime(2020, 1, 1))
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

    # 4 cracked hashes credited to task A, present in THIS job's hashfile
    for i in range(4):
        h = Hashes(sub_ciphertext=f"{i:032x}", ciphertext=f"c{i}",
                   hash_type=1000, cracked=True, task_id=task_a.id,
                   recovered_at=datetime(2021, 1, 1))
        db.session.add(h)
        db.session.commit()
        db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
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
    # Short form: hashcat writes '41 mins', the dashboard renders '41m' so the
    # ETA column matches the elapsed/runtime figures beside it (_eta_compact).
    assert g['eta'] == '41m'


@pytest.mark.security
def test_recovered_is_scoped_to_the_jobs_hashfile(app, db_session):
    # A task is reusable across jobs/hashfiles, so the parent 'recovered' must
    # count only cracks that live in THIS job's hashfile -- not every job that ran
    # the same task (the reported bug, which counted Hashes.task_id globally).
    job, task_a, _ = _seed_running_job()          # 4 cracked in this job's hashfile
    other_hf = Hashfiles(name="other", customer_id=job.customer_id, owner_id=job.owner_id)
    db.session.add(other_hf)
    db.session.commit()
    # same task cracked 3 more hashes, but they belong to a DIFFERENT hashfile
    for i in range(3):
        h = Hashes(sub_ciphertext=f"{i + 90:032x}", ciphertext=f"o{i}",
                   hash_type=1000, cracked=True, task_id=task_a.id)
        db.session.add(h)
        db.session.commit()
        db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=other_hf.id))
    db.session.commit()
    g = {grp['task_id']: grp for grp in _build(job)['groups']}[task_a.id]
    assert g['recovered'] == 4                     # not 7


@pytest.mark.security
def test_recovered_counts_per_account_in_hashfile(app, db_session):
    # One cracked hash shared by multiple usernames in the hashfile counts once
    # per account, matching the recovered totals shown elsewhere (email/analytics).
    job, task_a, _ = _seed_running_job()          # 4 single-account cracks
    shared = Hashes(sub_ciphertext="ab" * 16, ciphertext="shared",
                    hash_type=1000, cracked=True, task_id=task_a.id,
                    recovered_at=datetime(2021, 1, 1))
    db.session.add(shared)
    db.session.commit()
    for uname in ("alice", "bob"):
        db.session.add(HashfileHashes(hash_id=shared.id, hashfile_id=job.hashfile_id,
                                      username=uname))
    db.session.commit()
    g = {grp['task_id']: grp for grp in _build(job)['groups']}[task_a.id]
    assert g['recovered'] == 6                     # 4 + 2 accounts on the shared hash


@pytest.mark.security
def test_recovered_scoped_to_run_with_hashfile_total_denominator(app, db_session):
    # X counts only cracks from the CURRENT run (recovered_at >= job.started_at);
    # an earlier crack of the same task/hashfile is excluded. The job-level
    # denominator is the hashfile's UNRECOVERED (uncracked) accounts.
    job, task_a, _ = _seed_running_job()          # 4 cracked this run (recovered_at 2021)
    old = Hashes(sub_ciphertext="cd" * 16, ciphertext="old", hash_type=1000,
                 cracked=True, task_id=task_a.id, recovered_at=datetime(2019, 1, 1))
    db.session.add(old)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=old.id, hashfile_id=job.hashfile_id))
    for i in range(3):                            # 3 still-uncracked accounts
        u = Hashes(sub_ciphertext=f"{i + 50:032x}", ciphertext=f"u{i}",
                   hash_type=1000, cracked=False)
        db.session.add(u)
        db.session.commit()
        db.session.add(HashfileHashes(hash_id=u.id, hashfile_id=job.hashfile_id))
    db.session.commit()

    dash = _build(job)
    g = {grp['task_id']: grp for grp in dash['groups']}[task_a.id]
    assert g['recovered'] == 4                     # the pre-run crack (2019) is excluded
    # hashfile: 4 (run) + 1 (old) cracked + 3 uncracked = 8 accounts in total.
    # Y is the hashfile's TOTAL, not what is left: a denominator that shrank as X
    # grew meant two moving numbers and a ratio that never reached 1.
    assert dash['hashfile_total'] == 8


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
def test_dashboard_recovered_links_to_analytics(app, client):
    """The recovered "X" on both the task row and the per-chunk sub-row links to
    that job's hashfile analytics."""
    from tests.unit.helpers import login, make_admin
    job, _, _ = _seed_running_job()
    login(client, make_admin())
    resp = client.get("/dashboard/jobs")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert 'class="rec-x-link"' in html
    assert f'customer_id={job.customer_id}' in html
    assert f'hashfile_id={job.hashfile_id}' in html
    # the whole "X/Y" is the link now: >=3 anchors (2 task rows + task_a's active
    # chunk), and the /Y denominator closes the anchor (both X and Y enclosed).
    assert html.count('class="rec-x-link"') >= 3
    # Y is the hashfile's total accounts (4), so this reads "4/4". Under the old
    # "unrecovered left" denominator the same row rendered "4/0" -- four recovered
    # out of zero remaining, which is what prompted the change back.
    assert '/4</span></a>' in html


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


def _seed_task_with_chunk_statuses(statuses, email):
    """Create a Running job with one chunked task whose chunks have `statuses`,
    and return its derived dashboard group. Used to pin the parent-status logic."""
    user = Users(first_name="A", last_name="D", email_address=email,
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
    total = len(statuses)
    for i, st in enumerate(statuses, start=1):
        db.session.add(JobTasks(job_id=job.id, task_id=task.id, status=st,
                                chunk_no=i, chunk_total=total))
    db.session.commit()
    return _build(job)["groups"][0]


@pytest.mark.security
@pytest.mark.parametrize("statuses, expected", [
    # The reported bug: a canceled task that had finished some chunks first must
    # still read 'Canceled', not fall through to 'Queued'.
    (["Completed", "Completed", "Canceled", "Canceled", "Canceled"], "Canceled"),
    (["Canceled", "Canceled", "Canceled"], "Canceled"),          # all canceled
    (["Canceled"], "Canceled"),                                  # single-chunk task
    # Regression guards for the other branches:
    (["Completed", "Completed", "Queued", "Queued"], "Queued"),  # pending work remains
    (["Completed", "Completed", "Completed"], "Completed"),
    (["Running", "Queued", "Canceled"], "Running"),              # any running wins
    (["Queued", "Canceled"], "Queued"),                         # pending beats a lone cancel
    # Expired: the runtime cap stopped this attack. Before the status existed
    # these rows were 'Canceled'; before the ladder learned about them they
    # counted in no bucket at all and fell through to the else -> 'Queued', so
    # the dashboard showed a capped attack as still waiting to run, forever.
    (["Expired"], "Expired"),                                    # single chunk
    (["Expired", "Expired", "Expired"], "Expired"),              # all expired
    (["Completed", "Completed", "Expired"], "Expired"),          # some finished first
    # Expired outranks Canceled: the cap is the more specific fact, and it is
    # what an operator looking at a capped job needs to see.
    (["Canceled", "Expired"], "Expired"),
    # ...but neither outranks live or pending work.
    (["Running", "Expired"], "Running"),
    (["Queued", "Expired"], "Queued"),
    # Terminal fallback: a status outside running/queued/expired/canceled/
    # completed (e.g. 'Importing') with not-all-completed lands on the else.
    (["Completed", "Importing"], "Queued"),
])
def test_job_task_group_status_derivation(app, db_session, statuses, expected):
    g = _seed_task_with_chunk_statuses(statuses, email=f"{abs(hash(tuple(statuses)))}@e.com")
    assert g["status"] == expected


def test_attack_label_handles_missing_task():
    """_attack_label tolerates a task that was deleted out from under a chunk."""
    from hashview.main.routes import _attack_label
    assert _attack_label(None) == ''


def test_job_task_groups_skips_other_jobs_tasks(app, db_session):
    """_job_task_groups is fed every JobTask but must group only those belonging
    to the job being rendered (the jt.job_id != job.id skip)."""
    user = Users(first_name="A", last_name="D", email_address="multi@e.com",
                 password="x" * 60, admin=True)
    db.session.add(user)
    db.session.commit()
    cust = Customers(name="MultiCo")
    db.session.add(cust)
    db.session.commit()
    hf = Hashfiles(name="hf", customer_id=cust.id, owner_id=user.id)
    db.session.add(hf)
    db.session.commit()
    mine = Jobs(name="mine", owner_id=user.id, customer_id=cust.id,
                hashfile_id=hf.id, status="Running", priority=3)
    other = Jobs(name="other", owner_id=user.id, customer_id=cust.id,
                 hashfile_id=hf.id, status="Running", priority=3)
    db.session.add_all([mine, other])
    db.session.commit()
    t_mine = Tasks(name="mine-task", owner_id=user.id, hc_attackmode=0)
    t_other = Tasks(name="other-task", owner_id=user.id, hc_attackmode=0)
    db.session.add_all([t_mine, t_other])
    db.session.commit()
    db.session.add(JobTasks(job_id=mine.id, task_id=t_mine.id, status="Running"))
    db.session.add(JobTasks(job_id=other.id, task_id=t_other.id, status="Running"))
    db.session.commit()

    groups = _job_task_groups(
        [mine], JobTasks.query.all(),
        {t.id: t for t in Tasks.query.all()},
        {}, {}, {},
    )[mine.id]["groups"]
    grouped = {g["task_id"] for g in groups}
    assert grouped == {t_mine.id}            # only this job's task, other skipped


# --------------------------------------------------------- auto-cancel column


def test_auto_cancel_counts_down_from_the_earliest_chunk_start(app, db_session):
    """Time left before Settings.max_runtime_tasks cancels the attack.

    Measured from the EARLIEST chunk start, which is what the cap itself uses
    (api/routes.py _parent_task_started_at). A task fans out across agents, so
    any single chunk's started_at would under-report the parent's elapsed time
    and the column would disagree with the reaper that acts on it.
    """
    from datetime import datetime, timedelta

    from hashview.main.routes import _job_task_groups
    job, task_a, _ = _seed_running_job()
    rows = JobTasks.query.filter_by(job_id=job.id, task_id=task_a.id).all()
    # Oldest chunk started 1h ago, a later one 5m ago: the cap follows the oldest.
    rows[0].started_at = datetime.now() - timedelta(hours=1)
    for r in rows[1:]:
        r.started_at = datetime.now() - timedelta(minutes=5)
    db.session.commit()

    dash = _job_task_groups([job], JobTasks.query.filter_by(job_id=job.id).all(),
                            {t.id: t for t in Tasks.query.all()}, {}, {}, {},
                            max_runtime_tasks=3)[job.id]
    g = {grp['task_id']: grp for grp in dash['groups']}[task_a.id]

    # 3h cap, oldest chunk 1h in -> ~2h left (not 2h55m, which the newer chunk
    # would have given).
    assert g['cancel_in'].startswith('1h 59m') or g['cancel_in'].startswith('2h')


def test_auto_cancel_is_absent_when_the_cap_is_disabled(app, db_session):
    """max_runtime_tasks of 0 means no cap, so there is nothing to count down."""
    from hashview.main.routes import _job_task_groups
    job, task_a, _ = _seed_running_job()

    dash = _job_task_groups([job], JobTasks.query.filter_by(job_id=job.id).all(),
                            {t.id: t for t in Tasks.query.all()}, {}, {}, {},
                            max_runtime_tasks=0)[job.id]

    assert all(g['cancel_in'] is None for g in dash['groups'])


def test_auto_cancel_floors_at_zero_rather_than_going_negative(app, db_session):
    """Past its deadline the honest reading is "any moment now", not "-4m": the
    reaper cancels on the next heartbeat."""
    from datetime import datetime, timedelta

    from hashview.main.routes import _job_task_groups
    job, task_a, _ = _seed_running_job()
    for r in JobTasks.query.filter_by(job_id=job.id, task_id=task_a.id).all():
        r.started_at = datetime.now() - timedelta(hours=10)
    db.session.commit()

    dash = _job_task_groups([job], JobTasks.query.filter_by(job_id=job.id).all(),
                            {t.id: t for t in Tasks.query.all()}, {}, {}, {},
                            max_runtime_tasks=1)[job.id]
    g = {grp['task_id']: grp for grp in dash['groups']}[task_a.id]

    assert g['cancel_in'] == '0s'


def test_auto_cancel_column_only_renders_when_the_cap_is_on(app, client):
    """The column is hidden entirely when max_runtime_tasks is unset, so an
    install that does not use the cap gains no empty column."""
    from tests.unit.helpers import login, make_admin
    _seed_running_job()
    login(client, make_admin())

    # No Settings row at all: the column must stay hidden rather than raise.
    assert Settings.query.first() is None
    assert "Auto-cancel" not in client.get("/dashboard/jobs").get_data(as_text=True)

    settings = Settings(retention_period=30, max_runtime_jobs=0, max_runtime_tasks=0)
    db.session.add(settings)
    db.session.commit()

    assert "Auto-cancel" not in client.get("/dashboard/jobs").get_data(as_text=True)

    settings.max_runtime_tasks = 5
    db.session.commit()

    assert "Auto-cancel" in client.get("/dashboard/jobs").get_data(as_text=True)


# ------------------------------------------------ expanded chunk row layout


@pytest.mark.security
def test_expanding_a_task_does_not_render_a_chunk_summary_row(app, client):
    """The "N completed / N running / N queued" strip under an expanded task is
    gone: the counts are already on the parent row, and it cost a full-width
    row of vertical space per expanded task."""
    from tests.unit.helpers import login, make_admin
    _seed_running_job()
    login(client, make_admin())

    html = client.get("/dashboard/jobs").get_data(as_text=True)

    assert "chunk-row" in html          # the chunks themselves still render
    assert "chunk-sub" not in html
    assert "completed ·" not in html


@pytest.mark.security
def test_chunk_id_sits_under_task_not_status(app, client):
    """A chunk's id and slice name WHICH piece of the task the row is -- a
    continuation of the task name above it, not a status. They render in the
    Task column, indented, leaving Status empty on chunk rows."""
    from tests.unit.helpers import login, make_admin
    _seed_running_job()
    login(client, make_admin())

    html = client.get("/dashboard/jobs").get_data(as_text=True)
    row = re.search(r'<tr class="chunk-row".*?</tr>', html, re.S).group(0)
    cells = re.findall(r'<td\b[^>]*>(.*?)</td>', row, re.S)
    attrs = re.findall(r'<td\b([^>]*)>', row)

    # column order: spacer, Task, Status, Agent, Keyspace, Recovered, Rate, ETA...
    # Spelled out, not a bare "#3": on its own that read as an id of something
    # unstated, sitting directly under a task name.
    assert cells[1].startswith("Chunk #")
    assert "padding-left" in attrs[1]        # indented under the task name
    assert cells[2].strip() == ""            # Status is left empty on chunk rows


@pytest.mark.security
def test_chunk_keyspace_sits_under_the_keyspace_column(app, client):
    """A chunk's own keyspace belongs under Keyspace, where the parent task row
    shows the whole attack's -- not appended to the chunk id under Task.

    The value is bare ("1.2B"), not "1.2B keyspace": under a column headed
    Keyspace the word repeats the header back at the reader.
    """
    from tests.unit.helpers import login, make_admin
    _seed_running_job()
    # The fixture leaves chunk_keyspace unset, so the cell would render empty
    # and the assertions below would pass without proving anything.
    for row_ in JobTasks.query.filter_by(status="Running").all():
        row_.chunk_keyspace = 1_200_000_000
    db.session.commit()
    login(client, make_admin())

    html = client.get("/dashboard/jobs").get_data(as_text=True)
    row = re.search(r'<tr class="chunk-row".*?</tr>', html, re.S).group(0)
    cells = re.findall(r'<td\b[^>]*>(.*?)</td>', row, re.S)

    assert "keyspace" not in cells[1].lower()   # not under Task any more
    assert cells[4].strip() != ""               # ...under Keyspace instead
    assert "keyspace" not in cells[4].lower()   # and without repeating the header


@pytest.mark.security
def test_every_empty_cell_uses_the_same_dash_placeholder(app, client):
    """One placeholder, so "no data yet" looks the same in every column.

    Written inline per cell the dashes inherited each column's colour and
    alignment: Rate and Auto-cancel were --text-dim, ETA --text-mute, Recovered
    had no colour at all (so it rendered in the brightest default text), and
    Agent's sat left while the rest were centred.

    Only the dashes that were already there are normalised. The chunk row's
    Agent cell renders blank when unassigned and is deliberately left blank --
    a placeholder there would be new UI, not a fix.
    """
    from tests.unit.helpers import login, make_admin
    _seed_running_job()
    login(client, make_admin())

    # Finish every chunk so the task row has no agent, rate or eta to show --
    # the state the placeholder exists for. The seeded fixture fills every cell,
    # so without this the table renders no dashes and the assertion below would
    # pass by vacuum. It did exactly that on the first draft.
    for row in JobTasks.query.all():
        row.status = "Completed"
        row.agent_id = None
    for agent in Agents.query.all():
        agent.hc_status = ""
    db.session.commit()

    html = client.get("/dashboard/jobs").get_data(as_text=True)
    table = html[html.index('class="tbl rj-tasks"'):]

    assert '<span class="dash">—</span>' in table
    # ...and no BARE em dash left to inherit whatever colour its column had.
    bare = re.findall(r'(?<!class="dash">)—', table)
    assert bare == [], f"{len(bare)} unstyled dash(es) left in the task table"


@pytest.mark.security
def test_the_dash_placeholder_rule_is_actually_served(app, client):
    """The markup and the rule that styles it live in different templates.

    _dash_jobs.html.j2 emits <span class="dash">, home.html.j2 carries the rule.
    A merge once kept the spans and dropped the rule, so every dash silently
    went back to inheriting its column's alignment -- the spans were all still
    there, and nothing failed. This asserts the rule reaches the page.
    """
    from tests.unit.helpers import login, make_admin
    _seed_running_job()
    login(client, make_admin())

    css = client.get("/").get_data(as_text=True)
    rule = re.search(r'\.rj-tasks \.dash \{([^}]*)\}', css)
    assert rule, "no .rj-tasks .dash rule served -- the dashes will not be centred"
    body = rule.group(1)
    assert "text-align: center" in body      # centres it
    assert "display: block" in body          # ...regardless of the column's align
    assert "var(--text-mute)" in body        # one shade for all of them
