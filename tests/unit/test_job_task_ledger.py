"""The ledger: one row per ATTACK, and where its keyspace stands.

JobTasks rows are dispatch receipts. Once chunks are issued on demand the set of
them for a task changes over the life of a run, so everything previously answered
by counting or scanning those rows -- how many attacks a job has, what order they
are in, how far along it is -- needs somewhere stable to live.

While the plan is still materialised in full at queue time, the ledger must agree
exactly with the rows it describes: that agreement is what makes it safe to
switch the write path over to minting later, because any divergence then is a bug
in the new writes rather than in the new reads.

The accounting identity pinned here is the one the whole design rests on:

    sum(chunk_keyspace over an attack's rows) == ledger.keyspace_pos

and, while everything is issued up front, keyspace_pos == keyspace.
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
    JobTaskLedger,
    JobTasks,
    Rules,
    Settings,
    Tasks,
    Users,
    Wordlists,
    db,
)
from hashview.utils.utils import build_job_task_commands

pytestmark = pytest.mark.security


def _seed(attackmode=0, wl_type="static", wl_size=1_000_000, rule_size=100,
          enabled_chunking=True, benchmark_speed=1000, target=60, mask=None,
          assignments=1):
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
    wl = Wordlists(name="wl", owner_id=user.id, type=wl_type,
                   path="control/wordlists/wl.gz", size=wl_size, checksum="0" * 64)
    db.session.add(wl)
    db.session.commit()
    rule = Rules(name="r", owner_id=user.id, path="control/rules/r.rule",
                 checksum="0" * 64, size=rule_size)
    db.session.add(rule)
    db.session.commit()
    task = Tasks(name="t", owner_id=user.id, hc_attackmode=attackmode,
                 wl_id=(wl.id if attackmode != 3 else None),
                 rule_id=(rule.id if attackmode == 0 else None),
                 hc_mask=mask, loopback=False)
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
    for _ in range(assignments):
        db.session.add(JobTasks(job_id=job.id, task_id=task.id, status="Not Started"))
    db.session.commit()
    return job, task


def _ledgers(job):
    return JobTaskLedger.query.filter_by(job_id=job.id).order_by(
        JobTaskLedger.position).all()


def _rows(ledger):
    return JobTasks.query.filter_by(ledger_id=ledger.id).all()


def test_a_split_task_is_one_ledger_entry_not_many(app, db_session):
    job, _ = _seed()
    build_job_task_commands(job)
    db.session.commit()

    rows = JobTasks.query.filter_by(job_id=job.id).all()
    assert len(rows) > 1, "expected the task to split"
    ledgers = _ledgers(job)
    assert len(ledgers) == 1, "N chunks are ONE attack"
    assert {r.ledger_id for r in rows} == {ledgers[0].id}


def test_the_ledger_accounts_for_every_issued_unit(app, db_session):
    """sum(chunk_keyspace) == keyspace_pos, and everything is issued up front."""
    job, _ = _seed()
    build_job_task_commands(job)
    db.session.commit()

    ledger = _ledgers(job)[0]
    assert ledger.keyspace == 1_000_000, "base loop for -a 0 is the wordlist"
    assert ledger.keyspace_source == "exact"
    assert sum(r.chunk_keyspace for r in _rows(ledger)) == ledger.keyspace_pos
    assert ledger.keyspace_pos == ledger.keyspace, "materialised plan == fully issued"


def test_the_amplifier_is_the_rule_count(app, db_session):
    """total_candidates = keyspace * amp; for -a 0 the amplifier is the rules."""
    job, _ = _seed(rule_size=100)
    build_job_task_commands(job)
    db.session.commit()

    assert _ledgers(job)[0].amp == 100


def test_a_whole_unchunked_task_still_accounts_for_its_keyspace(app, db_session):
    """Chunking off: one row covering the whole attack, and the sums still hold."""
    job, _ = _seed(enabled_chunking=False)
    build_job_task_commands(job)
    db.session.commit()

    ledger = _ledgers(job)[0]
    rows = _rows(ledger)
    assert len(rows) == 1
    assert ledger.keyspace == 1_000_000
    assert sum(r.chunk_keyspace for r in rows) == ledger.keyspace_pos == ledger.keyspace


def test_a_mask_task_has_no_keyspace_until_an_agent_measures_it(app, db_session):
    """hashcat splits a mask between its base and device loops based on the hash
    mode and -S, not on the mask alone, so the server cannot compute this. The
    attack stays Pending and runs whole, which needs no --skip/--limit and is
    therefore correct whatever the unit turns out to be."""
    job, _ = _seed(attackmode=3, mask="?d?d?d?d?d")
    build_job_task_commands(job)
    db.session.commit()

    ledger = _ledgers(job)[0]
    assert ledger.keyspace is None
    assert ledger.state == "Pending"
    assert ledger.chunkable is True, "it CAN be split, once measured"


def test_a_dynamic_wordlist_attack_is_unmeasurable_and_runs_whole(app, db_session):
    job, _ = _seed(wl_type="dynamic")
    build_job_task_commands(job)
    db.session.commit()

    ledger = _ledgers(job)[0]
    assert ledger.chunkable is False
    assert ledger.state == "Unmeasurable"
    assert len(_rows(ledger)) == 1


def test_one_task_assigned_twice_is_two_ledger_entries(app, db_session):
    """(job_id, task_id) is NOT unique over attacks -- a dynamic-wordlist task may
    be assigned to the same job more than once, and each is its own attack."""
    job, task = _seed(wl_type="dynamic", assignments=2)
    build_job_task_commands(job)
    db.session.commit()

    ledgers = _ledgers(job)
    assert len(ledgers) == 2
    assert [ledger.task_id for ledger in ledgers] == [task.id, task.id]
    assert [ledger.position for ledger in ledgers] == [0, 1]


def test_positions_follow_the_queue_order(app, db_session):
    job, first = _seed(wl_type="dynamic")
    user_id = first.owner_id
    second = Tasks(name="t2", owner_id=user_id, hc_attackmode=3, hc_mask="?d?d",
                   loopback=False)
    db.session.add(second)
    db.session.commit()
    db.session.add(JobTasks(job_id=job.id, task_id=second.id, status="Not Started"))
    db.session.commit()

    build_job_task_commands(job)
    db.session.commit()

    ledgers = _ledgers(job)
    assert [ledger.task_id for ledger in ledgers] == [first.id, second.id]


def test_requeue_does_not_duplicate_or_advance_the_ledger(app, db_session):
    """Stop/start must be stable: same attacks, same accounting, no re-expansion."""
    job, _ = _seed()
    build_job_task_commands(job)
    db.session.commit()
    before_rows = {r.id for r in JobTasks.query.filter_by(job_id=job.id).all()}
    before = _ledgers(job)[0]
    keyspace, pos = before.keyspace, before.keyspace_pos

    build_job_task_commands(job)
    db.session.commit()

    ledgers = _ledgers(job)
    assert len(ledgers) == 1, "re-queue must not add a second attack"
    assert {r.id for r in JobTasks.query.filter_by(job_id=job.id).all()} == before_rows
    assert (ledgers[0].keyspace, ledgers[0].keyspace_pos) == (keyspace, pos)
    assert sum(r.chunk_keyspace for r in _rows(ledgers[0])) == ledgers[0].keyspace_pos


def test_the_fingerprint_changes_when_the_wordlist_is_replaced(app, db_session):
    """A wordlist re-uploaded under the same id changes its line count, which
    silently invalidates every offset computed against it. Nothing detected that."""
    job, task = _seed()
    build_job_task_commands(job)
    db.session.commit()
    before = _ledgers(job)[0].fingerprint

    wl = Wordlists.query.get(task.wl_id)
    wl.size = 2_000_000
    db.session.commit()
    build_job_task_commands(job)
    db.session.commit()

    assert _ledgers(job)[0].fingerprint != before


def test_job_assignments_counts_attacks_not_rows(app, db_session):
    """The jobs list, the hashfile modal and the task editor all ask this.

    All three used to count raw JobTasks rows in three slightly different ways,
    and a raw count is not stable once chunks are issued on demand: it grows
    through a run, and a freshly queued job can have no rows at all.
    """
    from hashview.utils.utils import job_assignments

    job, _ = _seed()
    build_job_task_commands(job)
    db.session.commit()

    assert JobTasks.query.filter_by(job_id=job.id).count() > 1
    entries = job_assignments([job.id])[job.id]
    assert len(entries) == 1
    assert entries[0]["entry_id"] == _ledgers(job)[0].id
    assert entries[0]["keyspace"] == 1_000_000


def test_job_assignments_falls_back_to_grouping_unqueued_rows(app, db_session):
    """A job that has never been queued has no ledger, and a job queued by a
    pre-ledger server has rows with ledger_id NULL. Both must still collapse a
    task's chunk rows into one attack rather than counting each."""
    from hashview.utils.utils import job_assignments

    job, task = _seed(enabled_chunking=False)
    # Rows shaped like a pre-ledger server's fan-out: slices, no ledger_id.
    JobTasks.query.filter_by(job_id=job.id).delete()
    db.session.commit()
    for n in range(3):
        db.session.add(JobTasks(job_id=job.id, task_id=task.id, status="Queued",
                                chunk_no=n + 1, chunk_total=3,
                                chunk_skip=n * 100, chunk_limit=100))
    db.session.commit()

    entries = job_assignments([job.id])[job.id]
    assert len(entries) == 1, "three chunk rows are one attack"
    assert entries[0]["task_id"] == task.id
    assert entries[0]["entry_id"] < 0, "negated row id, so it cannot collide with a ledger id"


def test_job_assignments_keeps_duplicate_dynamic_assignments_separate(app, db_session):
    from hashview.utils.utils import job_assignments

    job, _ = _seed(wl_type="dynamic", assignments=2)
    build_job_task_commands(job)
    db.session.commit()

    assert len(job_assignments([job.id])[job.id]) == 2
