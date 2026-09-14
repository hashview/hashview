"""Minting: cutting the next slice of an attack, sized for the agent asking.

Two properties matter here, and nothing else in the design substitutes for them.

COVERAGE. Minting is the only operation that both creates a row and advances the
cursor, and it does both atomically and by the same amount. So for any attack:

    sum(chunk_keyspace over its rows) == ledger.keyspace_pos

Every base-loop unit below the cursor is accounted for by exactly one row. A
violation means units were handed out that no row will ever run -- compute
missed, silently, which is the failure this whole design exists to prevent.

EXCLUSIVITY. The cursor moves with a compare-and-swap, not a read-then-write. A
plain SELECT inside an open transaction is a snapshot read; under MySQL's default
REPEATABLE READ it cannot see another agent's committed advance, so two agents
would read the same position, both write, and one slice would simply never be
issued. These tests force that interleaving.
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
from hashview.utils.utils import (
    build_job_task_commands,
    chunk_units,
    issue_slice,
    ledger_coverage_gaps,
)

pytestmark = pytest.mark.security


def _seed(wl_size=1_000_000, rule_size=100, target=60):
    user = Users(first_name="A", last_name="D", email_address="a@b.com",
                 password="x" * 60, admin=True)
    db.session.add(user)
    db.session.commit()
    db.session.add(Settings(retention_period=30, max_runtime_jobs=0, max_runtime_tasks=0,
                            enabled_chunking=True, chunk_target_duration=target))
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
    wl = Wordlists(name="wl", owner_id=user.id, type="static",
                   path="control/wordlists/wl.gz", size=wl_size, checksum="0" * 64)
    db.session.add(wl)
    db.session.commit()
    rule = Rules(name="r", owner_id=user.id, path="control/rules/r.rule",
                 checksum="0" * 64, size=rule_size)
    db.session.add(rule)
    db.session.commit()
    task = Tasks(name="t", owner_id=user.id, hc_attackmode=0, wl_id=wl.id,
                 rule_id=rule.id, loopback=False)
    db.session.add(task)
    db.session.commit()
    job = Jobs(name="j", owner_id=user.id, customer_id=cust.id, hashfile_id=hf.id,
               status="Ready", priority=3)
    db.session.add(job)
    db.session.commit()
    db.session.add(JobTasks(job_id=job.id, task_id=task.id, status="Not Started"))
    db.session.commit()
    build_job_task_commands(job)
    db.session.commit()
    return job, JobTaskLedger.query.filter_by(job_id=job.id).one()


def _agent(uuid, speed, hash_type=1000):
    a = Agents(name=uuid, src_ip="1.1.1.1", uuid=uuid, status="Idle")
    db.session.add(a)
    db.session.commit()
    db.session.add(AgentBenchmarks(agent_id=a.id, hash_type=hash_type, speed=speed))
    db.session.commit()
    return a


def _fresh(ledger):
    return JobTaskLedger.query.get(ledger.id)


def _issued(ledger):
    return sum((r.chunk_keyspace or 0)
               for r in JobTasks.query.filter_by(ledger_id=ledger.id).all())


def _assert_covered(ledger):
    """The accounting identity, plus a gap/overlap check over the actual ranges."""
    ledger = _fresh(ledger)
    rows = [r for r in JobTasks.query.filter_by(ledger_id=ledger.id).all()
            if r.chunk_skip is not None]
    assert sum(r.chunk_keyspace for r in rows) == ledger.keyspace_pos
    cursor = 0
    for row in sorted(rows, key=lambda r: r.chunk_skip):
        assert row.chunk_skip == cursor, "gap or overlap in the issued range"
        cursor += row.chunk_limit
    assert cursor == ledger.keyspace_pos
    assert not ledger_coverage_gaps()


def test_successive_mints_tile_the_keyspace(app, db_session):
    job, ledger = _seed()
    agent = _agent("a", speed=1000)

    seed_row = JobTasks.query.filter_by(ledger_id=ledger.id).one()
    first = issue_slice(job=job, ledger=_fresh(ledger), agent_id=agent.id,
                        hash_type=1000, target_seconds=60, row=seed_row)
    assert first is not None
    for _ in range(4):
        assert issue_slice(job=job, ledger=_fresh(ledger), agent_id=agent.id,
                           hash_type=1000, target_seconds=60) is not None
    _assert_covered(ledger)


def test_the_slice_is_sized_from_the_claiming_agents_own_benchmark(app, db_session):
    """The point of the change: a fast agent no longer takes the slow agent's bite.

    amp is the rule count (100), so units = speed * seconds / 100.
    """
    # min_slice is ceil(keyspace / DEFAULT_MAX_CHUNKS); keep it well below both
    # agents' bites so it is the AGENT, not the floor, deciding the size here.
    job, ledger = _seed(wl_size=100_000)
    slow = _agent("slow", speed=1_000)
    fast = _agent("fast", speed=10_000)

    seed_row = JobTasks.query.filter_by(ledger_id=ledger.id).one()
    slow_row = issue_slice(job=job, ledger=_fresh(ledger), agent_id=slow.id,
                           hash_type=1000, target_seconds=60, row=seed_row)
    fast_row = issue_slice(job=job, ledger=_fresh(ledger), agent_id=fast.id,
                           hash_type=1000, target_seconds=60)

    assert slow_row.chunk_limit == 600        # 1_000 * 60 / 100
    assert fast_row.chunk_limit == 6_000      # 10_000 * 60 / 100
    assert fast_row.chunk_limit == 10 * slow_row.chunk_limit
    _assert_covered(ledger)


class _StaleView:
    """A ledger as a concurrent heartbeat still sees it, mid-advance.

    Under MySQL's default REPEATABLE READ a plain SELECT inside an open
    transaction cannot see another agent's committed advance, so one of two
    concurrent minters is working from exactly this: the right attack, the wrong
    cursor. It cannot be reproduced with a live ORM object in a single-session
    unit test, because the identity map hands back the already-updated row.
    """

    def __init__(self, real, keyspace_pos, rev):
        for name in ('id', 'state', 'chunkable', 'keyspace', 'amp', 'min_slice',
                     'issued_count', 'task_id', 'job_id'):
            setattr(self, name, getattr(real, name))
        self.keyspace_pos = keyspace_pos
        self.rev = rev


def test_a_stale_cursor_read_resumes_after_the_other_agent(app, db_session):
    """The compare-and-swap must reject a stale position, and the retry must
    re-read and cut its slice AFTER the other agent's -- not re-issue the same
    range, and not skip one."""
    job, ledger = _seed()
    first_agent = _agent("first", speed=1000)
    second_agent = _agent("second", speed=2000)

    before = _fresh(ledger)
    stale = _StaleView(before, keyspace_pos=before.keyspace_pos, rev=before.rev)

    seed_row = JobTasks.query.filter_by(ledger_id=ledger.id).one()
    other = issue_slice(job=job, ledger=_fresh(ledger), agent_id=first_agent.id,
                        hash_type=1000, target_seconds=60, row=seed_row)
    assert other is not None and other.chunk_skip == 0
    assert _fresh(ledger).keyspace_pos > stale.keyspace_pos, "the cursor really moved"

    mine = issue_slice(job=job, ledger=stale, agent_id=second_agent.id,
                       hash_type=1000, target_seconds=60)

    assert mine is not None
    assert mine.id != other.id
    assert mine.chunk_skip == other.chunk_skip + other.chunk_limit, (
        "the retry must resume where the other agent stopped")
    _assert_covered(ledger)


def test_a_stale_view_of_a_seed_row_does_not_duplicate_it(app, db_session):
    """Losing the race while filling in an attack's seed row must not leave the
    seed row behind and mint a second one alongside it."""
    job, ledger = _seed()
    first_agent = _agent("first", speed=1000)
    second_agent = _agent("second", speed=1000)
    seed_row = JobTasks.query.filter_by(ledger_id=ledger.id).one()

    before = _fresh(ledger)
    stale = _StaleView(before, keyspace_pos=before.keyspace_pos, rev=before.rev)
    issue_slice(job=job, ledger=_fresh(ledger), agent_id=first_agent.id,
                hash_type=1000, target_seconds=60, row=seed_row)

    issue_slice(job=job, ledger=stale, agent_id=second_agent.id,
                hash_type=1000, target_seconds=60, row=seed_row)

    _assert_covered(ledger)


def test_the_final_slice_is_clamped_to_the_end(app, db_session):
    job, ledger = _seed(wl_size=1000, rule_size=1)
    agent = _agent("a", speed=1_000_000)          # far bigger than what remains

    seed_row = JobTasks.query.filter_by(ledger_id=ledger.id).one()
    row = issue_slice(job=job, ledger=_fresh(ledger), agent_id=agent.id,
                      hash_type=1000, target_seconds=3600, row=seed_row)

    assert row.chunk_skip == 0
    assert row.chunk_limit == 1000, "never runs past the end of the keyspace"
    assert _fresh(ledger).keyspace_pos == 1000
    _assert_covered(ledger)


def test_an_exhausted_attack_issues_nothing_more(app, db_session):
    job, ledger = _seed(wl_size=1000, rule_size=1)
    agent = _agent("a", speed=1_000_000)
    seed_row = JobTasks.query.filter_by(ledger_id=ledger.id).one()
    issue_slice(job=job, ledger=_fresh(ledger), agent_id=agent.id,
                hash_type=1000, target_seconds=3600, row=seed_row)

    assert issue_slice(job=job, ledger=_fresh(ledger), agent_id=agent.id,
                       hash_type=1000, target_seconds=3600) is None
    assert JobTasks.query.filter_by(ledger_id=ledger.id).count() == 1


def test_a_slice_is_never_zero_units(app, db_session):
    """A zero-length slice advances nothing, runs nothing, and would make the
    compare-and-swap write an unchanged value -- which MySQL reports as rowcount
    0 and we would read as "lost the race", looping forever."""
    job, ledger = _seed()
    fresh = _fresh(ledger)
    assert chunk_units(fresh, speed=1, target_seconds=1) >= 1
    assert chunk_units(fresh, speed=0, target_seconds=60) >= 1
    assert chunk_units(fresh, speed=None, target_seconds=60) >= 1


def test_chunk_count_stays_bounded_for_a_very_slow_agent(app, db_session):
    """min_slice keeps DEFAULT_MAX_CHUNKS bounding rows per attack even when the
    agent's own speed would ask for a far smaller bite."""
    job, ledger = _seed(wl_size=1_000_000, rule_size=1)
    fresh = _fresh(ledger)
    assert fresh.min_slice == 1000                      # ceil(1_000_000 / 1000)
    assert chunk_units(fresh, speed=1, target_seconds=1) == fresh.min_slice


def test_coverage_audit_reports_a_manufactured_gap(app, db_session):
    """The audit has to actually detect a hole, or it is decoration."""
    job, ledger = _seed()
    agent = _agent("a", speed=1000)
    seed_row = JobTasks.query.filter_by(ledger_id=ledger.id).one()
    issue_slice(job=job, ledger=_fresh(ledger), agent_id=agent.id,
                hash_type=1000, target_seconds=60, row=seed_row)
    assert not ledger_coverage_gaps()

    # Advance the cursor without issuing a row: units handed out that nothing runs.
    fresh = _fresh(ledger)
    fresh.keyspace_pos = fresh.keyspace_pos + 5000
    db.session.commit()

    gaps = ledger_coverage_gaps()
    assert len(gaps) == 1
    gap_ledger, issued = gaps[0]
    assert gap_ledger.id == ledger.id
    assert issued == _issued(ledger) < gap_ledger.keyspace_pos
