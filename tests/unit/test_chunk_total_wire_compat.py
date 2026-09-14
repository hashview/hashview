"""The server/agent temp-file key contract, pinned from both sides.

Every JobTasks row names three files -- the target hashfile, the crack outfile
and the potfile. The server bakes those names into ``JobTasks.command`` and the
agent has to arrive at the same key independently. Until 0.8.4 both sides ran the
same conditional ("chunks key on the JobTask id, whole tasks on the task id"), so
they agreed only by convention, and when they disagreed *nothing raised*: hashcat
wrote its cracks to a path the agent never read, and two runs of one task quietly
shared a potfile -- which makes hashcat skip hashes an earlier run already potted,
so the later run never re-emits them.

The server now keys every row on its own id, unconditionally. These tests pin
both halves of what makes that safe:

  * an UNMODIFIED pre-0.8.4 agent still agrees, because every stamped row carries
    a truthy ``chunk_total`` (``CHUNK_TOTAL_WHOLE`` for a whole task); and
  * a 0.8.4 agent agrees without relying on that flag at all, because it reads
    the key back out of the command the server actually built. That half needs
    both codebases importable at once, so it lives in
    tests/agent_unit/test_file_key_contract.py.

`_legacy_agent_file_key` is a deliberate copy of the shipped agent's expression
rather than an import: it has to keep asserting what the *old* code does even
after install/hashview-agent stops containing it.
"""

import json

import pytest

from hashview.models import (
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
from hashview.utils.utils import CHUNK_TOTAL_WHOLE, build_job_task_commands

pytestmark = pytest.mark.security


def _legacy_agent_file_key(job_task):
    """install/hashview-agent/hashview-agent.py as shipped in 0.8.3, verbatim."""
    return job_task['id'] if job_task.get('chunk_total') else job_task['task_id']


def _wire(row):
    """The subset of the serialized row the agent's key resolver reads."""
    return {'id': row.id, 'task_id': row.task_id,
            'chunk_total': row.chunk_total, 'command': row.command}


def _files(row):
    """The three per-run paths hashcat is told to use, from the built argv."""
    argv = json.loads(row.command)
    return {
        'target': [a for a in argv if a.startswith('control/hashes/hashfile_')][0],
        'crack': argv[argv.index('--outfile') + 1],
        'potfile': argv[argv.index('--potfile-path') + 1],
    }


def _seed(wl_type="static", enabled_chunking=False, assignments=1):
    user = Users(first_name="A", last_name="D", email_address="a@b.com",
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
    wl = Wordlists(name="wl", owner_id=user.id, type=wl_type,
                   path="control/wordlists/wl.gz", size=1_000_000, checksum="0" * 64)
    db.session.add(wl)
    db.session.commit()
    task = Tasks(name="t", owner_id=user.id, hc_attackmode=0, wl_id=wl.id, loopback=False)
    db.session.add(task)
    db.session.commit()
    job = Jobs(name="j", owner_id=user.id, customer_id=cust.id, hashfile_id=hf.id,
               status="Ready", priority=3)
    db.session.add(job)
    db.session.commit()
    for _ in range(assignments):
        db.session.add(JobTasks(job_id=job.id, task_id=task.id, status="Not Started"))
    db.session.commit()
    return job


def test_every_stamped_row_is_keyed_on_its_own_id(app, db_session):
    """The server's three file names all carry the row's own id."""
    job = _seed()
    build_job_task_commands(job)
    db.session.commit()

    for row in JobTasks.query.filter_by(job_id=job.id).all():
        for name, path in _files(row).items():
            assert path.endswith(f"_{row.id}.txt") or path.endswith(f"_{row.id}.pot"), (
                f"{name} for row {row.id} is {path}, not keyed on the row id")


def test_unmodified_old_agent_computes_the_same_key(app, db_session):
    """A 0.8.3 agent, untouched, still lands on the key the server used.

    This is what makes the change deployable without a fleet upgrade: the whole
    task's CHUNK_TOTAL_WHOLE sentinel is non-zero, so the old expression's
    truthiness test picks job_task['id'] -- which is now what the server used too.
    """
    job = _seed()
    build_job_task_commands(job)
    db.session.commit()

    row = JobTasks.query.filter_by(job_id=job.id).one()
    assert row.chunk_total == CHUNK_TOTAL_WHOLE
    assert row.chunk_total, "sentinel must be truthy or the old agent keys on task_id"
    assert _legacy_agent_file_key(_wire(row)) == row.id


def test_two_whole_rows_of_one_task_get_different_files(app, db_session):
    """jobs_assign_task allows a dynamic-wordlist task on one job twice.

    Under the old task_id-based naming both rows named the SAME potfile, crack
    outfile and target hashfile. Nothing errored; the second run simply inherited
    the first's potfile and skipped everything it had already cracked.
    """
    job = _seed(wl_type="dynamic", assignments=2)
    build_job_task_commands(job)
    db.session.commit()

    rows = JobTasks.query.filter_by(job_id=job.id).order_by(JobTasks.id).all()
    assert len(rows) == 2
    assert rows[0].task_id == rows[1].task_id, "same task, assigned twice"

    first, second = _files(rows[0]), _files(rows[1])
    for name in ('target', 'crack', 'potfile'):
        assert first[name] != second[name], f"both rows share a {name}: {first[name]}"

    # And an unmodified old agent agrees with the server on each.
    for row in rows:
        assert _legacy_agent_file_key(_wire(row)) == row.id


def test_a_minted_slice_is_still_keyed_on_its_own_row(app, db_session):
    """The key contract has to survive minting, where rows appear mid-run.

    A minted slice carries CHUNK_TOTAL_WHOLE like every other row -- there is no
    chunk COUNT any more, because the size of each slice depends on which agent
    claims it and the total is not known until the attack finishes. What matters
    is only that the value stays truthy, so an un-upgraded agent still keys its
    temp files on the row id.
    """
    from hashview.models import AgentBenchmarks, Agents, JobTaskLedger
    from hashview.utils.utils import issue_slice

    job = _seed(enabled_chunking=True)
    build_job_task_commands(job)
    db.session.commit()

    agent = Agents(name="ag", src_ip="1.1.1.1", uuid="u1", status="Idle")
    db.session.add(agent)
    db.session.commit()
    db.session.add(AgentBenchmarks(agent_id=agent.id, hash_type=1000, speed=1000))
    db.session.commit()

    ledger = JobTaskLedger.query.filter_by(job_id=job.id).one()
    seed_row = JobTasks.query.filter_by(ledger_id=ledger.id).one()
    minted = issue_slice(job=job, ledger=ledger, agent_id=agent.id, hash_type=1000,
                         target_seconds=60, row=seed_row)
    assert minted is not None

    assert minted.chunk_total == CHUNK_TOTAL_WHOLE
    assert minted.chunk_total, "must stay truthy for a pre-0.8.4 agent"
    assert _legacy_agent_file_key(_wire(minted)) == minted.id
    for name, path in _files(minted).items():
        assert path.endswith(f"_{minted.id}.txt") or path.endswith(f"_{minted.id}.pot"), name
