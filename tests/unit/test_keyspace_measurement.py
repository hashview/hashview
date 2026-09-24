"""Measuring a mask attack's keyspace, and refusing to trust a bad answer.

The server cannot compute this. hashcat splits a mask between its base loop --
which is exactly what --skip/--limit index -- and its own device-side loop, based
on the hash mode and on -S, not on the mask alone. Measured on hashcat 6.2.6:

    -a 3 -m 0    ?a?a?a?a?a?a  ->  95**4
    -a 3 -m 1800 ?a?a?a?a?a?a  ->  95**5
    -a 3 -S -m 0 ?a?a?a?a?a?a  ->  95**6

So the number has to come from an agent. What makes that safe rather than merely
trusting is that the server DOES know the candidate total exactly, and hashcat's
own split always divides it evenly -- `total % keyspace == 0`. A number that
fails that is not a keyspace, and the attack falls back to running WHOLE, which
emits no --skip/--limit and is correct under any unit.
"""


import json

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
    Settings,
    Tasks,
    Users,
    Wordlists,
    db,
)
from hashview.utils.clock import utcnow
from hashview.utils.utils import (
    build_job_task_commands,
    build_keyspace_command,
    record_keyspace_measurement,
    task_total_candidates,
)

pytestmark = pytest.mark.security


def _seed(attackmode=3, mask="?a?a?a?a?a?a", hash_type=0, wl_size=None):
    user = Users(first_name="A", last_name="D", email_address="a@b.com",
                 password="x" * 60, admin=True)
    db.session.add(user)
    db.session.commit()
    db.session.add(Settings(retention_period=30, max_runtime_jobs=0, max_runtime_tasks=0,
                            enabled_chunking=True, chunk_target_duration=60))
    cust = Customers(name="C")
    db.session.add(cust)
    db.session.commit()
    hf = Hashfiles(name="h", customer_id=cust.id, owner_id=user.id)
    db.session.add(hf)
    db.session.commit()
    h = Hashes(sub_ciphertext="0" * 32, ciphertext="AAA", hash_type=hash_type, cracked=False)
    db.session.add(h)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    wl = None
    if wl_size:
        wl = Wordlists(name="wl", owner_id=user.id, type="static",
                       path="control/wordlists/wl.gz", size=wl_size, checksum="0" * 64)
        db.session.add(wl)
        db.session.commit()
    task = Tasks(name="t", owner_id=user.id, hc_attackmode=attackmode,
                 hc_mask=mask, wl_id=(wl.id if wl else None), loopback=False)
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
    return job, task, JobTaskLedger.query.filter_by(job_id=job.id).one()


def test_the_probe_carries_the_hash_mode_and_no_hashfile(app, db_session):
    """`hashcat --keyspace` takes NO hashfile positional -- passing one is a usage
    error -- and the answer depends on -m, so the probe is built directly rather
    than by stripping flags off the run command."""
    job, task, _ = _seed(hash_type=1800)
    argv = build_keyspace_command(job.id, task.id)

    assert argv[-1] == "--keyspace"
    assert "-m" in argv and argv[argv.index("-m") + 1] == "1800"
    assert argv[argv.index("-a") + 1] == "3"
    assert "?a?a?a?a?a?a" in argv
    assert not any(a.startswith("control/hashes/") for a in argv)


def test_the_probe_for_a_hybrid_puts_the_mask_before_the_wordlist(app, db_session):
    """-a 7 is mask-then-wordlist; -a 6 is the other way round. Measured against
    real hashcat: -a 7 '?d?d' wl.txt reports 100, the mask's own keyspace."""
    job, task, _ = _seed(attackmode=7, mask="?d?d", wl_size=500)
    argv = build_keyspace_command(job.id, task.id)

    mask_at = argv.index("?d?d")
    wl_at = next(i for i, a in enumerate(argv) if a.startswith("control/wordlists/"))
    assert mask_at < wl_at


def test_a_measurement_is_stored_with_its_amplifier(app, db_session):
    """95**6 candidates over a 95**4 keyspace is an amplifier of 95**2."""
    job, task, ledger = _seed()
    assert task_total_candidates(task, None, None, None) == 95 ** 6

    assert record_keyspace_measurement(ledger, 95 ** 4, hc_major=6) is True

    fresh = JobTaskLedger.query.get(ledger.id)
    assert fresh.keyspace == 95 ** 4
    assert fresh.amp == 95 ** 2
    assert fresh.keyspace_source == "measured"
    assert fresh.hc_major == 6
    assert fresh.state == "Ready"


def test_a_keyspace_that_does_not_divide_the_total_is_refused(app, db_session):
    """hashcat's own split always divides the candidate total exactly, so a
    remainder means the number is not a keyspace -- a truncated read, a parse
    artefact, or an agent reporting something else."""
    job, task, ledger = _seed()

    assert record_keyspace_measurement(ledger, 95 ** 4 + 1, hc_major=6) is False

    fresh = JobTaskLedger.query.get(ledger.id)
    assert fresh.state == "Unmeasurable"
    assert fresh.keyspace is None, "never chunk on a number we could not check"


@pytest.mark.parametrize("bad", [0, -5, "not a number", None, 2 ** 63])
def test_unusable_measurements_fall_back_to_running_whole(app, db_session, bad):
    job, task, ledger = _seed()
    assert record_keyspace_measurement(ledger, bad, hc_major=6) is False
    assert JobTaskLedger.query.get(ledger.id).state == "Unmeasurable"


def test_a_keyspace_larger_than_the_total_is_refused(app, db_session):
    job, task, ledger = _seed()
    assert record_keyspace_measurement(ledger, 95 ** 7, hc_major=6) is False
    assert JobTaskLedger.query.get(ledger.id).state == "Unmeasurable"


def test_a_mask_attack_starts_pending_and_runs_whole_until_measured(app, db_session):
    job, task, ledger = _seed()
    assert ledger.state == "Pending"
    assert ledger.keyspace is None

    row = JobTasks.query.filter_by(ledger_id=ledger.id).one()
    assert "--skip" not in row.command, "no slicing on an unmeasured keyspace"


def test_an_unparseable_mask_is_never_measured(app, db_session):
    """A custom ?1-?4 charset means the server cannot compute the candidate total
    either, so there is nothing to check a measurement against."""
    job, task, ledger = _seed(mask="?1?1?1?1")
    assert task_total_candidates(task, None, None, None) is None
    assert record_keyspace_measurement(ledger, 1000, hc_major=6) is False
    assert JobTaskLedger.query.get(ledger.id).state == "Unmeasurable"


# --- the measurement has to happen BEFORE the attack is handed out ------------

DOMAIN = "localhost.test"


def _cookies(client, uuid):
    import hashview
    client.set_cookie("uuid", uuid, domain=DOMAIN)
    client.set_cookie("agent_version", hashview.__version__, domain=DOMAIN)


def _beat(client, uuid):
    resp = client.post("/v1/agents/heartbeat",
                       data=json.dumps({"agent_status": "Idle", "hc_status": ""}),
                       content_type="application/json")
    return json.loads(resp.get_data(as_text=True))


def _agent(uuid, hc_major=6, hash_type=0, speed=1000):
    a = Agents(name=uuid, src_ip="1.1.1.1", uuid=uuid, status="Idle",
               hc_version=(f"v{hc_major}.2.6" if hc_major else None), hc_major=hc_major)
    db.session.add(a)
    db.session.commit()
    db.session.add(AgentBenchmarks(agent_id=a.id, hash_type=hash_type, speed=speed))
    db.session.commit()
    return a


def _running(job):
    job.status = "Running"
    db.session.commit()


def test_a_mask_attack_is_measured_before_any_of_it_is_handed_out(app, client):
    """Otherwise the feature does nothing at all.

    The seed row carries a WHOLE-run command. If it were dispatched first, one
    agent would run the entire attack and the measurement would arrive with
    nothing left to split -- so the keyspace ask has to come before the work.
    """
    job, task, ledger = _seed()
    _running(job)
    _agent("capable", hc_major=6)

    _cookies(client, "capable")
    body = _beat(client, "capable")

    assert body["msg"] == "KEYSPACE", f"got {body['msg']} -- the attack was handed out unmeasured"
    assert body["ledger_id"] == ledger.id
    assert "--keyspace" in body["command"]
    assert JobTaskLedger.query.get(ledger.id).state == "Measuring"
    assert JobTasks.query.filter_by(ledger_id=ledger.id, status="Running").count() == 0


def test_after_measuring_the_attack_is_dispatched_in_slices(app, client):
    job, task, ledger = _seed()
    _running(job)
    _agent("capable", hc_major=6)

    _cookies(client, "capable")
    assert _beat(client, "capable")["msg"] == "KEYSPACE"

    resp = client.post("/v1/jobtask/keyspace",
                       data=json.dumps({"ledger_id": ledger.id, "keyspace": 95 ** 4}),
                       content_type="application/json")
    assert json.loads(resp.get_data(as_text=True))["status"] == 200
    assert JobTaskLedger.query.get(ledger.id).state == "Ready"

    body = _beat(client, "capable")
    assert body["msg"] == "START"
    row = JobTasks.query.get(body["job_task_id"])
    assert row.chunk_skip == 0 and row.chunk_limit > 0
    assert "--skip" in row.command, "now sliced, not whole"


def test_an_agent_with_no_hashcat_version_runs_the_attack_whole(app, client):
    """It cannot measure, so it must not be left idling -- it gets the work,
    un-sliced, which is exactly what happened before any of this existed."""
    job, task, ledger = _seed()
    _running(job)
    _agent("versionless", hc_major=None)

    _cookies(client, "versionless")
    body = _beat(client, "versionless")

    assert body["msg"] == "START"
    row = JobTasks.query.get(body["job_task_id"])
    assert "--skip" not in row.command
    assert "?a?a?a?a?a?a" in row.command


def test_a_measurement_that_never_comes_back_falls_back_to_a_whole_run(app, client):
    """A lease that expires must not stall the attack forever: Measuring blocks
    dispatch, so retrying indefinitely would mean the work never runs."""
    from datetime import timedelta

    job, task, ledger = _seed()
    _running(job)
    _agent("capable", hc_major=6)

    _cookies(client, "capable")
    assert _beat(client, "capable")["msg"] == "KEYSPACE"

    stale = JobTaskLedger.query.get(ledger.id)
    stale.measure_expires = utcnow() - timedelta(minutes=1)
    db.session.commit()

    body = _beat(client, "capable")
    assert JobTaskLedger.query.get(ledger.id).state == "Unmeasurable"
    assert body["msg"] == "START", "the attack must still run"
    assert "--skip" not in JobTasks.query.get(body["job_task_id"]).command


def test_a_measured_attack_is_withheld_from_a_different_hashcat_major(app, client):
    """hashcat 7 redefines --keyspace and --skip/--limit to whole-run units, so a
    slice measured under 6 addresses a different space entirely under 7."""
    job, task, ledger = _seed()
    _running(job)
    record_keyspace_measurement(JobTaskLedger.query.get(ledger.id), 95 ** 4, hc_major=6)
    _agent("hc7", hc_major=7)

    _cookies(client, "hc7")
    assert _beat(client, "hc7")["msg"] == "OK", "must not be given a slice measured under hc6"
