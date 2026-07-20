"""Security regression tests for agent task command injection (CWE-78).

User-controlled task masks and combinator rules were concatenated into a shell
command string on the server, stored on JobTasks.command, and executed by the
agent with shell=True (including a ``| tee`` pipeline). These tests cover input
validation, safe command construction, and rejection of known PoC payloads.
"""

import shlex

import pytest

import hashview.utils.utils as u
from hashview.models import Customers, HashfileHashes, Hashes, Jobs, Tasks, Users, db


def _seed_mask_task(app, mask):
    user = Users(
        first_name="A",
        last_name="B",
        email_address="agent-cmdi@example.com",
        password="x",
        admin=True,
    )
    customer = Customers(name="lab")
    db.session.add_all([user, customer])
    db.session.commit()

    hash_entry = Hashes(
        sub_ciphertext="deadbeef",
        ciphertext="00000000000000000000000000000000",
        hash_type=0,
        cracked=False,
    )
    db.session.add(hash_entry)
    db.session.commit()

    hashfile_id = 1
    db.session.add(
        HashfileHashes(hash_id=hash_entry.id, hashfile_id=hashfile_id, username=None)
    )
    job = Jobs(
        name="cmdi-job",
        status="Queued",
        hashfile_id=hashfile_id,
        customer_id=customer.id,
        owner_id=user.id,
    )
    task = Tasks(
        name="cmdi-task",
        owner_id=user.id,
        hc_attackmode=3,
        hc_mask=mask,
    )
    db.session.add_all([job, task])
    db.session.commit()
    return job, task


@pytest.mark.parametrize(
    "payload",
    [
        "?a;touch /tmp/hv_cmdi_proof;#",
        "?a;id>/tmp/hv_cmdi_id;#",
        "$(touch pwned)",
        "`id`",
    ],
)
def test_validate_hashcat_mask_rejects_injection(payload):
    with pytest.raises(ValueError, match="disallowed"):
        u.validate_hashcat_mask(payload)


@pytest.mark.parametrize(
    "payload",
    [
        "$();touch pwned",
        "x;id",
        "`whoami`",
    ],
)
def test_validate_hashcat_combinator_rule_rejects_injection(payload):
    with pytest.raises(ValueError, match="disallowed"):
        u.validate_hashcat_combinator_rule(payload)


def test_validate_hashcat_mask_allows_normal_masks():
    u.validate_hashcat_mask("?l?l?l?d?d?d")
    u.validate_hashcat_mask("password?d?d")


def test_build_hashcat_command_quotes_safe_mask(app):
    safe_mask = "?l?l?l?d?d"
    job, task = _seed_mask_task(app, safe_mask)
    cmd = u.build_hashcat_command(job.id, task.id)
    argv = shlex.split(cmd.replace("@HASHCATBINPATH@", "/usr/bin/hashcat"))
    assert argv[-1] == safe_mask
    assert "-a" in argv
    assert "3" in argv


def test_build_hashcat_command_rejects_malicious_mask(app):
    job, task = _seed_mask_task(app, "?a;touch /tmp/x;#")
    with pytest.raises(ValueError, match="disallowed"):
        u.build_hashcat_command(job.id, task.id)
