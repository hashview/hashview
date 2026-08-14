"""Security regression tests for agent task command injection (CWE-78).

User-controlled task masks and combinator rules were concatenated into a shell
command string on the server, stored on JobTasks.command, and executed by the
agent with shell=True (including a ``| tee`` pipeline). These tests cover input
validation, safe command construction, and rejection of known PoC payloads.
"""

import shlex

import pytest

import hashview.utils.utils as u
from hashview.models import (
    Customers,
    Hashes,
    HashfileHashes,
    Jobs,
    Tasks,
    Users,
    Wordlists,
    db,
)


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


# --------------------------------------------------------------------------- #
# The form is the real boundary: a mask/rule that never reaches the DB can     #
# never reach JobTasks.command. build_hashcat_command's validate call is the   #
# backstop for rows that predate the fix.                                      #
# --------------------------------------------------------------------------- #


def _task_form(app, **fields):
    """A bound TasksForm with CSRF off and the SelectField choices the route
    populates at request time (they're empty on the class)."""
    from werkzeug.datastructures import MultiDict

    from hashview.tasks.forms import TasksForm

    data = {"name": "form-task", "hc_attackmode": "3", "wl_id": "1",
            "wl_id_2": "1", "rule_id": "None"}
    data.update(fields)
    with app.test_request_context():
        form = TasksForm(formdata=MultiDict(data), meta={"csrf": False})
    form.wl_id.choices = [("1", "wl")]
    form.wl_id_2.choices = [("1", "wl")]
    form.rule_id.choices = [("None", "None")]
    return form


@pytest.mark.parametrize("field", ["mask", "j_rule", "k_rule"])
def test_tasks_form_rejects_injection_in_mask_and_rules(app, field):
    form = _task_form(app, **{field: "?a;touch /tmp/hv_cmdi_proof;#"})
    assert not form.validate()
    assert "disallowed" in " ".join(form.errors[field])


def test_tasks_form_accepts_a_normal_mask_and_rules(app):
    form = _task_form(app, mask="?l?l?l?d?d?d", j_rule="$-", k_rule="$!")
    assert form.validate(), form.errors


def test_tasks_form_accepts_empty_mask_and_rules(app):
    """The fields are optional; blank input must not be treated as an attack."""
    form = _task_form(app, mask="", j_rule="", k_rule="")
    assert form.validate(), form.errors


# --------------------------------------------------------------------------- #
# Every attackmode that interpolates user input, not just maskmode (3).        #
# --------------------------------------------------------------------------- #


def _seed_task(app, **task_fields):
    """Seed a job + task with a real wordlist, for any attackmode."""
    user = Users(
        first_name="A",
        last_name="B",
        email_address="agent-cmdi-modes@example.com",
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
    db.session.add(HashfileHashes(hash_id=hash_entry.id, hashfile_id=1, username=None))

    wordlist = Wordlists(
        name="wl",
        owner_id=user.id,
        type="static",
        path="control/wordlists/rockyou.txt",
        size=1,
        checksum="0" * 64,
    )
    job = Jobs(
        name="cmdi-job",
        status="Queued",
        hashfile_id=1,
        customer_id=customer.id,
        owner_id=user.id,
    )
    db.session.add_all([wordlist, job])
    db.session.commit()

    task = Tasks(name="cmdi-task", owner_id=user.id, wl_id=wordlist.id, **task_fields)
    db.session.add(task)
    db.session.commit()
    return job, task


def _argv(cmd):
    return shlex.split(cmd.replace("@HASHCATBINPATH@", "/usr/bin/hashcat"))


@pytest.mark.parametrize("attackmode", [3, 6, 7])
def test_build_hashcat_command_rejects_malicious_mask_in_every_mask_mode(app, attackmode):
    """Maskmode (3) and both hybrid modes (6, 7) interpolate hc_mask."""
    job, task = _seed_task(app, hc_attackmode=attackmode, hc_mask="?a;id>/tmp/hv;#")
    with pytest.raises(ValueError, match="disallowed"):
        u.build_hashcat_command(job.id, task.id)


@pytest.mark.parametrize("attackmode", [3, 6, 7])
def test_build_hashcat_command_keeps_a_spaced_mask_as_one_argument(app, attackmode):
    """shlex.quote, not just validation, is what makes the command safe.

    A space is legal in a mask and passes the validator, so it is the case that
    proves the value is *quoted*: unquoted, the agent's shlex.split would tear
    ``?l?l ?d`` into two argv entries and hashcat would be handed a bogus
    positional argument.
    """
    mask = "?l?l ?d?d"
    job, task = _seed_task(app, hc_attackmode=attackmode, hc_mask=mask)
    argv = _argv(u.build_hashcat_command(job.id, task.id))
    assert mask in argv
    assert argv[argv.index("-a") + 1] == str(attackmode)


def test_build_hashcat_command_rejects_malicious_combinator_rules(app):
    job, task = _seed_task(app, hc_attackmode=1, j_rule="$-;touch pwned", k_rule="$!")
    with pytest.raises(ValueError, match="disallowed"):
        u.build_hashcat_command(job.id, task.id)

    task.j_rule = "$-"
    task.k_rule = "`id`"
    db.session.commit()
    with pytest.raises(ValueError, match="disallowed"):
        u.build_hashcat_command(job.id, task.id)


def test_build_hashcat_command_quotes_combinator_rules(app):
    """-j/-k rules arrive as their own argv tokens, spaces and all."""
    job, task = _seed_task(app, hc_attackmode=1, j_rule="$- $x", k_rule="$!")
    argv = _argv(u.build_hashcat_command(job.id, task.id))
    assert argv[argv.index("-j") + 1] == "$- $x"
    assert argv[argv.index("-k") + 1] == "$!"


def test_build_hashcat_command_omits_absent_combinator_rules(app):
    """No j/k rule set (the common case) must not emit an empty -j/-k."""
    job, task = _seed_task(app, hc_attackmode=1)
    argv = _argv(u.build_hashcat_command(job.id, task.id))
    assert "-j" not in argv and "-k" not in argv


def test_normalize_task_rule_unwraps_legacy_tuple_values():
    """Some rows stored j_rule/k_rule as a 1-tuple. Those must reduce to the
    inner string (so it gets validated and quoted) rather than being rendered as
    ``('$-',)``; anything that isn't a string is dropped instead of stringified.
    """
    assert u._normalize_task_rule(("$-",)) == "$-"
    assert u._normalize_task_rule(()) is None
    assert u._normalize_task_rule(None) is None
    assert u._normalize_task_rule(123) is None
    assert u._normalize_task_rule("$-") == "$-"
