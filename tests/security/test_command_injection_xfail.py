"""Regression tests for issue #297 — command injection via task fields -> agent shell.

FINDING (HIGH): ``task.hc_mask`` / ``task.j_rule`` / ``task.k_rule`` are free-form
``StringField``s (``hashview/tasks/forms.py`` — NO validators). ``build_hashcat_command``
(``hashview/utils/utils.py``) concatenates them into the hashcat command string either
UNQUOTED (mask, attack modes 3/6/7) or single-quoted-but-UNESCAPED (j_rule/k_rule, attack
mode 1). That string is stored on ``JobTasks.command`` and the agent executes it verbatim
with ``subprocess.Popen(command, shell=True)``
(``install/hashview-agent/hashview-agent.py``). So ``; whoami #``, ``$(...)``, backticks,
``&&``, ``|``, newlines (mask), and a single-quote break-out (j_rule/k_rule) run on the
agent host.

These are STRICT XFAILS: each asserts the payload is neutralized (never embedded raw in
the command). It is NOT neutralized today, which PROVES the injection. When the bug is
fixed — mask quoted/validated, rules escaped — the assertions begin passing and the strict
xfail flips to a visible FAILURE, signalling that the ``@pytest.mark.xfail`` markers here
should be removed. Tracks GitHub issue #297.
"""

import pytest

from hashview import create_app
from hashview.models import (
    Customers,
    Hashes,
    Hashfiles,
    HashfileHashes,
    Jobs,
    Rules,
    Tasks,
    Users,
    Wordlists,
    db,
)


_BASE_OVERRIDES = {
    "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
    "SQLALCHEMY_TRACK_MODIFICATIONS": False,
    "MAIL_SUPPRESS_SEND": True,
    "SECRET_KEY": "security-test-secret",
    "SERVER_NAME": "localhost.test",
    "HASHVIEW_SKIP_SETUP": True,
    "HASHVIEW_SKIP_GUI_SETUP": True,
    "HASHVIEW_DISABLE_SCHEDULER": True,
    "WTF_CSRF_ENABLED": False,
}


@pytest.fixture()
def app():
    application = create_app(testing=True, config_overrides=dict(_BASE_OVERRIDES))
    with application.app_context():
        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()


def _seed_user(email="u@example.com", admin=False):
    u = Users(
        first_name="T",
        last_name="U",
        email_address=email,
        password="x" * 60,
        admin=admin,
    )
    db.session.add(u)
    db.session.commit()
    return u


def _seed_job_with_task(attackmode, *, hc_mask=None, j_rule=None, k_rule=None,
                        wl_path="rockyou.txt", rule_path="best64.rule"):
    """Seed the minimal graph build_hashcat_command needs and return (job, task)."""
    owner = _seed_user(email=f"owner{attackmode}@example.com", admin=True)
    cust = Customers(name=f"cust{attackmode}")
    db.session.add(cust)
    db.session.commit()

    # one hash + hashfile link so the hash_type lookup resolves
    h = Hashes(sub_ciphertext="ab" * 16, ciphertext="deadbeef",
               hash_type=0, cracked=False)
    db.session.add(h)
    db.session.commit()
    hf = Hashfiles(name="hf", customer_id=cust.id, owner_id=owner.id)
    db.session.add(hf)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    db.session.commit()

    wl = Wordlists(name="wl", owner_id=owner.id, type="Static",
                   path=wl_path, size=1000, checksum="0" * 64)
    wl2 = Wordlists(name="wl2", owner_id=owner.id, type="Static",
                    path="second.txt", size=1000, checksum="0" * 64)
    rule = Rules(name="rule", owner_id=owner.id, path=rule_path,
                 size=10, checksum="0" * 64)
    db.session.add_all([wl, wl2, rule])
    db.session.commit()

    task = Tasks(
        name=f"task{attackmode}",
        hc_attackmode=attackmode,
        owner_id=owner.id,
        wl_id=wl.id,
        wl_id_2=wl2.id,
        rule_id=(rule.id if attackmode == 0 else None),
        hc_mask=hc_mask,
        j_rule=j_rule,
        k_rule=k_rule,
    )
    db.session.add(task)
    db.session.commit()

    job = Jobs(name="job", status="Queued", customer_id=cust.id,
               owner_id=owner.id, hashfile_id=hf.id)
    db.session.add(job)
    db.session.commit()
    return job, task


# Shell metacharacters that, reaching a shell=True execution, would execute.
_SHELL_PAYLOADS = [
    "; whoami #",
    "$(whoami)",
    "`whoami`",
    "&& whoami",
    "| whoami",
    "x\nwhoami",
]


@pytest.mark.security
@pytest.mark.parametrize("payload", _SHELL_PAYLOADS)
@pytest.mark.parametrize("attackmode", [3, 6, 7])
@pytest.mark.xfail(
    strict=True,
    reason=(
        "FINDING #297 (HIGH): task.hc_mask is concatenated UNQUOTED into the hashcat "
        "command (build_hashcat_command -a 3/6/7) and the agent runs that string "
        "with subprocess.Popen(shell=True). Shell metacharacters in the mask "
        "therefore execute on the agent host. This strict-xfail asserts the payload "
        "is neutralized; it is NOT, proving the injection. Flips to a real failure "
        "once the mask is quoted/validated."
    ),
)
def test_mask_field_shell_injection(app, attackmode, payload):
    from hashview.utils.utils import build_hashcat_command

    job, task = _seed_job_with_task(attackmode, hc_mask=payload)
    cmd = build_hashcat_command(job.id, task.id)
    # Safe code would not embed the live metacharacters verbatim.
    assert payload not in cmd, (
        f"mask payload {payload!r} reached the command string RAW: {cmd!r}"
    )


@pytest.mark.security
# Only quote-break-out payloads belong here: j_rule/k_rule are single-quoted, so a
# literal single quote is what escapes the quoting and turns the rest into shell.
@pytest.mark.parametrize("payload", ["'; whoami #", "'`whoami`'", "' && whoami #"])
@pytest.mark.parametrize("field", ["j_rule", "k_rule"])
@pytest.mark.xfail(
    strict=True,
    reason=(
        "FINDING #297 (HIGH): task.j_rule / task.k_rule are wrapped in SINGLE quotes "
        "in build_hashcat_command (attackmode 1) but never escaped, so a literal "
        "single quote breaks out of the quoting and the rest executes under the "
        "agent's shell=True. This strict-xfail asserts break-out is impossible; it "
        "is not, proving the injection."
    ),
)
def test_combinator_rule_shell_injection(app, field, payload):
    from hashview.utils.utils import build_hashcat_command

    kwargs = {field: payload}
    job, task = _seed_job_with_task(1, **kwargs)
    cmd = build_hashcat_command(job.id, task.id)
    # A single-quote in the payload that survives into the command means the
    # quoting can be broken out of. Safe handling would escape it.
    assert payload not in cmd, (
        f"{field} payload {payload!r} embedded raw in command (quote break-out): {cmd!r}"
    )
