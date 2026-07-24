"""Regression tests for issue #297 — command injection via task fields -> agent shell.

ORIGINAL FINDING (HIGH): ``task.hc_mask`` / ``task.j_rule`` / ``task.k_rule`` are
free-form ``StringField``s (``hashview/tasks/forms.py`` — NO validators). The old
``build_hashcat_command`` concatenated them into a hashcat command *string* either
UNQUOTED (mask, attack modes 3/6/7) or single-quoted-but-UNESCAPED (j_rule/k_rule,
attack mode 1). That string was stored on ``JobTasks.command`` and the agent ran it
verbatim with ``subprocess.Popen(command, shell=True)``, so ``; whoami #``, ``$(...)``,
backticks, ``&&``, ``|``, newlines, and a single-quote break-out executed on the
agent host.

FIXED: ``build_hashcat_command`` now returns an argv LIST and the agent runs it with
``shell=False`` (see ``tests/agent_unit/test_argv_command.py`` for the agent half).
These tests are the server-side half and PASS: each payload must survive as exactly
ONE literal argv element, and the build must never emit a token that a shell would
have to be involved to produce. They are deliberately NOT xfails — if someone
reintroduces string concatenation, they fail.

Note for future edits: never assert ``payload not in argv``. Against an argv list
that check is inverted — a correctly-passed payload IS an element, so the assertion
fails precisely when the code is safe. Assert on element identity and token
boundaries instead.
"""

import pytest

from hashview import create_app
from hashview.models import (
    Customers,
    Hashes,
    HashfileHashes,
    Hashfiles,
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

# Payloads that broke out of the old single-quoting around -j / -k.
_QUOTE_BREAKOUT_PAYLOADS = ["'; whoami #", "'`whoami`'", "' && whoami #"]

_METACHARS = (";", "|", "&", "$", "`", "\n", "'", '"', ">", "<", "(", ")")


def _assert_payload_is_one_literal_token(argv, payload):
    """The payload must be exactly one whole argv element, and no other element may
    carry shell metacharacters — i.e. nothing was concatenated or shell-quoted."""
    assert isinstance(argv, list), f"command must be an argv list, got {type(argv)!r}"
    assert all(isinstance(el, str) for el in argv), f"non-str argv element in {argv!r}"

    assert argv.count(payload) == 1, (
        f"payload {payload!r} is not exactly one argv element: {argv!r}"
    )
    # No element may merely *contain* the payload: that would mean it was spliced
    # into a larger string (the old shell-string behaviour, e.g. "-a 3 ... mask").
    spliced = [el for el in argv if payload in el and el != payload]
    assert not spliced, (
        f"payload {payload!r} was concatenated into other tokens {spliced!r}: {argv!r}"
    )
    # Every metacharacter in the command must come from the payload element itself;
    # a quoted/escaped rendering would show up as extra metachars elsewhere.
    leaked = [el for el in argv
              if el != payload and any(m in el for m in _METACHARS)]
    assert not leaked, (
        f"shell metacharacters leaked into other argv tokens {leaked!r}: {argv!r}"
    )


@pytest.mark.security
@pytest.mark.parametrize("payload", _SHELL_PAYLOADS)
@pytest.mark.parametrize("attackmode", [3, 6, 7])
def test_mask_field_is_a_literal_argv_element(app, attackmode, payload):
    """task.hc_mask reaches hashcat as data for every mask-bearing attack mode."""
    from hashview.utils.utils import build_hashcat_command

    job, task = _seed_job_with_task(attackmode, hc_mask=payload)
    argv = build_hashcat_command(job.id, task.id)

    _assert_payload_is_one_literal_token(argv, payload)
    # Sanity: the mask is positioned as the attack mode expects it.
    assert argv[argv.index("-a") + 1] == str(attackmode)
    # -a 3: <target> <mask>; -a 6: <target> <wordlist> <mask>; -a 7: <target> <mask> <wordlist>
    mask_index = -2 if attackmode == 7 else -1
    assert argv[mask_index] == payload


@pytest.mark.security
@pytest.mark.parametrize("payload", _SHELL_PAYLOADS + _QUOTE_BREAKOUT_PAYLOADS)
@pytest.mark.parametrize("field,flag", [("j_rule", "-j"), ("k_rule", "-k")])
def test_combinator_rule_is_a_literal_argv_element(app, field, flag, payload):
    """task.j_rule / task.k_rule are argv elements, so the old single-quote
    break-out (``'; whoami #``) has nothing to break out of."""
    from hashview.utils.utils import build_hashcat_command

    job, task = _seed_job_with_task(1, **{field: payload})
    argv = build_hashcat_command(job.id, task.id)

    _assert_payload_is_one_literal_token(argv, payload)
    assert argv[argv.index(flag) + 1] == payload


@pytest.mark.security
def test_mask_chunk_submask_is_a_literal_argv_element(app):
    """A chunk's sub-mask overrides task.hc_mask; it must stay one literal token too."""
    from hashview.utils.utils import build_hashcat_command

    payload = "?d?d; whoami #"
    job, task = _seed_job_with_task(3, hc_mask="?d?d?d")
    argv = build_hashcat_command(job.id, task.id, chunk={"mask": payload})

    _assert_payload_is_one_literal_token(argv, payload)
    assert argv[-1] == payload
    assert "?d?d?d" not in argv          # the chunk mask replaced the task's
