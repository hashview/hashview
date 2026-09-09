"""Security-depth regression tests for Hashview.

Covers three areas the existing single PoC did not:

1. CSRF (positive) — a dedicated CSRF-ENABLED app (the shared unit app disables
   CSRF) that logs a user in and asserts the per-form ``validate_on_submit()``
   gate on a real create route (``/customers/add``) rejects a token-less POST (no
   row created) and accepts a POST carrying a valid token. Also pins the only
   live ``os.system`` sink (agent download) to a version-templated, non-user
   command.
2. Path traversal — wordlist / rule names that contain ``../`` or absolute paths
   must collapse to a bare basename inside the control dir.
3. IDOR — a second, non-owner, non-admin user must not be able to delete another
   user's hashfile (plus an owner control case).

NOTE — two findings that were originally proven here as strict xfails now live in
their own per-issue modules so each tracks a GitHub issue:

  - FINDING #297 (HIGH) command injection via task fields -> agent shell: FIXED
    (argv list + agent shell=False). Now a passing regression suite:
    tests/security/test_command_injection_argv.py
  - FINDING #298 (MEDIUM) missing CSRF on form-reading routes: still open,
    tracked as strict xfails in tests/security/test_csrf_xfail.py

This module deliberately contains only PASSING security tests.
"""

import inspect

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

# --------------------------------------------------------------------------- #
# App / fixtures                                                              #
# --------------------------------------------------------------------------- #

_BASE_OVERRIDES = {
    "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
    "SQLALCHEMY_TRACK_MODIFICATIONS": False,
    "MAIL_SUPPRESS_SEND": True,
    "SECRET_KEY": "security-test-secret",
    "SERVER_NAME": "localhost.test",
    "HASHVIEW_SKIP_SETUP": True,
    "HASHVIEW_SKIP_GUI_SETUP": True,
    "HASHVIEW_DISABLE_SCHEDULER": True,
}


def _make_app(csrf_enabled):
    overrides = dict(_BASE_OVERRIDES)
    overrides["WTF_CSRF_ENABLED"] = csrf_enabled
    return create_app(testing=True, config_overrides=overrides)


@pytest.fixture()
def csrf_app():
    """A dedicated app with CSRF ENABLED (the shared unit app disables it)."""
    app = _make_app(csrf_enabled=True)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def nocsrf_app():
    """CSRF-disabled app for the command-build / traversal / IDOR tests."""
    app = _make_app(csrf_enabled=False)
    with app.app_context():
        db.create_all()
        yield app
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


def _login(client, user):
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True


# --------------------------------------------------------------------------- #
# 1. CSRF coverage                                                            #
# --------------------------------------------------------------------------- #


@pytest.mark.security
def test_csrf_protected_create_rejects_without_token_and_accepts_with(csrf_app):
    """/customers/add is guarded by form.validate_on_submit(): with CSRF enabled,
    a token-less POST must NOT create the row; a POST with a valid token must.

    There is no global CSRFProtect (hashview/__init__.py), so the failure mode is
    a redirect with a flashed error and NO database write (not an HTTP 400). We
    assert the security-relevant invariant: no state change without a token.
    """
    app = csrf_app
    user = _seed_user()
    client = app.test_client()
    _login(client, user)

    # --- token-less POST: must be rejected (no customer created) ---
    resp = client.post("/customers/add", data={"name": "EvilCorp"})
    # validate_on_submit() fails CSRF -> flash + redirect, never a write.
    assert resp.status_code in (200, 302, 400)
    assert Customers.query.filter_by(name="EvilCorp").first() is None, (
        "CSRF gate failed: customer was created without a CSRF token"
    )

    # --- POST with a valid token: must succeed ---
    # Get a token the realistic way: render the customers page (which emits a
    # csrf_token() hidden field bound to THIS client's session cookie) and reuse
    # that exact token + cookie for the POST, exactly as a browser would.
    import re

    page = client.get("/customers")
    assert page.status_code == 200
    m = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', page.get_data(as_text=True))
    assert m, "expected a csrf_token field in the rendered customers page"
    token = m.group(1)

    resp = client.post(
        "/customers/add",
        data={"name": "GoodCorp", "csrf_token": token},
        follow_redirects=False,
    )
    assert resp.status_code in (200, 302)
    assert Customers.query.filter_by(name="GoodCorp").first() is not None, (
        "valid-token POST should have created the customer"
    )


# --------------------------------------------------------------------------- #
# 2. Command construction safety (the os.system sink; the user-controlled       #
#    injection findings are split out — see module docstring)                  #
# --------------------------------------------------------------------------- #


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


@pytest.mark.security
def test_agents_download_no_shell_execution(nocsrf_app, monkeypatch):
    """The agents download route must not shell out or execute any shell commands.

    The tarfile is built using Python's tarfile module, never via os.system,
    os.popen, or subprocess (which all funnel through subprocess.Popen).
    Tripwiring the actual sinks catches any regression regardless of alias
    (e.g. `import os as _o; _o.system(...)`) or mechanism (e.g.
    `subprocess.run(..., shell=True)`) -- a source-string check for the
    literal text "os.system" would miss both.
    """
    import os
    import subprocess

    app = nocsrf_app
    user = _seed_user(admin=True)
    client = app.test_client()
    _login(client, user)

    def _fail_popen(*args, **kwargs):
        pytest.fail(f"shell-out via subprocess.Popen: args={args!r} kwargs={kwargs!r}")

    def _fail_system(cmd):
        pytest.fail(f"shell-out via os.system: {cmd!r}")

    def _fail_popen_builtin(*args, **kwargs):
        pytest.fail(f"shell-out via os.popen: args={args!r} kwargs={kwargs!r}")

    monkeypatch.setattr(subprocess, "Popen", _fail_popen)
    monkeypatch.setattr(os, "system", _fail_system)
    monkeypatch.setattr(os, "popen", _fail_popen_builtin)

    resp = client.get("/agents/download")
    assert resp.status_code == 200
    assert resp.data[:2] == b"\x1f\x8b", "Response must be a gzip stream"

    import hashview.agents.routes as agents_routes
    source = inspect.getsource(agents_routes)
    assert "shell=True" not in source, "agents/routes.py must not shell out"


# --------------------------------------------------------------------------- #
# 3. Path traversal in wordlist / rule names                                  #
# --------------------------------------------------------------------------- #


@pytest.mark.security
@pytest.mark.parametrize(
    "evil_path",
    [
        "../../../../etc/passwd",
        "/etc/shadow",
        "sub/dir/payload.txt",
        "..\\..\\windows\\system32",
    ],
)
def test_wordlist_path_collapses_to_basename(nocsrf_app, evil_path):
    """build_hashcat_command derives the on-agent wordlist path from
    wordlist.path.split('/')[-1] (basename), then prefixes control/wordlists/.
    A traversal / absolute path must never produce an absolute or parent-escaping
    path in the command."""
    from hashview.utils.utils import build_hashcat_command

    job, task = _seed_job_with_task(0, wl_path=evil_path)
    # build_hashcat_command returns an argv list; join it so these substring
    # checks (prefix + no-traversal) inspect the whole invocation.
    cmd = " ".join(build_hashcat_command(job.id, task.id))

    # The wordlist must always be referenced under the relative control dir.
    assert "control/wordlists/" in cmd
    # No absolute path and no parent-escape sequence reached the command.
    assert "/etc/passwd" not in cmd
    assert "/etc/shadow" not in cmd
    assert "../" not in cmd
    # The forward-slash basename is what survives (windows back-slashes are not
    # split by split('/'), so they are documented below).
    if "/" in evil_path:
        base = evil_path.split("/")[-1]
        assert f"control/wordlists/{base}" in cmd or base + ".gz" in cmd


@pytest.mark.security
def test_rule_path_collapses_to_basename(nocsrf_app):
    """rules_file.path.split('/')[-1] must drop any traversal prefix."""
    from hashview.utils.utils import build_hashcat_command

    job, task = _seed_job_with_task(0, rule_path="../../../../etc/passwd")
    cmd = " ".join(build_hashcat_command(job.id, task.id))   # argv list -> joined for substring checks
    assert "control/rules/passwd" in cmd
    assert "/etc/passwd" not in cmd
    assert "../" not in cmd


# --------------------------------------------------------------------------- #
# 3b. Command injection via task mask / rule fields (issue #297)              #
# build_hashcat_command returns an argv LIST run by the agent with shell=False,#
# so free-form fields land as literal argv elements, never shell-interpreted. #
# --------------------------------------------------------------------------- #


@pytest.mark.security
def test_mask_field_shell_injection_is_a_literal_argv_element(nocsrf_app):
    """A mask carrying shell metacharacters must be ONE literal argv element
    (issue #297): `;`, `$()`, backticks, `|`, newlines reach hashcat as data."""
    from hashview.utils.utils import build_hashcat_command

    payload = "?d?d ; touch /tmp/pwned #\n$(id)`whoami`|cat /etc/passwd"
    job, task = _seed_job_with_task(3, hc_mask=payload)   # -a 3 mask mode
    argv = build_hashcat_command(job.id, task.id)

    assert isinstance(argv, list)
    # The whole payload is exactly one argv element (never split on the
    # metacharacters), so execve hands it to hashcat as a single argument.
    assert payload in argv
    assert argv.count(payload) == 1
    assert argv[-1] == payload                       # it's the mask argument


@pytest.mark.security
def test_combinator_rule_shell_injection_is_a_literal_argv_element(nocsrf_app):
    """The combinator -j/-k rules were single-quoted (unescaped) into a shell
    string, so a `'` broke out. As argv elements they cannot (issue #297)."""
    from hashview.utils.utils import build_hashcat_command

    j_payload = "$1' ; rm -rf / ; '"                 # single-quote break-out attempt
    k_payload = "`whoami`"
    job, task = _seed_job_with_task(1, j_rule=j_payload, k_rule=k_payload)  # -a 1 combinator
    argv = build_hashcat_command(job.id, task.id)

    assert isinstance(argv, list)
    # Each rule is exactly one literal argv element, right after its flag.
    assert argv[argv.index("-j") + 1] == j_payload
    assert argv[argv.index("-k") + 1] == k_payload
    # The build never emitted standalone shell-metacharacter tokens.
    assert ";" not in argv and "&&" not in argv and "|" not in argv


# --------------------------------------------------------------------------- #
# 4. IDOR / broken object-level authorization                                 #
# --------------------------------------------------------------------------- #


@pytest.mark.security
def test_idor_user_b_cannot_delete_user_a_hashfile(nocsrf_app):
    """User B (non-owner, non-admin) must not delete User A's hashfile.

    hashfiles_delete gates on (current_user.admin or owner_id == current_user.id);
    a denied B is redirected with a flash and the hashfile survives.
    """
    app = nocsrf_app
    user_a = _seed_user(email="a@example.com", admin=False)
    user_b = _seed_user(email="b@example.com", admin=False)
    cust = Customers(name="c")
    db.session.add(cust)
    db.session.commit()

    hf = Hashfiles(name="a-secret-hashfile", customer_id=cust.id, owner_id=user_a.id)
    db.session.add(hf)
    db.session.commit()
    hf_id = hf.id

    client = app.test_client()
    _login(client, user_b)

    resp = client.post(f"/hashfiles/delete/{hf_id}", follow_redirects=False)
    # App pattern for denial here is a redirect (302) + flash, not 403.
    assert resp.status_code in (302, 403), (
        f"expected redirect/forbidden for non-owner delete, got {resp.status_code}"
    )
    db.session.expire_all()
    assert Hashfiles.query.get(hf_id) is not None, (
        "IDOR: user B deleted user A's hashfile"
    )


@pytest.mark.security
def test_owner_can_delete_own_hashfile(nocsrf_app):
    """Control case: the owner CAN delete their own hashfile (proves the IDOR
    test above is denying on ownership, not on some unrelated failure)."""
    app = nocsrf_app
    user_a = _seed_user(email="owner@example.com", admin=False)
    cust = Customers(name="c2")
    db.session.add(cust)
    db.session.commit()
    hf = Hashfiles(name="own-hashfile", customer_id=cust.id, owner_id=user_a.id)
    db.session.add(hf)
    db.session.commit()
    hf_id = hf.id

    client = app.test_client()
    _login(client, user_a)
    resp = client.post(f"/hashfiles/delete/{hf_id}", follow_redirects=False)
    assert resp.status_code in (302, 200)
    db.session.expire_all()
    assert Hashfiles.query.get(hf_id) is None, "owner should be able to delete own hashfile"
