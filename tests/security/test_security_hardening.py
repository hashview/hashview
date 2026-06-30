"""Security-depth regression tests for Hashview.

Covers four areas the existing single PoC did not:

1. CSRF — a dedicated CSRF-ENABLED app (the shared unit app disables CSRF) that
   logs a user in and asserts the per-form ``validate_on_submit()`` gate on a
   real create route (``/customers/add``) rejects a token-less POST (no row
   created) and accepts a POST carrying a valid token.
2. Command construction safety — feeds shell metacharacters through the
   user-controlled task fields (``hc_mask``, ``j_rule``, ``k_rule``) that
   ``build_hashcat_command`` interpolates RAW into the command string the agent
   later runs via ``subprocess.Popen(..., shell=True)``. These are STRICT XFAILS
   that document a real, confirmed injection (see module docstring "FINDINGS").
3. Path traversal — wordlist / rule names that contain ``../`` or absolute paths
   must collapse to a bare basename inside the control dir.
4. IDOR — a second, non-owner, non-admin user must not be able to delete another
   user's hashfile.

================================ FINDINGS ================================

[F1 — HIGH] Command injection via task fields -> agent shell.
  hashview/utils/utils.py:902,905,907  (build_hashcat_command, mask)
  hashview/utils/utils.py:891,896      (build_hashcat_command, j_rule/k_rule)
  task.hc_mask / task.j_rule / task.k_rule are free-form StringFields
  (hashview/tasks/forms.py — NO validators) and are concatenated UNQUOTED /
  single-quoted into the command string stored on JobTasks.command. The agent
  executes that exact string with shell=True
  (install/hashview-agent/hashview-agent.py:130), so `; whoami #`, `$(...)`,
  backticks, `&&`, single-quote-break-out, and newlines in those fields run on
  the agent host. Encoded below as strict xfails.

[F2 — MEDIUM] State-changing POST routes with NO CSRF protection.
  No global CSRFProtect is installed (hashview/__init__.py:321). Routes that read
  request.form directly instead of calling form.validate_on_submit() are NOT
  CSRF-protected, e.g.:
    - hashview/customers/routes.py:102  /customers/edit   (request.form)
    - hashview/customers/routes.py:159  /customers/delete (request.form)
    - hashview/hashfiles/routes.py:133  /hashfiles/delete (no token check)
    - hashview/agents/routes.py          GET state-changers (authorize/deauthorize/delete)
  Documented by test_csrf_unprotected_edit_route_is_a_finding (strict xfail).
=========================================================================
"""

import os
import subprocess

import pytest

from hashview import create_app
from hashview.models import (
    Customers,
    Hashes,
    Hashfiles,
    HashfileHashes,
    Jobs,
    JobTasks,
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


@pytest.mark.security
@pytest.mark.xfail(
    strict=True,
    reason=(
        "FINDING F2 (MEDIUM): /customers/edit reads request.form directly and "
        "there is no global CSRFProtect, so a token-less cross-site POST mutates "
        "state. This strict-xfail PROVES the gap: the edit succeeds with no token. "
        "It will flip to a failure (alerting the maintainer) once the route is "
        "CSRF-protected."
    ),
)
def test_csrf_unprotected_edit_route_is_a_finding(csrf_app):
    """Document that /customers/edit is NOT CSRF protected.

    We assert the route IS protected (rename rejected without a token). Because it
    is actually unprotected, the rename goes through and this assertion fails ->
    strict xfail flags the real, open finding.
    """
    app = csrf_app
    user = _seed_user()
    cust = Customers(name="OrigName")
    db.session.add(cust)
    db.session.commit()
    cust_id = cust.id

    client = app.test_client()
    _login(client, user)

    client.post(
        "/customers/edit",
        data={"customer_id": cust_id, "name": "HijackedName"},
    )
    db.session.expire_all()
    renamed = Customers.query.get(cust_id).name
    # If the route were CSRF protected, the token-less edit would be rejected and
    # the name would still be 'OrigName'. Asserting that here makes the test FAIL
    # under the current (unprotected) code -> strict xfail = documented finding.
    assert renamed == "OrigName", (
        "CSRF-unprotected: /customers/edit mutated state without a token "
        f"(name is now {renamed!r})"
    )


# --------------------------------------------------------------------------- #
# 2. Command construction safety                                              #
# --------------------------------------------------------------------------- #

# Shell metacharacters that, reaching a shell=True execution, would execute.
_SHELL_PAYLOADS = [
    "; whoami #",
    "$(whoami)",
    "`whoami`",
    "&& whoami",
    "| whoami",
    "x\nwhoami",
]


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
@pytest.mark.parametrize("payload", _SHELL_PAYLOADS)
@pytest.mark.parametrize("attackmode", [3, 6, 7])
@pytest.mark.xfail(
    strict=True,
    reason=(
        "FINDING F1 (HIGH): task.hc_mask is concatenated UNQUOTED into the hashcat "
        "command (build_hashcat_command -a 3/6/7) and the agent runs that string "
        "with subprocess.Popen(shell=True) (hashview-agent.py:130). Shell "
        "metacharacters in the mask therefore execute on the agent host. This "
        "strict-xfail asserts the payload is neutralized; it is NOT, proving the "
        "injection. Flips to a real failure once the mask is quoted/validated."
    ),
)
def test_mask_field_shell_injection(nocsrf_app, attackmode, payload):
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
        "FINDING F1 (HIGH): task.j_rule / task.k_rule are wrapped in SINGLE quotes "
        "in build_hashcat_command (attackmode 1) but never escaped, so a literal "
        "single quote breaks out of the quoting and the rest executes under the "
        "agent's shell=True. This strict-xfail asserts break-out is impossible; it "
        "is not, proving the injection."
    ),
)
def test_combinator_rule_shell_injection(nocsrf_app, field, payload):
    from hashview.utils.utils import build_hashcat_command

    kwargs = {field: payload}
    job, task = _seed_job_with_task(1, **kwargs)
    cmd = build_hashcat_command(job.id, task.id)
    # A single-quote in the payload that survives into the command means the
    # quoting can be broken out of. Safe handling would escape it.
    assert payload not in cmd, (
        f"{field} payload {payload!r} embedded raw in command (quote break-out): {cmd!r}"
    )


@pytest.mark.security
def test_agents_download_os_system_uses_trusted_version_only(nocsrf_app, monkeypatch):
    """The only live os.system() sink (agents/routes.py:243) builds its command
    from hashview.__version__, which is a package constant — NOT user input.

    Pin that no request data reaches it: we tripwire os.system to capture the
    string and assert it is exactly the version-templated tar command with no
    user-controlled component. (We do not actually run tar.)
    """
    app = nocsrf_app
    user = _seed_user(admin=True)
    client = app.test_client()
    _login(client, user)

    import hashview.agents.routes as agents_routes
    from flask import Response

    captured = {}

    def fake_system(cmd):
        captured["cmd"] = cmd
        return 0

    monkeypatch.setattr(agents_routes.os, "system", fake_system)
    # Don't actually serve a file off disk; the os.system cmd is what we inspect.
    monkeypatch.setattr(
        agents_routes,
        "send_from_directory",
        lambda *a, **k: Response("ok", status=200),
    )

    resp = client.get("/agents/download")
    assert resp.status_code == 200
    cmd = captured["cmd"]
    # version is e.g. '0.8.3' — no shell metacharacters, fixed template.
    import hashview

    assert hashview.__version__ in cmd
    assert cmd.startswith("tar -czf hashview/control/tmp/hashview-agent.")
    for meta in (";", "|", "&", "$(", "`", "\n"):
        assert meta not in cmd, f"unexpected shell metachar {meta!r} in os.system cmd: {cmd!r}"


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
    cmd = build_hashcat_command(job.id, task.id)

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
    cmd = build_hashcat_command(job.id, task.id)
    assert "control/rules/passwd" in cmd
    assert "/etc/passwd" not in cmd
    assert "../" not in cmd


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
