"""xfail regression tests documenting the open API-audit issues.

Each test asserts the *correct* (post-fix) behavior and is marked
``@pytest.mark.xfail(strict=True)`` keyed to its GitHub issue. They therefore
fail today (XFAIL) and will turn into a hard failure (XPASS, strict) the moment
the underlying bug is fixed — that is the signal to drop the xfail marker and
fold the test into the normal suite.

Issue tracker: https://github.com/hashview/hashview/issues

Auth/cookie model mirrors tests/unit/test_api_endpoints.py: the ``uuid`` cookie
is matched against ``Users.api_key`` (user routes) or ``Agents.uuid`` (agent
routes); the cookie domain must equal the test ``SERVER_NAME`` (localhost.test)
for Werkzeug 3.x to send it.

Not represented here (cannot be expressed as a clean behavioral xfail):
  * #222 unauthenticated agent registration / no rate limiting — no defined
    limit to assert against; needs a design decision first.
  * #223 AlchemyEncoder denylist vs allowlist — a hardening preference, not an
    observable behavior change with the current model set.
  * #228 N+1 queries — a performance characteristic; would need a brittle
    query-count probe rather than a behavioral assertion.
  * #231 dead-code / debug-print removal — nothing to assert behaviorally.
"""

import inspect
import json
import os

import pytest

import hashview
import hashview.api.routes as api_routes
from hashview.models import (
    Agents,
    Customers,
    Hashes,
    HashfileHashes,
    Hashfiles,
    Jobs,
    JobTasks,
    Rules,
    Tasks,
    Users,
    Wordlists,
)
from hashview.models import db as _db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def admin_user(app):
    user = Users(
        first_name="Admin",
        last_name="User",
        email_address="admin@example.test",
        password="hashed-pw",
        admin=True,
        api_key="user-api-key-admin",
    )
    _db.session.add(user)
    _db.session.commit()
    return user


@pytest.fixture()
def agent_a(app):
    agent = Agents(
        name="agent-a", src_ip="127.0.0.1", uuid="agent-uuid-a", status="Authorized"
    )
    _db.session.add(agent)
    _db.session.commit()
    return agent


@pytest.fixture()
def agent_b(app):
    agent = Agents(
        name="agent-b", src_ip="127.0.0.1", uuid="agent-uuid-b", status="Authorized"
    )
    _db.session.add(agent)
    _db.session.commit()
    return agent


def _json_body(resp):
    return json.loads(resp.get_data(as_text=True))


def _auth(client, value):
    client.set_cookie("uuid", value, domain="localhost.test")


def _seed_crackable_job(owner, *, assigned_agent=None, limit_recovered=False):
    """Seed customer -> hashfile -> (uncracked) hash + junction -> job -> job_task.

    Returns (job, job_task, ciphertext, crack_line). The crack_line is the
    ``<ciphertext>:<hex(plaintext)>`` body an agent uploads to recover the hash.
    """
    from hashview.utils.utils import get_md5_hash

    cust = Customers(name="CrackCo")
    _db.session.add(cust)
    _db.session.commit()

    hashfile = Hashfiles(name="hf", customer_id=cust.id, owner_id=owner.id)
    _db.session.add(hashfile)
    _db.session.commit()

    ciphertext = "deadbeefcafef00d"
    plaintext = "hunter2"
    h = Hashes(
        sub_ciphertext=get_md5_hash(ciphertext),
        ciphertext=ciphertext,
        hash_type=1000,
        cracked=False,
    )
    _db.session.add(h)
    _db.session.commit()
    _db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hashfile.id))
    _db.session.commit()

    job = Jobs(
        name="crack-job",
        status="Running",
        hashfile_id=hashfile.id,
        customer_id=cust.id,
        owner_id=owner.id,
        limit_recovered=limit_recovered,
    )
    _db.session.add(job)
    _db.session.commit()

    job_task = JobTasks(
        job_id=job.id,
        task_id=1,
        status="Running",
        agent_id=(assigned_agent.id if assigned_agent else None),
    )
    _db.session.add(job_task)
    _db.session.commit()

    crack_line = f"{ciphertext}:{plaintext.encode().hex()}"
    return job, job_task, ciphertext, crack_line


# ---------------------------------------------------------------------------
# #217 — /v1/jobs/start can never start an API-created (Ready) job
# ---------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.xfail(strict=True, reason="#217: start guard requires status=='Queued', "
                                       "so a Ready job created via /v1/jobs/add can never start")
def test_217_jobs_start_starts_a_ready_job(client, admin_user):
    cust = Customers(name="StartCo")
    _db.session.add(cust)
    _db.session.commit()
    job = Jobs(name="ready-job", status="Ready", customer_id=cust.id, owner_id=admin_user.id)
    _db.session.add(job)
    _db.session.commit()
    _db.session.add(JobTasks(job_id=job.id, task_id=1, status="Not Started"))
    _db.session.commit()

    _auth(client, admin_user.api_key)
    resp = client.post(f"/v1/jobs/start/{job.id}")
    body = _json_body(resp)

    assert body["status"] == 200
    assert Jobs.query.get(job.id).status == "Queued"


# ---------------------------------------------------------------------------
# #218 — null-deref 500s where a clean 4xx is expected
# ---------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.xfail(strict=True, reason="#218: HashfileHashes...first() is None -> .hash_id AttributeError -> 500")
def test_218_get_hashtype_unknown_hashfile_returns_404(client, admin_user):
    _auth(client, admin_user.api_key)
    resp = client.get("/v1/getHashType/999999")
    assert resp.status_code == 404


@pytest.mark.security
@pytest.mark.xfail(strict=True, reason="#218: user caller has no Agents row -> agent.id AttributeError -> 500")
def test_218_jobtasks_assignment_user_caller_no_500(client, admin_user):
    # Route allows user=True, agent=True, but only an agent has an Agents row;
    # a user caller hits agent.id on None. Should be handled gracefully.
    _auth(client, admin_user.api_key)
    resp = client.get("/v1/jobTasks/1")
    assert resp.status_code in (200, 404)


@pytest.mark.security
@pytest.mark.xfail(strict=True, reason="#218: JobTasks.query.get(bad) is None -> .job_id AttributeError -> 500")
def test_218_uploadcrackfile_bad_jobtask_returns_404(client, agent_a):
    _auth(client, agent_a.uuid)
    resp = client.post(
        "/v1/uploadCrackFile/999999",
        data=json.dumps({"file": ""}),
        content_type="application/json",
    )
    assert resp.status_code == 404


@pytest.mark.security
@pytest.mark.xfail(strict=True, reason="#218: search_json['hash'] raises KeyError when 'hash' key absent")
def test_218_search_missing_hash_key_is_handled(client, admin_user):
    _auth(client, admin_user.api_key)
    resp = client.post(
        "/v1/search",
        data=json.dumps({"not_hash": "x"}),
        content_type="application/json",
    )
    body = _json_body(resp)
    assert "Invalid" in str(body.get("msg", ""))


# ---------------------------------------------------------------------------
# #219 — broken SQLAlchemy filter (Hashes.task_id is not None == filter(True))
# ---------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.xfail(strict=True, reason="#219: source still contains the no-op `Hashes.task_id is not None` filter")
def test_219_jobs_add_uses_proper_null_filter():
    src = inspect.getsource(api_routes.v1_api_post_add_job)
    assert "Hashes.task_id is not None" not in src
    assert "Hashes.task_id.isnot(None)" in src


# ---------------------------------------------------------------------------
# #220 — limit_recovered job IS marked Completed after a recovery
#
# This is NOT a bug (the audit finding was wrong): although the explicit
# job.status='Completed' block in the limit_recovered path is commented out,
# the cancel loop calls update_job_task_status('Canceled') for every task, and
# that helper marks the job Completed once no task is still active. So this is a
# *passing* regression test that pins the real behavior; the commented-out code
# is redundant cleanup only (see #231). See the comment posted on issue #220.
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_220_limit_recovered_job_marked_completed(client, agent_a):
    owner = Users(
        first_name="O", last_name="W", email_address="o@example.test",
        password="pw", admin=True, api_key="owner-key",
    )
    _db.session.add(owner)
    _db.session.commit()

    job, job_task, _ct, crack_line = _seed_crackable_job(
        owner, assigned_agent=agent_a, limit_recovered=True
    )

    _auth(client, agent_a.uuid)
    resp = client.post(
        f"/v1/uploadCrackFile/{job_task.id}",
        data=json.dumps({"file": crack_line}),
        content_type="application/json",
    )
    assert _json_body(resp)["status"] == 200
    assert Jobs.query.get(job.id).status == "Completed"


# ---------------------------------------------------------------------------
# #221 — unauthorized should be a real 401/403, not a 3xx redirect (-> 200)
# ---------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.xfail(strict=True, reason="#221: unauthorized redirects to /v1/not_authorized (HTTP 3xx -> 200)")
def test_221_unauthorized_returns_401_or_403(client):
    resp = client.get("/v1/rules")
    assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# #224 — internal exception text must not leak to the client
# ---------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.xfail(strict=True, reason="#224: handler returns f'...: {e}', leaking raw exception text")
def test_224_exception_detail_not_leaked(client, admin_user, monkeypatch):
    secret = "INTERNAL-LEAK-TOKEN-zzz"

    def boom():
        raise RuntimeError(secret)

    # Force the route's commit to fail; the except block must not echo the
    # raw exception message back to the caller.
    monkeypatch.setattr(_db.session, "commit", boom)

    _auth(client, admin_user.api_key)
    resp = client.post(
        "/v1/customers/add",
        data=json.dumps({"name": "Boom"}),
        content_type="application/json",
    )
    assert secret not in resp.get_data(as_text=True)


# ---------------------------------------------------------------------------
# #225 — crack uploads must verify the agent is assigned the job_task
# ---------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.xfail(strict=True, reason="#225: no ownership check — any authorized agent can submit cracks for any task")
def test_225_crackfile_upload_rejects_unassigned_agent(client, agent_a, agent_b):
    owner = Users(
        first_name="O", last_name="W", email_address="o2@example.test",
        password="pw", admin=True, api_key="owner-key-2",
    )
    _db.session.add(owner)
    _db.session.commit()

    # Task is assigned to agent_b ...
    _job, job_task, _ct, crack_line = _seed_crackable_job(owner, assigned_agent=agent_b)

    # ... but agent_a (a different authorized agent) uploads results for it.
    _auth(client, agent_a.uuid)
    resp = client.post(
        f"/v1/uploadCrackFile/{job_task.id}",
        data=json.dumps({"file": crack_line}),
        content_type="application/json",
    )
    body = _json_body(resp)
    assert body.get("status") == 403


# ---------------------------------------------------------------------------
# #226 — temp files in control/tmp must be cleaned up after a download
# ---------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.xfail(strict=True, reason="#226: rule download leaves the generated .gz in control/tmp forever")
def test_226_rule_download_cleans_up_tmp(client, app, admin_user, tmp_path, monkeypatch):
    monkeypatch.setattr(app, "root_path", str(tmp_path))
    rules_dir = os.path.join(str(tmp_path), "control", "rules")
    tmp_dir = os.path.join(str(tmp_path), "control", "tmp")
    os.makedirs(rules_dir, exist_ok=True)
    os.makedirs(tmp_dir, exist_ok=True)

    rule_path = os.path.join(rules_dir, "served.txt")
    with open(rule_path, "wb") as fh:
        fh.write(b"$!\n$@\n")
    rule = Rules(name="served", owner_id=admin_user.id, path=rule_path, size=2, checksum="0" * 64)
    _db.session.add(rule)
    _db.session.commit()

    _auth(client, admin_user.api_key)
    resp = client.get(f"/v1/rules/{rule.id}")
    assert resp.status_code == 200
    # The transient .gz must not be left behind.
    assert os.listdir(tmp_dir) == []


# ---------------------------------------------------------------------------
# #227 — /v1/hashfiles/<id> must use app.root_path, not a CWD-relative path
# ---------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.xfail(strict=True, reason="#227: writes to hardcoded 'hashview/control/tmp/' but serves from 'control/tmp/'")
def test_227_hashfile_download_uses_root_path(client, app, admin_user, tmp_path, monkeypatch):
    monkeypatch.setattr(app, "root_path", str(tmp_path))
    # chdir so the route's CWD-relative open()/send_from_directory don't touch
    # the real repo tree; create both dirs the buggy code references.
    monkeypatch.chdir(tmp_path)
    os.makedirs(os.path.join(str(tmp_path), "control", "tmp"), exist_ok=True)
    os.makedirs(os.path.join(str(tmp_path), "hashview", "control", "tmp"), exist_ok=True)

    cust = Customers(name="HFCo")
    _db.session.add(cust)
    _db.session.commit()
    hashfile = Hashfiles(name="hf", customer_id=cust.id, owner_id=admin_user.id)
    _db.session.add(hashfile)
    _db.session.commit()
    h = Hashes(sub_ciphertext="0" * 32, ciphertext="abc123", hash_type=1000, cracked=False)
    _db.session.add(h)
    _db.session.commit()
    _db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hashfile.id))
    _db.session.commit()

    _auth(client, admin_user.api_key)
    resp = client.get(f"/v1/hashfiles/{hashfile.id}")
    assert resp.status_code == 200
    assert b"abc123" in resp.data


# ---------------------------------------------------------------------------
# #229 — list endpoints should return native JSON, not a JSON-encoded string
# ---------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.xfail(strict=True, reason="#229: payload is json.dumps()'d into a string, forcing clients to double-parse")
def test_229_rules_list_is_native_json(client, admin_user):
    _auth(client, admin_user.api_key)
    resp = client.get("/v1/rules")
    body = _json_body(resp)
    assert isinstance(body["rules"], list)


# ---------------------------------------------------------------------------
# #230 — /v1/updateWordlist mutates state, so it should accept POST
# ---------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.xfail(strict=True, reason="#230: route is GET-only for a state-mutating action")
def test_230_update_wordlist_accepts_post(client, admin_user, monkeypatch):
    monkeypatch.setattr(api_routes, "update_dynamic_wordlist", lambda *a, **kw: None)
    wl = Wordlists(
        name="dyn", owner_id=admin_user.id, type="dynamic",
        path="/nonexistent/dyn.txt", size=1, checksum="0" * 64,
    )
    _db.session.add(wl)
    _db.session.commit()

    _auth(client, admin_user.api_key)
    resp = client.post(f"/v1/updateWordlist/{wl.id}")
    assert resp.status_code != 405


# ---------------------------------------------------------------------------
# #232 — __version__ should track the dev branch (v0.8.3)
# ---------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.xfail(strict=True, reason="#232: __version__ still '0.8.2' on the v0.8.3-dev branch")
def test_232_version_is_0_8_3():
    assert hashview.__version__ == "0.8.3"
