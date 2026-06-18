"""Regression tests for previously-untested hashview.api.routes behavior.

These complement test_api_endpoints.py and test_api_agent_protocol.py, filling
gaps surfaced by a route-by-route review of ``hashview/api/routes.py``:

- The ``AlchemyEncoder`` secret denylist (passwords / api keys / OAuth + Slack
  secrets must never be serialized to an agent or user).
- ``POST /v1/search`` (cracked-plaintext disclosure + auth boundary).
- ``POST /v1/jobtask/status`` (agent updates a jobtask's status).
- ``POST /v1/uploadCrackFile/<job_task_id>`` (core crack ingestion, incl. the
  one-and-done cancellation path).
- ``POST /v1/jobs/start/<id>`` success / invalid-id / non-owner branches.
- ``POST /v1/jobs/add`` "not enough data" branch.
- ``GET /v1/wordlists`` list + ``GET /v1/wordlists/<id>`` static & dynamic
  download.
- ``POST /v1/agents/heartbeat`` Working (benchmark parse) / Canceled / Pending
  branches.
- ``POST /v1/hashfiles/upload/...`` invalid file-format branch.

Auth recap (see ``is_authorized``): the 'uuid' cookie maps to ``Users.api_key``
(user routes) or ``Agents.uuid`` with an active status (agent routes). The
cookie domain must equal the test SERVER_NAME (localhost.test) for Werkzeug 3.x
to send it.
"""

import gzip
import json
import os

import pytest

import hashview
from hashview.models import (
    Agents,
    Customers,
    Hashes,
    HashfileHashes,
    Hashfiles,
    JobNotifications,
    Jobs,
    JobTasks,
    Rules,
    Settings,
    Tasks,
    Users,
    Wordlists,
)
from hashview.models import db as _db
from hashview.utils.utils import get_md5_hash

DOMAIN = "localhost.test"


# ---------------------------------------------------------------------------
# Shared helpers / fixtures
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
def regular_user(app):
    user = Users(
        first_name="Reg",
        last_name="Ular",
        email_address="reg@example.test",
        password="hashed-pw",
        admin=False,
        api_key="user-api-key-regular",
    )
    _db.session.add(user)
    _db.session.commit()
    return user


@pytest.fixture()
def authorized_agent(app):
    agent = Agents(
        name="agent-1",
        src_ip="127.0.0.1",
        uuid="agent-uuid-ok",
        status="Authorized",
    )
    _db.session.add(agent)
    _db.session.commit()
    return agent


def _body(resp):
    return json.loads(resp.get_data(as_text=True))


def _auth(client, value):
    client.set_cookie("uuid", value, domain=DOMAIN)


def _seed_customer(name="Acme"):
    cust = Customers(name=name)
    _db.session.add(cust)
    _db.session.commit()
    return cust


def _seed_hashfile(customer_id, owner_id, name="hf"):
    hf = Hashfiles(name=name, customer_id=customer_id, owner_id=owner_id)
    _db.session.add(hf)
    _db.session.commit()
    return hf


def _seed_hash(hash_type, cracked, ciphertext, sub=None, plaintext=None):
    h = Hashes(
        sub_ciphertext=sub if sub is not None else get_md5_hash(ciphertext),
        ciphertext=ciphertext,
        hash_type=hash_type,
        cracked=cracked,
        plaintext=plaintext,
    )
    _db.session.add(h)
    _db.session.commit()
    return h


# ---------------------------------------------------------------------------
# AlchemyEncoder secret denylist  (security invariant)
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_alchemy_encoder_omits_user_secrets(app):
    """Serializing a Users row must never expose password or api_key.

    Takes the ``app`` fixture so the encoder's ``dir(obj)`` walk (which touches
    Flask-SQLAlchemy's ``query`` descriptor) runs inside an app context.
    """
    from hashview.api.routes import AlchemyEncoder

    user = Users(
        first_name="Secret",
        last_name="Holder",
        email_address="s@e.test",
        password="super-secret-bcrypt",
        admin=True,
        api_key="super-secret-api-key",
    )
    dumped = json.loads(json.dumps(user, cls=AlchemyEncoder))
    assert "password" not in dumped
    assert "api_key" not in dumped
    # Non-secret columns still serialize.
    assert dumped["email_address"] == "s@e.test"


@pytest.mark.security
def test_admin_settings_never_leaks_stored_secrets(client, admin_user):
    """GET /v1/admin/settings is reachable by any user OR agent, so stored
    secrets (Slack bot token, Azure client secret) must be stripped from the
    serialized Settings payload."""
    settings_row = Settings(
        retention_period=30,
        max_runtime_tasks=0,
        max_runtime_jobs=0,
        slack_bot_token="xoxb-LEAK-ME-NOT",
        azure_client_secret="azure-LEAK-ME-NOT",
    )
    _db.session.add(settings_row)
    _db.session.commit()

    _auth(client, admin_user.api_key)
    resp = client.get("/v1/admin/settings")
    body = _body(resp)
    assert body["status"] == 200
    # The settings collection is serialized as a JSON *string*; the raw secret
    # values must not appear anywhere in it.
    assert "xoxb-LEAK-ME-NOT" not in body["settings"]
    assert "azure-LEAK-ME-NOT" not in body["settings"]


# ---------------------------------------------------------------------------
# POST /v1/search
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_search_returns_plaintext_for_cracked_hash(client, admin_user):
    """A cracked hash search returns its hash_type and plaintext."""
    _seed_hash(1000, True, "deadbeefdeadbeef", plaintext="hunter2")

    _auth(client, admin_user.api_key)
    resp = client.post("/v1/search", json={"hash": "deadbeefdeadbeef"})
    body = _body(resp)
    assert body["status"] == 200
    assert body["msg"]["plaintext"] == "hunter2"
    assert body["msg"]["hash_type"] == 1000


@pytest.mark.security
def test_search_uncracked_hash_reports_no_results(client, admin_user):
    """An uncracked (or unknown) hash must not be returned as a result."""
    _seed_hash(1000, False, "feedfacefeedface")

    _auth(client, admin_user.api_key)
    resp = client.post("/v1/search", json={"hash": "feedfacefeedface"})
    body = _body(resp)
    assert body["status"] == 200
    assert "No Results" in body["msg"]


@pytest.mark.security
def test_search_empty_hash_is_invalid(client, admin_user):
    """An empty hash value and an empty body are both 'Invalid Search'."""
    _auth(client, admin_user.api_key)
    assert _body(client.post("/v1/search", json={"hash": ""}))["status"] == 500
    assert _body(client.post("/v1/search", json={}))["status"] == 500


@pytest.mark.security
def test_search_rejects_agent_cookie(client, authorized_agent):
    """/v1/search is user-only; an agent credential is refused."""
    _auth(client, authorized_agent.uuid)
    resp = client.post("/v1/search", json={"hash": "x"})
    assert 300 <= resp.status_code < 400
    assert "not_authorized" in resp.headers.get("Location", "")


# ---------------------------------------------------------------------------
# POST /v1/jobtask/status
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_jobtask_status_updates_status(client, authorized_agent, admin_user):
    """An agent can advance its jobtask's status; a Queued job flips to Running."""
    cust = _seed_customer()
    hf = _seed_hashfile(cust.id, admin_user.id)
    job = Jobs(name="j", status="Queued", hashfile_id=hf.id,
               customer_id=cust.id, owner_id=admin_user.id)
    _db.session.add(job)
    _db.session.commit()
    jt = JobTasks(job_id=job.id, task_id=1, status="Queued",
                  agent_id=authorized_agent.id)
    _db.session.add(jt)
    _db.session.commit()

    _auth(client, authorized_agent.uuid)
    resp = client.post("/v1/jobtask/status",
                       json={"job_task_id": jt.id, "task_status": "Running"})
    body = _body(resp)
    assert body["status"] == 200
    assert JobTasks.query.get(jt.id).status == "Running"
    assert Jobs.query.get(job.id).status == "Running"


@pytest.mark.security
def test_jobtask_status_unknown_id_returns_500(client, authorized_agent):
    """update_job_task_status returns False for a missing jobtask -> 500."""
    _auth(client, authorized_agent.uuid)
    resp = client.post("/v1/jobtask/status",
                       json={"job_task_id": 999999, "task_status": "Running"})
    assert _body(resp)["status"] == 500


@pytest.mark.security
def test_jobtask_status_rejects_user_cookie(client, admin_user):
    """/v1/jobtask/status is agent-only; a user credential is refused."""
    _auth(client, admin_user.api_key)
    resp = client.post("/v1/jobtask/status",
                       json={"job_task_id": 1, "task_status": "Running"})
    assert 300 <= resp.status_code < 400
    assert "not_authorized" in resp.headers.get("Location", "")


# ---------------------------------------------------------------------------
# POST /v1/uploadCrackFile/<job_task_id>
# ---------------------------------------------------------------------------


def _seed_job_for_crack(admin_user, limit_recovered=False, ciphertext="abcd1234ef",
                        hash_type=1000):
    """Seed customer -> hashfile -> (hash via junction) -> job -> jobtask."""
    cust = _seed_customer("CrackCo")
    hf = _seed_hashfile(cust.id, admin_user.id, name="crack-hf")
    h = _seed_hash(hash_type, False, ciphertext)
    _db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    _db.session.commit()
    job = Jobs(name="crackjob", status="Running", hashfile_id=hf.id,
               customer_id=cust.id, owner_id=admin_user.id,
               limit_recovered=limit_recovered)
    _db.session.add(job)
    _db.session.commit()
    jt = JobTasks(job_id=job.id, task_id=7, status="Running")
    _db.session.add(jt)
    _db.session.commit()
    return job, jt, h


@pytest.mark.security
def test_uploadcrackfile_marks_hash_cracked(
    client, authorized_agent, admin_user, monkeypatch
):
    """A hash:hexplain line recovers the matching hash and records provenance."""
    monkeypatch.setattr(
        "hashview.api.routes.process_recovered_hash_notifications",
        lambda *a, **kw: None,
    )
    job, jt, h = _seed_job_for_crack(admin_user, ciphertext="abcd1234ef")
    hex_plain = "password".encode().hex()  # hashcat hex_plain field

    _auth(client, authorized_agent.uuid)
    resp = client.post(f"/v1/uploadCrackFile/{jt.id}",
                       json={"file": f"abcd1234ef:{hex_plain}"})
    body = _body(resp)
    assert body["status"] == 200

    refreshed = Hashes.query.get(h.id)
    assert refreshed.cracked
    assert refreshed.plaintext == "password"
    assert refreshed.task_id == jt.task_id
    assert refreshed.recovered_by == job.owner_id


@pytest.mark.security
def test_uploadcrackfile_one_and_done_cancels_remaining_tasks(
    client, authorized_agent, admin_user, monkeypatch
):
    """A limit_recovered (one-and-done) job cancels all jobtasks after the first
    recovery."""
    monkeypatch.setattr(
        "hashview.api.routes.process_recovered_hash_notifications",
        lambda *a, **kw: None,
    )
    job, jt, h = _seed_job_for_crack(
        admin_user, limit_recovered=True, ciphertext="abcd1234ef")
    # A second, still-running task that must be canceled once a hash is recovered.
    other = JobTasks(job_id=job.id, task_id=8, status="Queued")
    _db.session.add(other)
    _db.session.commit()
    hex_plain = "letmein".encode().hex()

    _auth(client, authorized_agent.uuid)
    resp = client.post(f"/v1/uploadCrackFile/{jt.id}",
                       json={"file": f"abcd1234ef:{hex_plain}"})
    assert _body(resp)["status"] == 200

    statuses = {t.id: t.status for t in JobTasks.query.filter_by(job_id=job.id)}
    assert all(s == "Canceled" for s in statuses.values())


@pytest.mark.security
def test_uploadcrackfile_rejects_user_cookie(client, admin_user):
    """/v1/uploadCrackFile/<id> is agent-only; a user credential is refused."""
    _auth(client, admin_user.api_key)
    resp = client.post("/v1/uploadCrackFile/1", json={"file": ""})
    assert 300 <= resp.status_code < 400
    assert "not_authorized" in resp.headers.get("Location", "")


# ---------------------------------------------------------------------------
# POST /v1/jobs/start/<id>
# ---------------------------------------------------------------------------


def _seed_startable_job(owner, status="Queued"):
    cust = _seed_customer("StartCo")
    hf = _seed_hashfile(cust.id, owner.id, name="start-hf")
    job = Jobs(name="startable", status=status, hashfile_id=hf.id,
               customer_id=cust.id, owner_id=owner.id, priority=3)
    _db.session.add(job)
    _db.session.commit()
    jt = JobTasks(job_id=job.id, task_id=1, status="Ready")
    _db.session.add(jt)
    _db.session.commit()
    return job, jt


@pytest.mark.security
def test_jobs_start_success_queues_tasks(client, admin_user, monkeypatch):
    """A Queued job owned by the caller is started: tasks queued + command built."""
    monkeypatch.setattr(
        "hashview.api.routes.build_hashcat_command",
        lambda job_id, task_id: f"hashcat -j{job_id} -t{task_id}",
    )
    job, jt = _seed_startable_job(admin_user, status="Queued")

    _auth(client, admin_user.api_key)
    resp = client.post(f"/v1/jobs/start/{job.id}")
    body = _body(resp)
    assert body["status"] == 200
    assert body["msg"] == "Job started"

    refreshed = JobTasks.query.get(jt.id)
    assert refreshed.status == "Queued"
    assert refreshed.priority == job.priority
    assert refreshed.command == f"hashcat -j{job.id} -t{jt.task_id}"
    assert Jobs.query.get(job.id).queued_at is not None


@pytest.mark.security
def test_jobs_start_invalid_id_returns_400(client, admin_user):
    """Starting a nonexistent job (no job / no tasks) returns 400 Invalid job ID."""
    _auth(client, admin_user.api_key)
    resp = client.post("/v1/jobs/start/424242")
    body = _body(resp)
    assert body["status"] == 400
    assert "Invalid job ID" in body["msg"]


@pytest.mark.security
def test_jobs_start_non_owner_returns_403(client, admin_user, regular_user):
    """A non-admin who does not own the Queued job cannot start it."""
    job, _ = _seed_startable_job(admin_user, status="Queued")

    _auth(client, regular_user.api_key)
    resp = client.post(f"/v1/jobs/start/{job.id}")
    body = _body(resp)
    assert body["status"] == 403
    # The job stays Queued (not promoted) when the caller is unauthorized.
    assert Jobs.query.get(job.id).status == "Queued"


# ---------------------------------------------------------------------------
# POST /v1/jobs/add — "not enough data" branch
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_jobs_add_without_effective_tasks_returns_500(client, admin_user):
    """jobs/add needs historical cracked hashes of the same type to pick tasks;
    with none it returns a 500 'Not enough data' instead of an empty job."""
    cust = _seed_customer("NoDataCo")
    hf = _seed_hashfile(cust.id, admin_user.id, name="nodata-hf")
    h = _seed_hash(1000, False, "00ff00ff00ff")
    _db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    _db.session.commit()

    _auth(client, admin_user.api_key)
    resp = client.post("/v1/jobs/add", json={
        "name": "nodata-job",
        "hashfile_id": hf.id,
        "customer_id": cust.id,
    })
    body = _body(resp)
    assert body["status"] == 500
    assert "Not enough data" in body["msg"]
    # No orphan job rows are left behind for this hashfile.
    assert Jobs.query.filter_by(name="nodata-job").first() is None or \
        JobTasks.query.count() == 0


# ---------------------------------------------------------------------------
# GET /v1/wordlists  and  GET /v1/wordlists/<id>
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_wordlists_list_returns_seeded(client, admin_user):
    """GET /v1/wordlists serializes the wordlist collection."""
    wl = Wordlists(name="rockyou", owner_id=admin_user.id, type="static",
                   path="/x/rockyou.gz", size=10, checksum="0" * 64)
    _db.session.add(wl)
    _db.session.commit()

    _auth(client, admin_user.api_key)
    resp = client.get("/v1/wordlists")
    body = _body(resp)
    assert body["status"] == 200
    assert "rockyou" in body["wordlists"]


@pytest.mark.security
def test_wordlist_download_static_serves_gz_as_is(
    client, app, admin_user, tmp_path, monkeypatch
):
    """A static wordlist is stored compressed and served byte-for-byte."""
    monkeypatch.setattr(app, "root_path", str(tmp_path))
    wl_dir = os.path.join(str(tmp_path), "control", "wordlists")
    os.makedirs(wl_dir, exist_ok=True)
    os.makedirs(os.path.join(str(tmp_path), "control", "tmp"), exist_ok=True)

    raw = b"alpha\nbeta\n"
    gz_path = os.path.join(wl_dir, "static.gz")
    with gzip.open(gz_path, "wb") as fh:
        fh.write(raw)
    wl = Wordlists(name="static-wl", owner_id=admin_user.id, type="static",
                   path=gz_path, size=2, checksum="0" * 64)
    _db.session.add(wl)
    _db.session.commit()

    _auth(client, admin_user.api_key)
    resp = client.get(f"/v1/wordlists/{wl.id}")
    assert resp.status_code == 200
    # Served bytes are the stored .gz; decompressing yields the original.
    assert gzip.decompress(resp.data) == raw


@pytest.mark.security
def test_wordlist_download_dynamic_compresses_on_the_fly(
    client, app, admin_user, tmp_path, monkeypatch
):
    """A dynamic wordlist is stored as plaintext .txt and gzip-compressed when
    served."""
    monkeypatch.setattr(app, "root_path", str(tmp_path))
    wl_dir = os.path.join(str(tmp_path), "control", "wordlists")
    os.makedirs(wl_dir, exist_ok=True)
    os.makedirs(os.path.join(str(tmp_path), "control", "tmp"), exist_ok=True)

    raw = b"dynword1\ndynword2\n"
    txt_path = os.path.join(wl_dir, "dynamic.txt")
    with open(txt_path, "wb") as fh:
        fh.write(raw)
    wl = Wordlists(name="dyn-wl", owner_id=admin_user.id, type="dynamic",
                   path=txt_path, size=2, checksum="0" * 64)
    _db.session.add(wl)
    _db.session.commit()

    _auth(client, admin_user.api_key)
    resp = client.get(f"/v1/wordlists/{wl.id}")
    assert resp.status_code == 200
    assert gzip.decompress(resp.data) == raw


@pytest.mark.security
def test_wordlist_download_missing_returns_404(client, admin_user):
    """GET /v1/wordlists/<id> for an unknown id returns a 404 JSON error."""
    _auth(client, admin_user.api_key)
    resp = client.get("/v1/wordlists/424242")
    assert resp.status_code == 404
    assert _body(resp)["status"] == 404


# ---------------------------------------------------------------------------
# POST /v1/agents/heartbeat — Working / Canceled / Pending branches
# ---------------------------------------------------------------------------


def _cur_version():
    return hashview.__version__


@pytest.mark.security
def test_heartbeat_working_parses_benchmark(client, app, admin_user):
    """A Working agent with hc_status has its benchmark (Speed #) recorded."""
    _db.session.add(Settings(retention_period=30, max_runtime_tasks=0,
                             max_runtime_jobs=0))
    agent = Agents(name="w", src_ip="127.0.0.1", uuid="agent-working",
                   status="Authorized")
    _db.session.add(agent)
    _db.session.commit()

    cust = _seed_customer("HbCo")
    hf = _seed_hashfile(cust.id, admin_user.id, name="hb-hf")
    job = Jobs(name="hbjob", status="Running", hashfile_id=hf.id,
               customer_id=cust.id, owner_id=admin_user.id)
    _db.session.add(job)
    _db.session.commit()
    jt = JobTasks(job_id=job.id, task_id=1, status="Running", agent_id=agent.id)
    _db.session.add(jt)
    _db.session.commit()

    client.set_cookie("uuid", agent.uuid, domain=DOMAIN)
    client.set_cookie("agent_version", _cur_version(), domain=DOMAIN)
    resp = client.post("/v1/agents/heartbeat", json={
        "agent_status": "Working",
        "hc_status": "{'Speed #': '4321 H/s'}",
    })
    assert resp.status_code == 200
    refreshed = Agents.query.get(agent.id)
    assert refreshed.status == "Working"
    assert refreshed.benchmark == "4321 H/s"


@pytest.mark.security
def test_heartbeat_working_with_canceled_task_tells_agent_canceled(
    client, app, admin_user
):
    """A Working agent whose assigned task was canceled is told to stop."""
    _db.session.add(Settings(retention_period=30, max_runtime_tasks=0,
                             max_runtime_jobs=0))
    agent = Agents(name="c", src_ip="127.0.0.1", uuid="agent-canceled",
                   status="Authorized")
    _db.session.add(agent)
    _db.session.commit()
    cust = _seed_customer("CancCo")
    hf = _seed_hashfile(cust.id, admin_user.id, name="canc-hf")
    job = Jobs(name="cjob", status="Running", hashfile_id=hf.id,
               customer_id=cust.id, owner_id=admin_user.id)
    _db.session.add(job)
    _db.session.commit()
    jt = JobTasks(job_id=job.id, task_id=1, status="Canceled", agent_id=agent.id)
    _db.session.add(jt)
    _db.session.commit()

    client.set_cookie("uuid", agent.uuid, domain=DOMAIN)
    client.set_cookie("agent_version", _cur_version(), domain=DOMAIN)
    resp = client.post("/v1/agents/heartbeat", json={
        "agent_status": "Working", "hc_status": "",
    })
    body = _body(resp)
    assert body["msg"] == "Canceled"


@pytest.mark.security
def test_heartbeat_pending_agent_is_turned_away(client, app):
    """A registered-but-Pending agent is told 'Go Away' (not given work)."""
    _db.session.add(Settings(retention_period=30, max_runtime_tasks=0,
                             max_runtime_jobs=0))
    agent = Agents(name="p", src_ip="127.0.0.1", uuid="agent-pending",
                   status="Pending")
    _db.session.add(agent)
    _db.session.commit()

    client.set_cookie("uuid", agent.uuid, domain=DOMAIN)
    client.set_cookie("agent_version", _cur_version(), domain=DOMAIN)
    resp = client.post("/v1/agents/heartbeat", json={
        "agent_status": "Idle", "hc_status": "",
    })
    assert _body(resp)["msg"] == "Go Away"


# ---------------------------------------------------------------------------
# POST /v1/hashfiles/upload/... — invalid file-format branch
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_hashfile_upload_invalid_file_format_returns_400(client, admin_user):
    """A file_format outside 0..5 is rejected with a descriptive 400."""
    cust = _seed_customer("FmtCo")
    _auth(client, admin_user.api_key)
    resp = client.post(
        f"/v1/hashfiles/upload/{cust.id}/9/0/myfile",
        data="some:hash:data",
        content_type="text/plain",
    )
    body = _body(resp)
    assert body["status"] == 400
    assert "Invalid file format" in body["msg"]


# ---------------------------------------------------------------------------
# Identified latent issues (xfail strict -> flips to XPASS when fixed)
#
# These assert the *desired* behavior of two rough edges surfaced by the API
# review. They XFAIL against today's code and turn into a hard failure (strict
# XPASS) the moment the underlying bug is fixed -- the signal to drop the marker
# and fold the test into the normal suite. Same convention as
# tests/unit/test_api_hashfiles_xfail.py.
# ---------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.xfail(strict=True, reason="search with no 'hash' key raises KeyError "
                                       "instead of the JSON 'Invalid Search' envelope")
def test_search_missing_hash_key_returns_invalid_envelope(client, admin_user):
    """A POST body that is present but omits the 'hash' key should be answered
    with the same graceful ``{status: 500, msg: 'Invalid Search'}`` envelope as
    an empty hash -- not an unhandled ``KeyError`` (HTML 500). The route does
    ``if search_json['hash']`` with no guard for the absent key.
    """
    _auth(client, admin_user.api_key)
    resp = client.post("/v1/search", json={"not_hash": "oops"})
    body = _body(resp)
    assert body["status"] == 500
    assert body["msg"] == "Invalid Search"


@pytest.mark.security
@pytest.mark.xfail(strict=True, reason="update_job_task_status nulls agent_id before "
                                       "looking the agent up, so hc_status is never cleared")
def test_canceling_task_clears_assigned_agents_hc_status(app, admin_user):
    """Canceling (or completing) a task that an agent is running should clear
    that agent's ``hc_status``. Today the helper sets ``jobtask.agent_id = None``
    *before* ``Agents.query.get(jobtask.agent_id)``, so the lookup is always
    ``get(None)`` -> ``None`` (and emits a SAWarning), leaving the stale running
    status on the agent forever.
    """
    from hashview.utils.utils import update_job_task_status

    cust = _seed_customer("HcCo")
    hf = _seed_hashfile(cust.id, admin_user.id, name="hc-hf")
    job = Jobs(name="hcjob", status="Running", hashfile_id=hf.id,
               customer_id=cust.id, owner_id=admin_user.id)
    _db.session.add(job)
    _db.session.commit()
    agent = Agents(name="busy", src_ip="127.0.0.1", uuid="agent-busy",
                   status="Working", hc_status="RUNNING-STATUS")
    _db.session.add(agent)
    _db.session.commit()
    canceled = JobTasks(job_id=job.id, task_id=1, status="Running",
                        agent_id=agent.id)
    # A second still-running task keeps the job out of the completion/notify path
    # so this test isolates the hc_status clearing behavior.
    still_running = JobTasks(job_id=job.id, task_id=2, status="Running")
    _db.session.add_all([canceled, still_running])
    _db.session.commit()

    update_job_task_status(canceled.id, "Canceled")

    assert Agents.query.get(agent.id).hc_status == ""
