"""Regression tests for issue #370 (expanded scope) — unaudited /v1 API surface.

FINDING (MEDIUM): beyond the un-audited auth gate (covered by
``test_api_auth_audit_xfail.py`` / PR #371), a route-by-route sweep of
``hashview/api/routes.py`` shows audit coverage is narrower than "CRUD is
logged". Only 8 events are ever written (customer/rule/wordlist/job/task/
hashfile create+delete). Still invisible in audit.log:

  - State-changing endpoints that skip ``log_event`` entirely:
    ``/v1/jobs/start/<id>``, ``/v1/hashes/import/<type>``,
    ``/v1/uploadCrackFile/<job_task_id>``, ``/v1/jobtask/status``.
  - Reads that move sensitive data: ``/v1/search`` (returns recovered
    plaintexts) and wordlist downloads (``/v1/wordlists/<id>``).

These are STRICT XFAILs (same pattern as tests/security/test_csrf_xfail.py
for #298 and test_api_auth_audit_xfail.py for #370): each test asserts the
audit event IS written. Because it is not, the assertion fails and the strict
xfail flags the real, open finding. When the events are implemented, the
tests flip to visible FAILURES and the ``@pytest.mark.xfail`` markers should
be removed. Tracks GitHub issue #370 (expanded-scope section).

Expected event names (adjust the tests if the implementation picks others):
  - ``job.start``            POST /v1/jobs/start/<id>
  - ``hashes.import``        POST /v1/hashes/import/<hash_type>
  - ``jobtask.crackfile``    POST /v1/uploadCrackFile/<job_task_id>
  - ``jobtask.status``       POST /v1/jobtask/status
  - ``search.query``         POST /v1/search
  - ``wordlist.download``    GET  /v1/wordlists/<id>
"""

import gzip
import hashlib
import json
import os

import pytest

from hashview import create_app
from hashview.models import (
    Agents,
    Customers,
    Hashes,
    HashfileHashes,
    Hashfiles,
    Jobs,
    JobTasks,
    Users,
    Wordlists,
)
from hashview.models import db as _db
from hashview.utils.audit import AUDIT_FILE, configure_audit_logging, logs_dir
from hashview.utils.utils import get_md5_hash

DOMAIN = "localhost.test"

_BASE_OVERRIDES = {
    "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
    "SQLALCHEMY_TRACK_MODIFICATIONS": False,
    "MAIL_SUPPRESS_SEND": True,
    "SECRET_KEY": "security-test-secret",
    "SERVER_NAME": DOMAIN,
    "HASHVIEW_SKIP_SETUP": True,
    "HASHVIEW_SKIP_GUI_SETUP": True,
    "HASHVIEW_DISABLE_SCHEDULER": True,
    "WTF_CSRF_ENABLED": False,
}


@pytest.fixture()
def audit_app(tmp_path):
    """Dedicated in-memory app with the audit logger pointed into tmp_path."""
    overrides = dict(_BASE_OVERRIDES)
    overrides["HASHVIEW_LOGS_DIR"] = str(tmp_path / "logs")
    application = create_app(testing=True, config_overrides=overrides)
    with application.app_context():
        _db.create_all()
        configure_audit_logging(application)  # idempotent; re-point handlers
        yield application
        _db.session.remove()
        _db.drop_all()


@pytest.fixture()
def client(audit_app):
    return audit_app.test_client()


@pytest.fixture()
def api_user():
    user = Users(
        first_name="Api",
        last_name="Auditee",
        email_address="api-auditee@example.test",
        password="x" * 60,
        admin=True,
        api_key="scope-audit-key",
    )
    _db.session.add(user)
    _db.session.commit()
    return user


@pytest.fixture()
def authorized_agent():
    agent = Agents(
        name="audit-agent",
        src_ip="127.0.0.1",
        uuid="scope-audit-agent-uuid",
        status="Authorized",
    )
    _db.session.add(agent)
    _db.session.commit()
    return agent


def _auth(client, value):
    client.set_cookie("uuid", value, domain=DOMAIN)


def _audit_entries(app):
    path = os.path.join(logs_dir(app), AUDIT_FILE)
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _events(app, name):
    return [e for e in _audit_entries(app) if e["event"] == name]


def _seed_job(owner, status="Ready", jobtask_status="Ready", agent_id=None):
    """Customer -> hashfile -> job -> one jobtask; returns (job, jobtask)."""
    cust = Customers(name="AuditCo")
    _db.session.add(cust)
    _db.session.commit()
    hf = Hashfiles(name="audit-hf", customer_id=cust.id, owner_id=owner.id)
    _db.session.add(hf)
    _db.session.commit()
    job = Jobs(name="audit-job", status=status, hashfile_id=hf.id,
               customer_id=cust.id, owner_id=owner.id, priority=3)
    _db.session.add(job)
    _db.session.commit()
    jt = JobTasks(job_id=job.id, task_id=1, status=jobtask_status,
                  agent_id=agent_id)
    _db.session.add(jt)
    _db.session.commit()
    return job, jt


# ---------------------------------------------------------------------------
# State-changing endpoints that never call log_event
# ---------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.xfail(
    strict=True,
    reason=(
        "FINDING #370 (MEDIUM): POST /v1/jobs/start/<id> queues a job and "
        "rebuilds its task commands without writing any audit event, while "
        "job.create/job.delete are both audited. Flips to a failure once "
        "job.start is emitted."
    ),
)
def test_job_start_writes_audit_event(client, audit_app, api_user, monkeypatch):
    """Starting a job over the API must leave a job.start audit trace."""
    # jobs_start calls build_job_task_commands(job); stub it (same contract as
    # tests/unit/test_api_routes_regression.py) so the test doesn't need the
    # full task/wordlist graph the real command builder walks.
    def _fake_build_job_task_commands(job):
        for row in JobTasks.query.filter_by(job_id=job.id).all():
            row.status = "Queued"
            row.priority = job.priority
            row.command = "stub"

    monkeypatch.setattr(
        "hashview.api.routes.build_job_task_commands",
        _fake_build_job_task_commands,
    )
    job, _ = _seed_job(api_user, status="Ready")

    _auth(client, api_user.api_key)
    resp = client.post(f"/v1/jobs/start/{job.id}")
    body = json.loads(resp.get_data(as_text=True))
    assert body["status"] == 200  # the start itself works; only audit is missing

    events = _events(audit_app, "job.start")
    assert events and events[-1]["actor"] == api_user.email_address, (
        "No 'job.start' audit event was written for POST /v1/jobs/start — "
        "starting a cracking job via the API is invisible in the Logs menu"
    )


@pytest.mark.security
@pytest.mark.xfail(
    strict=True,
    reason=(
        "FINDING #370 (MEDIUM): POST /v1/hashes/import/<type> bulk-marks "
        "hashes as cracked (writes plaintexts) without any audit event. "
        "Flips to a failure once hashes.import is emitted."
    ),
)
def test_hashes_import_writes_audit_event(
    client, audit_app, api_user, tmp_path, monkeypatch
):
    """A founds import over the API must leave a hashes.import audit trace."""
    monkeypatch.setattr(
        "hashview.api.routes.process_recovered_hash_notifications",
        lambda *a, **kw: None,
    )
    # The route writes its temp file under <root_path>/control/tmp; point
    # root_path at tmp_path so the test never touches the real checkout.
    monkeypatch.setattr(audit_app, "root_path", str(tmp_path))
    os.makedirs(os.path.join(str(tmp_path), "control", "tmp"), exist_ok=True)

    plaintext = "synthetic-audit-pw"
    ciphertext = hashlib.md5(plaintext.encode()).hexdigest()  # nosec B324 - MD5 as test fixture data, not for security
    _db.session.add(Hashes(
        hash_type=0,
        sub_ciphertext=get_md5_hash(ciphertext.lower()),
        ciphertext=ciphertext,
        cracked=False,
    ))
    _db.session.commit()

    _auth(client, api_user.api_key)
    resp = client.post(
        "/v1/hashes/import/0",
        data=f"{ciphertext}:{plaintext}",
        content_type="text/plain",
    )
    body = json.loads(resp.get_data(as_text=True))
    assert body["status"] == 200  # the import itself works; only audit is missing

    events = _events(audit_app, "hashes.import")
    assert events and events[-1]["actor"] == api_user.email_address, (
        "No 'hashes.import' audit event was written for POST /v1/hashes/import "
        "— bulk plaintext imports are invisible in the Logs menu"
    )


@pytest.mark.security
@pytest.mark.xfail(
    strict=True,
    reason=(
        "FINDING #370 (MEDIUM): POST /v1/uploadCrackFile/<job_task_id> "
        "(agent crack ingestion, which can also cancel a one-and-done job's "
        "remaining tasks) writes no audit event. Flips to a failure once "
        "jobtask.crackfile is emitted."
    ),
)
def test_uploadcrackfile_writes_audit_event(
    client, audit_app, api_user, authorized_agent, monkeypatch
):
    """Agent crack-file ingestion must leave a jobtask.crackfile audit trace."""
    monkeypatch.setattr(
        "hashview.api.routes.process_recovered_hash_notifications",
        lambda *a, **kw: None,
    )
    job, jt = _seed_job(api_user, status="Running", jobtask_status="Running",
                        agent_id=authorized_agent.id)
    ciphertext = "abcd1234ef"
    h = Hashes(hash_type=1000, sub_ciphertext=get_md5_hash(ciphertext),
               ciphertext=ciphertext, cracked=False)
    _db.session.add(h)
    _db.session.commit()
    _db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=job.hashfile_id))
    _db.session.commit()

    _auth(client, authorized_agent.uuid)
    hex_plain = b"synthpass".hex()
    resp = client.post(f"/v1/uploadCrackFile/{jt.id}",
                       json={"file": f"{ciphertext}:{hex_plain}"})
    body = json.loads(resp.get_data(as_text=True))
    assert body["status"] == 200  # ingestion works; only audit is missing

    events = _events(audit_app, "jobtask.crackfile")
    assert events, (
        "No 'jobtask.crackfile' audit event was written for POST "
        "/v1/uploadCrackFile — agent crack ingestion is invisible in the "
        "Logs menu"
    )


@pytest.mark.security
@pytest.mark.xfail(
    strict=True,
    reason=(
        "FINDING #370 (MEDIUM): POST /v1/jobtask/status transitions task and "
        "job state (Queued->Running->Completed) without any audit event. "
        "Flips to a failure once jobtask.status is emitted."
    ),
)
def test_jobtask_status_change_writes_audit_event(
    client, audit_app, api_user, authorized_agent
):
    """An agent-driven jobtask state transition must be audited."""
    job, jt = _seed_job(api_user, status="Queued", jobtask_status="Queued",
                        agent_id=authorized_agent.id)

    _auth(client, authorized_agent.uuid)
    resp = client.post("/v1/jobtask/status",
                       json={"job_task_id": jt.id, "task_status": "Running"})
    body = json.loads(resp.get_data(as_text=True))
    assert body["status"] == 200
    assert JobTasks.query.get(jt.id).status == "Running"  # transition works

    events = _events(audit_app, "jobtask.status")
    assert events, (
        "No 'jobtask.status' audit event was written for POST "
        "/v1/jobtask/status — task/job state transitions are invisible in "
        "the Logs menu"
    )


# ---------------------------------------------------------------------------
# Reads that move sensitive data
# ---------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.xfail(
    strict=True,
    reason=(
        "FINDING #370 (MEDIUM): POST /v1/search returns recovered plaintexts "
        "with no audit event — the exact exfiltration path a stolen API key "
        "would use. Flips to a failure once search.query is emitted."
    ),
)
def test_search_writes_audit_event(client, audit_app, api_user):
    """A /v1/search that returns a plaintext must leave an audit trace."""
    _db.session.add(Hashes(
        hash_type=1000, sub_ciphertext=get_md5_hash("deadbeefdeadbeef"),
        ciphertext="deadbeefdeadbeef", cracked=True, plaintext="synth-hunter2",
    ))
    _db.session.commit()

    _auth(client, api_user.api_key)
    resp = client.post("/v1/search", json={"hash": "deadbeefdeadbeef"})
    body = json.loads(resp.get_data(as_text=True))
    assert body["msg"]["plaintext"] == "synth-hunter2"  # plaintext disclosed

    events = _events(audit_app, "search.query")
    assert events and events[-1]["actor"] == api_user.email_address, (
        "No 'search.query' audit event was written for POST /v1/search — "
        "plaintext disclosure via search is invisible in the Logs menu"
    )


@pytest.mark.security
@pytest.mark.xfail(
    strict=True,
    reason=(
        "FINDING #370 (MEDIUM): GET /v1/wordlists/<id> serves a full wordlist "
        "download with no audit event. Flips to a failure once "
        "wordlist.download is emitted."
    ),
)
def test_wordlist_download_writes_audit_event(
    client, audit_app, api_user, tmp_path, monkeypatch
):
    """Downloading a wordlist over the API must leave an audit trace."""
    monkeypatch.setattr(audit_app, "root_path", str(tmp_path))
    wl_dir = os.path.join(str(tmp_path), "control", "wordlists")
    os.makedirs(wl_dir, exist_ok=True)
    os.makedirs(os.path.join(str(tmp_path), "control", "tmp"), exist_ok=True)

    gz_path = os.path.join(wl_dir, "audit-static.gz")
    with gzip.open(gz_path, "wb") as fh:
        fh.write(b"alpha\nbeta\n")
    wl = Wordlists(name="audit-static-wl", owner_id=api_user.id, type="static",
                   path=gz_path, size=2, checksum="0" * 64)
    _db.session.add(wl)
    _db.session.commit()

    _auth(client, api_user.api_key)
    resp = client.get(f"/v1/wordlists/{wl.id}")
    assert resp.status_code == 200  # the download itself works

    events = _events(audit_app, "wordlist.download")
    assert events and events[-1]["actor"] == api_user.email_address, (
        "No 'wordlist.download' audit event was written for GET "
        "/v1/wordlists/<id> — wordlist exfiltration is invisible in the "
        "Logs menu"
    )
