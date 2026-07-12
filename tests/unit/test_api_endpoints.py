"""Unit tests for hashview.api.routes.

Each test exercises a route from the ``api`` Blueprint using the in-memory
SQLite app + Flask test_client fixtures provided by ``tests/unit/conftest.py``.
All tests are marked ``@pytest.mark.security`` so the parent autouse fixtures
that require Playwright + a live HTTP server are skipped.

Auth model recap (see ``is_authorized``):
- The 'uuid' cookie value is matched against either ``Users.api_key`` (when
  the route allows users) or ``Agents.uuid`` (when the route allows agents,
  with status in Online/Working/Idle/Authorized).
- Unauthorized requests are answered with a redirect to ``/v1/not_authorized``
  (or, for two buggy routes, the typo'd ``/vi/not_authorized``).
"""

import json
import os
from unittest import mock

import pytest

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

# ---------------------------------------------------------------------------
# Local fixtures
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


def _json_body(resp):
    """Return parsed JSON body from a Flask test response."""
    return json.loads(resp.get_data(as_text=True))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_admin_settings_authorized_returns_200_with_settings(client, admin_user):
    """GET /v1/admin/settings with a valid user api_key cookie returns 200."""
    settings_row = Settings(
        retention_period=30,
        max_runtime_tasks=0,
        max_runtime_jobs=0,
    )
    _db.session.add(settings_row)
    _db.session.commit()

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.get("/v1/admin/settings")

    assert resp.status_code == 200
    body = _json_body(resp)
    assert body["status"] == 200
    assert "settings" in body


@pytest.mark.security
def test_admin_settings_no_cookie_redirects_to_not_authorized(client):
    """GET /v1/admin/settings without a cookie redirects to /v1/not_authorized."""
    resp = client.get("/v1/admin/settings")
    assert 300 <= resp.status_code < 400
    location = resp.headers.get("Location", "")
    assert "/v1/not_authorized" in location


@pytest.mark.security
def test_customers_list_authorized_returns_seeded_customer(client, admin_user):
    """GET /v1/customers returns the seeded Customer in the JSON-string body."""
    cust = Customers(name="Acme")
    _db.session.add(cust)
    _db.session.commit()

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.get("/v1/customers")

    assert resp.status_code == 200
    body = _json_body(resp)
    # Route returns the customer collection serialized as a JSON string under
    # the (oddly named) "users" key.
    assert "Acme" in body["users"]


@pytest.mark.security
def test_customers_add_with_body_returns_status_and_id_key(client, admin_user):
    """POST /v1/customers/add with a name-only JSON body creates a Customer."""
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/customers/add",
        data=json.dumps({"name": "Globex"}),
        content_type="application/json",
    )
    body = _json_body(resp)
    assert body["status"] == 200
    assert body["msg"] == "Customer added"
    assert isinstance(body["customer_id"], int)
    assert Customers.query.filter_by(name="Globex").first() is not None


@pytest.mark.security
def test_customers_add_missing_body_returns_400(client, admin_user):
    """POST /v1/customers/add with no JSON body returns status 400."""
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/customers/add",
        data="",
        content_type="application/json",
    )
    body = _json_body(resp)
    assert body["status"] == 400
    assert "Missing" in body["msg"]


@pytest.mark.security
def test_wordlists_add_writes_file_and_creates_row(
    client, app, admin_user, tmp_path, monkeypatch
):
    """POST /v1/wordlists/add/<name> stores the wordlist gzip-compressed at rest
    and creates a row whose checksum is the sha256 of the compressed file."""
    import gzip
    # Point the route at a tmp directory and create the dirs the ingest uses.
    monkeypatch.setattr(app, "root_path", str(tmp_path))
    os.makedirs(os.path.join(str(tmp_path), "control", "wordlists"), exist_ok=True)
    os.makedirs(os.path.join(str(tmp_path), "control", "tmp"), exist_ok=True)

    body_text = "alpha\nbeta\n"
    # The cookie domain must match the test SERVER_NAME (localhost.test) for
    # Werkzeug 3.x to send it.
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/wordlists/add/my-list",
        data=body_text,
        content_type="text/plain",
    )

    body = _json_body(resp)
    assert body["status"] == 200
    assert body["msg"] == "Wordlist added"

    row = Wordlists.query.filter_by(name="my-list").first()
    assert row is not None
    assert row.type == "static"
    assert row.owner_id == admin_user.id
    # Wordlists are stored gzip-compressed at rest; the stored .gz decompresses
    # back to the original body.
    assert row.path.endswith(".gz")
    with gzip.open(row.path, "rb") as fh:
        assert fh.read() == body_text.encode()


@pytest.mark.security
def test_jobs_start_rejects_agent_cookie(client, authorized_agent):
    """POST /v1/jobs/start/<id> with an agent cookie redirects to not_authorized.

    The route uses ``is_authorized(user=True, agent=False, ...)`` so even a
    valid agent uuid must be refused.
    """
    # Cookie is genuinely sent (domain matches SERVER_NAME) so this exercises
    # the privilege boundary itself: a real, authorized agent credential must
    # still be rejected on a user-only route.
    client.set_cookie("uuid", authorized_agent.uuid, domain="localhost.test")
    resp = client.post("/v1/jobs/start/1")
    assert 300 <= resp.status_code < 400
    location = resp.headers.get("Location", "")
    assert "not_authorized" in location


@pytest.mark.security
def test_no_uuid_cookie_does_not_match_null_api_key(client):
    """A request with no 'uuid' cookie must be refused even when a key-less user exists.

    api_key is nullable and is NOT set at user creation (only via
    /profile/generate_api_key), so a user can legitimately have api_key=NULL.
    is_authorized() must reject an absent/empty uuid outright — otherwise
    userAuthorized(None) would run ``filter_by(api_key=None)`` -> ``WHERE
    api_key IS NULL`` and authenticate as that key-less user. Sending an
    unrelated cookie (no 'uuid') ensures ``request.cookies`` is truthy, so this
    exercises the value guard rather than the empty-cookies short-circuit.
    """
    keyless = Users(
        first_name="Key",
        last_name="Less",
        email_address="keyless@example.test",
        password="hashed-pw",
        admin=True,
        api_key=None,
    )
    _db.session.add(keyless)
    _db.session.commit()
    assert keyless.api_key is None

    # No uuid cookie at all, but a non-empty cookie jar.
    client.set_cookie("decoy", "irrelevant", domain="localhost.test")
    resp = client.post("/v1/jobs/start/1")
    assert 300 <= resp.status_code < 400
    assert "not_authorized" in resp.headers.get("Location", "")

    # An explicitly empty uuid is likewise refused.
    client.set_cookie("uuid", "", domain="localhost.test")
    resp = client.post("/v1/jobs/start/1")
    assert 300 <= resp.status_code < 400
    assert "not_authorized" in resp.headers.get("Location", "")


@pytest.mark.security
def test_jobs_start_returns_400_when_job_already_queued(client, admin_user):
    """POST /v1/jobs/start/<id> for a job already Running/Queued returns 400.

    Per issue #217 the guard rejects jobs that are already Running or Queued
    (and allows Ready jobs to start), so an already-Queued job is the case
    that must still 400.
    """
    cust = Customers(name="CustForJob")
    _db.session.add(cust)
    _db.session.commit()

    hashfile = Hashfiles(
        name="hf",
        customer_id=cust.id,
        owner_id=admin_user.id,
    )
    _db.session.add(hashfile)
    _db.session.commit()

    job = Jobs(
        name="my-job",
        status="Queued",
        hashfile_id=hashfile.id,
        customer_id=cust.id,
        owner_id=admin_user.id,
    )
    _db.session.add(job)
    _db.session.commit()

    # The route requires at least one JobTask for the status-guard branch
    # to be reachable. Seed one so we hit the status check rather than the
    # "Invalid job ID" fallback.
    from hashview.models import JobTasks
    job_task = JobTasks(
        job_id=job.id,
        task_id=1,
        status="Not Started",
    )
    _db.session.add(job_task)
    _db.session.commit()

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(f"/v1/jobs/start/{job.id}")
    body = _json_body(resp)
    assert body["status"] == 400
    assert "queued" in body["msg"].lower()


@pytest.mark.security
def test_hashes_import_unsupported_hash_type_returns_403(client, admin_user):
    """POST /v1/hashes/import/<n> for an unsupported hash type returns 403."""
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/hashes/import/500",
        data="x",
        content_type="text/plain",
    )
    body = _json_body(resp)
    assert body["status"] == 403
    assert "Unsupported" in body["msg"]


# NTLM('password') — used by the hashes/import tests below.
NTLM_PASSWORD_HASH = "8846F7EAEE8FB117AD06BDD830B7586C"


@pytest.mark.security
def test_ntlm_hash_hex_and_pure_md4_fallback():
    """ntlm_hash_hex produces the canonical NTLM hash, and the pure-Python
    MD4 fallback (used where OpenSSL 3.x drops md4) matches RFC 1320."""
    import binascii

    from hashview.utils.utils import _md4_pure, ntlm_hash_hex

    assert ntlm_hash_hex("password") == NTLM_PASSWORD_HASH
    # RFC 1320 test vectors exercise the fallback implementation directly.
    assert binascii.hexlify(_md4_pure(b"")).decode() == "31d6cfe0d16ae931b73c59d7e0c089c0"
    assert binascii.hexlify(_md4_pure(b"abc")).decode() == "a448017aaf21d8525fc10ae87aa6729d"
    assert (
        binascii.hexlify(_md4_pure(b"1234567890" * 8)).decode()
        == "e33b4ddc9c38f2199c3e7b164fcc0536"
    )


def _import_dirs(app, tmp_path, monkeypatch):
    """Point the app at a tmp root (the route writes into control/tmp)."""
    monkeypatch.setattr(app, "root_path", str(tmp_path))
    os.makedirs(os.path.join(str(tmp_path), "control", "tmp"), exist_ok=True)


@pytest.mark.security
def test_hashes_import_ntlm_marks_hash_cracked(
    client, app, admin_user, tmp_path, monkeypatch
):
    """POST /v1/hashes/import/1000 imports a valid NTLM hash:plaintext pair.

    Regression for the str/int comparison bug: the route declared
    ``<int:hash_type>`` but guarded on ``hash_type == '1000'`` (string), so
    the NTLM branch was unreachable and every request 403'd 'Unsupported
    Hashtype'. Now compares as int and the import path actually runs.
    """
    from hashview.utils.utils import get_md5_hash

    _import_dirs(app, tmp_path, monkeypatch)
    record = Hashes(
        sub_ciphertext=get_md5_hash(NTLM_PASSWORD_HASH),
        ciphertext=NTLM_PASSWORD_HASH,
        hash_type=1000,
        cracked=False,
    )
    _db.session.add(record)
    _db.session.commit()

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/hashes/import/1000",
        data=f"{NTLM_PASSWORD_HASH}:password",
        content_type="text/plain",
    )

    body = _json_body(resp)
    assert body["status"] == 200
    assert body["msg"] == "OK"
    assert record.cracked
    assert record.plaintext == "password"
    assert record.recovered_by == admin_user.id


@pytest.mark.security
def test_hashes_import_ntlm_lowercase_hash_marks_cracked(
    client, app, admin_user, tmp_path, monkeypatch
):
    """Regression: a lowercase hash (as hashcat emits) must verify and import.

    ntlm_hash_hex returns uppercase hex, so a case-sensitive compare rejected
    every real hashcat upload with 'Plaintext ... was found to be invalid.'
    Hashview stores/serves NTLM hashes in lowercase, so seed lowercase here.
    """
    from hashview.utils.utils import get_md5_hash

    _import_dirs(app, tmp_path, monkeypatch)
    lower_hash = NTLM_PASSWORD_HASH.lower()
    record = Hashes(
        sub_ciphertext=get_md5_hash(lower_hash),
        ciphertext=lower_hash,
        hash_type=1000,
        cracked=False,
    )
    _db.session.add(record)
    _db.session.commit()

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/hashes/import/1000",
        data=f"{lower_hash}:password",
        content_type="text/plain",
    )

    body = _json_body(resp)
    assert body["status"] == 200, body
    assert body["msg"] == "OK"
    assert record.cracked
    assert record.recovered_by == admin_user.id


@pytest.mark.security
def test_hashes_import_invalid_plaintext_returns_500(
    client, app, admin_user, tmp_path, monkeypatch
):
    """A hash:plaintext pair that fails the MD4 verification is rejected."""
    _import_dirs(app, tmp_path, monkeypatch)
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/hashes/import/1000",
        data=f"{NTLM_PASSWORD_HASH}:not-the-password",
        content_type="text/plain",
    )
    body = _json_body(resp)
    assert body["status"] == 500
    assert "invalid" in body["msg"].lower()


@pytest.mark.security
def test_error_route_rejects_user_cookie(client, admin_user):
    """POST /v1/error with a user cookie redirects to not_authorized.

    The route uses ``is_authorized(user=False, agent=True, ...)`` so a valid
    user api_key cookie is refused on this agent-only route.
    """
    # Cookie is genuinely sent (domain matches SERVER_NAME) so this exercises
    # the privilege boundary itself: a real user credential must be rejected on
    # an agent-only route.
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/error",
        data=json.dumps({"error": "oh no"}),
        content_type="application/json",
    )
    assert resp.status_code in {301, 302, 303, 307, 308}
    location = resp.headers.get("Location") or ""
    assert "not_authorized" in location


@pytest.mark.security
def test_error_route_accepts_agent_cookie_returns_ok(
    client, admin_user, authorized_agent, monkeypatch
):
    """POST /v1/error with a valid agent cookie returns status 200 / msg OK."""
    # notify_admins -> send_email / send_pushover; stub them out so we don't
    # try to actually send mail in the test.
    import hashview.utils.utils as utils_mod

    monkeypatch.setattr(utils_mod, "send_email", lambda *a, **kw: True)
    monkeypatch.setattr(utils_mod, "send_pushover", lambda *a, **kw: None)

    client.set_cookie("uuid", authorized_agent.uuid, domain="localhost.test")
    resp = client.post(
        "/v1/error",
        data=json.dumps({"error": "agent saw something"}),
        content_type="application/json",
    )
    body = _json_body(resp)
    assert body["status"] == 200
    assert body["msg"] == "OK"


@pytest.mark.security
def test_api_route_without_cookie_redirects_to_not_authorized(client):
    """GET /v1/rules without a cookie redirects to /v1/not_authorized."""
    resp = client.get("/v1/rules")
    assert 300 <= resp.status_code < 400
    location = resp.headers.get("Location", "")
    assert "not_authorized" in location


# ---------------------------------------------------------------------------
# DELETE /v1/jobs/<id>
# ---------------------------------------------------------------------------


@pytest.fixture()
def regular_user(app):
    user = Users(
        first_name="Regular",
        last_name="User",
        email_address="regular@example.test",
        password="hashed-pw",
        admin=False,
        api_key="user-api-key-regular",
    )
    _db.session.add(user)
    _db.session.commit()
    return user


def _seed_job(owner):
    """Seed a customer + job with one JobTask and one JobNotification."""
    cust = Customers(name="DeleteCo")
    _db.session.add(cust)
    _db.session.commit()
    job = Jobs(
        name="doomed-job",
        status="Ready",
        customer_id=cust.id,
        owner_id=owner.id,
    )
    _db.session.add(job)
    _db.session.commit()
    _db.session.add(JobTasks(job_id=job.id, task_id=1, status="Not Started"))
    _db.session.add(JobNotifications(owner_id=owner.id, job_id=job.id, method="email"))
    _db.session.commit()
    return job


@pytest.mark.security
def test_jobs_delete_removes_job_and_children(client, admin_user):
    """DELETE /v1/jobs/<id> removes the job plus its JobTasks/JobNotifications."""
    job = _seed_job(admin_user)
    job_id = job.id

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.delete(f"/v1/jobs/{job_id}")

    body = _json_body(resp)
    assert body["status"] == 200
    assert body["msg"] == "Job deleted"
    assert Jobs.query.get(job_id) is None
    assert JobTasks.query.filter_by(job_id=job_id).count() == 0
    assert JobNotifications.query.filter_by(job_id=job_id).count() == 0


@pytest.mark.security
def test_jobs_delete_missing_returns_404(client, admin_user):
    """DELETE /v1/jobs/<id> for a nonexistent job returns a 404 JSON error."""
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.delete("/v1/jobs/424242")
    assert resp.status_code == 404
    body = _json_body(resp)
    assert body["status"] == 404
    assert "not found" in body["msg"].lower()


@pytest.mark.security
def test_jobs_delete_rejects_agent_cookie(client, authorized_agent):
    """DELETE /v1/jobs/<id> is user-only: a valid agent uuid is refused."""
    client.set_cookie("uuid", authorized_agent.uuid, domain="localhost.test")
    resp = client.delete("/v1/jobs/1")
    assert 300 <= resp.status_code < 400
    assert "not_authorized" in resp.headers.get("Location", "")


@pytest.mark.security
def test_jobs_delete_non_owner_returns_403(client, admin_user, regular_user):
    """A non-admin user cannot delete somebody else's job."""
    job = _seed_job(admin_user)
    job_id = job.id

    client.set_cookie("uuid", regular_user.api_key, domain="localhost.test")
    resp = client.delete(f"/v1/jobs/{job_id}")

    body = _json_body(resp)
    assert body["status"] == 403
    assert Jobs.query.get(job_id) is not None
    assert JobTasks.query.filter_by(job_id=job_id).count() == 1


# ---------------------------------------------------------------------------
# GET /v1/hashfiles/hash_type/<hash_type>
# ---------------------------------------------------------------------------


def _seed_hash(hashfile_id, hash_type, cracked):
    """Seed one Hashes row linked to a hashfile via HashfileHashes."""
    h = Hashes(
        sub_ciphertext="0" * 32,
        ciphertext="deadbeef",
        hash_type=hash_type,
        cracked=cracked,
    )
    _db.session.add(h)
    _db.session.commit()
    _db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hashfile_id))
    _db.session.commit()
    return h


@pytest.mark.security
def test_hashfiles_by_hash_type_lists_matching_with_counts(client, admin_user):
    """Only hashfiles containing the requested type are listed, with counts
    scoped to that type (files can hold mixed hash types)."""
    cust = Customers(name="TypeCo")
    _db.session.add(cust)
    _db.session.commit()

    hf_ntlm = Hashfiles(name="ntlm-only", customer_id=cust.id, owner_id=admin_user.id)
    hf_sha = Hashfiles(name="sha-only", customer_id=cust.id, owner_id=admin_user.id)
    hf_mixed = Hashfiles(name="mixed", customer_id=cust.id, owner_id=admin_user.id)
    _db.session.add_all([hf_ntlm, hf_sha, hf_mixed])
    _db.session.commit()

    # ntlm-only: 3 hashes of type 1000, one cracked
    _seed_hash(hf_ntlm.id, 1000, False)
    _seed_hash(hf_ntlm.id, 1000, True)
    _seed_hash(hf_ntlm.id, 1000, False)
    # sha-only: type 1800 only -> must NOT appear for 1000
    _seed_hash(hf_sha.id, 1800, False)
    # mixed: one type-1000 hash and one type-1800 hash -> counts scoped to 1000
    _seed_hash(hf_mixed.id, 1000, False)
    _seed_hash(hf_mixed.id, 1800, True)

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.get("/v1/hashfiles/hash_type/1000")

    body = _json_body(resp)
    assert body["status"] == 200
    by_name = {entry["name"]: entry for entry in body["hashfiles"]}
    assert set(by_name) == {"ntlm-only", "mixed"}
    assert by_name["ntlm-only"]["total_hashes"] == 3
    assert by_name["ntlm-only"]["cracked_hashes"] == 1
    assert by_name["mixed"]["total_hashes"] == 1
    assert by_name["mixed"]["cracked_hashes"] == 0
    assert by_name["mixed"]["hash_type"] == 1000


@pytest.mark.security
def test_hashfiles_by_hash_type_unused_type_returns_empty_list(client, admin_user):
    """A hash type with no hashfiles is a valid empty result, not an error."""
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.get("/v1/hashfiles/hash_type/99999")
    body = _json_body(resp)
    assert body["status"] == 200
    assert body["hashfiles"] == []


@pytest.mark.security
def test_hashfiles_by_hash_type_rejects_agent_cookie(client, authorized_agent):
    """GET /v1/hashfiles/hash_type/<n> is user-only."""
    client.set_cookie("uuid", authorized_agent.uuid, domain="localhost.test")
    resp = client.get("/v1/hashfiles/hash_type/1000")
    assert 300 <= resp.status_code < 400
    assert "not_authorized" in resp.headers.get("Location", "")


# ---------------------------------------------------------------------------
# POST /v1/rules/add/<name> and GET /v1/rules/<id> (download)
# ---------------------------------------------------------------------------


def _rules_dirs(app, tmp_path, monkeypatch):
    """Point the app at a tmp root and create the dirs the rules routes use."""
    monkeypatch.setattr(app, "root_path", str(tmp_path))
    os.makedirs(os.path.join(str(tmp_path), "control", "rules"), exist_ok=True)
    os.makedirs(os.path.join(str(tmp_path), "control", "tmp"), exist_ok=True)


@pytest.mark.security
def test_rules_add_plaintext_writes_file_and_creates_row(
    client, app, admin_user, tmp_path, monkeypatch
):
    """POST /v1/rules/add/<name> stores the rule PLAINTEXT at rest (unlike
    wordlists) with size/checksum computed over the plaintext file."""
    import hashlib

    _rules_dirs(app, tmp_path, monkeypatch)
    body_text = "$1\n$2"  # 2 lines (get_linecount = '\n' count + 1)

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/rules/add/my-rules",
        data=body_text,
        content_type="text/plain",
    )

    body = _json_body(resp)
    assert body["status"] == 200
    assert body["msg"] == "Rule added"
    assert isinstance(body["rule_id"], int)

    row = Rules.query.get(body["rule_id"])
    assert row.name == "my-rules"
    assert row.owner_id == admin_user.id
    assert row.path.endswith(".txt")
    with open(row.path, "rb") as fh:
        assert fh.read() == body_text.encode()
    assert row.size == 2
    assert row.checksum == hashlib.sha256(body_text.encode()).hexdigest()


@pytest.mark.security
def test_rules_add_gzip_body_stored_plaintext(
    client, app, admin_user, tmp_path, monkeypatch
):
    """A gzip-compressed upload body is decompressed before landing on disk."""
    import gzip

    _rules_dirs(app, tmp_path, monkeypatch)
    plain = b"^a\n^b\n^c"

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/rules/add/gz-rules",
        data=gzip.compress(plain),
        content_type="application/octet-stream",
    )

    body = _json_body(resp)
    assert body["status"] == 200
    row = Rules.query.get(body["rule_id"])
    with open(row.path, "rb") as fh:
        assert fh.read() == plain
    assert row.size == 3


@pytest.mark.security
def test_rules_add_empty_body_returns_400(client, admin_user):
    """POST /v1/rules/add/<name> with no body returns 400."""
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post("/v1/rules/add/empty", data="", content_type="text/plain")
    body = _json_body(resp)
    assert body["status"] == 400
    assert "Missing" in body["msg"]


@pytest.mark.security
def test_rules_add_bad_gzip_returns_400(
    client, app, admin_user, tmp_path, monkeypatch
):
    """A body with gzip magic bytes but corrupt content is rejected with 400
    and leaves no orphan file in control/rules."""
    _rules_dirs(app, tmp_path, monkeypatch)

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/rules/add/bad-gz",
        data=b"\x1f\x8bthis is not a real gzip stream",
        content_type="application/octet-stream",
    )

    body = _json_body(resp)
    assert body["status"] == 400
    assert Rules.query.filter_by(name="bad-gz").first() is None
    assert os.listdir(os.path.join(str(tmp_path), "control", "rules")) == []


@pytest.mark.security
def test_rules_download_missing_returns_404(client, admin_user):
    """GET /v1/rules/<id> for a nonexistent rule returns a 404 JSON error
    (previously an AttributeError -> 500 HTML page)."""
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.get("/v1/rules/424242")
    assert resp.status_code == 404
    body = _json_body(resp)
    assert body["status"] == 404


@pytest.mark.security
def test_rules_download_serves_gzip_roundtrip(
    client, app, admin_user, tmp_path, monkeypatch
):
    """GET /v1/rules/<id> serves the plaintext-at-rest rule as gzip bytes
    (compressed in pure Python; the os.system shell call is gone)."""
    import gzip

    _rules_dirs(app, tmp_path, monkeypatch)
    content = b"$!\n$@\n"
    rule_path = os.path.join(str(tmp_path), "control", "rules", "served.txt")
    with open(rule_path, "wb") as fh:
        fh.write(content)
    rule = Rules(
        name="served",
        owner_id=admin_user.id,
        path=rule_path,
        size=3,
        checksum="0" * 64,
    )
    _db.session.add(rule)
    _db.session.commit()

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.get(f"/v1/rules/{rule.id}")
    assert resp.status_code == 200
    assert gzip.decompress(resp.data) == content


@pytest.mark.security
def test_send_generated_file_removes_file_after_response_close(app, tmp_path):
    """Generated API download files are removed after the response closes."""
    from hashview.api import routes as api_routes

    tmp_dir = tmp_path / "control" / "tmp"
    tmp_dir.mkdir(parents=True)
    generated = tmp_dir / "download.txt"
    generated.write_bytes(b"payload")

    with app.test_request_context("/v1/generated"):
        response = api_routes._send_generated_file(str(tmp_dir), generated.name)
        assert b"".join(response.response) == b"payload"
        assert generated.exists()

        response.close()
        assert not generated.exists()


@pytest.mark.security
def test_remove_file_logs_warning_on_oserror(app, tmp_path, monkeypatch):
    """A cleanup failure is logged (not swallowed) so admins can troubleshoot."""
    from hashview.api import routes as api_routes

    def boom(_path):
        raise OSError("permission denied")

    monkeypatch.setattr(api_routes.os, "remove", boom)

    with app.app_context():
        with mock.patch.object(api_routes.current_app.logger, "warning") as warn:
            api_routes._remove_file(str(tmp_path / "stuck.txt"))

    assert warn.called
    logged = " ".join(str(a) for a in warn.call_args.args)
    assert "stuck.txt" in logged


# ---------------------------------------------------------------------------
# POST /v1/tasks/add
# ---------------------------------------------------------------------------


def _seed_wordlist(owner):
    wl = Wordlists(
        name="api-wl",
        owner_id=owner.id,
        type="static",
        path="/nonexistent/api-wl.gz",
        size=1,
        checksum="0" * 64,
    )
    _db.session.add(wl)
    _db.session.commit()
    return wl


def _seed_rule(owner):
    rule = Rules(
        name="api-rule",
        owner_id=owner.id,
        path="/nonexistent/api-rule.txt",
        size=1,
        checksum="0" * 64,
    )
    _db.session.add(rule)
    _db.session.commit()
    return rule


def _post_task(client, payload):
    return client.post(
        "/v1/tasks/add",
        data=json.dumps(payload),
        content_type="application/json",
    )


@pytest.mark.security
def test_tasks_add_creates_wordlist_plus_rule_task(client, admin_user):
    """POST /v1/tasks/add with name/wl_id/rule_id creates a mode-0 task."""
    wl = _seed_wordlist(admin_user)
    rule = _seed_rule(admin_user)

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = _post_task(client, {"name": "api wl+rule", "wl_id": wl.id, "rule_id": rule.id})

    body = _json_body(resp)
    assert body["status"] == 200
    assert body["msg"] == "Task added"
    task = Tasks.query.get(body["task_id"])
    assert task.hc_attackmode == 0
    assert task.wl_id == wl.id
    assert task.rule_id == rule.id
    assert task.owner_id == admin_user.id


@pytest.mark.security
def test_tasks_add_rule_is_optional(client, admin_user):
    """Omitting rule_id creates a plain dictionary task (rule_id None)."""
    wl = _seed_wordlist(admin_user)

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = _post_task(client, {"name": "api wl only", "wl_id": wl.id})

    body = _json_body(resp)
    assert body["status"] == 200
    task = Tasks.query.get(body["task_id"])
    assert task.hc_attackmode == 0
    assert task.rule_id is None


@pytest.mark.security
def test_tasks_add_validation_errors_return_400(client, admin_user):
    """Each invalid input is rejected with a 400 and a specific message."""
    wl = _seed_wordlist(admin_user)
    existing = Tasks(name="taken", owner_id=admin_user.id, wl_id=wl.id, hc_attackmode=0)
    _db.session.add(existing)
    _db.session.commit()

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")

    # Missing JSON body
    resp = client.post("/v1/tasks/add", data="", content_type="application/json")
    assert _json_body(resp)["status"] == 400

    # Missing / empty name
    assert _json_body(_post_task(client, {"wl_id": wl.id}))["status"] == 400
    assert _json_body(_post_task(client, {"name": "  ", "wl_id": wl.id}))["status"] == 400

    # Duplicate name
    body = _json_body(_post_task(client, {"name": "taken", "wl_id": wl.id}))
    assert body["status"] == 400
    assert "already exists" in body["msg"]

    # Missing / invalid wl_id
    assert _json_body(_post_task(client, {"name": "t1"}))["status"] == 400
    assert _json_body(_post_task(client, {"name": "t1", "wl_id": "abc"}))["status"] == 400
    assert _json_body(_post_task(client, {"name": "t1", "wl_id": 424242}))["status"] == 400

    # Invalid rule_id
    body = _json_body(_post_task(client, {"name": "t1", "wl_id": wl.id, "rule_id": 424242}))
    assert body["status"] == 400
    assert "rule_id" in body["msg"]

    # Nothing was created along the way
    assert Tasks.query.count() == 1


@pytest.mark.security
def test_tasks_add_rejects_agent_cookie(client, authorized_agent):
    """POST /v1/tasks/add is user-only."""
    client.set_cookie("uuid", authorized_agent.uuid, domain="localhost.test")
    resp = _post_task(client, {"name": "agent-task", "wl_id": 1})
    assert 300 <= resp.status_code < 400
    assert "not_authorized" in resp.headers.get("Location", "")


# ---------------------------------------------------------------------------
# POST /v1/jobs/add — JobNotifications regression
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_jobs_add_creates_notification_rows(client, admin_user):
    """Regression: /v1/jobs/add used to construct JobNotifications with
    notify_email/notify_pushover kwargs that don't exist on the model (and no
    owner_id), so every call 500'd after committing the job. It must now
    create one (owner, job, method) row per requested channel."""
    cust = Customers(name="NotifyCo")
    _db.session.add(cust)
    _db.session.commit()

    hashfile = Hashfiles(name="hf-notify", customer_id=cust.id, owner_id=admin_user.id)
    _db.session.add(hashfile)
    _db.session.commit()

    # The hashfile's hash type is read from its first linked hash.
    _seed_hash(hashfile.id, 1000, False)

    # The route requires at least one historical cracked hash of the same type
    # attributed to a task ("effective tasks" gate).
    wl = _seed_wordlist(admin_user)
    task = Tasks(name="effective", owner_id=admin_user.id, wl_id=wl.id, hc_attackmode=0)
    _db.session.add(task)
    _db.session.commit()
    cracked = Hashes(
        sub_ciphertext="1" * 32,
        ciphertext="cafebabe",
        hash_type=1000,
        cracked=True,
        task_id=task.id,
    )
    _db.session.add(cracked)
    _db.session.commit()

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.post(
        "/v1/jobs/add",
        data=json.dumps({
            "name": "notify-job",
            "hashfile_id": hashfile.id,
            "customer_id": cust.id,
            "notify_email": True,
            "notify_slack": True,
        }),
        content_type="application/json",
    )

    body = _json_body(resp)
    assert body["status"] == 200
    assert body["msg"] == "Job added"

    rows = JobNotifications.query.filter_by(job_id=body["job_id"]).all()
    assert {r.method for r in rows} == {"email", "slack"}
    assert all(r.owner_id == admin_user.id for r in rows)


# ---------------------------------------------------------------------------
# DELETE /v1/hashfiles/<hashfile_id>
# ---------------------------------------------------------------------------


def _seed_hashfile(owner, name="doomed-hf"):
    """Seed a customer + hashfile owned by *owner*."""
    cust = Customers(name="HFDelCo-" + name)
    _db.session.add(cust)
    _db.session.commit()
    hf = Hashfiles(name=name, customer_id=cust.id, owner_id=owner.id)
    _db.session.add(hf)
    _db.session.commit()
    return hf


@pytest.mark.security
def test_hashfiles_delete_cascades_and_keeps_cracked(client, admin_user):
    """DELETE /v1/hashfiles/<id> removes the hashfile + its links; orphaned
    uncracked hashes are deleted, cracked hashes are kept (web-UI cascade)."""
    hf = _seed_hashfile(admin_user)
    hf_id = hf.id
    uncracked_id = _seed_hash(hf_id, 1000, False).id
    cracked_id = _seed_hash(hf_id, 1000, True).id

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.delete(f"/v1/hashfiles/{hf_id}")

    body = _json_body(resp)
    assert body["status"] == 200
    assert body["msg"] == "Hashfile deleted"
    assert body["hashfile_id"] == hf_id
    # Bulk cascade deletes use synchronize_session=False; expire cached state so
    # the assertions below read the committed rows rather than stale objects.
    _db.session.expire_all()
    assert Hashfiles.query.get(hf_id) is None
    assert HashfileHashes.query.filter_by(hashfile_id=hf_id).count() == 0
    assert Hashes.query.get(uncracked_id) is None       # orphaned uncracked hash removed
    assert Hashes.query.get(cracked_id) is not None     # cracked hash retained


@pytest.mark.security
def test_hashfiles_delete_missing_returns_404(client, admin_user):
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.delete("/v1/hashfiles/424242")
    assert resp.status_code == 404
    body = _json_body(resp)
    assert body["status"] == 404
    assert "not found" in body["msg"].lower()


@pytest.mark.security
def test_hashfiles_delete_rejects_agent_cookie(client, authorized_agent):
    """User-only: a valid agent uuid is refused with the not-authorized redirect."""
    client.set_cookie("uuid", authorized_agent.uuid, domain="localhost.test")
    resp = client.delete("/v1/hashfiles/1")
    assert 300 <= resp.status_code < 400
    assert "not_authorized" in resp.headers.get("Location", "")


@pytest.mark.security
def test_hashfiles_delete_non_owner_returns_403(client, admin_user, regular_user):
    """A non-admin cannot delete another user's hashfile."""
    hf = _seed_hashfile(admin_user)
    hf_id = hf.id
    client.set_cookie("uuid", regular_user.api_key, domain="localhost.test")
    resp = client.delete(f"/v1/hashfiles/{hf_id}")
    body = _json_body(resp)
    assert body["status"] == 403
    assert Hashfiles.query.get(hf_id) is not None       # not deleted


@pytest.mark.security
def test_hashfiles_delete_refuses_when_assigned_to_job(client, admin_user):
    """A hashfile still attached to a job cannot be deleted (409)."""
    hf = _seed_hashfile(admin_user)
    hf_id = hf.id
    job = Jobs(name="uses-hf", status="Ready", customer_id=hf.customer_id,
               owner_id=admin_user.id, hashfile_id=hf_id)
    _db.session.add(job)
    _db.session.commit()

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.delete(f"/v1/hashfiles/{hf_id}")
    assert resp.status_code == 409
    body = _json_body(resp)
    assert body["status"] == 409
    assert "associated with a job" in body["msg"].lower()
    assert Hashfiles.query.get(hf_id) is not None       # not deleted


@pytest.mark.security
def test_hashfiles_delete_admin_can_delete_others(client, admin_user, regular_user):
    """An admin can delete a hashfile owned by another user."""
    hf = _seed_hashfile(regular_user)
    hf_id = hf.id
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.delete(f"/v1/hashfiles/{hf_id}")
    body = _json_body(resp)
    assert body["status"] == 200
    assert Hashfiles.query.get(hf_id) is None
