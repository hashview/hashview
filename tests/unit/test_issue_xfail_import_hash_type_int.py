"""xfail regression tests for the hash_type int/str mismatch in issue #444.

``import_hashfilehashes`` (hashview/utils/utils.py:665) decides how to normalise
an incoming hash by comparing ``hash_type`` against **string** literals. The web
UI supplies it as a string (form field) so those branches fire; the API route is
declared ``<int:hash_type>`` (hashview/api/routes.py:1257) so it supplies an
``int`` and every one of them is skipped:

    utils.py:688  if hash_type in ('300', '1731', '1000')   # hash_only, lowercase
    utils.py:690  elif hash_type == '2100'                  # hash_only, DCC2 normalise
    utils.py:697  if hash_type == '2100'                    # hash_only, DCC2 username
    utils.py:711  if hash_type == '300' or ... == '1731'    # user_hash, lowercase
    utils.py:714  elif hash_type == '2100'                  # user_hash, DCC2 normalise
    utils.py:725  if hash_type in ('300', '1731', '1000')   # user_hash, lowercase
    utils.py:743  if hash_type == '18200'                   # kerberos, AS-REP username

The headline consequence is the lowercasing. hashcat emits hex hashes lowercased,
so the ``md5(ciphertext)`` lookup that ingests crack results
(api/routes.py:1708) never matches a row the API stored uppercase — the hash is
cracked by an agent and silently stays ``cracked=0`` forever, and its plaintext
never reaches the ``(DYNAMIC) All Recovered Passwords`` wordlist. The comment at
utils.py:721-723 already spells out this exact failure mode for the ``:725``
branch it introduces.

Two sites in the same function already carry the fix and its rationale
(``str(hash_type) == '2100'`` at :683, and :708 with the comment "hash_type
arrives as an int on the API path"); the neighbours were missed.

Only case-*sensitive* input is affected, which is why this is invisible in
practice for tools that already emit lowercase. One existing test does pass an
int (tests/unit/test_machine_account_filter.py:133), but it exercises only the
already-fixed machine-account filter at :708 — nothing in the suite crosses the
int/str boundary for the normalisation branches above.

NOT covered here: recovering rows already written uppercase by the API. Those
stay unmatchable after a code fix and need a data migration (lowercase
``ciphertext``, recompute ``sub_ciphertext``) — tracked separately in #444, and
deliberately not pinned to a shape here.

Each test asserts the *correct* (post-fix) behavior and is
``@pytest.mark.xfail(strict=True)``, so it XFAILs today and turns into a hard
XPASS failure the moment the bug is fixed — the signal to drop the marker.
The non-xfail tests are guard rails: behavior a fix must not regress.
"""

import json
from pathlib import Path

import pytest

from hashview.models import (
    Agents,
    Customers,
    Hashes,
    HashfileHashes,
    Jobs,
    JobTasks,
    Users,
    Wordlists,
    db,
)
from hashview.utils.utils import (
    get_md5_hash,
    import_hashfilehashes,
    update_dynamic_wordlist,
)

DOMAIN = "localhost.test"

# NTLM of "password", as an NTDS/Excel-sourced dump routinely presents it.
NT_UPPER = "8846F7EAEE8FB117AD06BDD830B7586C"
NT_LOWER = NT_UPPER.lower()


# --------------------------------------------------------------------------
# Fixtures / helpers
# --------------------------------------------------------------------------


@pytest.fixture()
def api_user(app):
    user = Users(first_name="Api", last_name="User",
                 email_address="api@example.test", password="x" * 60,
                 admin=True, api_key="user-api-key-444")
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture()
def crack_agent(app):
    agent = Agents(name="rig-1", src_ip="127.0.0.1", uuid="agent-uuid-444",
                   status="Authorized")
    db.session.add(agent)
    db.session.commit()
    return agent


@pytest.fixture()
def customer(app):
    cust = Customers(name="Acme")
    db.session.add(cust)
    db.session.commit()
    return cust


def _seed_cracked(ciphertext, plaintext, hash_type=1000):
    """A hash already recovered by an earlier job, stored the way the UI path
    stores it (lowercased) — the corpus a later import should instacrack against."""
    h = Hashes(sub_ciphertext=get_md5_hash(ciphertext), ciphertext=ciphertext,
               hash_type=hash_type, cracked=True, plaintext=plaintext)
    db.session.add(h)
    db.session.commit()
    return h


def _dynamic_wordlist(tmp_path, name, owner_id):
    path = str(tmp_path / (name.replace(" ", "_") + ".txt"))
    Path(path).touch()
    wl = Wordlists(name=name, owner_id=owner_id, type="dynamic", path=path,
                   checksum="", size=0)
    db.session.add(wl)
    db.session.commit()
    return wl


def _import_file(tmp_path, contents, file_type, hash_type, hashfile_id=1):
    """Call import_hashfilehashes directly with the given hash_type type."""
    path = tmp_path / "upload.txt"
    path.write_text(contents)
    assert import_hashfilehashes(hashfile_id=hashfile_id,
                                 hashfile_path=str(path),
                                 file_type=file_type,
                                 hash_type=hash_type)


def _api_upload(client, api_user, customer, body, file_format=5, hash_type=1000,
                name="probe-hf"):
    """POST a hashfile through the real API route, which passes hash_type as int.

    The 200 is asserted here, not left to the caller: without it a cookie-domain
    or auth regression would 302 to /v1/not_authorized and every xfail below
    would still be green, for the wrong reason.
    """
    client.set_cookie("uuid", api_user.api_key, domain=DOMAIN)
    resp = client.post(
        f"/v1/hashfiles/upload/{customer.id}/{file_format}/{hash_type}/{name}",
        data=body, content_type="text/plain")
    body = json.loads(resp.get_data(as_text=True))
    assert body["status"] == 200, body
    return body


def _crack_via_agent(client, crack_agent, api_user, customer, hashfile_id,
                     ciphertext, plaintext):
    """Run a job over ``hashfile_id`` and have the agent report one recovery,
    the way hashcat does it: with the ciphertext lowercased."""
    job = Jobs(name="j", status="Running", hashfile_id=hashfile_id,
               customer_id=customer.id, owner_id=api_user.id)
    db.session.add(job)
    db.session.commit()
    job_task = JobTasks(job_id=job.id, task_id=7, status="Running")
    db.session.add(job_task)
    db.session.commit()

    client.set_cookie("uuid", crack_agent.uuid, domain=DOMAIN)
    resp = client.post(f"/v1/uploadCrackFile/{job_task.id}",
                       json={"file": f"{ciphertext}:{plaintext.encode().hex()}"})
    body = json.loads(resp.get_data(as_text=True))
    assert body["status"] == 200, body


# --------------------------------------------------------------------------
# Guard rails — behavior a fix must preserve (not xfail)
# --------------------------------------------------------------------------


@pytest.mark.security
def test_ui_string_hash_type_still_lowercases_ntlm(app, tmp_path):
    """The UI path passes hash_type as a string and already works. A fix must
    not disturb it — it is the behavior the API path is missing."""
    _import_file(tmp_path, NT_UPPER + "\n", "hash_only", "1000")

    assert Hashes.query.one().ciphertext == NT_LOWER


@pytest.mark.security
def test_pwdump_is_unaffected_by_the_hash_type_argument(app, tmp_path):
    """pwdump hardcodes hash_type='1000' at the call site (utils.py:739) and
    lowercases unconditionally, so it is correct for either argument type.
    Pinned so a fix isn't credited with repairing a path that was never broken."""
    line = f"alice:1001:aad3b435b51404eeaad3b435b51404ee:{NT_UPPER}:::\n"
    _import_file(tmp_path, line, "pwdump", 1000)

    assert Hashes.query.one().ciphertext == NT_LOWER


@pytest.mark.security
def test_hash_type_column_holds_an_integer_after_a_string_import(app, tmp_path):
    """``import_hash_only`` writes ``hash_type`` straight into an Integer column.
    The proposed fix (normalise to ``str`` at the top of the function) makes the
    API path pass a string too, so pin that a string argument still lands as an
    integer and stays findable by the int-keyed queries elsewhere.

    This asserts the backend's numeric coercion, not application logic — it
    holds on SQLite (INTEGER affinity) and MySQL alike. It is here because the
    proposed fix is the thing that would newly rely on it.
    """
    _import_file(tmp_path, NT_UPPER + "\n", "hash_only", "1000")
    db.session.expire_all()

    assert Hashes.query.one().hash_type == 1000
    assert Hashes.query.filter_by(hash_type=1000).count() == 1


# --------------------------------------------------------------------------
# #444: the lowercasing branches are dead on the API path
# --------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.xfail(strict=True,
                   reason="#444: utils.py:688 compares an int hash_type to strings, so hash_only NTLM is not lowercased")
def test_hash_only_ntlm_is_lowercased_when_hash_type_is_an_int(app, tmp_path):
    _import_file(tmp_path, NT_UPPER + "\n", "hash_only", 1000)

    assert Hashes.query.one().ciphertext == NT_LOWER


@pytest.mark.security
@pytest.mark.xfail(strict=True,
                   reason="#444: utils.py:725 compares an int hash_type to strings, so user_hash NTLM is not lowercased")
def test_user_hash_ntlm_is_lowercased_when_hash_type_is_an_int(app, tmp_path):
    _import_file(tmp_path, f"alice:{NT_UPPER}\n", "user_hash", 1000)

    assert Hashes.query.one().ciphertext == NT_LOWER


@pytest.mark.security
@pytest.mark.xfail(strict=True,
                   reason="#444: utils.py:711 compares an int hash_type to strings, so user_hash mysql41 is not lowercased")
def test_user_hash_mysql41_is_lowercased_when_hash_type_is_an_int(app, tmp_path):
    """hash_type 300 takes its own branch (utils.py:711), distinct from the
    ``else`` at :720 that 1000 falls through to. Both are dead on the API path.

    Only the casing is pinned. That branch also hands the *whole* ``user:hash``
    line to ``import_hash_only`` instead of the hash field, so the ciphertext is
    stored as ``alice:fcf7…`` on the UI path too — a separate defect (#445),
    deliberately not blessed by an equality assertion here.
    """
    digest = "FCF7C1B8749CF99D88E5F34271D636178FB5D130"
    _import_file(tmp_path, f"alice:{digest}\n", "user_hash", 300)

    stored = Hashes.query.one().ciphertext
    assert digest.lower() in stored
    assert stored == stored.lower()


@pytest.mark.security
@pytest.mark.xfail(strict=True,
                   reason="#444: utils.py:714 compares an int hash_type to '2100', so user_hash DCC2 is not normalised")
def test_user_hash_dcc2_is_normalised_when_hash_type_is_an_int(app, tmp_path):
    """Only the ciphertext is pinned. The ``:714`` branch also sets
    ``username = line.split(':')[0]`` *after* rebinding ``line`` to the hash, so
    it stores the whole DCC2 ciphertext as the username — a pre-existing defect
    of the UI path too, and out of scope for #444."""
    _import_file(tmp_path,
                 "alice:$DCC2$10240#Alice#A1B2C3D4E5F60718293A4B5C6D7E8F90\n",
                 "user_hash", 2100)

    assert Hashes.query.one().ciphertext == (
        "$DCC2$10240#alice#a1b2c3d4e5f60718293a4b5c6d7e8f90")


@pytest.mark.security
@pytest.mark.xfail(strict=True,
                   reason="#444: the API route passes hash_type as an int, so the uploaded ciphertext is stored verbatim")
def test_api_upload_stores_ntlm_lowercased(client, app, api_user, customer):
    _api_upload(client, api_user, customer, NT_UPPER + "\n")

    assert Hashes.query.one().ciphertext == NT_LOWER


# --------------------------------------------------------------------------
# #444: the consequences operators actually see
# --------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.xfail(strict=True,
                   reason="#444: the uppercase row has a different sub_ciphertext, so import_hash_only's dedup misses the cracked corpus")
def test_api_upload_instacracks_against_the_existing_corpus(client, app, api_user,
                                                            customer):
    """The same hash recovered by an earlier job must be reported as
    instacracked, not imported a second time as a fresh uncracked row."""
    _seed_cracked(NT_LOWER, "password")

    body = _api_upload(client, api_user, customer, NT_UPPER + "\n")

    assert body["instacracked"] == 1
    assert Hashes.query.count() == 1


@pytest.mark.security
@pytest.mark.xfail(strict=True,
                   reason="#444: the agent reports lowercase ciphertexts, so md5(ciphertext) never matches the uppercase row")
def test_agent_crack_report_marks_an_api_imported_hash_cracked(
        client, app, api_user, customer, crack_agent, monkeypatch):
    """The end-to-end failure: an API-imported hash is cracked by an agent and
    stays uncracked in the DB, so it is re-queued on every subsequent job."""
    monkeypatch.setattr("hashview.api.routes.process_recovered_hash_notifications",
                        lambda *a, **kw: None)
    body = _api_upload(client, api_user, customer, NT_UPPER + "\n")
    imported = Hashes.query.one()

    _crack_via_agent(client, crack_agent, api_user, customer,
                     body["hashfile_id"], NT_LOWER, "password")

    refreshed = Hashes.query.get(imported.id)
    assert refreshed.cracked
    assert refreshed.plaintext == "password"


@pytest.mark.security
@pytest.mark.xfail(strict=True,
                   reason="#444: the API-imported hash never flips to cracked, so its plaintext never enters the recovered corpus")
def test_recovered_plaintext_reaches_the_dynamic_all_wordlist(
        client, app, api_user, customer, crack_agent, tmp_path, monkeypatch):
    """The reported symptom: crack a hash that was uploaded through the API and
    its plaintext is still absent from (DYNAMIC) All Recovered Passwords."""
    monkeypatch.setattr("hashview.api.routes.process_recovered_hash_notifications",
                        lambda *a, **kw: None)
    wordlist = _dynamic_wordlist(tmp_path, "(DYNAMIC) All Recovered Passwords",
                                 api_user.id)
    body = _api_upload(client, api_user, customer, NT_UPPER + "\n")

    _crack_via_agent(client, crack_agent, api_user, customer,
                     body["hashfile_id"], NT_LOWER, "password")

    update_dynamic_wordlist(wordlist.id)

    assert Path(wordlist.path).read_text().splitlines() == ["password"]


@pytest.mark.security
@pytest.mark.xfail(strict=True,
                   reason="#444: the uppercase duplicate row is a second hash_type 1000 ciphertext, so it lands in the NTLM wordlist too")
def test_dynamic_ntlm_wordlist_has_no_case_duplicates(client, app, api_user,
                                                      customer, tmp_path):
    """(DYNAMIC) All NTLM Hashes writes every hash_type 1000 ciphertext
    (utils.py:913). A case-duplicate row means the agent cracks the same hash
    twice on any task fed this list."""
    _seed_cracked(NT_LOWER, "password")
    wordlist = _dynamic_wordlist(tmp_path, "(DYNAMIC) All NTLM Hashes",
                                 api_user.id)

    _api_upload(client, api_user, customer, NT_UPPER + "\n")
    update_dynamic_wordlist(wordlist.id)

    assert Path(wordlist.path).read_text().splitlines() == [NT_LOWER]


# --------------------------------------------------------------------------
# #444: the other dead branches — usernames and DCC2 normalisation
# --------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.xfail(strict=True,
                   reason="#444: utils.py:743 compares an int hash_type to '18200', so the ':' split is skipped and the ciphertext is stored as the username")
def test_kerberos_asrep_username_excludes_the_ciphertext(app, tmp_path):
    """An 18200 (AS-REP) line carries ``principal:ciphertext`` in its 4th
    ``$``-delimited field. Without the ``:`` split the whole tail — principal
    *and* hash — is stored as the username, and is then written verbatim into
    (DYNAMIC) All Usernames."""
    line = "$krb5asrep$23$svc_sql@corp.local:3e156ada591263b8aab0965f5aebd837\n"
    _import_file(tmp_path, line, "kerberos", 18200)

    assert HashfileHashes.query.one().username == "svc_sql@corp.local"


@pytest.mark.security
@pytest.mark.xfail(strict=True,
                   reason="#444: utils.py:690/697 compare an int hash_type to '2100', so DCC2 is neither normalised nor given a username")
def test_hash_only_dcc2_is_normalised_and_keeps_its_username(app, tmp_path):
    """DCC2 must be stored with hashcat's ``$DCC2$`` casing and the account name
    lifted out of the ciphertext, or the hash is unmatchable and the account is
    invisible in the hashfile view."""
    _import_file(tmp_path, "$DCC2$10240#Alice#A1B2C3D4E5F60718293A4B5C6D7E8F90\n",
                 "hash_only", 2100)

    stored = Hashes.query.one()
    assert stored.ciphertext == (
        "$DCC2$10240#alice#a1b2c3d4e5f60718293a4b5c6d7e8f90")
    assert HashfileHashes.query.one().username == "alice"
