"""Tests for ``GET /v1/hashfiles/<id>/export/<fmt>`` (issue #368).

The web UI's hashfile Download modal (``/hashfiles/download/<id>/<fmt>``) is
``@login_required`` and so unreachable with an API key; before this route the
only /v1 hashfile download returned the *uncracked* hashes. Clients such as
hate_crack need the cracked ``hash:plain`` pairs to pre-seed a potfile.

Contract pinned here:
  * Same four formats as the UI, byte-identical to the UI for the same data
    (both render through ``hashview.utils.hashfile_export``).
  * Plaintexts stored as hashcat ``$HEX[...]`` markers pass through unchanged,
    so ``cracked`` output is a valid potfile.
  * User-only: an agent uuid or no cookie is redirected to /v1/not_authorized.
  * Unknown hashfile id or format is a *real* HTTP 404, so a client that streams
    a 200 body to disk never saves a JSON error as its hashfile.
  * The control/tmp scratch file is removed after serving (#226).
"""

import json
import os

import pytest

from hashview.models import Agents, Hashes, HashfileHashes, Hashfiles, Users, db
from hashview.utils.hashfile_export import HASHFILE_EXPORT_FORMATS
from hashview.utils.utils import get_md5_hash

DOMAIN = "localhost.test"

# Synthetic plaintexts: plain ASCII, non-Latin-1 Unicode, and a $HEX marker as
# stored for a recovered password that is not valid UTF-8.
SEED = [
    ("aaa111", "plain-one", True),
    ("bbb222", "пароль-密码-🔒", True),
    ("ccc333", "$HEX[00ff10]", True),
    ("ddd444", None, False),
]


@pytest.fixture()
def api_user(app):
    user = Users(first_name="A", last_name="B", email_address="export@e.test",
                 password="x" * 60, admin=True, api_key="test-api-key")
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture()
def hashfile(app, api_user):
    hf = Hashfiles(name="export dump", customer_id=1, owner_id=api_user.id)
    db.session.add(hf)
    db.session.commit()
    for ciphertext, plaintext, cracked in SEED:
        h = Hashes(sub_ciphertext=get_md5_hash(ciphertext), ciphertext=ciphertext,
                   hash_type=0, cracked=cracked, plaintext=plaintext)
        db.session.add(h)
        db.session.commit()
        db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
        db.session.commit()
    return hf


def _auth(client, value):
    client.set_cookie("uuid", value, domain=DOMAIN)


def _lines(resp):
    return [ln for ln in resp.data.decode("utf-8").split("\n") if ln]


def _tmp_listing(app):
    return set(os.listdir(os.path.join(app.root_path, "control", "tmp")))


def test_export_cracked_is_potfile_ready(client, api_user, hashfile):
    _auth(client, api_user.api_key)
    resp = client.get(f"/v1/hashfiles/{hashfile.id}/export/cracked")
    assert resp.status_code == 200
    assert resp.mimetype == "text/plain"
    assert sorted(_lines(resp)) == sorted([
        "aaa111:plain-one",
        "bbb222:пароль-密码-🔒",
        "ccc333:$HEX[00ff10]",
    ])
    assert resp.data.endswith(b"\n")


def test_export_hashes_lists_every_ciphertext(client, api_user, hashfile):
    _auth(client, api_user.api_key)
    resp = client.get(f"/v1/hashfiles/{hashfile.id}/export/hashes")
    assert resp.status_code == 200
    assert sorted(_lines(resp)) == ["aaa111", "bbb222", "ccc333", "ddd444"]


def test_export_all_annotates_only_cracked(client, api_user, hashfile):
    _auth(client, api_user.api_key)
    lines = _lines(client.get(f"/v1/hashfiles/{hashfile.id}/export/all"))
    assert "aaa111:plain-one" in lines
    assert "ddd444" in lines
    assert not any(ln.startswith("ddd444:") for ln in lines)


def test_export_plains_omits_hashes(client, api_user, hashfile):
    _auth(client, api_user.api_key)
    lines = _lines(client.get(f"/v1/hashfiles/{hashfile.id}/export/plains"))
    assert sorted(lines) == sorted(["plain-one", "пароль-密码-🔒", "$HEX[00ff10]"])


@pytest.mark.parametrize("fmt", HASHFILE_EXPORT_FORMATS)
def test_export_matches_web_download_bytes(app, client, api_user, hashfile, fmt):
    """UI and API must produce identical bodies for the same format."""
    with client.session_transaction() as sess:
        sess["_user_id"] = str(api_user.id)
        sess["_fresh"] = True
    web = client.get(f"/hashfiles/download/{hashfile.id}/{fmt}")
    assert web.status_code == 200

    _auth(client, api_user.api_key)
    api = client.get(f"/v1/hashfiles/{hashfile.id}/export/{fmt}")
    assert api.status_code == 200
    assert api.data == web.data


def test_export_empty_selection_is_empty_200(client, api_user):
    hf = Hashfiles(name="nothing cracked", customer_id=1, owner_id=api_user.id)
    db.session.add(hf)
    db.session.commit()
    h = Hashes(sub_ciphertext=get_md5_hash("eee555"), ciphertext="eee555",
               hash_type=0, cracked=False)
    db.session.add(h)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    db.session.commit()

    _auth(client, api_user.api_key)
    resp = client.get(f"/v1/hashfiles/{hf.id}/export/cracked")
    assert resp.status_code == 200
    assert resp.data == b""


def test_export_unknown_format_is_real_404(client, api_user, hashfile):
    _auth(client, api_user.api_key)
    resp = client.get(f"/v1/hashfiles/{hashfile.id}/export/bogus")
    assert resp.status_code == 404
    body = json.loads(resp.data)
    assert body["status"] == 404 and body["type"] == "Error"
    assert "cracked" in body["msg"]


def test_export_unknown_hashfile_is_real_404(client, api_user):
    _auth(client, api_user.api_key)
    resp = client.get("/v1/hashfiles/999999/export/cracked")
    assert resp.status_code == 404
    assert json.loads(resp.data)["msg"] == "Hashfile not found"


@pytest.mark.security
def test_export_rejects_agent_uuid(client, hashfile):
    agent = Agents(name="agent-1", src_ip="127.0.0.1", uuid="agent-uuid-export",
                   status="Authorized")
    db.session.add(agent)
    db.session.commit()
    _auth(client, agent.uuid)
    resp = client.get(f"/v1/hashfiles/{hashfile.id}/export/cracked")
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/v1/not_authorized")


@pytest.mark.security
def test_export_rejects_missing_cookie(client, hashfile):
    resp = client.get(f"/v1/hashfiles/{hashfile.id}/export/cracked")
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/v1/not_authorized")


def test_export_removes_temp_file(app, client, api_user, hashfile):
    _auth(client, api_user.api_key)
    before = _tmp_listing(app)
    resp = client.get(f"/v1/hashfiles/{hashfile.id}/export/all")
    assert resp.status_code == 200
    assert resp.data
    assert _tmp_listing(app) == before


@pytest.mark.parametrize("fmt", HASHFILE_EXPORT_FORMATS)
def test_export_lists_shared_hash_once(client, api_user, fmt):
    """Two accounts sharing one hash (routine in an NTLM dump) are one Hashes
    row with two HashfileHashes links. The UI export always emitted that hash
    once; both routes must keep doing so. Pins the shared formatter itself,
    which the byte-parity test above cannot, since both routes use it."""
    hf = Hashfiles(name="shared", customer_id=1, owner_id=api_user.id)
    db.session.add(hf)
    db.session.commit()
    h = Hashes(sub_ciphertext=get_md5_hash("fff666"), ciphertext="fff666",
               hash_type=1000, cracked=True, plaintext="shared-plain")
    db.session.add(h)
    db.session.commit()
    for username in ("user-one", "user-two"):
        db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id, username=username))
    db.session.commit()

    with client.session_transaction() as sess:
        sess["_user_id"] = str(api_user.id)
        sess["_fresh"] = True
    web = client.get(f"/hashfiles/download/{hf.id}/{fmt}")
    _auth(client, api_user.api_key)
    api = client.get(f"/v1/hashfiles/{hf.id}/export/{fmt}")

    for resp in (web, api):
        assert resp.status_code == 200
        assert len(_lines(resp)) == 1
