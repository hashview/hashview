"""Unit tests for compressed-at-rest wordlist storage (server + agent).

Covers the change that stores all wordlists gzip-compressed (gzip -9):
  - the utils ingest/compression helpers,
  - UI + API uploads (plain text AND gzip, with rejection of malformed gzip),
  - the download endpoint (static served verbatim, dynamic compressed on the fly),
  - the launch-time migration that compresses pre-existing static wordlists,
  - build_hashcat_command emitting the '.gz' path the agent stores,
  - the agent's rewritten sync_wordlists logic (extracted + executed in
    isolation so the whole agent script doesn't have to be importable).

All tests use the in-memory SQLite app from tests/unit/conftest.py. The test
body runs inside the ``app`` fixture's app context, so helpers that read
``current_app`` work without a nested ``app.app_context()`` (nesting would
open a separate SQLAlchemy session scope and hide committed changes from the
outer session). The autouse ``_clean_control_dirs`` fixture removes any files
these tests drop into the real hashview/control/{wordlists,tmp} dirs.
"""

import ast
import gzip
import hashlib
import io
import json
import logging
import os
import secrets
import sys
import zlib
from pathlib import Path

import pytest

from hashview.models import Hashes, HashfileHashes, Jobs, Rules, Tasks, Users, Wordlists, db
from hashview.setup import compress_existing_wordlists_if_needed
from hashview.utils.utils import (
    build_hashcat_command,
    compress_to_gz,
    ensure_gz,
    get_filehash,
    get_filesize,
    get_linecount,
    gz_linecount,
    ingest_static_wordlist_file,
    is_gzip,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
PKG_ROOT = REPO_ROOT / "hashview"
CONTROL = PKG_ROOT / "control"
# WORDLISTS_DIR / TMP_DIR are repointed at a per-test isolated root by the
# autouse ``_isolated_control_root`` fixture below; the module-level values are
# only placeholders so imports resolve.
WORDLISTS_DIR = CONTROL / "wordlists"
TMP_DIR = CONTROL / "tmp"
AGENT_SCRIPT = REPO_ROOT / "install" / "hashview-agent" / "hashview-agent.py"

# Cookie domain must match the unit conftest's SERVER_NAME or Werkzeug 3.x
# won't send the cookie (its set_cookie default domain is 'localhost').
COOKIE_DOMAIN = "localhost.test"


@pytest.fixture(autouse=True)
def _isolated_control_root(app, tmp_path, monkeypatch):
    """Give each test a private hashview root so wordlist files never touch the
    shared real ``hashview/control/`` tree.

    These tests write real files under ``control/{wordlists,tmp}``. Deriving
    that location from the package dir made every test in the process share one
    mutable directory: a slow teardown, an errored test, or a stray background
    file operation could delete or collide with another test's in-flight file
    (a rare source of ``os.path.exists`` flakiness), and the snapshot-diff
    cleanup leaked orphaned ``.gz`` files over time. Pointing ``app.root_path``
    at a per-test ``tmp_path`` isolates all of it (pytest cleans tmp_path up);
    ``templates``/``static`` are symlinked back so render paths still resolve.
    """
    root = tmp_path / "hvroot"
    root.mkdir()
    for name in ("templates", "static"):
        os.symlink(PKG_ROOT / name, root / name)
    for sub in ("wordlists", "tmp", "hashes", "rules", "logs", "wordlists_import"):
        (root / "control" / sub).mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(app, "root_path", str(root))
    # Tests that write dynamic wordlists reference these module globals directly;
    # repoint them at the isolated dirs so they match app.root_path.
    monkeypatch.setattr(sys.modules[__name__], "WORDLISTS_DIR", root / "control" / "wordlists")
    monkeypatch.setattr(sys.modules[__name__], "TMP_DIR", root / "control" / "tmp")


def _make_user(api_key="testapikey"):
    user = Users(first_name="A", last_name="D", email_address="a@e.com",
                 password="x" * 60, admin=True, api_key=api_key)
    db.session.add(user)
    db.session.commit()
    return user


def _auth(client, api_key):
    client.set_cookie("uuid", api_key, domain=COOKIE_DOMAIN)


def _login(client, user):
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True


# ---------------------------------------------------------------------------
# Helpers: ingest / compression primitives
# ---------------------------------------------------------------------------

def test_helpers_roundtrip(app, tmp_path):
    plain = tmp_path / "wl.txt"
    plain.write_bytes(b"alpha\nbravo\ncharlie\n")
    gz = tmp_path / "wl.txt.gz"
    compress_to_gz(str(plain), str(gz), 9)

    assert is_gzip(str(gz)) is True
    assert is_gzip(str(plain)) is False
    # same line-count semantics across plain and gz
    assert gz_linecount(str(gz)) == get_linecount(str(plain))
    assert get_filesize(str(gz)) == os.path.getsize(gz)
    # ensure_gz idempotency
    assert ensure_gz("abc") == "abc.gz"
    assert ensure_gz("abc.gz") == "abc.gz"
    assert ensure_gz("d.txt") == "d.txt.gz"


@pytest.mark.parametrize("data", [
    pytest.param(b"a\nb\nc\n", id="terminated"),
    pytest.param(b"a\nb\nc", id="unterminated"),
    pytest.param(b"", id="empty"),
    pytest.param(b"\n\n\n", id="newlines-only"),
])
def test_get_linecount_and_gz_linecount_match_splitlines_oracle(app, tmp_path, data):
    """#435: get_linecount/gz_linecount must count real lines, not '\\n' + 1
    unconditionally. len(data.splitlines()) is the oracle: it counts a
    trailing-newline-terminated file's lines correctly AND still counts a
    final unterminated line, exactly matching the intended semantics."""
    expected = len(data.splitlines())

    plain = tmp_path / "wl.txt"       # tmp_path is unique per parametrized call
    plain.write_bytes(data)
    assert get_linecount(str(plain)) == expected

    gz = tmp_path / "wl.gz"
    with gzip.open(str(gz), "wb") as f:
        f.write(data)
    assert gz_linecount(str(gz)) == expected


def test_ingest_plaintext(app, tmp_path):
    user = _make_user()
    content = b"password\n123456\nletmein\n"
    src = tmp_path / "u.txt"
    src.write_bytes(content)

    wl = ingest_static_wordlist_file(str(src), user.id, "MyList")

    assert wl.type == "static"
    assert wl.path.endswith(".gz")
    assert is_gzip(wl.path)
    assert wl.checksum == get_filehash(wl.path)          # checksum of the .gz
    assert wl.size == get_linecount(str(src))            # line count
    assert wl.byte_size == os.path.getsize(wl.path)
    with gzip.open(wl.path, "rb") as f:
        assert f.read() == content


def test_ingest_gzip_recompresses_to_max(app, tmp_path):
    user = _make_user()
    content = b"".join(b"line-%d\n" % i for i in range(5000))
    weak = tmp_path / "weak.gz"
    with gzip.open(str(weak), "wb", compresslevel=1) as f:
        f.write(content)

    wl = ingest_static_wordlist_file(str(weak), user.id, "GzList")

    assert is_gzip(wl.path)
    assert wl.size == content.count(b"\n")
    assert wl.checksum == get_filehash(wl.path)
    with gzip.open(wl.path, "rb") as f:
        assert f.read() == content
    # re-compressed at -9 should be no larger than the level-1 upload
    assert os.path.getsize(wl.path) <= os.path.getsize(weak)


def test_ingest_rejects_fake_gzip(app, tmp_path):
    user = _make_user()
    bad = tmp_path / "bad.gz"
    bad.write_bytes(b"\x1f\x8b\x08\x00garbagegarbage")
    with pytest.raises((OSError, EOFError, zlib.error)):
        ingest_static_wordlist_file(str(bad), user.id, "BadGz")


# ---------------------------------------------------------------------------
# UI upload route
# ---------------------------------------------------------------------------

def test_ui_upload_plaintext(app, client):
    user = _make_user()
    _login(client, user)
    content = b"foo\nbar\nbaz\n"
    resp = client.post(
        "/wordlists/add",
        data={"name": "UIList", "wordlist": (io.BytesIO(content), "list.txt"), "submit": "upload"},
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    assert resp.status_code in (302, 200)
    wl = Wordlists.query.filter_by(name="UIList").first()
    assert wl is not None
    assert wl.path.endswith(".gz") and is_gzip(wl.path)
    assert wl.checksum == get_filehash(wl.path)
    assert wl.size == content.count(b"\n")
    assert wl.byte_size == os.path.getsize(wl.path)


def test_ui_upload_gzip(app, client):
    user = _make_user()
    _login(client, user)
    content = b"alpha\nbeta\n"
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as f:
        f.write(content)
    buf.seek(0)
    resp = client.post(
        "/wordlists/add",
        data={"name": "UIGz", "wordlist": (buf, "list.gz"), "submit": "upload"},
        content_type="multipart/form-data",
    )
    assert resp.status_code in (302, 200)
    wl = Wordlists.query.filter_by(name="UIGz").first()
    assert wl is not None and is_gzip(wl.path)
    with gzip.open(wl.path, "rb") as f:
        assert f.read() == content


def test_ui_upload_rejects_fake_gzip(app, client):
    user = _make_user()
    _login(client, user)
    resp = client.post(
        "/wordlists/add",
        data={"name": "FakeGz", "wordlist": (io.BytesIO(b"\x1f\x8bnotreallygzip"), "x.gz"), "submit": "upload"},
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    assert resp.status_code in (302, 200)
    assert Wordlists.query.filter_by(name="FakeGz").first() is None


def test_ui_upload_ajax_returns_json_ok(app, client):
    """The modal posts with X-Requested-With: fetch and expects a JSON OK
    (so it can show 'Done' and then reload) instead of a redirect."""
    user = _make_user()
    _login(client, user)
    content = b"foo\nbar\n"
    resp = client.post(
        "/wordlists/add",
        data={"name": "AjaxList", "wordlist": (io.BytesIO(content), "list.txt"), "submit": "upload"},
        content_type="multipart/form-data",
        headers={"X-Requested-With": "fetch"},
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["status"] == "ok"
    assert body["redirect"].endswith("/wordlists")
    wl = Wordlists.query.filter_by(name="AjaxList").first()
    assert wl is not None and is_gzip(wl.path)


def test_ui_upload_ajax_invalid_gzip_returns_json_error(app, client):
    user = _make_user()
    _login(client, user)
    resp = client.post(
        "/wordlists/add",
        data={"name": "AjaxBad", "wordlist": (io.BytesIO(b"\x1f\x8bnotreallygzip"), "x.gz"), "submit": "upload"},
        content_type="multipart/form-data",
        headers={"X-Requested-With": "fetch"},
    )
    assert resp.status_code == 400
    body = resp.get_json()
    assert body["status"] == "error" and body["msg"]
    assert Wordlists.query.filter_by(name="AjaxBad").first() is None


def test_ui_upload_ajax_no_file_returns_json_error(app, client):
    user = _make_user()
    _login(client, user)
    resp = client.post(
        "/wordlists/add",
        data={"name": "NoFile", "submit": "upload"},
        content_type="multipart/form-data",
        headers={"X-Requested-With": "fetch"},
    )
    assert resp.status_code == 400
    assert resp.get_json()["status"] == "error"


def test_delete_static_removes_db_row_and_file(app, client, tmp_path):
    user = _make_user()
    _login(client, user)
    src = tmp_path / "del.txt"
    src.write_bytes(b"a\nb\nc\n")
    wl = ingest_static_wordlist_file(str(src), user.id, "DelMe")
    db.session.add(wl)
    db.session.commit()
    wl_id, path = wl.id, wl.path
    assert os.path.exists(path)

    resp = client.post(f"/wordlists/delete/{wl_id}")
    assert resp.status_code in (302, 200)
    assert Wordlists.query.get(wl_id) is None     # row gone
    assert not os.path.exists(path)               # file gone from disk


def test_delete_dynamic_is_blocked_and_keeps_file(app, client):
    user = _make_user()
    _login(client, user)
    txt = WORDLISTS_DIR / "dyndel.txt"
    txt.write_bytes(b"dyn\n")
    wl = Wordlists(name="(DYNAMIC) keep", owner_id=user.id, type="dynamic",
                   path=str(txt), checksum=get_filehash(str(txt)),
                   size=get_linecount(str(txt)), byte_size=os.path.getsize(txt))
    db.session.add(wl)
    db.session.commit()
    wl_id = wl.id

    resp = client.post(f"/wordlists/delete/{wl_id}")
    assert resp.status_code in (302, 200)
    assert Wordlists.query.get(wl_id) is not None  # not deleted
    assert os.path.exists(str(txt))                # file kept on disk


def test_delete_task_associated_is_blocked_and_keeps_file(app, client, tmp_path):
    user = _make_user()
    _login(client, user)
    src = tmp_path / "used.txt"
    src.write_bytes(b"a\nb\n")
    wl = ingest_static_wordlist_file(str(src), user.id, "UsedWL")
    db.session.add(wl)
    db.session.commit()
    wl_id, path = wl.id, wl.path
    db.session.add(Tasks(name="t", hc_attackmode=0, owner_id=user.id, wl_id=wl_id))
    db.session.commit()

    resp = client.post(f"/wordlists/delete/{wl_id}")
    assert resp.status_code in (302, 200)
    assert Wordlists.query.get(wl_id) is not None  # blocked: still associated
    assert os.path.exists(path)                    # file kept on disk


def test_wordlists_list_page_renders_with_status_modal(app, client):
    """The wordlists page renders (Jinja-clean) and includes the upload
    status-stepper markup wired by the modal JS."""
    user = _make_user()
    _login(client, user)
    resp = client.get("/wordlists")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    # the upload status stepper, incl. the intermediate "Receiving on server"
    # step shown after the bytes finish transferring but before compression
    assert "wl-step-upload" in html
    assert "wl-step-receive" in html
    assert "wl-step-compress" in html
    assert "hvWlSubmit" in html and "hvWlPhase" in html


# ---------------------------------------------------------------------------
# API upload route
# ---------------------------------------------------------------------------

def test_api_upload_plaintext(app, client):
    _make_user(api_key="apikeytext")
    _auth(client, "apikeytext")
    content = b"one\ntwo\nthree\n"
    resp = client.post("/v1/wordlists/add/ApiText", data=content, content_type="text/plain")
    body = resp.get_json()
    assert body["status"] == 200
    wl = Wordlists.query.get(body["wordlist_id"])
    assert wl.name == "ApiText" and is_gzip(wl.path)
    assert wl.size == content.count(b"\n")
    with gzip.open(wl.path, "rb") as f:
        assert f.read() == content


def test_api_upload_gzip_bytes(app, client):
    _make_user(api_key="apikeygz")
    _auth(client, "apikeygz")
    content = b"red\ngreen\nblue\n"
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as f:
        f.write(content)
    resp = client.post("/v1/wordlists/add/ApiGz", data=buf.getvalue(),
                       content_type="application/octet-stream")
    body = resp.get_json()
    assert body["status"] == 200
    wl = Wordlists.query.get(body["wordlist_id"])
    assert is_gzip(wl.path)
    with gzip.open(wl.path, "rb") as f:
        assert f.read() == content


def test_api_upload_rejects_fake_gzip(app, client):
    _make_user(api_key="apikeybad")
    _auth(client, "apikeybad")
    resp = client.post("/v1/wordlists/add/ApiBad", data=b"\x1f\x8bjunkjunkjunk",
                       content_type="application/octet-stream")
    body = resp.get_json()
    assert body["status"] == 400
    assert Wordlists.query.filter_by(name="ApiBad").first() is None


# ---------------------------------------------------------------------------
# Download endpoint
# ---------------------------------------------------------------------------

def test_download_static_served_verbatim(app, client, tmp_path):
    user = _make_user(api_key="dlkey")
    _auth(client, "dlkey")
    content = b"static-a\nstatic-b\nstatic-c\n"
    src = tmp_path / "s.txt"
    src.write_bytes(content)
    wl = ingest_static_wordlist_file(str(src), user.id, "DLStatic")
    db.session.add(wl)
    db.session.commit()
    wl_id, wl_checksum = wl.id, wl.checksum

    resp = client.get(f"/v1/wordlists/{wl_id}")
    assert resp.status_code == 200
    body = resp.data
    assert body[:2] == b"\x1f\x8b"
    # served verbatim -> sha256(body) equals the stored checksum
    assert hashlib.sha256(body).hexdigest() == wl_checksum
    assert gzip.decompress(body) == content


def test_download_dynamic_compressed_on_the_fly(app, client, monkeypatch):
    user = _make_user(api_key="dlkey2")
    _auth(client, "dlkey2")
    content = b"dyn1\ndyn2\n"
    txt = WORDLISTS_DIR / "dyntest.txt"
    txt.write_bytes(content)
    wl = Wordlists(name="(DYNAMIC) test", owner_id=user.id, type="dynamic",
                   path=str(txt), checksum=get_filehash(str(txt)),
                   size=get_linecount(str(txt)), byte_size=os.path.getsize(txt))
    db.session.add(wl)
    db.session.commit()
    txt_checksum = wl.checksum

    # The dynamic download now regenerates into a per-request temp file rather
    # than compressing the stored .txt; make regeneration reproduce the stored
    # bytes so we still verify on-the-fly gzip and the untouched DB checksum.
    import shutil

    import hashview.api.routes as routes_mod
    def _regen(wl_id, dest_path=None):
        shutil.copyfile(Wordlists.query.get(wl_id).path, dest_path)
        return dest_path
    monkeypatch.setattr(routes_mod, "update_dynamic_wordlist", _regen)

    resp = client.get(f"/v1/wordlists/{wl.id}")
    assert resp.status_code == 200
    body = resp.data
    assert body[:2] == b"\x1f\x8b"
    assert gzip.decompress(body) == content
    # DB checksum unchanged and is the plaintext hash (NOT the gz hash): the
    # download path passes dest_path, so update_dynamic_wordlist skips metadata.
    assert Wordlists.query.get(wl.id).checksum == txt_checksum
    assert txt_checksum == get_filehash(str(txt))


def test_download_missing_wordlist_404(app, client):
    _make_user(api_key="dlkey3")
    _auth(client, "dlkey3")
    resp = client.get("/v1/wordlists/99999")
    assert resp.status_code == 404


def test_download_static_missing_file_returns_json_404(app, client):
    # Regression: a static row that outlived its file on disk (e.g. a wordlist
    # stranded across an upgrade, with a relative legacy path) must return a
    # clean, parseable JSON 404 -- not send_from_directory's bare HTML page.
    user = _make_user(api_key="dlmiss")
    _auth(client, "dlmiss")
    wl = Wordlists(name="Stranded", owner_id=user.id, type="static",
                   path="hashview/control/wordlists/deadbeefdeadbeef.gz",
                   checksum="0" * 64, size=0, byte_size=1)
    db.session.add(wl)
    db.session.commit()

    resp = client.get(f"/v1/wordlists/{wl.id}")
    assert resp.status_code == 404
    data = resp.get_json()
    assert data and data["type"] == "Error"
    assert "missing on disk" in data["msg"]


# ---------------------------------------------------------------------------
# Launch migration: compress_existing_wordlists_if_needed
# ---------------------------------------------------------------------------

def test_launch_migration(app, tmp_path):
    user = _make_user()
    # 1) static + uncompressed
    s_content = b"a\nb\nc\nd\n"
    s_path = tmp_path / "old_static.txt"
    s_path.write_bytes(s_content)
    expected_lines = get_linecount(str(s_path))
    static_wl = Wordlists(name="OldStatic", owner_id=user.id, type="static",
                          path=str(s_path), checksum=get_filehash(str(s_path)),
                          size=expected_lines)

    # 2) static + already gzip (a new-style row)
    g_content = b"x\ny\n"
    g_path = tmp_path / "already.gz"
    with gzip.open(str(g_path), "wb", compresslevel=9) as f:
        f.write(g_content)
    gz_wl = Wordlists(name="AlreadyGz", owner_id=user.id, type="static",
                      path=str(g_path), checksum=get_filehash(str(g_path)),
                      size=g_content.count(b"\n") + 1)

    # 3) dynamic (must stay uncompressed; only byte_size backfilled)
    d_content = b"dyn\n"
    d_path = tmp_path / "dyn.txt"
    d_path.write_bytes(d_content)
    dyn_wl = Wordlists(name="(DYNAMIC) x", owner_id=user.id, type="dynamic",
                       path=str(d_path), checksum=get_filehash(str(d_path)),
                       size=get_linecount(str(d_path)))

    # 4) missing file
    miss_wl = Wordlists(name="Missing", owner_id=user.id, type="static",
                        path=str(tmp_path / "nope.txt"), checksum="0" * 64, size=0)

    # 5) Rules row (#435): stored size simulates a pre-fix (count + 1) value,
    # which the backfill must recompute from the actual rule file.
    r_content = b"r1\nr2\nr3\n"
    r_path = tmp_path / "old.rule"
    r_path.write_bytes(r_content)
    rule = Rules(name="OldRule", owner_id=user.id, path=str(r_path),
                checksum=get_filehash(str(r_path)), size=r_content.count(b"\n") + 1)

    db.session.add_all([static_wl, gz_wl, dyn_wl, miss_wl, rule])
    db.session.commit()
    ids = (static_wl.id, gz_wl.id, dyn_wl.id, miss_wl.id)
    rule_id = rule.id
    gz_checksum_before = gz_wl.checksum
    dyn_checksum_before = dyn_wl.checksum
    rule_checksum_before = rule.checksum

    # Called directly (no nested app_context): the test already runs inside the
    # app fixture's context, and per-row commits expire our tracked objects so
    # the re-queries below see the committed values.
    compress_existing_wordlists_if_needed(db)

    static_wl = Wordlists.query.get(ids[0])
    gz_wl = Wordlists.query.get(ids[1])
    dyn_wl = Wordlists.query.get(ids[2])
    miss_wl = Wordlists.query.get(ids[3])

    # static uncompressed -> compressed, old plaintext deleted, checksum=sha256(.gz)
    assert static_wl.path.endswith(".gz") and is_gzip(static_wl.path)
    assert not s_path.exists()
    assert static_wl.size == expected_lines           # no line-count drift
    assert static_wl.checksum == get_filehash(static_wl.path)
    assert static_wl.byte_size == os.path.getsize(static_wl.path)
    with gzip.open(static_wl.path, "rb") as f:
        assert f.read() == s_content

    # already gzip -> path/checksum untouched, byte_size backfilled, and
    # (#435) .size recomputed from the actual .gz content -- this row's
    # size=3 simulated a pre-fix (count + 1) value; the correct count is 2.
    assert gz_wl.path == str(g_path)
    assert gz_wl.checksum == gz_checksum_before
    assert gz_wl.byte_size == os.path.getsize(g_path)
    assert gz_wl.size == g_content.count(b"\n") == 2

    # dynamic -> never compressed, byte_size backfilled, checksum unchanged
    assert dyn_wl.path == str(d_path)
    assert not dyn_wl.path.endswith(".gz")
    assert dyn_wl.checksum == dyn_checksum_before
    assert dyn_wl.byte_size == os.path.getsize(d_path)

    # missing file -> row left intact
    assert miss_wl.byte_size is None
    assert miss_wl.path.endswith("nope.txt")

    # Rules row (#435) -> size recomputed from the actual rule file, checksum
    # and path untouched.
    rule = Rules.query.get(rule_id)
    assert rule.path == str(r_path)
    assert rule.checksum == rule_checksum_before
    assert rule.size == r_content.count(b"\n") == 3

    # idempotent: second run is a no-op
    path_after = static_wl.path
    checksum_after = static_wl.checksum
    # (#435) the one-time line-count backfill is marker-guarded: deliberately
    # corrupt gz_wl.size and rule.size and confirm the second run does NOT
    # touch either again (a 14M-line rockyou.txt.gz must not be re-counted
    # every boot).
    gz_wl = Wordlists.query.get(ids[1])
    gz_wl.size = 999
    rule.size = 998
    db.session.commit()
    compress_existing_wordlists_if_needed(db)
    static_wl = Wordlists.query.get(ids[0])
    gz_wl = Wordlists.query.get(ids[1])
    rule = Rules.query.get(rule_id)
    assert static_wl.path == path_after
    assert static_wl.checksum == checksum_after
    assert gz_wl.size == 999                          # untouched: marker already set
    assert rule.size == 998                           # untouched: marker already set


def test_migration_normalizes_relative_wordlist_path(app, client, tmp_path):
    # A legacy row with a RELATIVE .gz path whose file IS present in the
    # wordlists dir (the exact shape that stranded wordlist 6) gets its path
    # rewritten to absolute, so the download route and cracking commands find it
    # regardless of the process CWD.
    user = _make_user(api_key="relkey")
    _auth(client, "relkey")
    content = b"one\ntwo\n"
    gzname = secrets.token_hex(8) + ".gz"
    abs_gz = WORDLISTS_DIR / gzname
    with gzip.open(str(abs_gz), "wb", compresslevel=9) as f:
        f.write(content)
    rel_path = os.path.join("hashview", "control", "wordlists", gzname)   # legacy relative form
    wl = Wordlists(name="RelPath", owner_id=user.id, type="static",
                   path=rel_path, checksum=get_filehash(str(abs_gz)), size=2, byte_size=None)
    db.session.add(wl)
    db.session.commit()
    wl_id = wl.id

    compress_existing_wordlists_if_needed(db)

    wl = Wordlists.query.get(wl_id)
    assert os.path.isabs(wl.path)
    assert os.path.abspath(wl.path) == os.path.abspath(str(abs_gz))
    assert wl.byte_size == os.path.getsize(str(abs_gz))
    # end-to-end: it now serves
    resp = client.get(f"/v1/wordlists/{wl_id}")
    assert resp.status_code == 200
    assert gzip.decompress(resp.data) == content


def test_migration_compresses_into_wordlists_dir(app, tmp_path):
    # A static, uncompressed legacy file living OUTSIDE the wordlists dir must be
    # compressed INTO the absolute wordlists dir (not next to the source), so it
    # lands where the download route serves from.
    user = _make_user(api_key="cmpkey")
    content = b"aa\nbb\ncc\n"
    src = tmp_path / "legacy_plain.txt"
    src.write_bytes(content)
    wl = Wordlists(name="LegacyPlain", owner_id=user.id, type="static",
                   path=str(src), checksum=get_filehash(str(src)), size=3)
    db.session.add(wl)
    db.session.commit()
    wl_id = wl.id

    compress_existing_wordlists_if_needed(db)

    wl = Wordlists.query.get(wl_id)
    assert os.path.isabs(wl.path)
    assert os.path.dirname(os.path.abspath(wl.path)) == os.path.abspath(str(WORDLISTS_DIR))
    assert is_gzip(wl.path)
    assert not src.exists()   # old plaintext removed after the durable commit
    with gzip.open(wl.path, "rb") as f:
        assert f.read() == content


# ---------------------------------------------------------------------------
# build_hashcat_command emits the .gz path the agent stores
# ---------------------------------------------------------------------------

def _setup_job_for_wordlist(user, wl, attackmode=0, rule_id=None):
    hsh = Hashes(sub_ciphertext="0" * 8, ciphertext="abcd", hash_type=0, cracked=False)
    db.session.add(hsh)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=hsh.id, hashfile_id=1))
    job = Jobs(name="j", status="Queued", hashfile_id=1, customer_id=1, owner_id=user.id)
    db.session.add(job)
    task = Tasks(name="t", hc_attackmode=attackmode, owner_id=user.id, wl_id=wl.id, rule_id=rule_id)
    db.session.add(task)
    db.session.commit()
    return job, task


@pytest.mark.parametrize("attackmode", [0, 1, 6, 7])
def test_build_hashcat_command_static_gz(app, tmp_path, attackmode):
    user = _make_user()
    src = tmp_path / "hc.txt"
    src.write_bytes(b"a\nb\n")
    wl = ingest_static_wordlist_file(str(src), user.id, "HCList")
    db.session.add(wl)
    db.session.commit()
    gz_basename = os.path.basename(wl.path)            # '<hex>.gz'
    job, task = _setup_job_for_wordlist(user, wl, attackmode=attackmode)
    if attackmode in (6, 7):
        task.hc_mask = "?d?d"
        db.session.commit()
    cmd = build_hashcat_command(job.id, task.id)

    expected = "control/wordlists/" + gz_basename
    assert expected in cmd
    # agent stores the file under exactly this basename
    assert ensure_gz(gz_basename) == gz_basename


def test_build_hashcat_command_combinator_uses_second_wordlist(app, tmp_path):
    """Combinator (`-a 1`) must reference BOTH wordlists, not wordlist 1 twice.

    Regression test for a copy/paste bug: the second dictionary path was
    computed from `wordlist` (the first list) and then never used, so the
    emitted command listed wordlist 1 in both dictionary positions. With the
    fix the command must contain the distinct wordlist-2 path.
    """
    user = _make_user()
    src1 = tmp_path / "left.txt"
    src1.write_bytes(b"a\nb\n")
    src2 = tmp_path / "right.txt"
    src2.write_bytes(b"c\nd\ne\n")
    wl1 = ingest_static_wordlist_file(str(src1), user.id, "Left")
    wl2 = ingest_static_wordlist_file(str(src2), user.id, "Right")
    db.session.add_all([wl1, wl2])
    db.session.commit()
    gz1 = "control/wordlists/" + os.path.basename(wl1.path)
    gz2 = "control/wordlists/" + os.path.basename(wl2.path)
    assert gz1 != gz2

    job, task = _setup_job_for_wordlist(user, wl1, attackmode=1)
    task.wl_id_2 = wl2.id
    db.session.commit()

    cmd = " ".join(build_hashcat_command(job.id, task.id))   # argv list -> joined for substring checks
    assert " -a 1 " in cmd
    assert gz1 in cmd                      # left dictionary
    assert gz2 in cmd                      # right dictionary — the bug dropped this


def test_build_hashcat_command_static_dict_plus_rule(app, tmp_path):
    user = _make_user()
    src = tmp_path / "hc.txt"
    src.write_bytes(b"a\nb\n")
    wl = ingest_static_wordlist_file(str(src), user.id, "HCRule")
    db.session.add(wl)
    db.session.commit()
    gz_basename = os.path.basename(wl.path)
    rule = Rules(name="r", owner_id=user.id, path="control/rules/best64.rule",
                 checksum="0" * 64, size=1)
    db.session.add(rule)
    db.session.commit()
    job, task = _setup_job_for_wordlist(user, wl, attackmode=0, rule_id=rule.id)
    cmd = " ".join(build_hashcat_command(job.id, task.id))   # argv list -> joined for substring checks
    assert "-r control/rules/best64.rule" in cmd
    assert "control/wordlists/" + gz_basename in cmd


def test_build_hashcat_command_dynamic_gz_suffix(app):
    user = _make_user()
    txt = WORDLISTS_DIR / "dyncmd.txt"
    txt.write_bytes(b"a\nb\n")
    wl = Wordlists(name="(DYNAMIC) cmd", owner_id=user.id, type="dynamic",
                   path=str(txt), checksum=get_filehash(str(txt)),
                   size=get_linecount(str(txt)), byte_size=os.path.getsize(txt))
    db.session.add(wl)
    db.session.commit()
    job, task = _setup_job_for_wordlist(user, wl, attackmode=0)
    cmd = build_hashcat_command(job.id, task.id)
    # dynamic '<name>.txt' -> agent stores '<name>.txt.gz'; server emits same
    assert "control/wordlists/dyncmd.txt.gz" in cmd


# ---------------------------------------------------------------------------
# Agent sync_wordlists logic (extracted + executed in isolation)
# ---------------------------------------------------------------------------

class _FakeManifest:
    def __init__(self, data=None):
        self.data = data or {}
        self.saved = 0

    def save(self):
        self.saved += 1


class _FakeApi:
    def __init__(self, entries, files):
        self._entries = entries
        self._files = files
        self.download_calls = []

    def getWordlists(self):
        # Native list, matching the server's post-#229 response (no double-encode).
        return self._entries

    def get_wordlists_file(self, wid):
        self.download_calls.append(wid)
        return self._files.get(wid)


def _load_agent_sync(manifest, api_obj):
    """Extract _gz_name/_sha256_file/sync_wordlists from the agent script and
    exec them in a namespace with injected globals (so we don't import the
    whole agent, which parses argv and reads config at import time)."""
    src = AGENT_SCRIPT.read_text()
    tree = ast.parse(src)
    wanted = {"_gz_name", "_safe_control_filename", "_sha256_file",
              "_prune_orphan_files", "sync_wordlists"}
    chunks = []
    found = set()
    for n in tree.body:
        if isinstance(n, ast.FunctionDef) and n.name in wanted:
            seg = ast.get_source_segment(src, n)
            assert seg is not None, f"could not extract source for {n.name}"
            chunks.append(seg)
            found.add(n.name)
    missing = wanted - found
    assert not missing, f"agent functions not found at module level: {missing}"
    ns = {"os": os, "hashlib": hashlib, "json": json, "secrets": secrets,
          "logging": logging,
          "LOG": logging.getLogger("test-agent-sim"),
          "print": print, "api": api_obj, "wordlists_manifest": manifest}
    exec("\n\n".join(chunks), ns)
    return ns


def _gz_bytes(content):
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as f:
        f.write(content)
    return buf.getvalue()


def test_agent_sync_static_verifies_and_stores_gz(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    gzb = _gz_bytes(b"a\nb\n")
    checksum = hashlib.sha256(gzb).hexdigest()
    entries = [{"id": 1, "checksum": checksum, "type": "static", "path": "/srv/control/wordlists/abc.gz"}]
    manifest = _FakeManifest()
    api_obj = _FakeApi(entries, {1: gzb})
    ns = _load_agent_sync(manifest, api_obj)

    ns["sync_wordlists"]()

    stored = tmp_path / "control" / "wordlists" / "abc.gz"
    assert stored.exists()
    assert stored.read_bytes() == gzb
    assert manifest.data["1"] == {"checksum": checksum, "filename": "abc.gz"}


def test_agent_sync_static_checksum_mismatch_dropped(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    gzb = _gz_bytes(b"a\nb\n")
    entries = [{"id": 1, "checksum": "deadbeef", "type": "static", "path": "/x/abc.gz"}]
    manifest = _FakeManifest()
    ns = _load_agent_sync(manifest, _FakeApi(entries, {1: gzb}))

    ns["sync_wordlists"]()

    assert not (tmp_path / "control" / "wordlists" / "abc.gz").exists()
    assert "1" not in manifest.data


def test_agent_sync_skips_dynamic_entries(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # Dynamic wordlists are fetched on demand per task by
    # maybe_update_dynamic_wordlist, NOT by sync_wordlists. sync must skip them:
    # no download, no stored file, no manifest entry.
    gzb = _gz_bytes(b"dyn\n")
    entries = [{"id": 2, "checksum": "plaintexthash", "type": "dynamic",
                "path": "/x/dynamic-foo.txt"}]
    manifest = _FakeManifest()
    api_obj = _FakeApi(entries, {2: gzb})
    ns = _load_agent_sync(manifest, api_obj)

    ns["sync_wordlists"]()

    assert api_obj.download_calls == []
    assert not (tmp_path / "control" / "wordlists" / "dynamic-foo.txt.gz").exists()
    assert "2" not in manifest.data


def test_agent_sync_transition_guard_resets_txt_manifest(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # legacy manifest entry stored a decompressed '.txt' filename
    manifest = _FakeManifest({"9": {"checksum": "old", "filename": "legacy.txt"}})
    ns = _load_agent_sync(manifest, _FakeApi([], {}))

    ns["sync_wordlists"]()

    assert "9" not in manifest.data


def test_agent_sync_no_redownload_when_checksum_matches(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    entries = [{"id": 1, "checksum": "C", "type": "static", "path": "/x/abc.gz"}]
    manifest = _FakeManifest({"1": {"checksum": "C", "filename": "abc.gz"}})
    api_obj = _FakeApi(entries, {1: b"shouldnotbeused"})
    ns = _load_agent_sync(manifest, api_obj)

    ns["sync_wordlists"]()

    assert api_obj.download_calls == []                 # no download
    assert manifest.data["1"] == {"checksum": "C", "filename": "abc.gz"}
