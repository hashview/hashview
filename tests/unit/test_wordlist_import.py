"""Unit tests for the server-side wordlist drop-folder import
(hashview.utils.wordlist_import + POST /wordlists/import).

Users scp/rsync large wordlists into ``control/wordlists_import/`` and trigger
an import from the Wordlists page. The import reuses ``ingest_static_wordlist_file``
(so the result is byte-identical to a GUI upload — stored gzip-compressed at
rest), is audit-logged, and removes the original on success.

These tests:
  - monkeypatch ``wordlist_import.import_dir`` to an isolated tmp drop folder so
    they never touch the real ``control/wordlists_import/`` (both
    ``list_importable`` and ``run_import`` look the function up as a module
    global, so one patch covers both);
  - re-point the audit logger into tmp_path (HASHVIEW_LOGS_DIR) to assert the
    ``wordlist.create`` / ``wordlist.import_failed`` lines;
  - clean up any ``.gz`` the ingest drops into the real ``control/wordlists``.

The import logic (``run_import``) is exercised directly inside the ``app``
fixture's context — the same proven pattern as test_wordlist_gzip_storage.py,
which avoids the separate-session-scope pitfall of a nested ``app.app_context()``
(that wrapping now lives in ``run_import_async``, the thread target). The route
is tested with a synchronous fake thread so the queued call is observable.

All tests are marked ``@pytest.mark.security`` so the parent autouse fixtures
that need Playwright + a live HTTP server are skipped (see conftest).
"""

import gzip
import json
import os
import time
from pathlib import Path

import pytest

from hashview.models import Users, Wordlists
from hashview.models import db as _db
from hashview.utils import wordlist_import as wli
from hashview.utils.audit import AUDIT_FILE, configure_audit_logging, logs_dir
from hashview.utils.utils import is_gzip

REPO_ROOT = Path(__file__).resolve().parents[2]
WORDLISTS_DIR = REPO_ROOT / "hashview" / "control" / "wordlists"


@pytest.fixture(autouse=True)
def _clean_wordlists_dir():
    """Remove any .gz the ingest drops into the real control/wordlists dir."""
    before = set(os.listdir(WORDLISTS_DIR)) if WORDLISTS_DIR.exists() else set()
    yield
    if WORDLISTS_DIR.exists():
        for name in set(os.listdir(WORDLISTS_DIR)) - before:
            try:
                os.remove(WORDLISTS_DIR / name)
            except OSError:
                pass


@pytest.fixture()
def drop(tmp_path, monkeypatch):
    """An isolated drop folder; point wordlist_import.import_dir at it."""
    d = tmp_path / "wordlists_import"
    d.mkdir()
    monkeypatch.setattr(wli, "import_dir", lambda app: str(d))
    return d


@pytest.fixture()
def audit(app, tmp_path):
    """Re-point the audit logger into tmp_path and return a line reader."""
    app.config["HASHVIEW_LOGS_DIR"] = str(tmp_path / "logs")
    configure_audit_logging(app)

    def read(event=None):
        path = os.path.join(logs_dir(app), AUDIT_FILE)
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8") as fh:
            rows = [json.loads(line) for line in fh if line.strip()]
        return [r for r in rows if event is None or r["event"] == event]

    return read


def _user():
    u = Users(first_name="Imp", last_name="Orter", email_address="imp@example.com",
              password="x" * 60, admin=True)
    _db.session.add(u)
    _db.session.commit()
    return u


def _login(client, user):
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True


def _make_stable(path, age=wli.QUIESCE_SECONDS + 60):
    """Write a file's mtime into the past so it passes the quiescence guard."""
    past = time.time() - age
    os.utime(path, (past, past))


# ---------------------------------------------------------------------------
# run_import — the import logic (called directly, in-context)
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_import_plaintext_creates_row_and_removes_original(app, drop, audit):
    user = _user()
    content = b"password\n123456\nletmein\n"
    src = drop / "rockyou-sample.txt"
    src.write_bytes(content)
    _make_stable(src)

    summary = wli.run_import(app, ["rockyou-sample.txt"], user.id)

    assert summary["imported"] == ["rockyou-sample.txt"]
    wl = Wordlists.query.filter_by(name="rockyou-sample").first()
    assert wl is not None
    assert wl.type == "static" and wl.owner_id == user.id
    assert wl.path.endswith(".gz") and is_gzip(wl.path)
    assert wl.size == content.count(b"\n")          # get_linecount semantics
    with gzip.open(wl.path, "rb") as fh:
        assert fh.read() == content
    # the original drop file is gone (consumed on success)
    assert not src.exists()
    assert not (drop / "rockyou-sample.txt.importing").exists()

    created = audit("wordlist.create")
    assert created and created[-1]["detail"] == "imported from drop folder"
    assert created[-1]["actor"] == user.email_address
    assert created[-1]["actor_id"] == user.id


@pytest.mark.security
def test_import_gz_recompresses(app, drop):
    user = _user()
    content = b"".join(b"line-%d\n" % i for i in range(2000))
    src = drop / "big.gz"
    with gzip.open(str(src), "wb", compresslevel=1) as fh:
        fh.write(content)
    _make_stable(src)

    summary = wli.run_import(app, ["big.gz"], user.id)

    assert summary["imported"] == ["big.gz"]
    wl = Wordlists.query.filter_by(name="big").first()   # trailing .gz dropped
    assert wl is not None and is_gzip(wl.path)
    assert wl.size == content.count(b"\n")
    with gzip.open(wl.path, "rb") as fh:
        assert fh.read() == content
    assert not src.exists()


@pytest.mark.security
def test_too_fresh_file_is_skipped(app, drop):
    """A file still being copied (recent mtime) is left untouched."""
    user = _user()
    src = drop / "fresh.txt"
    src.write_bytes(b"a\nb\n")
    # do NOT age it — mtime is now → not quiescent

    summary = wli.run_import(app, ["fresh.txt"], user.id)

    assert summary["skipped"] == ["fresh.txt"]
    assert summary["imported"] == []
    assert src.exists()                                  # untouched
    assert Wordlists.query.filter_by(name="fresh").first() is None


@pytest.mark.security
def test_binary_file_rejected_to_failed(app, drop, audit):
    """A non-text, non-gz file (NUL bytes) is rejected and left as .failed."""
    user = _user()
    src = drop / "image.txt"
    src.write_bytes(b"PNG\x00\x00\x01binary\x00payload")
    _make_stable(src)

    summary = wli.run_import(app, ["image.txt"], user.id)

    assert summary["failed"] == ["image.txt"]
    assert Wordlists.query.filter_by(name="image").first() is None
    assert not src.exists()                              # renamed aside
    assert (drop / "image.txt.failed").exists()          # kept for diagnosis
    failed = audit("wordlist.import_failed")
    assert failed and failed[-1]["outcome"] == "failure"
    assert "image.txt" in (failed[-1]["detail"] or "")


@pytest.mark.security
def test_missing_file_is_skipped_not_failed(app, drop):
    user = _user()
    summary = wli.run_import(app, ["does-not-exist.txt"], user.id)
    assert summary["skipped"] == ["does-not-exist.txt"]
    assert summary["imported"] == [] and summary["failed"] == []


@pytest.mark.security
def test_basename_traversal_is_neutralised(app, drop):
    """A posted path with directory components is reduced to its basename, so it
    can only ever resolve inside the drop folder (and here, to nothing)."""
    user = _user()
    summary = wli.run_import(app, ["../../../etc/passwd"], user.id)
    # basename 'passwd' isn't in the drop folder → skipped, never read
    assert summary["imported"] == []
    assert summary["failed"] == []


# ---------------------------------------------------------------------------
# list_importable — the UI listing
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_list_importable_flags(app, drop):
    # a stable pending file
    ready = drop / "ready.txt"
    ready.write_bytes(b"a\nb\n")
    _make_stable(ready)
    # a still-uploading file (recent mtime)
    uploading = drop / "uploading.txt"
    uploading.write_bytes(b"x\n")
    # an in-progress claim and a prior failure
    (drop / "inflight.txt.importing").write_bytes(b"")
    (drop / "broken.txt.failed").write_bytes(b"")
    # noise that must be ignored
    (drop / ".hidden").write_bytes(b"secret\n")

    listed = {f["name"]: f for f in wli.list_importable(app)}

    assert listed["ready.txt"]["status"] == "pending"
    assert listed["ready.txt"]["uploading"] is False
    assert listed["ready.txt"]["size"]                       # human size rendered
    assert listed["uploading.txt"]["uploading"] is True
    assert listed["inflight.txt"]["status"] == "importing"
    assert listed["broken.txt"]["status"] == "failed"
    assert ".hidden" not in listed                           # dotfiles skipped


# ---------------------------------------------------------------------------
# POST /wordlists/import — route validation + non-blocking dispatch
# ---------------------------------------------------------------------------


class _SyncThread:
    """Stand-in for threading.Thread that runs the target inline so the queued
    call is observable within the request (no real background thread)."""

    def __init__(self, target=None, args=(), daemon=None, **_):
        self._target, self._args = target, args

    def start(self):
        self._target(*self._args)


@pytest.mark.security
def test_import_route_queues_selected(app, client, drop, monkeypatch):
    user = _user()
    _login(client, user)
    src = drop / "queued.txt"
    src.write_bytes(b"a\nb\nc\n")
    _make_stable(src)

    calls = []
    monkeypatch.setattr("hashview.wordlists.routes.run_import_async",
                        lambda app_, files, owner: calls.append((files, owner)))
    monkeypatch.setattr("hashview.wordlists.routes.threading.Thread", _SyncThread)

    resp = client.post("/wordlists/import", data={"files": "queued.txt"})

    assert resp.status_code in (301, 302)               # redirect, not blocked
    assert calls == [(["queued.txt"], user.id)]         # right file, importer owns it


@pytest.mark.security
def test_import_route_all_flag_queues_everything_pending(app, client, drop, monkeypatch):
    user = _user()
    _login(client, user)
    for n in ("one.txt", "two.txt"):
        p = drop / n
        p.write_bytes(b"a\n")
        _make_stable(p)
    # an uploading file must NOT be swept up by "all"
    busy = drop / "busy.txt"
    busy.write_bytes(b"a\n")

    calls = []
    monkeypatch.setattr("hashview.wordlists.routes.run_import_async",
                        lambda app_, files, owner: calls.append((files, owner)))
    monkeypatch.setattr("hashview.wordlists.routes.threading.Thread", _SyncThread)

    resp = client.post("/wordlists/import", data={"all": "1"})

    assert resp.status_code in (301, 302)
    assert calls and sorted(calls[0][0]) == ["one.txt", "two.txt"]
    assert "busy.txt" not in calls[0][0]


@pytest.mark.security
def test_import_route_nothing_to_import_warns(app, client, drop, monkeypatch):
    user = _user()
    _login(client, user)
    calls = []
    monkeypatch.setattr("hashview.wordlists.routes.run_import_async",
                        lambda app_, files, owner: calls.append((files, owner)))
    monkeypatch.setattr("hashview.wordlists.routes.threading.Thread", _SyncThread)

    # request import of a file that isn't in the folder
    resp = client.post("/wordlists/import", data={"files": "ghost.txt"},
                       follow_redirects=True)
    assert resp.status_code == 200
    assert calls == []                                   # nothing dispatched
    assert b"Nothing to import" in resp.data


@pytest.mark.security
def test_import_route_requires_login(app, client, drop):
    resp = client.post("/wordlists/import", data={"all": "1"})
    # @login_required → redirect to the login page
    assert resp.status_code in (301, 302)
    assert "/login" in resp.headers.get("Location", "")


# ---------------------------------------------------------------------------
# Template wiring — GET /wordlists renders the import panel
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_wordlists_page_lists_drop_files(app, client, drop):
    user = _user()
    _login(client, user)
    ready = drop / "panel.txt"
    ready.write_bytes(b"a\nb\n")
    _make_stable(ready)

    resp = client.get("/wordlists")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "Import from server" in html
    assert "panel.txt" in html
    assert 'name="files" value="panel.txt"' in html      # selectable checkbox
    assert "Import selected" in html and "Import all" in html


@pytest.mark.security
def test_wordlists_page_shows_hint_when_drop_empty(app, client, drop):
    user = _user()
    _login(client, user)
    resp = client.get("/wordlists")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    # empty folder → discovery hint, no import form
    assert "control/wordlists_import/" in html
    assert "Import from server" not in html
