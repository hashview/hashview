"""Unit tests for the (DYNAMIC) Website Keywords wordlist feature.

Covers:
  - registration of the new dynamic wordlist (setup seeding + hashview.py),
  - the alembic migration that adds Settings crawl_* columns + Jobs.crawl_url,
  - the crawl settings in the Settings UI,
  - the conditional job-creation "Website URL" step,
  - the CeWL-style crawler (against a local http.server),
  - the end-to-end regenerate path: /v1/updateWordlist resolves the agent's
    running job, crawls the job URL, writes the wordlist, and the download
    endpoint serves a gzip of it.

Uses the in-memory SQLite app from tests/unit/conftest.py. Cookie domain must
match SERVER_NAME (localhost.test) for Werkzeug 3.x to send it.
"""

import gzip
import importlib.util
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, inspect, text
from alembic.migration import MigrationContext
from alembic.operations import Operations

from hashview.models import (db, Users, Wordlists, Jobs, Tasks, JobTasks, Agents, Settings)
from hashview.setup import (_DYNAMIC_WORDLISTS, add_default_dynamic_wordlists,
                            default_dynamic_wordlists_need_added)
from hashview.jobs.routes import _job_uses_website_keywords
from hashview.utils.crawler import crawl_website_keywords
from hashview.utils.utils import update_dynamic_wordlist, get_filehash, get_linecount

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTROL = REPO_ROOT / "hashview" / "control"
WORDLISTS_DIR = CONTROL / "wordlists"
TMP_DIR = CONTROL / "tmp"
# The crawl_* / jobs.crawl_url DDL that used to live in its own migration
# (5c2e1f4a9d37) is now part of the v0.8.3-dev squash migration; this test
# exercises the crawl columns + existing-row backfill through that squash.
MIGRATION = REPO_ROOT / "migrations" / "versions" / "c8b3f0a14d27_squash_v0_8_3_dev_schema_delta.py"
WL_NAME = "(DYNAMIC) Website Keywords"
COOKIE_DOMAIN = "localhost.test"


@pytest.fixture(autouse=True)
def _clean_control_dirs():
    def snap(d):
        return set(os.listdir(d)) if d.exists() else set()
    before = {WORDLISTS_DIR: snap(WORDLISTS_DIR), TMP_DIR: snap(TMP_DIR)}
    yield
    for d, names in before.items():
        if not d.exists():
            continue
        for n in set(os.listdir(d)) - names:
            try:
                os.remove(d / n)
            except OSError:
                pass


def _admin(api_key="wk-api-key"):
    u = Users(first_name="A", last_name="D", email_address="a@e.com",
              password="x" * 60, admin=True, api_key=api_key)
    db.session.add(u)
    db.session.commit()
    return u


def _login(client, user):
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True


# ---------------------------------------------------------------------------
# 1. Registration / seeding
# ---------------------------------------------------------------------------

def test_wordlist_registered_in_setup_and_hashview_py():
    assert any(name == WL_NAME for name, _ in _DYNAMIC_WORDLISTS)
    # hashview.py (the standalone CLI) seeds the same list
    assert WL_NAME in (REPO_ROOT / "hashview.py").read_text()


def test_seed_creates_and_is_idempotent(app, tmp_path, monkeypatch):
    # Redirect the seed list to a tmp file so we don't touch the real control dir.
    seed_path = str(tmp_path / "dyn-website-keywords.txt")
    monkeypatch.setattr("hashview.setup._DYNAMIC_WORDLISTS",
                        ((WL_NAME, seed_path),))
    assert default_dynamic_wordlists_need_added(db) is True
    add_default_dynamic_wordlists(db)

    row = Wordlists.query.filter_by(name=WL_NAME).first()
    assert row is not None and row.type == "dynamic" and row.size == 0
    assert os.path.exists(seed_path)
    assert default_dynamic_wordlists_need_added(db) is False

    add_default_dynamic_wordlists(db)            # second run: no duplicate
    assert Wordlists.query.filter_by(name=WL_NAME).count() == 1


# ---------------------------------------------------------------------------
# 2. Migration (isolated, SQLite batch mode)
# ---------------------------------------------------------------------------

# Minimal base tables the v0.8.3-dev squash touches on SQLite (the MySQL-only
# CHARACTER SET widenings are dialect-guarded and skipped here). Enough to let
# the squash's batch_alter_table / create_index / create_table ops run.
_SQUASH_BASE_TABLES = (
    "CREATE TABLE wordlists (id INTEGER PRIMARY KEY)",
    "CREATE TABLE settings (id INTEGER PRIMARY KEY, enabled_job_weights BOOLEAN)",
    "CREATE TABLE jobs (id INTEGER PRIMARY KEY, name VARCHAR(50))",
    "CREATE TABLE users (id INTEGER PRIMARY KEY, first_name VARCHAR(50), "
    "last_name VARCHAR(50), email_address VARCHAR(50))",
    "CREATE TABLE tasks (id INTEGER PRIMARY KEY)",
    "CREATE TABLE hashfile_hashes (id INTEGER PRIMARY KEY, hashfile_id INTEGER)",
    "CREATE TABLE agents (id INTEGER PRIMARY KEY)",
    "CREATE TABLE job_tasks (id INTEGER PRIMARY KEY)",
    "CREATE TABLE hashfiles (id INTEGER PRIMARY KEY)",
)


def test_migration_adds_columns_and_backfills(tmp_path):
    # The crawl_* columns now ship inside the squashed v0.8.3-dev migration,
    # which sits directly on top of the last released head.
    spec = importlib.util.spec_from_file_location("m_squash", MIGRATION)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.revision == "c8b3f0a14d27"
    assert mod.down_revision == "8a5b0fff063d"

    dbfile = tmp_path / "m.sqlite"
    eng = create_engine(f"sqlite:///{dbfile}")
    with eng.begin() as conn:
        for stmt in _SQUASH_BASE_TABLES:
            conn.execute(text(stmt))
        conn.execute(text("INSERT INTO settings (id, enabled_job_weights) VALUES (1, 0)"))
        conn.execute(text("INSERT INTO jobs (id, name) VALUES (1, 'j')"))

    with eng.begin() as conn:
        with Operations.context(MigrationContext.configure(conn)):
            mod.upgrade()

    insp = inspect(eng)
    scols = {c["name"] for c in insp.get_columns("settings")}
    assert {"crawl_min_word_length", "crawl_user_agent", "crawl_force_lowercase",
            "crawl_depth", "crawl_threads"} <= scols
    assert "crawl_url" in {c["name"] for c in insp.get_columns("jobs")}
    # existing settings row backfilled via server_default
    with eng.connect() as conn:
        row = conn.execute(text("SELECT crawl_min_word_length, crawl_depth, crawl_threads, "
                                "crawl_force_lowercase FROM settings WHERE id=1")).first()
    assert row[0] == 8 and row[1] == 2 and row[2] == 5 and row[3] in (1, True)

    with eng.begin() as conn:
        with Operations.context(MigrationContext.configure(conn)):
            mod.downgrade()
    assert "crawl_url" not in {c["name"] for c in inspect(eng).get_columns("jobs")}
    assert "crawl_threads" not in {c["name"] for c in inspect(eng).get_columns("settings")}


# ---------------------------------------------------------------------------
# 3. Settings model defaults + Settings UI
# ---------------------------------------------------------------------------

def test_settings_model_defaults(app):
    s = Settings(retention_period=30, max_runtime_jobs=0, max_runtime_tasks=0)
    db.session.add(s)
    db.session.commit()
    s = Settings.query.first()
    assert s.crawl_min_word_length == 8
    assert s.crawl_force_lowercase is True
    assert s.crawl_depth == 2 and s.crawl_threads == 5
    assert "Hashview-Crawler" in s.crawl_user_agent


def test_settings_ui_shows_and_saves_crawl_fields(app, client):
    user = _admin()
    db.session.add(Settings(retention_period=30, max_runtime_jobs=0, max_runtime_tasks=0))
    db.session.commit()
    _login(client, user)

    resp = client.get("/settings")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "set-crawl-ua" in html and "set-crawl-minlen" in html

    resp = client.post("/settings", data={
        "retention_period": "30", "max_runtime_jobs": "0", "max_runtime_tasks": "0",
        "agent_timeout_minutes": "60", "chunk_target_duration": "3600",
        "crawl_min_word_length": "10", "crawl_user_agent": "MyUA/9",
        "crawl_force_lowercase": "y", "crawl_depth": "3", "crawl_threads": "7",
        "submit": "Update",
    }, follow_redirects=False)
    assert resp.status_code in (302, 200)
    s = Settings.query.first()
    assert s.crawl_min_word_length == 10 and s.crawl_user_agent == "MyUA/9"
    assert s.crawl_depth == 3 and s.crawl_threads == 7 and s.crawl_force_lowercase is True


# ---------------------------------------------------------------------------
# 4. Job-creation URL step
# ---------------------------------------------------------------------------

def _make_wk_wordlist():
    wl = Wordlists(name=WL_NAME, owner_id=1, type="dynamic",
                   path=str(WORDLISTS_DIR / "dynamic-website-keywords.txt"),
                   checksum="0" * 64, size=0)
    db.session.add(wl)
    db.session.commit()
    return wl


def _make_job_with_task(user, wl_id=None):
    job = Jobs(name="j", status="Incomplete", customer_id=1, owner_id=user.id)
    db.session.add(job)
    task = Tasks(name="t", hc_attackmode=0, owner_id=user.id, wl_id=wl_id)
    db.session.add(task)
    db.session.commit()
    db.session.add(JobTasks(job_id=job.id, task_id=task.id, status="Not Started"))
    db.session.commit()
    return job, task


def test_job_uses_website_keywords_helper(app):
    user = _admin()
    wl = _make_wk_wordlist()
    job, _ = _make_job_with_task(user, wl_id=wl.id)
    assert _job_uses_website_keywords(job.id) is True
    # a job whose task uses a different (static) wordlist
    other = Wordlists(name="Static", owner_id=1, type="static",
                      path=str(WORDLISTS_DIR / "x.gz"), checksum="1" * 64, size=1)
    db.session.add(other)
    db.session.commit()
    job2, _ = _make_job_with_task(user, wl_id=other.id)
    assert _job_uses_website_keywords(job2.id) is False


def test_job_website_step_shows_and_stores_url(app, client):
    user = _admin()
    _login(client, user)
    wl = _make_wk_wordlist()
    job, _ = _make_job_with_task(user, wl_id=wl.id)

    resp = client.get(f"/jobs/{job.id}/website")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "show-website" in html and "Website URL" in html

    resp = client.post(f"/jobs/{job.id}/website",
                       data={"crawl_url": "https://example.com", "submit": "Next"},
                       follow_redirects=False)
    # The wizard chain is website -> provider_input -> summary; the provider_input
    # step self-skips to summary when no task uses a provider-backed wordlist.
    assert resp.status_code == 302 and f"/jobs/{job.id}/provider_input" in resp.headers["Location"]
    assert Jobs.query.get(job.id).crawl_url == "https://example.com"


def test_job_website_step_skipped_when_not_applicable(app, client):
    user = _admin()
    _login(client, user)
    static = Wordlists(name="Static", owner_id=1, type="static",
                       path=str(WORDLISTS_DIR / "x.gz"), checksum="1" * 64, size=1)
    db.session.add(static)
    db.session.commit()
    job, _ = _make_job_with_task(user, wl_id=static.id)

    # The website step self-skips to the next step (/provider_input, which then
    # self-skips to /summary for a job with no provider wordlist).
    resp = client.get(f"/jobs/{job.id}/website", follow_redirects=False)
    assert resp.status_code == 302 and f"/jobs/{job.id}/provider_input" in resp.headers["Location"]


# ---------------------------------------------------------------------------
# 5. Crawler (against a local http.server)
# ---------------------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    PAGES = {}

    def do_GET(self):
        body = self.PAGES.get(self.path.split("?")[0])
        if body is None:
            self.send_response(404); self.end_headers(); return
        body = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _serve(pages):
    _Handler.PAGES = pages
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, srv.server_address[1]


def test_crawler_extracts_unique_words_respecting_settings():
    pages = {
        "/": ("<html><head><style>bodyfont</style></head><body>"
              "HASHVIEW hashview keyboard alpha cat "
              "<script>secretjavascript</script>"
              "<a href='/page2.html'>more</a>"
              "<a href='https://offsite.example/secretexternal'>x</a>"
              "</body></html>"),
        "/page2.html": "<html><body>passwordlist developer</body></html>",
    }
    srv, port = _serve(pages)
    try:
        base = f"http://127.0.0.1:{port}/"
        s = SimpleNamespace(crawl_min_word_length=8, crawl_user_agent="t",
                            crawl_force_lowercase=True, crawl_depth=1, crawl_threads=3)
        words = crawl_website_keywords(base, s)
        # long words, lowercased, deduped (HASHVIEW + hashview -> one)
        assert {"hashview", "keyboard", "passwordlist", "developer"} <= words
        # short words filtered, <script>/<style>/offsite excluded
        assert "alpha" not in words and "cat" not in words
        assert "secretjavascript" not in words and "bodyfont" not in words
        assert "secretexternal" not in words

        # depth 0 -> page2 not reached
        s0 = SimpleNamespace(crawl_min_word_length=8, crawl_user_agent="t",
                             crawl_force_lowercase=True, crawl_depth=0, crawl_threads=3)
        words0 = crawl_website_keywords(base, s0)
        assert "hashview" in words0 and "passwordlist" not in words0
    finally:
        srv.shutdown()


def test_crawler_rejects_non_http_url():
    assert crawl_website_keywords("not-a-url", SimpleNamespace()) == set()
    assert crawl_website_keywords("", SimpleNamespace()) == set()


# ---------------------------------------------------------------------------
# 6. End-to-end regenerate via /v1/updateWordlist + download
# ---------------------------------------------------------------------------

def _running_agent_job(user, wl, url):
    agent = Agents(name="a", src_ip="127.0.0.1", uuid="agent-wk", status="Working")
    db.session.add(agent)
    job = Jobs(name="jr", status="Running", customer_id=1, owner_id=user.id, crawl_url=url)
    db.session.add(job)
    task = Tasks(name="tr", hc_attackmode=0, owner_id=user.id, wl_id=wl.id)
    db.session.add(task)
    db.session.commit()
    db.session.add(JobTasks(job_id=job.id, task_id=task.id, status="Running", agent_id=agent.id))
    db.session.commit()
    return agent, job


def test_update_wordlist_resolves_job_crawls_and_downloads(app, client, monkeypatch):
    user = _admin()
    db.session.add(Settings(retention_period=30, max_runtime_jobs=0, max_runtime_tasks=0))
    db.session.commit()

    wl_path = WORDLISTS_DIR / "dynamic-website-keywords.txt"
    wl_path.write_text("")          # seed empty
    wl = Wordlists(name=WL_NAME, owner_id=user.id, type="dynamic",
                   path=str(wl_path), checksum="0" * 64, size=0)
    db.session.add(wl)
    db.session.commit()

    agent, job = _running_agent_job(user, wl, "https://target.example")

    seen = {}
    def fake_crawl(url, settings):
        seen["url"] = url
        return {"foo", "bar", "baz"}
    monkeypatch.setattr("hashview.utils.crawler.crawl_website_keywords", fake_crawl)

    client.set_cookie("uuid", agent.uuid, domain=COOKIE_DOMAIN)
    resp = client.get(f"/v1/updateWordlist/{wl.id}")
    assert resp.status_code == 200 and resp.get_json()["status"] == 200

    # the per-job URL was resolved from the agent's Running JobTask
    assert seen["url"] == "https://target.example"
    # words written (sorted, unique) + metadata refreshed
    assert wl_path.read_text().split() == ["bar", "baz", "foo"]
    wl = Wordlists.query.get(wl.id)
    assert wl.size == get_linecount(str(wl_path))
    assert wl.checksum == get_filehash(str(wl_path))

    # download serves a gzip that decompresses to the crawled words
    resp = client.get(f"/v1/wordlists/{wl.id}")
    assert resp.status_code == 200 and resp.data[:2] == b"\x1f\x8b"
    assert gzip.decompress(resp.data).split() == [b"bar", b"baz", b"foo"]


def test_update_wordlist_no_job_url_leaves_file_unchanged(app, monkeypatch):
    user = _admin()
    db.session.add(Settings(retention_period=30, max_runtime_jobs=0, max_runtime_tasks=0))
    db.session.commit()
    wl_path = WORDLISTS_DIR / "dynamic-website-keywords.txt"
    wl_path.write_text("preexisting\n")
    wl = Wordlists(name=WL_NAME, owner_id=user.id, type="dynamic",
                   path=str(wl_path), checksum="0" * 64, size=0)
    db.session.add(wl)
    db.session.commit()

    def boom(url, settings):
        raise AssertionError("crawler must not run without a job URL")
    monkeypatch.setattr("hashview.utils.crawler.crawl_website_keywords", boom)

    update_dynamic_wordlist(wl.id, job_id=None)
    assert wl_path.read_text() == "preexisting\n"
