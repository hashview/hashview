"""Regression tests: the Website Keywords crawl must never serve a stale list.

The (DYNAMIC) Website Keywords wordlist is regenerated on every agent request:
the crawl result is written to a randomly-named file under control/tmp and then
atomically moved onto ``wordlist.path``. The contract these tests pin down:

  1. Every regeneration writes a *fresh* random tmp file — a tmp file left over
     from an earlier crawl is never read, reused, or served.
  2. A crawl that yields nothing (every fetch failed, unreachable host, bad URL)
     replaces the live wordlist with a *blank* file — the previous run's words
     must not survive.
  3. A crawl that *raises* likewise leaves a blank wordlist, not the previous
     content, and the Wordlists row metadata (size/checksum) matches the blank
     file so the agent isn't told a stale size.
  4. Back-to-back crawls fully replace, never union or append.
  5. The download endpoint serves the current crawl's bytes, not the prior gzip.

Points 1, 2, 4 and 5-on-success already hold. The "crawl *raises*" half of point 3
does not: the exception escapes _generate_website_keywords before the tmp file is
written, so os.replace never runs and the previous job's words stay live and get
served. Those three tests are strict xfails against issue #377 — remove the
markers when it's fixed.

Uses the in-memory SQLite app from tests/unit/conftest.py.
"""

import gzip
import os
from pathlib import Path

import pytest

from hashview.models import db, Users, Wordlists, Jobs, Tasks, JobTasks, Agents, Settings
from hashview.utils.utils import (update_dynamic_wordlist, get_filehash, get_linecount,
                                  job_wordlist_path)

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTROL = REPO_ROOT / "hashview" / "control"
WORDLISTS_DIR = CONTROL / "wordlists"
TMP_DIR = CONTROL / "tmp"
WL_NAME = "(DYNAMIC) Website Keywords"
COOKIE_DOMAIN = "localhost.test"


@pytest.fixture(autouse=True)
def _clean_control_dirs():
    """Remove any files these tests add to control/{wordlists,tmp}."""
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


def _admin(api_key="stale-api-key"):
    user = Users(first_name="A", last_name="D", email_address="a@e.com",
                 password="x" * 60, admin=True, api_key=api_key)
    db.session.add(user)
    db.session.commit()
    return user


def _settings():
    db.session.add(Settings(retention_period=30, max_runtime_jobs=0, max_runtime_tasks=0))
    db.session.commit()


def _wordlist(user, initial=""):
    path = WORDLISTS_DIR / "dynamic-website-keywords.txt"
    path.write_text(initial)
    wordlist = Wordlists(name=WL_NAME, owner_id=user.id, type="dynamic",
                         path=str(path), checksum=get_filehash(str(path)),
                         size=get_linecount(str(path)))
    db.session.add(wordlist)
    db.session.commit()
    return wordlist, path


def _job_path(wordlist, job):
    """Where THIS job's copy of a job-scoped dynamic list lives.

    Website Keywords is crawled per job, so the live file for a regeneration is
    the job's own copy rather than the shared path stored on the row.
    """
    return Path(job_wordlist_path(wordlist, job.id))


def _running_agent_job(user, wordlist, url, uuid="agent-stale"):
    agent = Agents(name="a", src_ip="127.0.0.1", uuid=uuid, status="Working")
    db.session.add(agent)
    job = Jobs(name="jr", status="Running", customer_id=1, owner_id=user.id, crawl_url=url)
    db.session.add(job)
    task = Tasks(name="tr", hc_attackmode=0, owner_id=user.id, wl_id=wordlist.id)
    db.session.add(task)
    db.session.commit()
    db.session.add(JobTasks(job_id=job.id, task_id=task.id, status="Running",
                            agent_id=agent.id))
    db.session.commit()
    return agent, job


def _record_tmp_sources(monkeypatch):
    """Capture the tmp path handed to os.replace on each regeneration."""
    seen = []
    real_replace = os.replace

    def spy(src, dst, *a, **kw):
        seen.append(str(src))
        return real_replace(src, dst, *a, **kw)

    monkeypatch.setattr(os, "replace", spy)
    return seen


# ---------------------------------------------------------------------------
# 1. Fresh random tmp file per crawl; leftovers are never reused
# ---------------------------------------------------------------------------

def test_each_crawl_uses_a_new_random_tmp_file(app, monkeypatch):
    """Two regenerations must stage through two different tmp filenames."""
    user = _admin()
    _settings()
    wordlist, path = _wordlist(user)
    job = Jobs(name="j", status="Running", customer_id=1, owner_id=user.id,
               crawl_url="https://target.example")
    db.session.add(job)
    db.session.commit()

    monkeypatch.setattr("hashview.utils.crawler.crawl_website_keywords",
                        lambda url, settings: {"alpha"})
    seen = _record_tmp_sources(monkeypatch)

    update_dynamic_wordlist(wordlist.id, job_id=job.id)
    update_dynamic_wordlist(wordlist.id, job_id=job.id)

    assert len(seen) == 2, "each regeneration should stage through control/tmp"
    assert seen[0] != seen[1], "tmp filename must be random per crawl, not reused"
    for src in seen:
        assert Path(src).parent == TMP_DIR
        assert not os.path.exists(src), "tmp file must be moved, not left behind"


def test_preexisting_tmp_file_is_never_read_or_served(app, monkeypatch):
    """A stale control/tmp leftover must not influence the regenerated list."""
    user = _admin()
    _settings()
    wordlist, path = _wordlist(user)
    job = Jobs(name="j", status="Running", customer_id=1, owner_id=user.id,
               crawl_url="https://target.example")
    db.session.add(job)
    db.session.commit()

    stale_tmp = TMP_DIR / "deadbeefdeadbeef.txt"
    stale_tmp.write_text("stalecachedword\n")

    monkeypatch.setattr("hashview.utils.crawler.crawl_website_keywords",
                        lambda url, settings: {"freshword"})
    update_dynamic_wordlist(wordlist.id, job_id=job.id)

    live = _job_path(wordlist, job)
    assert live.read_text().split() == ["freshword"]
    assert "stalecachedword" not in live.read_text()
    # and the leftover is untouched, i.e. it was neither consumed nor moved
    assert stale_tmp.exists()


# ---------------------------------------------------------------------------
# 2/3. Failed crawl -> blank wordlist, never the previous content
# ---------------------------------------------------------------------------

def test_empty_crawl_result_blanks_the_previous_wordlist(app, monkeypatch):
    user = _admin()
    _settings()
    wordlist, path = _wordlist(user)
    job = Jobs(name="j", status="Running", customer_id=1, owner_id=user.id,
               crawl_url="https://unreachable.invalid")
    db.session.add(job)
    db.session.commit()
    # seed a previous run in THIS job's copy, which is what a re-crawl replaces
    live = _job_path(wordlist, job)
    live.write_text("previousrun\nanotherword\n")

    monkeypatch.setattr("hashview.utils.crawler.crawl_website_keywords",
                        lambda url, settings: set())
    update_dynamic_wordlist(wordlist.id, job_id=job.id)

    assert live.read_text() == "", "a crawl that found nothing must yield a blank list"
    wordlist = Wordlists.query.get(wordlist.id)
    assert wordlist.byte_size == 0
    assert wordlist.size == get_linecount(str(live))
    assert wordlist.checksum == get_filehash(str(live))


@pytest.mark.xfail(strict=True, reason="issue #377: a raising crawl leaves the "
                                       "previous run's wordlist live on disk")
def test_crawl_exception_yields_blank_wordlist_not_stale_words(app, monkeypatch):
    """If the crawler blows up, the agent must get a blank list, not last run's."""
    user = _admin()
    _settings()
    wordlist, path = _wordlist(user, initial="previousrun\nanotherword\n")
    job = Jobs(name="j", status="Running", customer_id=1, owner_id=user.id,
               crawl_url="https://target.example")
    db.session.add(job)
    db.session.commit()

    def boom(url, settings):
        raise RuntimeError("DNS exploded mid-crawl")

    monkeypatch.setattr("hashview.utils.crawler.crawl_website_keywords", boom)
    update_dynamic_wordlist(wordlist.id, job_id=job.id)

    text = path.read_text()
    assert "previousrun" not in text and "anotherword" not in text
    assert text == "", "a failed crawl must replace the wordlist with a blank file"
    wordlist = Wordlists.query.get(wordlist.id)
    assert wordlist.byte_size == 0, "metadata must describe the blank file, not the stale one"
    assert wordlist.size == get_linecount(str(path))
    assert wordlist.checksum == get_filehash(str(path))


@pytest.mark.xfail(strict=True, reason="issue #377: the crawl exception escapes "
                                       "update_dynamic_wordlist entirely")
def test_crawl_exception_leaves_no_tmp_debris(app, monkeypatch):
    user = _admin()
    _settings()
    wordlist, path = _wordlist(user, initial="previousrun\n")
    job = Jobs(name="j", status="Running", customer_id=1, owner_id=user.id,
               crawl_url="https://target.example")
    db.session.add(job)
    db.session.commit()

    before = set(os.listdir(TMP_DIR))

    def boom(url, settings):
        raise RuntimeError("boom")

    monkeypatch.setattr("hashview.utils.crawler.crawl_website_keywords", boom)
    update_dynamic_wordlist(wordlist.id, job_id=job.id)

    assert set(os.listdir(TMP_DIR)) == before, "failed crawl must not leak tmp files"


# ---------------------------------------------------------------------------
# 4. Back-to-back crawls fully replace
# ---------------------------------------------------------------------------

def test_second_crawl_replaces_rather_than_unions(app, monkeypatch):
    user = _admin()
    _settings()
    wordlist, path = _wordlist(user)
    job = Jobs(name="j", status="Running", customer_id=1, owner_id=user.id,
               crawl_url="https://target.example")
    db.session.add(job)
    db.session.commit()

    results = [{"firstcrawl", "shared"}, {"secondcrawl", "shared"}]
    monkeypatch.setattr("hashview.utils.crawler.crawl_website_keywords",
                        lambda url, settings: results.pop(0))

    live = _job_path(wordlist, job)
    update_dynamic_wordlist(wordlist.id, job_id=job.id)
    assert live.read_text().split() == ["firstcrawl", "shared"]

    update_dynamic_wordlist(wordlist.id, job_id=job.id)
    assert live.read_text().split() == ["secondcrawl", "shared"]
    assert "firstcrawl" not in live.read_text()


def test_different_job_urls_do_not_share_results(app, monkeypatch):
    """A second job's crawl must not inherit the first job's words."""
    user = _admin()
    _settings()
    wordlist, path = _wordlist(user)
    job_a = Jobs(name="a", status="Running", customer_id=1, owner_id=user.id,
                 crawl_url="https://a.example")
    job_b = Jobs(name="b", status="Running", customer_id=1, owner_id=user.id,
                 crawl_url="https://b.example")
    db.session.add_all([job_a, job_b])
    db.session.commit()

    by_url = {"https://a.example": {"awords"}, "https://b.example": set()}
    monkeypatch.setattr("hashview.utils.crawler.crawl_website_keywords",
                        lambda url, settings: by_url[url])

    live_a, live_b = _job_path(wordlist, job_a), _job_path(wordlist, job_b)

    update_dynamic_wordlist(wordlist.id, job_id=job_a.id)
    assert live_a.read_text().split() == ["awords"]

    # job B's site yields nothing -> blank, NOT job A's leftovers
    update_dynamic_wordlist(wordlist.id, job_id=job_b.id)
    assert live_b.read_text() == ""
    # and job B's crawl leaves job A's own copy intact
    assert live_a.read_text().split() == ["awords"]


# ---------------------------------------------------------------------------
# 5. The download endpoint serves the current crawl
# ---------------------------------------------------------------------------

@pytest.mark.xfail(strict=True, reason="issue #377: /v1/wordlists serves the "
                                       "cached previous crawl after a failed one")
def test_download_after_failed_crawl_serves_blank_gzip(app, client, monkeypatch):
    user = _admin()
    _settings()
    wordlist, path = _wordlist(user)
    agent, job = _running_agent_job(user, wordlist, "https://target.example")
    client.set_cookie("uuid", agent.uuid, domain=COOKIE_DOMAIN)

    monkeypatch.setattr("hashview.utils.crawler.crawl_website_keywords",
                        lambda url, settings: {"goodword"})
    assert client.get(f"/v1/updateWordlist/{wordlist.id}").status_code == 200
    first = client.get(f"/v1/wordlists/{wordlist.id}")
    assert first.status_code == 200
    assert gzip.decompress(first.data).split() == [b"goodword"]

    def boom(url, settings):
        raise RuntimeError("crawl failed on the next job")

    monkeypatch.setattr("hashview.utils.crawler.crawl_website_keywords", boom)
    assert client.get(f"/v1/updateWordlist/{wordlist.id}").status_code == 200
    second = client.get(f"/v1/wordlists/{wordlist.id}")
    assert second.status_code == 200
    assert gzip.decompress(second.data) == b"", \
        "download must serve the blank current list, not the cached previous crawl"
