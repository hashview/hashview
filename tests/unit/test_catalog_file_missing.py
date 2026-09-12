"""Missing-file detection for Rules/Wordlists rows (issue #383).

A catalog row can outlive its file on disk. utils.resolve_control_file is the
single place that decides whether it has, so that the listings, the task
pickers, the download routes, the /v1 listings and the scheduled sweep can
never disagree.
"""

import gzip
import os
import secrets

from flask import current_app

from hashview.models import Rules, Wordlists
from hashview.models import db as _db
from hashview.utils.utils import (
    missing_rule_ids,
    missing_wordlist_ids,
    resolve_control_file,
    rule_file_missing,
    wordlist_file_missing,
)
from tests.unit.helpers import (
    login,
    make_admin,
    make_rule_with_file,
    make_wordlist_with_file,
)


def _row(model, owner_id, path, **kw):
    obj = model(owner_id=owner_id, path=path, **kw)
    _db.session.add(obj)
    _db.session.commit()
    return obj


def _rule(owner_id, path, name="r"):
    return _row(Rules, owner_id, path, name=name, size=1, checksum="c" * 64)


def _wordlist(owner_id, path, name="w", wl_type="static"):
    return _row(Wordlists, owner_id, path, name=name, type=wl_type,
                size=1, byte_size=1, checksum="c" * 64)


# --------------------------------------------------------- resolve_control_file

def test_resolve_finds_file_by_basename_not_by_stored_dirname(app, tmp_path):
    """The stored dirname is ignored; only control/<subdir>/<basename> counts."""
    admin = make_admin()
    real = make_rule_with_file(admin.id)
    basename = os.path.basename(real.path)

    # A completely different (and nonexistent) directory in the stored path
    # still resolves, because only the basename is used.
    assert resolve_control_file(str(tmp_path / basename), 'rules') == real.path


def test_resolve_is_confined_to_the_control_dir(app, tmp_path):
    """A file that exists OUTSIDE control/<subdir> does not resolve."""
    outside = tmp_path / "elsewhere.rule"
    outside.write_bytes(b"$1\n")
    assert outside.exists()
    assert resolve_control_file(str(outside), 'rules') is None


def test_resolve_returns_none_for_empty_and_none_paths(app):
    assert resolve_control_file('', 'rules') is None
    assert resolve_control_file(None, 'wordlists') is None


def test_relative_seeded_path_resolves_regardless_of_cwd(app, tmp_path, monkeypatch):
    """The 'Best64 Rule' shape: a package-relative stored path.

    A raw os.path.exists(row.path) only works when the process CWD happens to
    be the repo root -- which is exactly what breaks under a systemd unit with
    a different WorkingDirectory. Resolution must not care.
    """
    admin = make_admin()
    real = make_rule_with_file(admin.id, name="Best64-shaped")
    basename = os.path.basename(real.path)
    relative = os.path.join('hashview', 'control', 'rules', basename)
    rule = _rule(admin.id, relative, name="seeded")

    monkeypatch.chdir(tmp_path)
    assert not os.path.exists(rule.path)          # the raw path is unusable here
    assert resolve_control_file(rule.path, 'rules') == real.path
    assert rule_file_missing(rule) is False


# ------------------------------------------------------------ single-row checks

def test_rule_with_missing_file_is_missing(app, tmp_path):
    admin = make_admin()
    assert rule_file_missing(_rule(admin.id, str(tmp_path / "gone.rule"))) is True


def test_rule_with_present_file_is_not_missing(app):
    admin = make_admin()
    assert rule_file_missing(make_rule_with_file(admin.id)) is False


def test_static_wordlist_with_missing_file_is_missing(app, tmp_path):
    admin = make_admin()
    assert wordlist_file_missing(_wordlist(admin.id, str(tmp_path / "gone.gz"))) is True


def test_empty_path_is_missing(app):
    """A row that can never be served must report missing, not 'fine'."""
    admin = make_admin()
    assert rule_file_missing(_rule(admin.id, '')) is True
    assert wordlist_file_missing(_wordlist(admin.id, '')) is True


# ------------------------------------------------- dynamic wordlists never alarm

def test_dynamic_wordlist_with_absent_file_is_not_missing(app, tmp_path):
    """Dynamic lists are regenerated from the DB on every download."""
    admin = make_admin()
    wl = _wordlist(admin.id, str(tmp_path / "never-created.txt"), wl_type="dynamic")
    assert wordlist_file_missing(wl) is False
    assert wl.id not in missing_wordlist_ids()


def test_dynamic_wordlist_with_zero_byte_file_is_not_missing(app):
    """The real-instance shape: every seeded dynamic-*.txt is 0 bytes.

    Guards against anyone 'improving' the probe to getsize() > 0, which would
    false-alarm on every dynamic row on every install.
    """
    admin = make_admin()
    wl = make_wordlist_with_file(admin.id, name="(DYNAMIC) All Recovered Passwords",
                                 content=b"", wl_type="dynamic")
    assert os.path.getsize(wl.path) == 0
    assert wordlist_file_missing(wl) is False
    assert wl.id not in missing_wordlist_ids()


def test_dynamic_type_check_is_case_insensitive(app, tmp_path):
    admin = make_admin()
    wl = _wordlist(admin.id, str(tmp_path / "gone.txt"), wl_type="Dynamic")
    assert wordlist_file_missing(wl) is False


# ------------------------------------------------------------------ bulk helpers

def test_missing_rule_ids_matches_the_per_row_predicate(app, tmp_path):
    admin = make_admin()
    make_rule_with_file(admin.id, name="present")
    gone = _rule(admin.id, str(tmp_path / "gone.rule"), name="gone")

    ids = missing_rule_ids()
    assert ids == {gone.id}
    assert ids == {r.id for r in Rules.query.all() if rule_file_missing(r)}


def test_missing_wordlist_ids_matches_the_per_row_predicate(app, tmp_path):
    admin = make_admin()
    make_wordlist_with_file(admin.id, name="present")
    gone = _wordlist(admin.id, str(tmp_path / "gone.gz"), name="gone")
    _wordlist(admin.id, str(tmp_path / "dyn.txt"), name="dyn", wl_type="dynamic")

    ids = missing_wordlist_ids()
    assert ids == {gone.id}
    assert ids == {w.id for w in Wordlists.query.all() if wordlist_file_missing(w)}


def test_bulk_helpers_accept_preloaded_rows(app, tmp_path):
    """Passing loaded rows must give the same answer as querying."""
    admin = make_admin()
    make_rule_with_file(admin.id, name="present")
    gone = _rule(admin.id, str(tmp_path / "gone.rule"), name="gone")

    assert missing_rule_ids(Rules.query.all()) == {gone.id} == missing_rule_ids()
    assert missing_wordlist_ids(Wordlists.query.all()) == missing_wordlist_ids()


# ----------------------------------------------------- the download routes agree

def test_rule_download_404s_when_file_missing(app, client, tmp_path):
    admin = make_admin()
    login(client, admin)
    rule = _rule(admin.id, str(tmp_path / "gone.rule"))

    resp = client.get(f"/rules/download/{rule.id}", follow_redirects=True)
    assert b"Rule file not found on disk" in resp.data


def test_rule_download_serves_a_present_file(app, client):
    admin = make_admin()
    login(client, admin)
    rule = make_rule_with_file(admin.id, content=b"$1\n$2\n")

    resp = client.get(f"/rules/download/{rule.id}")
    assert resp.status_code == 200
    assert resp.data == b"$1\n$2\n"


def test_wordlist_download_404s_when_file_missing(app, client, tmp_path):
    admin = make_admin()
    login(client, admin)
    wl = _wordlist(admin.id, str(tmp_path / "gone.gz"))

    resp = client.get(f"/wordlists/download/{wl.id}", follow_redirects=True)
    assert b"Wordlist file not found on disk" in resp.data


def test_wordlist_download_serves_a_present_file(app, client):
    admin = make_admin()
    login(client, admin)
    wl = make_wordlist_with_file(admin.id, content=b"alpha\nbravo\n")

    resp = client.get(f"/wordlists/download/{wl.id}")
    assert resp.status_code == 200
    assert gzip.decompress(resp.data) == b"alpha\nbravo\n"


def test_web_and_api_downloads_agree_on_a_relative_path(app, client, tmp_path, monkeypatch):
    """Before #383 these disagreed: the web route stat'd the raw stored path
    (CWD-dependent) while /v1 resolved by basename. Both now resolve."""
    admin = make_admin()
    admin.api_key = "api-key-" + secrets.token_hex(4)
    _db.session.commit()
    real = make_rule_with_file(admin.id)
    rule = _rule(admin.id, os.path.join('hashview', 'control', 'rules',
                                        os.path.basename(real.path)), name="rel")
    login(client, admin)
    monkeypatch.chdir(tmp_path)

    assert client.get(f"/rules/download/{rule.id}").status_code == 200
    client.set_cookie("uuid", admin.api_key, domain="localhost.test")
    assert client.get(f"/v1/rules/{rule.id}").status_code == 200


def test_v1_download_404_logs_the_row(app, client, tmp_path, caplog):
    """The 404 has to leave a trace on the SERVER; before #383 the only
    evidence an agent was spinning lived in that agent's own log."""
    admin = make_admin()
    admin.api_key = "api-key-" + secrets.token_hex(4)
    _db.session.commit()
    wl = _wordlist(admin.id, str(tmp_path / "gone.gz"))
    client.set_cookie("uuid", admin.api_key, domain="localhost.test")

    with caplog.at_level("WARNING", logger=current_app.logger.name):
        resp = client.get(f"/v1/wordlists/{wl.id}")

    assert resp.status_code == 404
    assert resp.get_json()["msg"].startswith("Wordlist file missing on disk")
    assert any("has no file on disk" in r.getMessage() for r in caplog.records)


def test_a_directory_shaped_path_is_reported_missing(app, tmp_path):
    """os.path.basename('/x/..') is '..' and basename('a/b/') is '', so those
    resolve to control/<subdir>/.. and to the directory itself -- both of which
    os.path.exists() calls True. The row then read as healthy and failed later in
    getsize() or os.replace() instead. Traversal itself is already neutralised by
    the basename call: '../../etc/passwd' resolves to 'passwd'."""
    for stored in ('/somewhere/..', 'a/b/', '..', '.', ''):
        assert resolve_control_file(stored, 'rules') is None, stored
        assert resolve_control_file(stored, 'wordlists') is None, stored
