"""Unit tests for the encrypted database backup feature.

The crypto/pipeline is exercised for real (openssl + gzip available); the
mysqldump stage is replaced with an injected command so no live MySQL is
needed. Route tests cover auth, CSRF-form gating, the JSON contract, the
download endpoint, and the non-MySQL error path.
"""

import gzip
import os
import shutil
import subprocess
import time

import pytest

from hashview.models import db, Users
from hashview.utils.backup import (
    create_encrypted_db_backup, purge_stale_backups, _write_defaults_file, BackupError,
    _sha256, _require_tools,
)
from sqlalchemy.engine.url import make_url

_requires_mysqldump = pytest.mark.skipif(
    shutil.which("mysqldump") is None,
    reason="mysqldump not installed",
)

MYSQL_URI = "mysql+mysqlconnector://bob:s3cr3t@localhost/hashview"
TMP_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                       "hashview", "control", "tmp")


@pytest.fixture(autouse=True)
def _clean_backups():
    def snap():
        return set(os.listdir(TMP_DIR)) if os.path.isdir(TMP_DIR) else set()
    before = snap()
    yield
    if os.path.isdir(TMP_DIR):
        for n in snap() - before:
            try:
                os.remove(os.path.join(TMP_DIR, n))
            except OSError:
                pass


def _user(admin=True, api_key="bk-key"):
    u = Users(first_name="A", last_name="D", email_address="a@e.com",
              password="x" * 60, admin=admin, api_key=api_key)
    db.session.add(u)
    db.session.commit()
    return u


def _login(client, user):
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True


# ---------------------------------------------------------------------------
# backup module
# ---------------------------------------------------------------------------

@_requires_mysqldump
def test_backup_roundtrip_decrypts(tmp_path):
    sql = b"-- MySQL dump\nCREATE TABLE t (id INT);\nINSERT INTO t VALUES (1);\n"
    sqlf = tmp_path / "fake.sql"
    sqlf.write_bytes(sql)

    enc_path, password, sha = create_encrypted_db_backup(
        MYSQL_URI, str(tmp_path), dump_cmd=["cat", str(sqlf)])

    assert enc_path.endswith(".sql.gz.enc") and os.path.exists(enc_path)
    assert oct(os.stat(enc_path).st_mode & 0o777) == oct(0o600)   # private
    assert len(password) >= 24 and sha and len(sha) == 64
    # decrypt with the returned one-time password -> gzip -> original SQL
    dec = subprocess.run(
        ["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-in", enc_path,
         "-pass", "pass:" + password],
        capture_output=True)
    assert dec.returncode == 0, dec.stderr
    assert gzip.decompress(dec.stdout) == sql


def test_backup_failed_dump_raises_and_cleans_up(tmp_path):
    with pytest.raises(BackupError):
        create_encrypted_db_backup(MYSQL_URI, str(tmp_path), dump_cmd=["bash", "-c", "exit 2"])
    # the critical guard: NO valid-looking .enc left behind on dump failure
    assert [f for f in os.listdir(tmp_path) if f.endswith(".enc")] == []


def test_backup_partial_dump_failure_raises(tmp_path):
    # mysqldump emits some bytes then dies -> must be treated as failure, not a backup
    with pytest.raises(BackupError):
        create_encrypted_db_backup(MYSQL_URI, str(tmp_path),
                                   dump_cmd=["bash", "-c", "printf partial; exit 3"])
    assert [f for f in os.listdir(tmp_path) if f.endswith(".enc")] == []


def test_backup_rejects_non_mysql(tmp_path):
    with pytest.raises(BackupError):
        create_encrypted_db_backup("sqlite:///x.db", str(tmp_path), dump_cmd=["true"])


def test_defaults_file_perms_and_port_omitted(tmp_path):
    path = _write_defaults_file(make_url(MYSQL_URI), str(tmp_path))
    try:
        assert oct(os.stat(path).st_mode & 0o777) == oct(0o600)
        content = open(path).read()
        assert "[client]" in content
        assert 'user="bob"' in content and 'password="s3cr3t"' in content
        assert "port=" not in content        # no port in URI -> no port line
    finally:
        os.remove(path)


def test_defaults_file_quotes_special_values(tmp_path):
    # values with '#', quotes, backslash must be quoted/escaped so MySQL's
    # option-file parser reads them verbatim (else the password truncates at '#').
    pw = 'pa#ss "x" \\y'
    user = 'us#er \\z'
    url = make_url(MYSQL_URI).set(password=pw, username=user)
    path = _write_defaults_file(url, str(tmp_path))
    try:
        content = open(path).read()
        assert ('password="' + pw.replace('\\', '\\\\').replace('"', '\\"') + '"') in content
        # round-trip through MySQL's own option-file parser (user is not redacted)
        import shutil
        mpd = shutil.which('my_print_defaults')
        if mpd:
            out = subprocess.run([mpd, '--defaults-file=' + path, 'client'],
                                 capture_output=True, text=True)
            assert ('--user=' + user) in out.stdout, out.stdout   # exact value recovered
    finally:
        os.remove(path)


def test_defaults_file_includes_port_when_present(tmp_path):
    path = _write_defaults_file(make_url("mysql+mysqlconnector://u:p@db:3307/hashview"), str(tmp_path))
    try:
        content = open(path).read()
        assert "port=3307" in content and 'host="db"' in content
    finally:
        os.remove(path)


def test_purge_stale_backups(tmp_path):
    old = tmp_path / "1111111111111111.sql.gz.enc"
    new = tmp_path / "2222222222222222.sql.gz.enc"
    other = tmp_path / "keep.txt"
    for p in (old, new, other):
        p.write_bytes(b"x")
    os.utime(old, (time.time() - 7200, time.time() - 7200))   # 2h old
    purge_stale_backups(str(tmp_path), max_age_seconds=3600)
    assert not old.exists()
    assert new.exists() and other.exists()


def test_purge_stale_backups_missing_dir_is_noop(tmp_path):
    # the function swallows OSError from a non-existent directory
    purge_stale_backups(str(tmp_path / "does-not-exist"))


def test_sha256_matches_hashlib(tmp_path):
    import hashlib
    # content just over one 1 MiB chunk -> exercises the multi-read loop
    data = b"x" * (1024 * 1024 + 7)
    path = tmp_path / "f.bin"
    path.write_bytes(data)
    assert _sha256(str(path)) == hashlib.sha256(data).hexdigest()

    # empty file -> single (zero-length) read path
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    assert _sha256(str(empty)) == hashlib.sha256(b"").hexdigest()


def test_require_tools_raises_when_tool_missing(monkeypatch):
    monkeypatch.setattr("hashview.utils.backup.shutil.which", lambda name: None)
    with pytest.raises(BackupError) as exc:
        _require_tools(need_mysqldump=True)
    assert "Missing required tool" in str(exc.value)
    # gzip/openssl still required even without mysqldump
    with pytest.raises(BackupError):
        _require_tools(need_mysqldump=False)


def test_require_tools_passes_when_present(monkeypatch):
    monkeypatch.setattr("hashview.utils.backup.shutil.which", lambda name: "/usr/bin/" + name)
    assert _require_tools() is None


# ---------------------------------------------------------------------------
# routes
# ---------------------------------------------------------------------------

@_requires_mysqldump
def test_backup_route_non_mysql_returns_error(app, client):
    """The test app uses sqlite -> the real route should report an error JSON
    (exercises form validation + the BackupError path, no mock)."""
    user = _user(admin=True); _login(client, user)
    resp = client.post("/settings/backup", headers={"X-Requested-With": "fetch"})
    assert resp.status_code == 500
    body = resp.get_json()
    assert body["status"] == "error" and "MySQL" in body["msg"]


def test_backup_route_success(app, client, monkeypatch):
    user = _user(admin=True); _login(client, user)

    def fake(uri, tmp_dir, dump_cmd=None):
        p = os.path.join(tmp_dir, "a1b2c3d4e5f60718.sql.gz.enc")
        with open(p, "wb") as f:
            f.write(b"ENCRYPTEDDATA")
        return p, "ONETIME-PASS-123", "f" * 64
    monkeypatch.setattr("hashview.settings.routes.create_encrypted_db_backup", fake)

    resp = client.post("/settings/backup", headers={"X-Requested-With": "fetch"})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["status"] == "ok"
    assert body["password"] == "ONETIME-PASS-123"
    assert body["sha256"] == "f" * 64
    assert body["download_url"].endswith("/settings/backup/download/a1b2c3d4e5f60718.sql.gz.enc")
    assert any("openssl enc -d" in line for line in body["instructions"])

    # and the download endpoint serves it as an attachment
    resp = client.get(body["download_url"])
    assert resp.status_code == 200
    assert resp.data == b"ENCRYPTEDDATA"
    cd = resp.headers.get("Content-Disposition", "")
    assert "attachment" in cd and "hashview-backup-" in cd and cd.endswith(".sql.gz.enc")


def test_backup_download_rejects_bad_token(app, client):
    user = _user(admin=True); _login(client, user)
    assert client.get("/settings/backup/download/not-a-token").status_code == 404
    assert client.get("/settings/backup/download/..%2f..%2fetc%2fpasswd").status_code == 404
    # well-formed token but no such file
    assert client.get("/settings/backup/download/0123456789abcdef.sql.gz.enc").status_code == 404


def test_backup_admin_only(app, client):
    operator = _user(admin=False); _login(client, operator)
    assert client.post("/settings/backup", headers={"X-Requested-With": "fetch"}).status_code == 403
    assert client.get("/settings/backup/download/0123456789abcdef.sql.gz.enc").status_code == 403


def test_settings_page_renders_backup_ui(app, client):
    user = _user(admin=True); _login(client, user)
    db.session.add(__import__("hashview").models.Settings(
        retention_period=30, max_runtime_jobs=0, max_runtime_tasks=0))
    db.session.commit()
    html = client.get("/settings").get_data(as_text=True)
    assert "hv-backup-btn" in html and "backup-modal" in html and "hvBackupDb" in html
    assert 'id="hv-backup-form"' in html and "csrf_token" in html
