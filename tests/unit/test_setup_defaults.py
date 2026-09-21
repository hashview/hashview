"""Regression tests for setup defaults + first-run routes
(function-coverage batch: setup)."""

import gzip
import os

import pytest

from hashview import setup as setup_mod
from hashview.models import Rules, Settings, Tasks, Users, Wordlists, db
from hashview.setup import (
    add_admin_user,
    add_default_rules,
    add_default_static_wordlist,
    add_default_tasks,
    admin_pass_needs_changed,
    admin_user_needs_added,
    compress_existing_wordlists_if_needed,
    default_rules_need_added,
    default_static_wordlist_need_added,
    default_tasks_need_added,
    settings_needs_added,
)
from hashview.users.routes import bcrypt
from hashview.utils.utils import get_filehash, is_gzip

RULE_LINES = [":", "u", "l", "c", "$1", "$2", "^a"]
WORD_LINES = ["password", "123456", "letmein", "dragon"]


@pytest.fixture
def seeded(app, tmp_path, monkeypatch):
    """A private control/ tree plus tiny stand-ins for the shipped seed archives.

    app.root_path is repointed at tmp_path so seeding writes real files without
    touching the shared hashview/control/ tree, and the seed sources are shrunk
    from 53 MB of rockyou to four words -- the code paths are identical and the
    suite stays fast. Returns the two source archives.
    """
    root = tmp_path / "hvroot"
    (root / "control").mkdir(parents=True)
    monkeypatch.setattr(app, "root_path", str(root))

    install = tmp_path / "install"
    install.mkdir()
    rule_gz = install / "best64.rule.gz"
    with gzip.open(rule_gz, "wb") as fh:
        fh.write(("\n".join(RULE_LINES) + "\n").encode())
    wl_gz = install / "rockyou.txt.gz"
    with gzip.open(wl_gz, "wb") as fh:
        fh.write(("\n".join(WORD_LINES) + "\n").encode())

    monkeypatch.setattr(setup_mod, "SEED_RULE_GZ", str(rule_gz))
    monkeypatch.setattr(setup_mod, "SEED_WORDLIST_GZ", str(wl_gz))
    return {"root": root, "rule_gz": rule_gz, "wordlist_gz": wl_gz, "install": install}

# --- predicate / adder pairs -----------------------------------------------

def test_default_tasks_added_once(app):
    assert default_tasks_need_added(db) is True
    add_default_tasks(db)
    assert default_tasks_need_added(db) is False
    assert Tasks.query.count() == 3


def test_default_rules_added_once(seeded):
    assert default_rules_need_added(db) is True
    add_default_rules(db)
    assert default_rules_need_added(db) is False

    rule = Rules.query.filter_by(name="Best64 Rule").first()
    assert rule is not None
    # Absolute, under the app's own control/rules -- where the download route
    # serves from. The path this used to store was relative and only resolved
    # while the process CWD happened to be the repo root.
    assert rule.path == os.path.join(str(seeded["root"]), "control", "rules",
                                     "best64.rule")
    # Rules are plaintext at rest: the file on disk is the DECOMPRESSED rule.
    with open(rule.path, "rb") as fh:
        assert fh.read().decode().split() == RULE_LINES
    assert rule.size == len(RULE_LINES)
    assert rule.checksum == get_filehash(rule.path)


def test_the_seeded_wordlist_stays_compressed(seeded):
    # Wordlists are stored gzip-at-rest. Seeding used to decompress 53 MB of
    # rockyou into 130 MB of plaintext purely so the pass that runs seconds
    # later could compress it straight back.
    assert default_static_wordlist_need_added(db) is True
    add_default_static_wordlist(db)
    assert default_static_wordlist_need_added(db) is False

    wl = Wordlists.query.filter_by(name="Rockyou.txt").first()
    assert wl is not None and wl.type == "static"
    assert wl.path.endswith(".gz")
    assert os.path.dirname(wl.path) == os.path.join(str(seeded["root"]),
                                                    "control", "wordlists")
    assert is_gzip(wl.path), "the seeded wordlist must be stored compressed"
    with gzip.open(wl.path, "rb") as fh:
        assert fh.read().decode().split() == WORD_LINES

    # The row must be written exactly as the compression pass would have left
    # it: checksum over the COMPRESSED file (what the agent verifies), line
    # count of the decompressed text, byte_size of what is on disk.
    assert wl.checksum == get_filehash(wl.path)
    assert wl.size == len(WORD_LINES)
    assert wl.byte_size == os.path.getsize(wl.path)

    # Nothing is unpacked into the install tree on the way past.
    assert sorted(p.name for p in seeded["install"].iterdir()) == [
        "best64.rule.gz", "rockyou.txt.gz"]


def test_seed_sources_resolve_from_the_repo_root_not_the_cwd(app, tmp_path, monkeypatch):
    """'install/rockyou.txt.gz' as written only resolves when the server was
    started from the repo root -- an implicit requirement nothing states or
    enforces, and one a container that sets any other WORKDIR quietly breaks.
    Resolving against the app's own location removes the dependency."""
    root = tmp_path / "hvroot"
    (root / "control").mkdir(parents=True)
    monkeypatch.setattr(app, "root_path", str(root))
    (tmp_path / "install").mkdir()
    seed = tmp_path / "install" / "best64.rule.gz"
    seed.write_bytes(b"not really gzip")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)          # no 'install/' here at all

    assert setup_mod._seed_source("install/best64.rule.gz") == str(seed)


def test_seed_source_falls_back_to_the_bare_path(app, tmp_path, monkeypatch):
    # Nothing beside the app root: an unusual layout that resolved the bare
    # path before must keep resolving it, so this never becomes a regression
    # for an install that was already working.
    root = tmp_path / "hvroot"
    (root / "control").mkdir(parents=True)
    monkeypatch.setattr(app, "root_path", str(root))

    assert setup_mod._seed_source("install/nope.gz") == "install/nope.gz"


def test_seeding_survives_control_on_another_filesystem(seeded, monkeypatch):
    """The #395 regression: control/ mounted as a volume.

    os.replace is a rename, and a rename cannot cross a device, so seeding died
    with EXDEV -- on the first boot and, because the need_added predicates stay
    True, on every boot after it, all of it swallowed by the caller's
    except/log. os.system is booby-trapped in the same way: its exit status was
    never checked, so a missing gzip binary failed just as silently.

    Both tripwires fire on USE, so this passes only while the seeding path
    contains neither call.
    """
    def no_rename(*args, **kwargs):
        raise OSError(18, "Invalid cross-device link")

    def no_shell(*args, **kwargs):
        raise AssertionError("seeding shelled out to os.system")

    monkeypatch.setattr(setup_mod.os, "replace", no_rename)
    monkeypatch.setattr(setup_mod.os, "rename", no_rename)
    monkeypatch.setattr(setup_mod.os, "system", no_shell)

    add_default_rules(db)
    add_default_static_wordlist(db)

    assert default_rules_need_added(db) is False
    assert default_static_wordlist_need_added(db) is False
    assert os.path.exists(Rules.query.first().path)
    assert os.path.exists(Wordlists.query.filter_by(type="static").first().path)


def test_the_seeded_wordlist_needs_no_second_compression_pass(seeded):
    # compress_existing_wordlists_if_needed runs a few lines after seeding on
    # the same boot. The seeded row is already in its final shape, so that pass
    # must find nothing to do -- no new file, no rewritten path or checksum.
    add_default_static_wordlist(db)
    wl = Wordlists.query.filter_by(name="Rockyou.txt").first()
    before = (wl.path, wl.checksum, wl.size, wl.byte_size)
    listing_before = sorted(os.listdir(os.path.dirname(wl.path)))

    compress_existing_wordlists_if_needed(db)

    wl = Wordlists.query.filter_by(name="Rockyou.txt").first()
    assert (wl.path, wl.checksum, wl.size, wl.byte_size) == before
    # Only the backfill marker the pass writes for itself is new.
    new_files = set(os.listdir(os.path.dirname(wl.path))) - set(listing_before)
    assert all(not f.endswith(".gz") for f in new_files), new_files


def test_admin_user_added_once(app):
    assert admin_user_needs_added(db) is True
    add_admin_user(db, bcrypt)
    assert admin_user_needs_added(db) is False
    assert Users.query.filter_by(admin=True).count() == 1


def test_admin_pass_needs_changed_detects_default(app):
    # No user id=1 -> needs changing.
    assert admin_pass_needs_changed(db, bcrypt) is True
    # Seed user id=1 still on the default password -> still True.
    add_admin_user(db, bcrypt)  # creates the default-password admin (id=1)
    assert admin_pass_needs_changed(db, bcrypt) is True
    # Change the password -> False.
    user = Users.query.get(1)
    user.password = bcrypt.generate_password_hash("a-much-better-password")
    db.session.commit()
    assert admin_pass_needs_changed(db, bcrypt) is False


def test_admin_pass_needs_changed_caches_bcrypt(app, monkeypatch):
    """The cost-12 bcrypt KDF runs on every request via the setup gate, so it must
    run at most once per unchanged admin hash and re-run only when the hash changes."""
    add_admin_user(db, bcrypt)  # id=1, still on the default password
    calls = {"n": 0}
    real = bcrypt.check_password_hash

    def counting(pw_hash, password):
        calls["n"] += 1
        return real(pw_hash, password)

    monkeypatch.setattr(bcrypt, "check_password_hash", counting)

    # First call runs the KDF; repeated calls with the same stored hash are cached.
    assert admin_pass_needs_changed(db, bcrypt) is True
    assert admin_pass_needs_changed(db, bcrypt) is True
    assert admin_pass_needs_changed(db, bcrypt) is True
    assert calls["n"] == 1

    # Changing the admin password changes the stored hash -> cache miss -> re-runs once.
    user = Users.query.get(1)
    user.password = bcrypt.generate_password_hash("a-much-better-password").decode("utf-8")
    db.session.commit()
    assert admin_pass_needs_changed(db, bcrypt) is False
    assert calls["n"] == 2
    # The new verdict is itself cached.
    assert admin_pass_needs_changed(db, bcrypt) is False
    assert calls["n"] == 2


def test_settings_needs_added_toggles(app):
    assert settings_needs_added(db) is True
    db.session.add(Settings(retention_period=1, max_runtime_tasks=0, max_runtime_jobs=0))
    db.session.commit()
    assert settings_needs_added(db) is False


# --- first-run routes ------------------------------------------------------

def _seed_default_admin():
    user = Users(first_name="admin", last_name="user", email_address="",
                 password=bcrypt.generate_password_hash("hashview").decode("utf-8"),
                 admin=True)
    db.session.add(user)
    db.session.commit()
    return user


def test_admin_pass_get_renders_when_default(app, client):
    _seed_default_admin()
    resp = client.get("/setup/admin-pass")
    assert resp.status_code == 200


def test_admin_pass_post_sets_password(app, client):
    _seed_default_admin()
    resp = client.post("/setup/admin-pass", data={
        "first_name": "Real", "last_name": "Admin",
        "email_address": "real@example.com",
        "password": "supersecurepassword", "confirm_password": "supersecurepassword",
        "submit": "Update",
    }, follow_redirects=False)
    assert resp.status_code in (301, 302)
    user = Users.query.get(1)
    assert user.first_name == "Real"
    assert not bcrypt.check_password_hash(user.password, "hashview")


def test_settings_get_renders_when_missing(app, client):
    _seed_default_admin()
    resp = client.get("/setup/settings")
    assert resp.status_code == 200


def test_settings_post_creates_settings(app, client):
    _seed_default_admin()
    resp = client.post("/setup/settings", data={
        "retention_period": "30", "max_runtime_tasks": "0",
        "max_runtime_jobs": "0", "submit": "Save",
    }, follow_redirects=False)
    assert resp.status_code in (301, 302)
    s = Settings.query.first()
    assert s is not None and s.retention_period == 30


def test_settings_get_redirects_when_present(app, client):
    _seed_default_admin()
    db.session.add(Settings(retention_period=1, max_runtime_tasks=0, max_runtime_jobs=0))
    db.session.commit()
    resp = client.get("/setup/settings", follow_redirects=False)
    assert resp.status_code in (301, 302)


# ------------------------------------------------- Settings singleton resolution


def test_settings_current_is_deterministic_with_duplicate_rows(app):
    """Settings is a singleton in intent but not in schema.

    A live instance was found with 98 rows -- id 1 holding the real configuration
    and 97 all-zero duplicates. Every reader used a bare .first(), which in SQL
    has no defined order: MySQL happens to return primary-key order for a plain
    scan of a small table, so id 1 won, but that is a property of the chosen plan
    rather than a guarantee. Had a zero row won, the instance would have silently
    switched to chunking disabled, no runtime caps and a retention period of 0,
    with nothing in any log to explain it.
    """
    real = Settings(retention_period=30, max_runtime_jobs=24, max_runtime_tasks=4,
                    enabled_chunking=True)
    db.session.add(real)
    db.session.commit()
    for _ in range(5):
        db.session.add(Settings(retention_period=0, max_runtime_jobs=0,
                                max_runtime_tasks=0))
    db.session.commit()

    assert Settings.query.count() == 6
    chosen = Settings.current()
    assert chosen.id == real.id
    assert chosen.enabled_chunking is True
    assert chosen.max_runtime_tasks == 4


def test_settings_current_is_none_before_setup(app):
    """No row yet is a real state -- the setup wizard keys on it."""
    assert Settings.current() is None


def test_no_unordered_settings_read_remains():
    """Every reader goes through Settings.current().

    A bare .first() anywhere reintroduces the nondeterminism for that one call
    site, which is worse than the original problem: different parts of the app
    could then disagree about which row is the configuration.
    """
    import pathlib
    offenders = []
    for path in pathlib.Path('hashview').rglob('*.py'):
        text = path.read_text(encoding='utf-8')
        if 'Settings.query.first()' in text or 'db.session.query(Settings).first()' in text:
            offenders.append(str(path))
    assert offenders == []
