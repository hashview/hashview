"""Regression tests for setup defaults + first-run routes
(function-coverage batch: setup)."""

from hashview import setup as setup_mod
from hashview.models import Rules, Settings, Tasks, Users, Wordlists, db
from hashview.setup import (
    add_admin_user,
    add_default_rules,
    add_default_static_wordlist,
    add_default_tasks,
    admin_pass_needs_changed,
    admin_user_needs_added,
    default_rules_need_added,
    default_static_wordlist_need_added,
    default_tasks_need_added,
    settings_needs_added,
)
from hashview.users.routes import bcrypt


# --- predicate / adder pairs -----------------------------------------------

def test_default_tasks_added_once(app):
    assert default_tasks_need_added(db) is True
    add_default_tasks(db)
    assert default_tasks_need_added(db) is False
    assert Tasks.query.count() == 3


def test_default_rules_added_once(app, monkeypatch):
    # The real adder shells out to gzip + os.replace; stub the file work and
    # the hash/size helpers so we exercise the DB-insert logic only.
    monkeypatch.setattr(setup_mod.os, "system", lambda cmd: 0)
    monkeypatch.setattr(setup_mod.os, "replace", lambda a, b: None)
    monkeypatch.setattr(setup_mod, "get_filehash", lambda p: "0" * 64)
    monkeypatch.setattr(setup_mod, "get_linecount", lambda p: 64)
    assert default_rules_need_added(db) is True
    add_default_rules(db)
    assert default_rules_need_added(db) is False
    assert Rules.query.filter_by(name="Best64 Rule").first() is not None


def test_default_static_wordlist_added_once(app, monkeypatch):
    monkeypatch.setattr(setup_mod.os, "system", lambda cmd: 0)
    monkeypatch.setattr(setup_mod.os, "replace", lambda a, b: None)
    monkeypatch.setattr(setup_mod, "get_filehash", lambda p: "0" * 64)
    monkeypatch.setattr(setup_mod, "get_linecount", lambda p: 100)
    assert default_static_wordlist_need_added(db) is True
    add_default_static_wordlist(db)
    assert default_static_wordlist_need_added(db) is False
    wl = Wordlists.query.filter_by(name="Rockyou.txt").first()
    assert wl is not None and wl.type == "static"


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
