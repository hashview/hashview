"""Regression tests for users routes and forms (function-coverage batch: users)."""

import pytest
from wtforms.validators import ValidationError

from hashview.models import Users, db
from hashview.users.forms import UsersForm
from tests.unit.helpers import login, make_admin, make_user


# --- _safe_next (open-redirect guard) --------------------------------------

def test_safe_next_allows_relative(app):
    from hashview.users.routes import _safe_next
    with app.test_request_context("/profile?next=/jobs"):
        assert _safe_next() == "/jobs"


def test_safe_next_rejects_offsite(app):
    from hashview.users.routes import _safe_next
    with app.test_request_context("/profile?next=https://evil.example"):
        assert _safe_next() != "https://evil.example"
    with app.test_request_context("/profile?next=//evil.example"):
        assert _safe_next() != "//evil.example"


# --- login / logout --------------------------------------------------------

def test_login_get_renders_anonymous(app, client):
    resp = client.get("/login")
    assert resp.status_code == 200


def test_login_get_authenticated_redirects_home(app, client):
    # An already-authenticated user has no business on the login form. GET /login
    # used to render the authenticated app shell with an empty content area (the
    # form lives in the `content_anon` block, suppressed when logged in), which
    # both looks broken and breaks the e2e login fixture. It must redirect home.
    admin = make_admin()
    login(client, admin)
    resp = client.get("/login", follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert "/login" not in resp.headers["Location"]


def test_logout_redirects_and_clears_session(app, client):
    admin = make_admin()
    login(client, admin)
    resp = client.get("/logout", follow_redirects=False)
    assert resp.status_code in (301, 302)
    # protected page now bounces to login
    resp2 = client.get("/users", follow_redirects=False)
    assert resp2.status_code in (301, 302)


# --- user listing / creation ------------------------------------------------

def test_users_list_shows_user(app, client):
    admin = make_admin(email="admin@example.com")
    login(client, admin)
    resp = client.get("/users")
    assert resp.status_code == 200
    assert b"admin@example.com" in resp.data


def test_users_add_creates_user(app, client):
    admin = make_admin()
    login(client, admin)
    resp = client.post("/users/add", data={
        "first_name": "New", "last_name": "Person",
        "email": "new@example.com", "password": "abcdefghijklmn",
        "confirm_password": "abcdefghijklmn", "submit": "Register",
    }, follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert Users.query.filter_by(email_address="new@example.com").first() is not None


def test_users_add_non_admin_rejected(app, client):
    user = make_user()
    login(client, user)
    resp = client.post("/users/add", data={
        "first_name": "New", "last_name": "Person",
        "email": "blocked@example.com", "password": "abcdefghijklmn",
        "confirm_password": "abcdefghijklmn", "submit": "Register",
    }, follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert Users.query.filter_by(email_address="blocked@example.com").first() is None


# --- profile ---------------------------------------------------------------

def test_profile_get_redirects_home(app, client):
    """The standalone profile page is gone (editing lives in the layout modal);
    a GET just redirects home."""
    admin = make_admin()
    login(client, admin)
    resp = client.get("/profile", follow_redirects=False)
    assert resp.status_code in (301, 302)


def test_profile_post_updates_user(app, client):
    admin = make_admin()
    login(client, admin)
    resp = client.post("/profile", data={
        "first_name": "Changed", "last_name": "Name",
        "email": "admin@example.com", "submit": "Update",
    }, follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert Users.query.get(admin.id).first_name == "Changed"


# --- test-notification + api-key endpoints ---------------------------------

def test_send_test_pushover_invokes_sender(app, client, monkeypatch):
    admin = make_admin()
    login(client, admin)
    calls = []
    monkeypatch.setattr("hashview.users.routes.send_pushover",
                        lambda u, s, b: calls.append(u.id))
    resp = client.get("/profile/send_test_pushover", follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert calls == [admin.id]


def test_send_test_slack_invokes_sender(app, client, monkeypatch):
    admin = make_admin()
    login(client, admin)
    calls = []
    monkeypatch.setattr("hashview.users.routes.send_slack",
                        lambda u, s, b: calls.append(u.id))
    resp = client.get("/profile/send_test_slack", follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert calls == [admin.id]


# --- administrative-notification opt-in (profile) --------------------------

def test_account_modal_shows_admin_optin_for_admin(app, client):
    """The account-settings modal (in the layout, on every page) offers the
    administrative-notification opt-in to admins."""
    admin = make_admin()
    login(client, admin)
    html = client.get("/", follow_redirects=True).get_data(as_text=True)
    # the actual control (the input is gated by current_user.admin; the prose
    # also appears in an ungated JS comment, so assert on the input name).
    assert 'name="admin_notifications_enabled"' in html


def test_account_modal_hides_admin_optin_for_non_admin(app, client):
    user = make_user()
    login(client, user)
    html = client.get("/", follow_redirects=True).get_data(as_text=True)
    assert 'name="admin_notifications_enabled"' not in html


def test_account_modal_admin_table_only_enabled_channels(app, client):
    """The admin-alerts preferences table renders a column only for each
    instance-enabled channel (email + slack on, pushover off here)."""
    from hashview.models import Settings
    s = Settings.query.first() or Settings(retention_period=1, max_runtime_jobs=0, max_runtime_tasks=0)
    s.email_enabled, s.pushover_enabled, s.slack_enabled = True, False, True
    db.session.add(s)
    db.session.commit()
    admin = make_admin()
    login(client, admin)
    html = client.get("/", follow_redirects=True).get_data(as_text=True)
    assert 'class="an-pref"' in html                      # the table is rendered
    assert 'name="admin_notify_email"' in html
    assert 'name="admin_notify_slack"' in html
    assert 'name="admin_notify_pushover"' not in html     # disabled channel column omitted


def test_profile_post_saves_admin_notif_prefs(app, client):
    """An admin's administrative-notification opt-in + channel choices persist."""
    admin = make_admin()
    login(client, admin)
    resp = client.post("/profile", data={
        "first_name": "A", "last_name": "D", "email": "admin@example.com",
        "admin_notifications_enabled": "y", "admin_notify_email": "y",
        "admin_notify_slack": "y", "submit": "Update",
    }, follow_redirects=False)
    assert resp.status_code in (301, 302)
    u = Users.query.get(admin.id)
    assert u.admin_notifications_enabled and u.admin_notify_email and u.admin_notify_slack
    assert not u.admin_notify_pushover          # unchecked stays off


def test_profile_post_ignores_admin_prefs_for_non_admin(app, client):
    """A non-admin POST can't change the admin-only notification fields."""
    user = make_user()
    user.admin_notifications_enabled = False      # known starting state
    user.admin_notify_email = False
    db.session.commit()
    login(client, user)
    resp = client.post("/profile", data={
        "first_name": "U", "last_name": "Sr", "email": "user@example.com",
        "admin_notifications_enabled": "y", "admin_notify_email": "y", "submit": "Update",
    }, follow_redirects=False)
    assert resp.status_code in (301, 302)
    u = Users.query.get(user.id)
    assert not u.admin_notifications_enabled and not u.admin_notify_email   # POST ignored


def test_send_test_email_success_flash(app, client, monkeypatch):
    admin = make_admin()
    login(client, admin)
    monkeypatch.setattr("hashview.users.routes.send_email", lambda u, s, b: True)
    resp = client.get("/profile/send_test_email", follow_redirects=True)
    assert resp.status_code == 200
    assert b"Email Sent" in resp.data


def test_send_test_email_failure_flash(app, client, monkeypatch):
    admin = make_admin()
    login(client, admin)
    monkeypatch.setattr("hashview.users.routes.send_email", lambda u, s, b: False)
    resp = client.get("/profile/send_test_email", follow_redirects=True)
    assert resp.status_code == 200
    assert b"Email Failure" in resp.data


def test_generate_api_key_sets_key(app, client):
    admin = make_admin()
    login(client, admin)
    assert admin.api_key is None
    resp = client.get("/profile/generate_api_key", follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert Users.query.get(admin.id).api_key is not None


# --- admin reset / promote / demote ----------------------------------------

def test_admin_reset_sends_email(app, client, monkeypatch):
    admin = make_admin()
    login(client, admin)
    target = make_user(email="target@example.com")
    calls = []
    monkeypatch.setattr("hashview.users.routes.send_email",
                        lambda u, s, b: calls.append(u.id) or True)
    resp = client.get(f"/admin_reset_password/{target.id}", follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert calls == [target.id]


def test_promote_user_sets_admin(app, client):
    admin = make_admin()
    login(client, admin)
    target = make_user()
    resp = client.post(f"/users/promote/{target.id}", follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert Users.query.get(target.id).admin is True


def test_demote_user_clears_admin(app, client):
    admin = make_admin()
    login(client, admin)
    target = make_admin(email="other@example.com")
    resp = client.post(f"/users/demote/{target.id}", follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert Users.query.get(target.id).admin is False


def test_promote_user_non_admin_forbidden(app, client):
    user = make_user()
    login(client, user)
    target = make_user(email="target2@example.com")
    resp = client.post(f"/users/promote/{target.id}", follow_redirects=False)
    assert resp.status_code == 403


# --- form validators --------------------------------------------------------

def test_validate_email_rejects_duplicate(app):
    make_user(email="dupe@example.com")
    form = UsersForm()

    class _Field:
        data = "dupe@example.com"

    with pytest.raises(ValidationError):
        form.validate_email(_Field())


def test_validate_pushover_requires_both(app):
    form = UsersForm()

    class _App:
        data = "appid"

    class _Empty:
        data = ""

    with pytest.raises(ValidationError):
        form.validate_pushover(_App(), _Empty())
    with pytest.raises(ValidationError):
        form.validate_pushover(_Empty(), _App())
    # both empty -> OK
    assert form.validate_pushover(_Empty(), _Empty()) is None
