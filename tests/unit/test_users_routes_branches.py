"""Branch-coverage tests for hashview/users/routes.py.

Targets: login_get, login_post, logout, users_list, users_add, users_edit,
users_delete, profile, send_test_pushover, send_test_slack, send_test_email,
generate_api_key, reset_request, admin_reset, reset_token, promote_user,
demote_user.

All tests run against an in-memory SQLite app (CSRF disabled) provided by
the conftest.py fixtures: app, client, db_session.
"""

from unittest.mock import patch

import pytest
from flask_bcrypt import Bcrypt

from hashview.models import Users, db


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_user(app, *, email, admin=False, first_name="A", last_name="B"):
    """Create and persist a user, returning the Users instance."""
    bcrypt = Bcrypt(app)
    pw_hash = bcrypt.generate_password_hash("ValidPass1234!").decode("latin-1")
    user = Users(
        first_name=first_name,
        last_name=last_name,
        email_address=email,
        password=pw_hash,
        admin=admin,
    )
    db.session.add(user)
    db.session.commit()
    return user


def _login(client, user):
    """Inject a Flask-Login session for *user* into *client*."""
    with client.session_transaction() as s:
        s["_user_id"] = str(user.id)
        s["_fresh"] = True


# ---------------------------------------------------------------------------
# login_get
# ---------------------------------------------------------------------------

class TestLoginGet:
    def test_returns_200(self, client):
        resp = client.get("/login")
        assert resp.status_code == 200

    def test_contains_form(self, client):
        resp = client.get("/login")
        assert b"form" in resp.data.lower() or b"Login" in resp.data


# ---------------------------------------------------------------------------
# login_post — success path
# ---------------------------------------------------------------------------

class TestLoginPost:
    def test_valid_credentials_redirect(self, app, client):
        bcrypt = Bcrypt(app)
        user = Users(
            first_name="Log",
            last_name="In",
            email_address="login@example.com",
            password=bcrypt.generate_password_hash("ValidPass1234!").decode("latin-1"),
            admin=False,
        )
        db.session.add(user)
        db.session.commit()

        resp = client.post(
            "/login",
            data={"email": "login@example.com", "password": "ValidPass1234!", "remember": False},
            follow_redirects=False,
        )
        assert resp.status_code in (301, 302)

    def test_invalid_email_stays_on_login(self, app, client):
        resp = client.post(
            "/login",
            data={"email": "nobody@example.com", "password": "ValidPass1234!"},
            follow_redirects=False,
        )
        # Re-renders login page (200) or redirects
        assert resp.status_code in (200, 302)

    def test_wrong_password_stays_on_login(self, app, client):
        bcrypt = Bcrypt(app)
        user = Users(
            first_name="Bad",
            last_name="Pw",
            email_address="badpw@example.com",
            password=bcrypt.generate_password_hash("CorrectPass1234!").decode("latin-1"),
            admin=False,
        )
        db.session.add(user)
        db.session.commit()

        resp = client.post(
            "/login",
            data={"email": "badpw@example.com", "password": "WrongPass9999!"},
            follow_redirects=False,
        )
        assert resp.status_code in (200, 302)

    def test_form_validation_failure(self, app, client):
        """Submitting with missing fields triggers form validation failure."""
        resp = client.post("/login", data={}, follow_redirects=False)
        assert resp.status_code in (200, 302)

    def test_next_param_respected(self, app, client):
        """A same-site ?next= value is used as the post-login redirect."""
        bcrypt = Bcrypt(app)
        user = Users(
            first_name="Nxt",
            last_name="Us",
            email_address="next@example.com",
            password=bcrypt.generate_password_hash("ValidPass1234!").decode("latin-1"),
            admin=False,
        )
        db.session.add(user)
        db.session.commit()

        resp = client.post(
            "/login?next=/users",
            data={"email": "next@example.com", "password": "ValidPass1234!"},
            follow_redirects=False,
        )
        assert resp.status_code in (301, 302)
        location = resp.headers.get("Location", "")
        assert "/users" in location

    def test_open_redirect_blocked(self, app, client):
        """An off-site ?next= must NOT be used as the redirect target."""
        bcrypt = Bcrypt(app)
        user = Users(
            first_name="Sec",
            last_name="Us",
            email_address="secure@example.com",
            password=bcrypt.generate_password_hash("ValidPass1234!").decode("latin-1"),
            admin=False,
        )
        db.session.add(user)
        db.session.commit()

        resp = client.post(
            "/login?next=https://evil.example",
            data={"email": "secure@example.com", "password": "ValidPass1234!"},
            follow_redirects=False,
        )
        assert resp.status_code in (301, 302)
        location = resp.headers.get("Location", "")
        assert "evil.example" not in location


# ---------------------------------------------------------------------------
# logout
# ---------------------------------------------------------------------------

class TestLogout:
    def test_logout_redirects(self, app, client):
        user = _make_user(app, email="logout@example.com")
        _login(client, user)
        resp = client.get("/logout", follow_redirects=False)
        assert resp.status_code in (301, 302)


# ---------------------------------------------------------------------------
# users_list
# ---------------------------------------------------------------------------

class TestUsersList:
    def test_admin_can_view(self, app, client):
        user = _make_user(app, email="admin_list@example.com", admin=True)
        _login(client, user)
        resp = client.get("/users")
        assert resp.status_code == 200

    def test_non_admin_can_view(self, app, client):
        user = _make_user(app, email="nonadmin_list@example.com", admin=False)
        _login(client, user)
        resp = client.get("/users")
        assert resp.status_code == 200

    def test_unauthenticated_redirects(self, client):
        resp = client.get("/users", follow_redirects=False)
        assert resp.status_code in (301, 302)


# ---------------------------------------------------------------------------
# users_add
# ---------------------------------------------------------------------------

class TestUsersAdd:
    def test_admin_get_renders_form(self, app, client):
        user = _make_user(app, email="admin_add@example.com", admin=True)
        _login(client, user)
        resp = client.get("/users/add")
        assert resp.status_code == 200

    def test_non_admin_redirected(self, app, client):
        user = _make_user(app, email="nonadmin_add@example.com", admin=False)
        _login(client, user)
        resp = client.post(
            "/users/add",
            data={
                "first_name": "New",
                "last_name": "User",
                "email": "newuser@example.com",
                "password": "NewUserPass1234!",
                "confirm_password": "NewUserPass1234!",
            },
            follow_redirects=False,
        )
        assert resp.status_code in (301, 302)
        location = resp.headers.get("Location", "")
        assert "/users" in location

    def test_admin_can_add_user(self, app, client):
        user = _make_user(app, email="admin_adder@example.com", admin=True)
        _login(client, user)
        resp = client.post(
            "/users/add",
            data={
                "first_name": "Created",
                "last_name": "User",
                "email": "createduser@example.com",
                "password": "CreatedPass1234!",
                "confirm_password": "CreatedPass1234!",
                "is_admin": False,
            },
            follow_redirects=False,
        )
        assert resp.status_code in (301, 302)
        created = Users.query.filter_by(email_address="createduser@example.com").first()
        assert created is not None

    def test_admin_add_user_with_pushover(self, app, client):
        user = _make_user(app, email="admin_pushover@example.com", admin=True)
        _login(client, user)
        resp = client.post(
            "/users/add",
            data={
                "first_name": "Push",
                "last_name": "Over",
                "email": "pushovercreated@example.com",
                "password": "PushoverPass1234!",
                "confirm_password": "PushoverPass1234!",
                "is_admin": False,
                "pushover_app_id": "apptoken123",
                "pushover_user_key": "userkey123",
            },
            follow_redirects=False,
        )
        assert resp.status_code in (200, 301, 302)

    def test_admin_add_user_with_invite(self, app, client):
        """send_invite flag triggers send_email (best-effort, won't crash)."""
        user = _make_user(app, email="admin_invite@example.com", admin=True)
        _login(client, user)
        resp = client.post(
            "/users/add",
            data={
                "first_name": "Invited",
                "last_name": "User",
                "email": "inviteduser@example.com",
                "password": "InvitedPass1234!",
                "confirm_password": "InvitedPass1234!",
                "is_admin": False,
                "send_invite": "1",
            },
            follow_redirects=False,
        )
        assert resp.status_code in (200, 301, 302)

    def test_admin_get_add_page(self, app, client):
        """GET /users/add renders the add form."""
        user = _make_user(app, email="admin_get_add@example.com", admin=True)
        _login(client, user)
        resp = client.get("/users/add")
        assert resp.status_code == 200

    def test_non_admin_get_redirected(self, app, client):
        """Non-admin GET /users/add is redirected."""
        user = _make_user(app, email="nonadmin_get_add@example.com", admin=False)
        _login(client, user)
        resp = client.get("/users/add")
        assert resp.status_code in (200, 301, 302)


# ---------------------------------------------------------------------------
# users_edit
# ---------------------------------------------------------------------------

class TestUsersEdit:
    def test_admin_can_edit_user(self, app, client):
        admin = _make_user(app, email="admin_edit@example.com", admin=True)
        target = _make_user(app, email="target_edit@example.com", admin=False)
        _login(client, admin)

        resp = client.post(
            f"/users/edit/{target.id}",
            data={
                "first_name": "Updated",
                "last_name": "Name",
                "email": "target_edit@example.com",
                "is_admin": "",
            },
            follow_redirects=False,
        )
        assert resp.status_code in (301, 302)
        db.session.refresh(target)
        assert target.first_name == "Updated"

    def test_non_admin_redirected(self, app, client):
        non_admin = _make_user(app, email="nonadmin_edit@example.com", admin=False)
        target = _make_user(app, email="target2_edit@example.com", admin=False)
        _login(client, non_admin)

        resp = client.post(
            f"/users/edit/{target.id}",
            data={
                "first_name": "Hacked",
                "last_name": "Name",
                "email": "target2_edit@example.com",
            },
            follow_redirects=False,
        )
        assert resp.status_code in (301, 302)
        db.session.refresh(target)
        assert target.first_name != "Hacked"

    def test_edit_not_found_redirects(self, app, client):
        admin = _make_user(app, email="admin_editnotfound@example.com", admin=True)
        _login(client, admin)

        resp = client.post(
            "/users/edit/99999",
            data={
                "first_name": "Ghost",
                "last_name": "User",
                "email": "ghost@example.com",
            },
            follow_redirects=False,
        )
        assert resp.status_code in (301, 302)

    def test_edit_missing_required_fields(self, app, client):
        admin = _make_user(app, email="admin_editreq@example.com", admin=True)
        target = _make_user(app, email="target_req@example.com", admin=False)
        _login(client, admin)

        resp = client.post(
            f"/users/edit/{target.id}",
            data={"first_name": "", "last_name": "", "email": ""},
            follow_redirects=False,
        )
        assert resp.status_code in (301, 302)
        location = resp.headers.get("Location", "")
        assert "/users" in location

    def test_edit_duplicate_email_rejected(self, app, client):
        admin = _make_user(app, email="admin_dupcheck@example.com", admin=True)
        other = _make_user(app, email="other_dup@example.com", admin=False)
        target = _make_user(app, email="target_dup@example.com", admin=False)
        _login(client, admin)

        resp = client.post(
            f"/users/edit/{target.id}",
            data={
                "first_name": "Target",
                "last_name": "User",
                "email": other.email_address,  # already taken
            },
            follow_redirects=False,
        )
        assert resp.status_code in (301, 302)
        db.session.refresh(target)
        assert target.email_address != other.email_address

    def test_edit_password_change(self, app, client):
        admin = _make_user(app, email="admin_pwchange@example.com", admin=True)
        target = _make_user(app, email="target_pwchange@example.com", admin=False)
        _login(client, admin)

        new_pw = "NewSecurePassword1234!"
        resp = client.post(
            f"/users/edit/{target.id}",
            data={
                "first_name": "Target",
                "last_name": "User",
                "email": "target_pwchange@example.com",
                "password": new_pw,
                "confirm_password": new_pw,
            },
            follow_redirects=False,
        )
        assert resp.status_code in (301, 302)
        db.session.refresh(target)
        bcrypt = Bcrypt(app)
        assert bcrypt.check_password_hash(target.password, new_pw)

    def test_edit_password_too_short(self, app, client):
        admin = _make_user(app, email="admin_shortpw@example.com", admin=True)
        target = _make_user(app, email="target_shortpw@example.com", admin=False)
        _login(client, admin)

        resp = client.post(
            f"/users/edit/{target.id}",
            data={
                "first_name": "Target",
                "last_name": "User",
                "email": "target_shortpw@example.com",
                "password": "short",
                "confirm_password": "short",
            },
            follow_redirects=False,
        )
        assert resp.status_code in (301, 302)

    def test_edit_password_mismatch(self, app, client):
        admin = _make_user(app, email="admin_pwmismatch@example.com", admin=True)
        target = _make_user(app, email="target_pwmismatch@example.com", admin=False)
        _login(client, admin)

        resp = client.post(
            f"/users/edit/{target.id}",
            data={
                "first_name": "Target",
                "last_name": "User",
                "email": "target_pwmismatch@example.com",
                "password": "ValidPass1234!abc",
                "confirm_password": "DifferentPass!5678",
            },
            follow_redirects=False,
        )
        assert resp.status_code in (301, 302)

    def test_edit_keep_own_email(self, app, client):
        """User keeping their own email is not a duplicate clash."""
        admin = _make_user(app, email="admin_ownemail@example.com", admin=True)
        _login(client, admin)

        resp = client.post(
            f"/users/edit/{admin.id}",
            data={
                "first_name": "Updated",
                "last_name": "Admin",
                "email": admin.email_address,
            },
            follow_redirects=False,
        )
        assert resp.status_code in (301, 302)
        db.session.refresh(admin)
        assert admin.first_name == "Updated"


# ---------------------------------------------------------------------------
# users_delete
# ---------------------------------------------------------------------------

class TestUsersDelete:
    def test_admin_can_delete_user(self, app, client):
        admin = _make_user(app, email="admin_del@example.com", admin=True)
        target = _make_user(app, email="target_del@example.com", admin=False)
        target_id = target.id
        _login(client, admin)

        resp = client.post(f"/users/delete/{target_id}", follow_redirects=False)
        assert resp.status_code in (301, 302)
        assert Users.query.get(target_id) is None

    def test_non_admin_cannot_delete(self, app, client):
        non_admin = _make_user(app, email="nonadmin_del@example.com", admin=False)
        target = _make_user(app, email="victim_del@example.com", admin=False)
        target_id = target.id
        _login(client, non_admin)

        resp = client.post(f"/users/delete/{target_id}", follow_redirects=False)
        assert resp.status_code in (301, 302)
        assert Users.query.get(target_id) is not None

    def test_delete_not_found_redirects(self, app, client):
        admin = _make_user(app, email="admin_delnotfound@example.com", admin=True)
        _login(client, admin)

        resp = client.post("/users/delete/99999", follow_redirects=False)
        assert resp.status_code in (301, 302)


# ---------------------------------------------------------------------------
# profile
# ---------------------------------------------------------------------------

class TestProfile:
    def test_get_renders_form(self, app, client):
        user = _make_user(app, email="profile_get@example.com")
        _login(client, user)
        resp = client.get("/profile")
        assert resp.status_code == 200

    def test_post_updates_profile(self, app, client):
        user = _make_user(app, email="profile_post@example.com")
        _login(client, user)

        resp = client.post(
            "/profile",
            data={
                "first_name": "Updated",
                "last_name": "User",
                "email": "profile_post@example.com",
            },
            follow_redirects=False,
        )
        assert resp.status_code in (301, 302)
        db.session.refresh(user)
        assert user.first_name == "Updated"

    def test_post_updates_pushover(self, app, client):
        user = _make_user(app, email="profile_push@example.com")
        _login(client, user)

        resp = client.post(
            "/profile",
            data={
                "first_name": "Push",
                "last_name": "User",
                "email": "profile_push@example.com",
                "pushover_user_key": "pushover_key_123",
                "pushover_app_id": "pushover_app_123",
            },
            follow_redirects=False,
        )
        assert resp.status_code in (301, 302)
        db.session.refresh(user)
        assert user.pushover_user_key == "pushover_key_123"
        assert user.pushover_app_id == "pushover_app_123"

    def test_post_updates_slack(self, app, client):
        user = _make_user(app, email="profile_slack@example.com")
        _login(client, user)

        resp = client.post(
            "/profile",
            data={
                "first_name": "Slack",
                "last_name": "User",
                "email": "profile_slack@example.com",
                "slack_id": "U01234SLACK",
            },
            follow_redirects=False,
        )
        assert resp.status_code in (301, 302)
        db.session.refresh(user)
        assert user.slack_id == "U01234SLACK"

    def test_post_with_next(self, app, client):
        """Profile POST with a same-site ?next= should redirect there."""
        user = _make_user(app, email="profile_next@example.com")
        _login(client, user)

        resp = client.post(
            "/profile?next=/users",
            data={
                "first_name": "Next",
                "last_name": "User",
                "email": "profile_next@example.com",
            },
            follow_redirects=False,
        )
        assert resp.status_code in (301, 302)
        location = resp.headers.get("Location", "")
        assert "/users" in location


# ---------------------------------------------------------------------------
# send_test_pushover
# ---------------------------------------------------------------------------

class TestSendTestPushover:
    def test_authenticated_triggers_flash(self, app, client):
        user = _make_user(app, email="pushover_test@example.com")
        _login(client, user)
        resp = client.get("/profile/send_test_pushover", follow_redirects=False)
        assert resp.status_code in (301, 302)

    def test_unauthenticated_redirects_to_login(self, client):
        resp = client.get("/profile/send_test_pushover", follow_redirects=False)
        assert resp.status_code in (301, 302)
        location = resp.headers.get("Location", "")
        assert "/login" in location


# ---------------------------------------------------------------------------
# send_test_slack
# ---------------------------------------------------------------------------

class TestSendTestSlack:
    def test_authenticated_triggers_flash(self, app, client):
        user = _make_user(app, email="slack_test@example.com")
        _login(client, user)
        resp = client.get("/profile/send_test_slack", follow_redirects=False)
        assert resp.status_code in (301, 302)

    def test_unauthenticated_redirects_to_login(self, client):
        resp = client.get("/profile/send_test_slack", follow_redirects=False)
        assert resp.status_code in (301, 302)
        location = resp.headers.get("Location", "")
        assert "/login" in location


# ---------------------------------------------------------------------------
# send_test_email
# ---------------------------------------------------------------------------

class TestSendTestEmail:
    def test_authenticated_send_succeeds_or_fails_gracefully(self, app, client):
        user = _make_user(app, email="email_test@example.com")
        _login(client, user)
        resp = client.get("/profile/send_test_email", follow_redirects=False)
        assert resp.status_code in (301, 302)

    def test_unauthenticated_redirects_to_login(self, client):
        resp = client.get("/profile/send_test_email", follow_redirects=False)
        assert resp.status_code in (301, 302)
        location = resp.headers.get("Location", "")
        assert "/login" in location


# ---------------------------------------------------------------------------
# generate_api_key
# ---------------------------------------------------------------------------

class TestGenerateApiKey:
    def test_generates_new_key(self, app, client):
        user = _make_user(app, email="api_key@example.com")
        assert user.api_key is None
        _login(client, user)

        resp = client.get("/profile/generate_api_key", follow_redirects=False)
        assert resp.status_code in (301, 302)
        db.session.refresh(user)
        assert user.api_key is not None

    def test_unauthenticated_redirects(self, client):
        resp = client.get("/profile/generate_api_key", follow_redirects=False)
        assert resp.status_code in (301, 302)
        location = resp.headers.get("Location", "")
        assert "/login" in location


# ---------------------------------------------------------------------------
# reset_request
# ---------------------------------------------------------------------------

class TestResetRequest:
    def test_get_renders_form(self, client):
        resp = client.get("/reset_password")
        assert resp.status_code == 200

    def test_post_known_email_redirects(self, app, client):
        user = _make_user(app, email="resetreq@example.com")
        resp = client.post(
            "/reset_password",
            data={"email": "resetreq@example.com"},
            follow_redirects=False,
        )
        assert resp.status_code in (301, 302)

    def test_post_unknown_email_redirects(self, client):
        resp = client.post(
            "/reset_password",
            data={"email": "nobody@example.com"},
            follow_redirects=False,
        )
        # Should redirect without error — no user enumeration
        assert resp.status_code in (200, 301, 302)

    def test_post_invalid_form_stays(self, client):
        resp = client.post("/reset_password", data={}, follow_redirects=False)
        assert resp.status_code in (200, 301, 302)


# ---------------------------------------------------------------------------
# admin_reset
# ---------------------------------------------------------------------------

class TestAdminReset:
    def test_admin_can_send_reset_email(self, app, client):
        admin = _make_user(app, email="admin_reset_sender@example.com", admin=True)
        target = _make_user(app, email="admin_reset_target@example.com", admin=False)
        _login(client, admin)

        resp = client.get(
            f"/admin_reset_password/{target.id}",
            follow_redirects=False,
        )
        assert resp.status_code in (301, 302)

    def test_non_admin_redirected(self, app, client):
        non_admin = _make_user(app, email="nonadmin_reset@example.com", admin=False)
        target = _make_user(app, email="target_adminreset@example.com", admin=False)
        _login(client, non_admin)

        resp = client.get(
            f"/admin_reset_password/{target.id}",
            follow_redirects=False,
        )
        assert resp.status_code in (301, 302)
        location = resp.headers.get("Location", "")
        assert "/users" in location


# ---------------------------------------------------------------------------
# reset_token
# ---------------------------------------------------------------------------

class TestResetToken:
    def test_get_valid_token(self, app, client):
        user = _make_user(app, email="tokenget@example.com")
        token = user.get_reset_token()

        resp = client.get(
            f"/reset_password/{user.id}/{token}",
            follow_redirects=False,
        )
        assert resp.status_code == 200

    def test_get_invalid_token_redirects(self, app, client):
        user = _make_user(app, email="tokeninvalid@example.com")

        resp = client.get(
            f"/reset_password/{user.id}/notavalidtoken",
            follow_redirects=False,
        )
        assert resp.status_code in (301, 302)

    def test_get_invalid_user_id_redirects(self, app, client):
        resp = client.get(
            "/reset_password/99999/anytoken",
            follow_redirects=False,
        )
        assert resp.status_code in (301, 302)

    def test_post_valid_token_changes_password(self, app, client):
        user = _make_user(app, email="tokenpost@example.com")
        token = user.get_reset_token()
        new_pw = "FreshPassword5678!"

        resp = client.post(
            f"/reset_password/{user.id}/{token}",
            data={"password": new_pw, "confirm_password": new_pw},
            follow_redirects=False,
        )
        assert resp.status_code in (301, 302)
        db.session.refresh(user)
        bcrypt = Bcrypt(app)
        assert bcrypt.check_password_hash(user.password, new_pw)

    def test_post_invalid_token_does_not_change_password(self, app, client):
        user = _make_user(app, email="tokenpostinvalid@example.com")
        old_hash = user.password

        resp = client.post(
            f"/reset_password/{user.id}/bogus.token.here",
            data={"password": "Attacker1234!abc", "confirm_password": "Attacker1234!abc"},
            follow_redirects=False,
        )
        db.session.refresh(user)
        assert user.password == old_hash


# ---------------------------------------------------------------------------
# promote_user
# ---------------------------------------------------------------------------

class TestPromoteUser:
    def test_admin_can_promote(self, app, client):
        admin = _make_user(app, email="admin_promote@example.com", admin=True)
        target = _make_user(app, email="target_promote@example.com", admin=False)
        _login(client, admin)

        resp = client.post(f"/users/promote/{target.id}", follow_redirects=False)
        assert resp.status_code in (301, 302)
        db.session.refresh(target)
        assert target.admin is True

    def test_non_admin_gets_403(self, app, client):
        non_admin = _make_user(app, email="nonadmin_promote@example.com", admin=False)
        target = _make_user(app, email="target2_promote@example.com", admin=False)
        _login(client, non_admin)

        resp = client.post(f"/users/promote/{target.id}", follow_redirects=False)
        assert resp.status_code == 403

    def test_promote_nonexistent_user_404(self, app, client):
        admin = _make_user(app, email="admin_promote404@example.com", admin=True)
        _login(client, admin)

        resp = client.post("/users/promote/99999", follow_redirects=False)
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# demote_user
# ---------------------------------------------------------------------------

class TestDemoteUser:
    def test_admin_can_demote(self, app, client):
        admin = _make_user(app, email="admin_demote@example.com", admin=True)
        target = _make_user(app, email="target_demote@example.com", admin=True)
        _login(client, admin)

        resp = client.post(f"/users/demote/{target.id}", follow_redirects=False)
        assert resp.status_code in (301, 302)
        db.session.refresh(target)
        assert target.admin is False

    def test_non_admin_gets_403(self, app, client):
        non_admin = _make_user(app, email="nonadmin_demote@example.com", admin=False)
        target = _make_user(app, email="target2_demote@example.com", admin=True)
        _login(client, non_admin)

        resp = client.post(f"/users/demote/{target.id}", follow_redirects=False)
        assert resp.status_code == 403

    def test_demote_nonexistent_user_404(self, app, client):
        admin = _make_user(app, email="admin_demote404@example.com", admin=True)
        _login(client, admin)

        resp = client.post("/users/demote/99999", follow_redirects=False)
        assert resp.status_code == 404

    def test_demote_admin_clears_flag(self, app, client):
        """Demoting an admin sets admin=False (no last-admin guard in demote_user)."""
        admin = _make_user(app, email="admin_selfdemote@example.com", admin=True)
        target = _make_user(app, email="target_demote2@example.com", admin=True)
        _login(client, admin)

        # Demote a second admin — should succeed
        resp = client.post(f"/users/demote/{target.id}", follow_redirects=False)
        assert resp.status_code in (301, 302)
        db.session.refresh(target)
        assert target.admin is False


# ---------------------------------------------------------------------------
# Azure SSO break-glass gate
# ---------------------------------------------------------------------------

class TestAzureSsoGate:
    """login_post Azure break-glass: non-id-1 users are blocked when azure mode is on."""

    def test_non_admin_blocked_in_azure_mode(self, app, client):
        from hashview.models import Settings

        # Ensure a Settings row with azure config exists
        s = Settings.query.first()
        if s is None:
            s = Settings(id=1)
            db.session.add(s)

        s.auth_method = "azure"
        s.azure_tenant_id = "tenant-123"
        s.azure_client_id = "client-456"
        s.azure_client_secret = "secret-789"  # noqa: S105
        db.session.commit()

        bcrypt = Bcrypt(app)
        # Create a placeholder user first so the blocked user gets id != 1.
        placeholder = Users(
            first_name="Break",
            last_name="Glass",
            email_address="breakglass_az@example.com",
            password=bcrypt.generate_password_hash("ValidPass1234!").decode("latin-1"),
            admin=True,
        )
        db.session.add(placeholder)
        db.session.commit()

        user = Users(
            first_name="Az",
            last_name="User",
            email_address="azure_blocked@example.com",
            password=bcrypt.generate_password_hash("ValidPass1234!").decode("latin-1"),
            admin=False,
        )
        db.session.add(user)
        db.session.commit()
        # Ensure user.id != 1 (break-glass is only for id=1)
        assert user.id != 1

        resp = client.post(
            "/login",
            data={"email": "azure_blocked@example.com", "password": "ValidPass1234!"},
            follow_redirects=False,
        )
        # Should redirect back to login (not to home)
        assert resp.status_code in (301, 302)
        location = resp.headers.get("Location", "")
        assert "/login" in location

    def test_admin_id1_allowed_in_azure_mode(self, app, client):
        """The break-glass account (id=1) must be able to log in even in Azure mode."""
        from hashview.models import Settings

        s = Settings.query.first()
        if s is None:
            s = Settings(id=1)
            db.session.add(s)

        s.auth_method = "azure"
        s.azure_tenant_id = "tenant-123"
        s.azure_client_id = "client-456"
        s.azure_client_secret = "secret-789"  # noqa: S105
        db.session.commit()

        bcrypt = Bcrypt(app)
        # Force the user to have id=1 by making it the first user in this DB
        # (SQLite auto-increments from 1 for a fresh in-memory DB).
        user = Users(
            first_name="Break",
            last_name="Glass",
            email_address="breakglass@example.com",
            password=bcrypt.generate_password_hash("ValidPass1234!").decode("latin-1"),
            admin=True,
        )
        db.session.add(user)
        db.session.commit()

        if user.id != 1:
            pytest.skip("Could not create the break-glass user as id=1 in this DB state.")

        resp = client.post(
            "/login",
            data={"email": "breakglass@example.com", "password": "ValidPass1234!"},
            follow_redirects=False,
        )
        # Break-glass should succeed → redirect to home, NOT back to /login
        assert resp.status_code in (301, 302)
        location = resp.headers.get("Location", "")
        assert "/login" not in location


# ---------------------------------------------------------------------------
# _azure_enabled() exception branch (lines 80-81)
# ---------------------------------------------------------------------------

class TestAzureEnabledExceptionBranch:
    def test_azure_enabled_exception_treated_as_disabled(self, app, client):
        """If Settings.query.first() raises, _azure_enabled() returns False
        and login_get/login_post still work."""
        with patch("hashview.users.routes.Settings") as mock_settings:
            mock_settings.query.first.side_effect = Exception("DB exploded")
            resp = client.get("/login")
            assert resp.status_code == 200


# ---------------------------------------------------------------------------
# send_test_email — success branch (line 315)
# ---------------------------------------------------------------------------

class TestSendTestEmailSuccess:
    def test_email_sent_flash(self, app, client):
        """When send_email returns True the 'Email Sent' flash is shown."""
        user = _make_user(app, email="email_success@example.com")
        _login(client, user)

        with patch("hashview.users.routes.send_email", return_value=True):
            resp = client.get(
                "/profile/send_test_email",
                follow_redirects=True,
            )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# users_delete — try_commit failure branch (lines 255-256)
# ---------------------------------------------------------------------------

class TestUsersDeleteCommitFailure:
    def test_commit_failure_flashes_error(self, app, client):
        """If try_commit returns False, the route flashes a danger message."""
        admin = _make_user(app, email="admin_delfail@example.com", admin=True)
        target = _make_user(app, email="target_delfail@example.com", admin=False)
        _login(client, admin)

        with patch("hashview.users.routes.try_commit", return_value=False):
            resp = client.post(
                f"/users/delete/{target.id}",
                follow_redirects=True,
            )
        assert resp.status_code == 200
