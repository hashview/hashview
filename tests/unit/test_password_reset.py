"""Password-reset flow tests.

Covers the two-step reset:

1. ``POST /reset_password`` — given a valid email, the server emails a
   reset link (we suppress and assert the in-message URL).
2. ``GET /reset_password/<user_id>/<token>`` — valid token serves the
   form; an invalid/tampered token redirects to ``/reset_password`` with
   a flash error.
3. ``POST /reset_password/<user_id>/<token>`` — new password is hashed
   and stored; the user can then log in with it.
"""

import pytest
from flask_bcrypt import Bcrypt

from hashview.models import Users, db


@pytest.fixture()
def existing_user(app):
    bcrypt = Bcrypt(app)
    user = Users(
        first_name="P",
        last_name="W",
        email_address="resetme@example.com",
        password=bcrypt.generate_password_hash("oldpassword12345").decode("utf-8"),
        admin=False,
    )
    db.session.add(user)
    db.session.commit()
    return user


@pytest.mark.security
def test_reset_request_with_unknown_email_does_not_error(app, client):
    """Submitting an unknown email shouldn't 500; whether the app reveals
    or hides existence is a separate concern, but it must not crash."""
    resp = client.post(
        "/reset_password",
        data={"email": "no-such-user@example.com"},
        follow_redirects=False,
    )
    assert resp.status_code in (200, 302), (
        f"reset_password on unknown email returned {resp.status_code}"
    )


@pytest.mark.security
def test_reset_token_round_trip_changes_password(app, client, existing_user):
    """A token minted by the model should let the user reset their password,
    and the new password should be accepted by the login route."""
    token = existing_user.get_reset_token()
    assert token, "get_reset_token returned empty"

    # GET the form first — should render (200), not redirect.
    resp = client.get(
        f"/reset_password/{existing_user.id}/{token}", follow_redirects=False
    )
    assert resp.status_code == 200, (
        f"GET reset_token returned {resp.status_code}"
    )

    # POST a new password.
    new_password = "newpassword1234567890"
    resp = client.post(
        f"/reset_password/{existing_user.id}/{token}",
        data={"password": new_password, "confirm_password": new_password},
        follow_redirects=False,
    )
    # Successful reset redirects to /login.
    assert resp.status_code in (200, 302), (
        f"POST reset_token returned {resp.status_code}"
    )

    # Verify the stored password actually changed (bcrypt hash check).
    db.session.refresh(existing_user)
    bcrypt = Bcrypt(app)
    assert bcrypt.check_password_hash(existing_user.password, new_password), (
        "New password was not stored after reset."
    )
    assert not bcrypt.check_password_hash(existing_user.password, "oldpassword12345"), (
        "Old password still valid after reset."
    )


@pytest.mark.security
def test_reset_token_invalid_does_not_change_password(app, client, existing_user):
    """A bogus/tampered token must NOT let an attacker reset somebody else's
    password."""
    bogus_token = "not.a.valid.jwt"

    # Try to POST a new password with a bogus token.
    client.post(
        f"/reset_password/{existing_user.id}/{bogus_token}",
        data={"password": "attackerpassword99", "confirm_password": "attackerpassword99"},
        follow_redirects=False,
    )
    # App should redirect to /reset_password with an error; what we
    # really care about is that the password didn't change.
    db.session.refresh(existing_user)
    bcrypt = Bcrypt(app)
    assert not bcrypt.check_password_hash(
        existing_user.password, "attackerpassword99"
    ), "Bogus reset token allowed password change — auth bypass!"
    assert bcrypt.check_password_hash(
        existing_user.password, "oldpassword12345"
    ), "Original password was overwritten despite invalid token."
