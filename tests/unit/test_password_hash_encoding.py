"""Password-hash storage round trips for the three bcrypt sites in this branch.

``bcrypt.generate_password_hash(...).decode(...)`` moved from latin-1 to utf-8 in
hashview/users/routes.py (add + edit) and hashview/auth/service.py (Azure JIT).
The decode itself is not observable -- a modular-crypt bcrypt digest is pure
ASCII, so both codecs produce the identical string; the change is consistency,
not a bug fix. What these tests pin is the behaviour that *is* observable and was
previously untested at all: a password whose characters live above U+00FF is
hashed and stored such that the login check later accepts it, and the Azure JIT
row gets a hash nothing can log in with.

The ``password`` column is a String(60) sized exactly for a bcrypt digest, so a
site that ever stored something wider than ASCII would truncate here and lock
the account out. That is the regression these guard against.
"""

import re

from hashview.models import Users, db
from tests.unit.helpers import login, make_admin

# Emoji + CJK + Cyrillic: every character is above U+00FF, i.e. exactly what
# latin-1 cannot represent.
NON_LATIN1_PASSWORD = "пароль-密码-🔒-ok"
BCRYPT_DIGEST = re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$")


def _bcrypt():
    """The app's single Bcrypt instance (created in users/routes.py, init_app'd
    by the factory) -- the same object the login route checks against."""
    from hashview.users.routes import bcrypt

    return bcrypt


def test_users_add_stores_an_ascii_bcrypt_digest_for_a_non_latin1_password(app, client):
    admin = make_admin()
    login(client, admin)

    resp = client.post("/users/add", data={
        "first_name": "Intl", "last_name": "User",
        "email": "intl@example.com",
        "password": NON_LATIN1_PASSWORD,
        "confirm_password": NON_LATIN1_PASSWORD,
        "submit": "Register",
    }, follow_redirects=False)
    assert resp.status_code in (301, 302)

    user = Users.query.filter_by(email_address="intl@example.com").first()
    assert user is not None
    assert BCRYPT_DIGEST.match(user.password), user.password
    # Fits the String(60) column with nothing lost.
    assert len(user.password) == 60


def test_users_add_password_verifies_on_login(app, client):
    """The whole point of the stored form: the login check must accept it."""
    admin = make_admin()
    login(client, admin)
    client.post("/users/add", data={
        "first_name": "Intl", "last_name": "User",
        "email": "intl-login@example.com",
        "password": NON_LATIN1_PASSWORD,
        "confirm_password": NON_LATIN1_PASSWORD,
        "submit": "Register",
    })

    user = Users.query.filter_by(email_address="intl-login@example.com").first()
    assert _bcrypt().check_password_hash(user.password, NON_LATIN1_PASSWORD)
    assert not _bcrypt().check_password_hash(user.password, "wrong-password-xx")


def test_users_edit_password_change_stores_a_verifiable_digest(app, client):
    admin = make_admin()
    login(client, admin)
    target = Users(first_name="T", last_name="U", email_address="edit@example.com",
                   password="x" * 60, admin=False)
    db.session.add(target)
    db.session.commit()
    target_id = target.id

    resp = client.post(f"/users/edit/{target_id}", data={
        "first_name": "T", "last_name": "U", "email": "edit@example.com",
        "password": NON_LATIN1_PASSWORD,
        "confirm_password": NON_LATIN1_PASSWORD,
    }, follow_redirects=False)
    assert resp.status_code in (301, 302)

    updated = Users.query.get(target_id)
    assert BCRYPT_DIGEST.match(updated.password), updated.password
    assert _bcrypt().check_password_hash(updated.password, NON_LATIN1_PASSWORD)


def test_azure_jit_provisioned_user_gets_an_unusable_ascii_digest(app):
    """The Azure JIT path (hashview/auth/service.py) had no test at all.

    Its account can never password-login, so the assertion is twofold: the
    column holds a well-formed bcrypt digest, and no empty/blank password
    satisfies it.
    """
    from hashview.auth.service import resolve_or_provision_azure_user

    class _Settings:
        azure_allowed_groups = None

    claims = {
        "oid": "00000000-0000-0000-0000-00000000abcd",
        "email": "jit@example.com",
        "given_name": "Jit",
        "family_name": "User",
    }

    user = resolve_or_provision_azure_user(claims, _Settings())

    assert user.id is not None
    assert user.auth_source == "azure"
    assert user.admin is False
    assert BCRYPT_DIGEST.match(user.password), user.password
    assert len(user.password) == 60
    for guess in ("", " ", "password"):
        assert not _bcrypt().check_password_hash(user.password, guess)


def test_azure_jit_password_is_random_per_account(app):
    """Two provisioned accounts must not share a digest -- a fixed one would be
    a shared credential the moment any hash is recovered."""
    from hashview.auth.service import resolve_or_provision_azure_user

    class _Settings:
        azure_allowed_groups = None

    first = resolve_or_provision_azure_user(
        {"oid": "oid-1", "email": "jit1@example.com"}, _Settings())
    second = resolve_or_provision_azure_user(
        {"oid": "oid-2", "email": "jit2@example.com"}, _Settings())

    assert first.password != second.password
