"""Match-or-provision the local Users row for a validated Entra identity.

This is the bridge that preserves Hashview's user_id ownership model under SSO:
once Entra has authenticated someone, we resolve them to an existing Users row
(by stable object id, else email) — preserving their id and all owner_id
relationships — or just-in-time provision a new non-admin row when permitted.
"""
import secrets

from flask import current_app
from sqlalchemy import func

from hashview.models import Users, db
from hashview.users.routes import bcrypt


class AzureLoginDenied(Exception):
    """A validated Entra identity is not permitted to sign in (group/claim gate)."""


def _email_from_claims(claims):
    # Preference: verified 'email', then UPN-ish 'preferred_username'/'upn'.
    # Guest (#EXT#) accounts often only carry a UPN.
    for key in ('email', 'preferred_username', 'upn'):
        value = claims.get(key)
        if value and '@' in value:
            return value.strip()
    return None


def _names_from_claims(claims):
    given = (claims.get('given_name') or '').strip()
    family = (claims.get('family_name') or '').strip()
    if not (given or family):
        name = (claims.get('name') or '').strip()
        if name:
            parts = name.split()
            given = parts[0]
            family = ' '.join(parts[1:]) or parts[0]
    return (given or 'Azure')[:64], (family or 'User')[:64]


def _group_permitted(claims, settings):
    """Group gate: when allowed-groups is configured it applies to ALL Azure
    logins. Empty allowed-groups => any authenticated tenant user is allowed."""
    allowed = [g.strip() for g in (settings.azure_allowed_groups or '').split(',') if g.strip()]
    if not allowed:
        return True
    groups = claims.get('groups')
    if groups is None:
        # "Groups overage": when a user is in too many groups Entra omits the
        # claim and returns _claim_names/_claim_sources pointing at MS Graph.
        # Fail safe (deny) rather than silently allow; a Graph fallback is a
        # documented future enhancement.
        if '_claim_names' in claims or '_claim_sources' in claims:
            current_app.logger.warning(
                'Azure groups overage: groups claim omitted; denying. '
                'Configure a Graph /me/memberOf fallback to support large group sets.')
        return False
    return bool(set(groups) & set(allowed))


def resolve_or_provision_azure_user(claims, settings):
    """Return the Users row for these validated Entra claims, provisioning a new
    non-admin row when needed and group-permitted. Raises AzureLoginDenied when
    the identity isn't allowed."""
    if not _group_permitted(claims, settings):
        raise AzureLoginDenied('not a member of an allowed group')

    oid = claims.get('oid')
    email = _email_from_claims(claims)

    user = None
    if oid:
        user = Users.query.filter_by(azure_oid=oid).first()
    if user is None and email:
        # Case-insensitive so 'Alice@x.com' (DB) matches 'alice@x.com' (claim)
        # and we never collide with the email_address UNIQUE constraint on JIT.
        user = Users.query.filter(func.lower(Users.email_address) == email.lower()).first()

    if user is not None:
        # Existing user: keep id, admin flag, and all owner_id relationships.
        if oid and not user.azure_oid:
            user.azure_oid = oid                 # backfill stable id for next time
        if user.id != 1 and user.auth_source != 'azure':
            user.auth_source = 'azure'           # never flip the setup admin
        db.session.commit()
        return user

    # Just-in-time provision (non-admin). Requires a usable email for NOT NULL +
    # UNIQUE; an account that can never password-login (random bcrypt hash).
    if not email:
        raise AzureLoginDenied('no usable email/UPN claim to provision an account')
    given, family = _names_from_claims(claims)
    random_pw = bcrypt.generate_password_hash(secrets.token_urlsafe(32)).decode('utf-8')
    user = Users(
        first_name=given,
        last_name=family,
        email_address=email[:255],
        password=random_pw,
        admin=False,
        auth_source='azure',
        azure_oid=oid,
    )
    db.session.add(user)
    try:
        db.session.commit()
    except Exception as exc:  # e.g. UNIQUE race / over-length on strict MySQL
        db.session.rollback()
        raise AzureLoginDenied(f'could not provision account: {exc}') from exc
    return user
