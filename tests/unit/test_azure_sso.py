"""Unit tests for the optional Microsoft Entra ID (Azure AD) OIDC SSO.

No real Azure: the Authlib client is monkeypatched to a fake that returns canned
(already-"validated") id_token claims, so we exercise *our* routing, matching,
JIT provisioning, group-gating, break-glass, and the secret-serialization
hardening. All tests are @pytest.mark.security so the parent Playwright autouse
fixtures are skipped (see conftest).
"""
import json

import pytest

from hashview.models import Settings, Users
from hashview.models import db as _db

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _settings(auth_method='local', groups=None, secret='sek', complete=True):
    s = Settings(
        retention_period=30, max_runtime_jobs=0, max_runtime_tasks=0,
        auth_method=auth_method,
        azure_tenant_id=('tid' if complete else None),
        azure_client_id=('cid' if complete else None),
        azure_client_secret=(secret if complete else None),
        azure_allowed_groups=groups,
    )
    _db.session.add(s)
    _db.session.commit()
    return s


def _user(id_=None, email='u@example.com', admin=False, password='correct horse'):
    from hashview.users.routes import bcrypt
    u = Users(first_name='T', last_name='U', email_address=email, admin=admin,
              password=bcrypt.generate_password_hash(password).decode('latin-1'))
    if id_ is not None:
        u.id = id_
    _db.session.add(u)
    _db.session.commit()
    return u


def _login_session(client, user):
    with client.session_transaction() as sess:
        sess['_user_id'] = str(user.id)
        sess['_fresh'] = True


class _FakeEntra:
    """Stand-in for the Authlib remote app; returns canned validated claims."""
    def __init__(self, claims):
        self._claims = claims

    def authorize_redirect(self, redirect_uri):
        from flask import redirect
        return redirect('https://login.microsoftonline.com/authorize?fake=1')

    def authorize_access_token(self):
        return {'userinfo': dict(self._claims)}

    def parse_id_token(self, token, nonce=None):
        return dict(self._claims)


def _patch_entra(monkeypatch, claims):
    monkeypatch.setattr('hashview.auth.routes.get_entra_client', lambda *a, **k: _FakeEntra(claims))


def _is_logged_in(client):
    with client.session_transaction() as sess:
        return '_user_id' in sess


# ---------------------------------------------------------------------------
# Local mode unchanged
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_local_mode_password_login_unchanged(client, app):
    _settings(auth_method='local')
    _user(id_=1, email='admin@example.com', admin=True, password='adminpass123')
    _user(email='reg@example.com', admin=False, password='regpass1234')

    r = client.post('/login', data={'email': 'admin@example.com', 'password': 'adminpass123'})
    assert r.status_code in (301, 302) and _is_logged_in(client)

    client2 = app.test_client()
    r = client2.post('/login', data={'email': 'reg@example.com', 'password': 'regpass1234'})
    assert r.status_code in (301, 302) and _is_logged_in(client2)


# ---------------------------------------------------------------------------
# Azure mode break-glass (setup admin id=1 only)
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_azure_mode_breakglass_admin_only(client, app):
    _settings(auth_method='azure')   # complete config -> _azure_enabled() True
    _user(id_=1, email='admin@example.com', admin=True, password='adminpass123')
    reg = _user(email='reg@example.com', admin=False, password='regpass1234')

    # id=1 break-glass still works in azure mode
    r = client.post('/login', data={'email': 'admin@example.com', 'password': 'adminpass123'})
    assert r.status_code in (301, 302) and _is_logged_in(client)

    # non-id1 with the CORRECT password is rejected (must use Microsoft)
    c2 = app.test_client()
    r = c2.post('/login', data={'email': 'reg@example.com', 'password': 'regpass1234'})
    assert r.status_code in (301, 302)
    assert '/login' in r.headers.get('Location', '')
    assert not _is_logged_in(c2)
    assert reg.id != 1


# ---------------------------------------------------------------------------
# Callback: match existing, JIT, group gating
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_callback_matches_existing_email_preserves_id_admin(client, monkeypatch):
    _settings(auth_method='azure')
    existing = _user(id_=7, email='Bob@x.com', admin=True)   # id != 1 (not the setup admin)
    before_id, before_count = existing.id, Users.query.count()
    _patch_entra(monkeypatch, {'email': 'bob@x.com', 'oid': 'o1', 'name': 'Bob B'})

    r = client.get('/login/azure/callback')
    assert r.status_code in (301, 302)
    assert '/login' not in r.headers.get('Location', '')   # success -> home
    assert Users.query.count() == before_count             # no duplicate
    u = Users.query.get(before_id)
    assert u.admin is True                                  # admin preserved
    assert u.azure_oid == 'o1'                              # backfilled
    assert u.auth_source == 'azure'


@pytest.mark.security
def test_jit_provisions_non_admin_in_allowed_group(client, monkeypatch):
    _settings(auth_method='azure', groups='G1,G2')
    before = Users.query.count()
    _patch_entra(monkeypatch, {'email': 'new@x.com', 'oid': 'o2', 'groups': ['G1'], 'name': 'New User'})

    r = client.get('/login/azure/callback')
    assert r.status_code in (301, 302) and '/login' not in r.headers.get('Location', '')
    assert Users.query.count() == before + 1
    u = Users.query.filter_by(email_address='new@x.com').first()
    assert u is not None and u.admin is False and u.auth_source == 'azure' and u.azure_oid == 'o2'


@pytest.mark.security
def test_denied_when_not_in_allowed_group(client, monkeypatch):
    _settings(auth_method='azure', groups='G1')
    before = Users.query.count()
    _patch_entra(monkeypatch, {'email': 'nope@x.com', 'oid': 'o3', 'groups': ['G9']})

    r = client.get('/login/azure/callback')
    assert r.status_code in (301, 302) and '/login' in r.headers.get('Location', '')
    assert Users.query.count() == before          # nothing provisioned
    assert not _is_logged_in(client)


@pytest.mark.security
def test_denied_on_groups_overage(client, monkeypatch):
    _settings(auth_method='azure', groups='G1')
    before = Users.query.count()
    # Overage: groups claim omitted, _claim_names present -> fail safe (deny).
    _patch_entra(monkeypatch, {'email': 'big@x.com', 'oid': 'o4', '_claim_names': {'groups': 'src1'}})

    r = client.get('/login/azure/callback')
    assert r.status_code in (301, 302) and '/login' in r.headers.get('Location', '')
    assert Users.query.count() == before


@pytest.mark.security
def test_empty_allowed_groups_allows_any_tenant_user(client, monkeypatch):
    _settings(auth_method='azure', groups=None)
    before = Users.query.count()
    _patch_entra(monkeypatch, {'email': 'any@x.com', 'oid': 'o5', 'name': 'Any One'})

    r = client.get('/login/azure/callback')
    assert r.status_code in (301, 302) and '/login' not in r.headers.get('Location', '')
    assert Users.query.count() == before + 1


@pytest.mark.security
def test_case_insensitive_email_match_no_duplicate(client, monkeypatch):
    _settings(auth_method='azure')
    _user(email='Alice@x.com', admin=False)
    before = Users.query.count()
    _patch_entra(monkeypatch, {'email': 'alice@x.com', 'oid': 'o6', 'name': 'Alice A'})

    r = client.get('/login/azure/callback')
    assert r.status_code in (301, 302) and '/login' not in r.headers.get('Location', '')
    assert Users.query.count() == before          # matched, not duplicated


# ---------------------------------------------------------------------------
# Open-redirect guard
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_open_redirect_guard(client, app, monkeypatch):
    _settings(auth_method='azure')
    _patch_entra(monkeypatch, {'email': 'r@x.com', 'oid': 'o7', 'name': 'R R'})

    # external next is dropped -> lands on home
    client.get('/login/azure?next=https://evil.com')
    r = client.get('/login/azure/callback')
    assert 'evil.com' not in r.headers.get('Location', '')

    # same-site next survives
    c2 = app.test_client()
    monkeypatch.setattr('hashview.auth.routes.get_entra_client', lambda *a, **k: _FakeEntra({'email': 'r@x.com', 'oid': 'o7'}))
    c2.get('/login/azure?next=/jobs')
    r = c2.get('/login/azure/callback')
    assert r.headers.get('Location', '').endswith('/jobs')


# ---------------------------------------------------------------------------
# Secret-serialization hardening (AlchemyEncoder)
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_alchemy_encoder_omits_secrets(app):
    from hashview.api.routes import AlchemyEncoder
    s = _settings(auth_method='azure', secret='SUPER-SECRET')
    s.slack_bot_token = 'xoxb-leak'
    _db.session.commit()
    u = _user(email='enc@x.com')
    u.api_key = 'API-KEY-LEAK'
    _db.session.commit()

    sdump = json.loads(json.dumps(s, cls=AlchemyEncoder))
    assert 'azure_client_secret' not in sdump
    assert 'slack_bot_token' not in sdump
    assert sdump.get('azure_tenant_id') == 'tid'   # non-secret config still present

    udump = json.loads(json.dumps(u, cls=AlchemyEncoder))
    assert 'password' not in udump and 'api_key' not in udump


@pytest.mark.security
def test_admin_settings_api_does_not_leak_secret(client):
    s = _settings(auth_method='azure', secret='SUPER-SECRET')
    s.slack_bot_token = 'xoxb-leak'
    _db.session.commit()
    admin = _user(id_=1, email='admin@example.com', admin=True, password='p')
    admin.api_key = 'admin-key'
    _db.session.commit()

    client.set_cookie('uuid', 'admin-key', domain='localhost.test')
    body = client.get('/v1/admin/settings').get_data(as_text=True)
    assert 'SUPER-SECRET' not in body
    assert 'xoxb-leak' not in body


# ---------------------------------------------------------------------------
# hashview/auth/oauth.py — config gate, signature cache, lazy client build
# ---------------------------------------------------------------------------


def test_azure_is_configured_gate(app):
    from hashview.auth.oauth import azure_is_configured
    assert azure_is_configured(None) is False
    assert azure_is_configured(_settings(auth_method='local')) is False
    assert azure_is_configured(_settings(auth_method='azure')) is True
    assert azure_is_configured(_settings(auth_method='azure', complete=False)) is False


def test_signature_changes_with_secret(app):
    from hashview.auth.oauth import _signature
    s1 = _settings(auth_method='azure', secret='one')
    sig1 = _signature(s1)
    s1.azure_client_secret = 'two'
    _db.session.commit()
    assert _signature(s1) != sig1
    # The plaintext secret never appears in the signature.
    assert 'two' not in _signature(s1)


def test_get_entra_client_none_when_unconfigured(app):
    from hashview.auth.oauth import get_entra_client
    assert get_entra_client(_settings(auth_method='local')) is None


def test_get_entra_client_builds_when_configured(app, monkeypatch):
    import hashview.auth.oauth as oauth_mod
    from hashview.auth.oauth import get_entra_client
    # Reset the module cache so this test is deterministic.
    oauth_mod._cache.update(sig=None, client=None)

    built = []

    class _FakeOAuth:
        def __init__(self, app=None):
            pass

        def register(self, **kw):
            built.append(kw)

        def create_client(self, name):
            return f"client:{name}"

    monkeypatch.setattr(oauth_mod, "OAuth", _FakeOAuth)
    s = _settings(auth_method='azure', secret='sek')
    client = get_entra_client(s)
    assert client == "client:entra"
    assert built and built[0]["client_id"] == "cid"
