"""Lazily-built, signature-cached Authlib OAuth client for Microsoft Entra ID.

The Azure config lives in the Settings DB row (admin-editable at runtime), so we
can't register the OIDC client at create_app() time. Instead we build it on first
use and cache it keyed by a signature of the relevant Settings fields; if the
admin changes tenant/client/secret/redirect the signature changes and we rebuild,
transparently picking up the new App-Registration (and its discovery metadata).
"""
import hashlib
import threading

from authlib.integrations.flask_client import OAuth
from flask import current_app

from hashview.models import Settings

# Entra v2.0 OIDC discovery; Authlib fetches + caches JWKS/endpoints per client.
_AUTHORITY = 'https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration'
_CLIENT_NAME = 'entra'

_lock = threading.Lock()
_cache = {'sig': None, 'client': None}


def azure_is_configured(settings):
    """True when Azure SSO is selected AND the required config is present."""
    return bool(
        settings
        and settings.auth_method == 'azure'
        and settings.azure_tenant_id
        and settings.azure_client_id
        and settings.azure_client_secret
    )


def _signature(settings):
    raw = '|'.join([
        settings.azure_tenant_id or '',
        settings.azure_client_id or '',
        # hash the secret so the cache key never holds the plaintext
        hashlib.sha256((settings.azure_client_secret or '').encode()).hexdigest(),
        settings.azure_redirect_uri or '',
    ])
    return hashlib.sha256(raw.encode()).hexdigest()


def get_entra_client(settings=None):
    """Return a registered Authlib remote-app for Entra, or None if unconfigured.

    Rebuilt only when the relevant Settings change (signature mismatch). Safe to
    call per-request; discovery metadata is cached on the client by Authlib.
    """
    if settings is None:
        settings = Settings.current()
    if not azure_is_configured(settings):
        return None
    sig = _signature(settings)
    with _lock:
        if _cache['sig'] != sig or _cache['client'] is None:
            # Fresh OAuth registry so we never reuse a stale client_id/secret.
            oauth = OAuth(current_app)
            oauth.register(
                name=_CLIENT_NAME,
                client_id=settings.azure_client_id,
                client_secret=settings.azure_client_secret,
                server_metadata_url=_AUTHORITY.format(tenant=settings.azure_tenant_id),
                client_kwargs={'scope': 'openid email profile'},
            )
            _cache['sig'] = sig
            _cache['client'] = oauth.create_client(_CLIENT_NAME)
        return _cache['client']
