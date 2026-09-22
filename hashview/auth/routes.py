"""Flask routes for Microsoft Entra ID (Azure AD) OIDC SSO web login.

Only active when Settings.auth_method == 'azure' and the App-Registration config
is present. Neither route is @login_required (they run pre-authentication); the
setup before_request only forces /setup while the install is unconfigured, so it
doesn't block these once setup is complete.
"""

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    request,
    session,
    url_for,
)
from flask_login import login_user

from hashview.auth.oauth import get_entra_client
from hashview.auth.service import AzureLoginDenied, resolve_or_provision_azure_user
from hashview.models import Settings, db
from hashview.utils.audit import log_event
from hashview.utils.clock import utcnow

auth = Blueprint('auth', __name__)

_NEXT_KEY = 'azure_next'


def _safe_next():
    """Same-site relative path from ?next, else None (open-redirect guard)."""
    nxt = request.args.get('next') or ''
    if nxt.startswith('/') and not nxt.startswith('//'):
        return nxt
    return None


def _redirect_uri(settings):
    if settings.azure_redirect_uri:
        return settings.azure_redirect_uri
    # SERVER_NAME carries :8443 and there is no PREFERRED_URL_SCHEME, so force
    # https — Entra requires an exact HTTPS redirect URI.
    return url_for('auth.azure_callback', _external=True, _scheme='https')


@auth.route('/login/azure')
def azure_login():
    settings = Settings.current()
    client = get_entra_client(settings)
    if client is None:
        flash('Microsoft sign-in is not configured.', 'danger')
        return redirect(url_for('users.login_get'))
    # Carry next in the server-side session (not in OAuth state, which Authlib
    # owns for CSRF). Sanitized to same-site before storing.
    session[_NEXT_KEY] = _safe_next()
    return client.authorize_redirect(_redirect_uri(settings))


@auth.route('/login/azure/callback')
def azure_callback():
    settings = Settings.current()
    client = get_entra_client(settings)
    if client is None:
        flash('Microsoft sign-in is not configured.', 'danger')
        return redirect(url_for('users.login_get'))

    try:
        # Validates state + the id_token (signature, iss, aud, exp, nonce) via
        # the discovered JWKS.
        token = client.authorize_access_token()
    except Exception:
        current_app.logger.info('Azure callback token exchange/validation failed.', exc_info=True)
        log_event('user.login_failed', outcome='failure', actor=(None, None),
                  detail='azure token exchange/validation failed')
        flash('Microsoft sign-in failed. Please try again.', 'danger')
        return redirect(url_for('users.login_get'))

    claims = token.get('userinfo')
    if not claims:
        # Fallback: explicitly parse/validate the id_token. Never accept an
        # unvalidated token.
        try:
            claims = client.parse_id_token(token, nonce=session.get('nonce'))
        except Exception:
            claims = None
    if not claims:
        log_event('user.login_failed', outcome='failure', actor=(None, None),
                  detail='azure: no validated id_token claims')
        flash('Microsoft sign-in failed. Please try again.', 'danger')
        return redirect(url_for('users.login_get'))

    try:
        user = resolve_or_provision_azure_user(claims, settings)
    except AzureLoginDenied as denied:
        log_event('user.login_failed', outcome='failure', actor=(None, None),
                  detail=f'azure denied: {denied}')
        flash('Your Microsoft account is not permitted to sign in to Hashview.', 'danger')
        return redirect(url_for('users.login_get'))

    login_user(user, remember=False)
    user.last_login_utc = utcnow()
    db.session.commit()
    log_event('user.login', actor=(user.email_address, user.id), detail='via azure')

    nxt = session.pop(_NEXT_KEY, None)
    return redirect(nxt or url_for('main.home'))
