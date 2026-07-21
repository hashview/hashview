"""HTTP client for external wordlist providers.

A "wordlist provider" (``hashview.models.WordlistProviders``) is a remote service
that generates a wordlist on demand. Hashview dictates the API; a provider exposes
two endpoints relative to its configured ``base_url``:

  GET  {base_url}/health
      Powers the Settings "Test connection" button. Auth header attached. Success
      is HTTP 200 with JSON ``{"status": "ok", "name": ..., "description": ...}``
      (name/description optional).

  POST {base_url}/generate    body: {"input": "<per-job provider_input>"}
      Returns HTTP 200 with the wordlist as newline-delimited UTF-8 text
      (``text/plain``), streamed. Any non-200 is treated as failure.

Authentication is per-provider:
  - ``bearer`` -> ``Authorization: Bearer <provider_secret>``
  - ``basic``  -> HTTP Basic ``(username, provider_secret)``

Design mirrors ``hashview/utils/crawler.py``: it uses ``requests`` (already a
dependency), **never raises** out of ``generate_wordlist``/``test_connection``, and
suppresses urllib3 TLS warnings for providers configured with ``verify_tls=False``
(internal/self-signed hosts). ``generate_wordlist`` writes to a random temp file and
atomically ``os.replace``s it onto the destination, so a failed or partial fetch
leaves the existing wordlist untouched — the same contract the crawler relies on.
"""
import os
import secrets
import shutil
from urllib.parse import urlparse

import requests
import urllib3
from flask import current_app

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Per-request timeouts (connect, read) in seconds.
HEALTH_TIMEOUT = (5, 15)
# Generation can be slow (the provider may crawl/compute); allow a long read.
GENERATE_TIMEOUT = (5, 300)
# Safety cap on a materialized wordlist so a hostile/misconfigured provider can't
# fill the disk. 2 GiB of newline-delimited text is already an enormous wordlist.
MAX_WORDLIST_BYTES = 2 * 1024 * 1024 * 1024
_STREAM_CHUNK = 1024 * 256


def validate_base_url(base_url):
    """Return ``base_url`` with any trailing slash stripped.

    Raises ``ValueError`` unless the scheme is http/https and a host is present.
    Blocks ``file://``/``gopher://``/etc. from an admin-supplied URL. Note: an admin
    may legitimately point a provider at internal infrastructure, so internal-IP
    ranges are intentionally NOT blocked here (documented as an accepted risk).
    """
    parsed = urlparse((base_url or '').strip())
    if parsed.scheme not in ('http', 'https'):
        raise ValueError('Provider base URL must be http or https.')
    if not parsed.netloc:
        raise ValueError('Provider base URL must include a host.')
    return base_url.strip().rstrip('/')


def build_request_kwargs(provider):
    """Build the per-provider ``requests`` kwargs: headers, auth, verify."""
    version = current_app.config.get('VERSION', 'dev') if current_app else 'dev'
    headers = {'User-Agent': 'Hashview/' + str(version)}
    auth = None
    if provider.auth_type == 'basic':
        auth = (provider.username or '', provider.provider_secret or '')
    else:  # 'bearer' (default)
        if provider.provider_secret:
            headers['Authorization'] = 'Bearer ' + provider.provider_secret
    return {'headers': headers, 'auth': auth, 'verify': bool(provider.verify_tls)}


def test_connection(provider):
    """Probe ``GET {base_url}/health``. Return ``(ok: bool, message: str)``.

    Never raises — a network/TLS error is reported as ``(False, <reason>)``.
    """
    try:
        base = validate_base_url(provider.base_url)
    except ValueError as exc:
        return False, str(exc)

    kwargs = build_request_kwargs(provider)
    try:
        resp = requests.get(base + '/health', timeout=HEALTH_TIMEOUT, **kwargs)
    except requests.exceptions.RequestException as exc:
        return False, 'Connection failed: ' + str(exc)

    if resp.status_code != 200:
        return False, 'Provider returned HTTP ' + str(resp.status_code) + '.'
    try:
        body = resp.json()
    except ValueError:
        return True, 'Reachable (non-JSON health response).'
    if body.get('status') == 'ok':
        name = body.get('name')
        return True, 'Connected' + ((' to ' + str(name)) if name else '') + '.'
    return False, 'Provider health status was not "ok".'


def generate_wordlist(provider, user_input, dest_path):
    """POST ``user_input`` to ``{base_url}/generate`` and materialize the result.

    Streams the response to a random temp file under ``control/tmp`` then atomically
    replaces ``dest_path``. Returns the number of bytes written on success, or
    ``None`` on any failure — in which case ``dest_path`` is left untouched. Never
    raises (mirrors the crawler's no-op-on-failure contract).
    """
    if not getattr(provider, 'enabled', True):
        current_app.logger.warning(
            'Wordlist provider %s is disabled; leaving wordlist unchanged.', provider.id)
        return None

    try:
        base = validate_base_url(provider.base_url)
    except ValueError as exc:
        current_app.logger.warning('Provider %s has an invalid base URL: %s', provider.id, exc)
        return None

    kwargs = build_request_kwargs(provider)
    kwargs['headers']['Content-Type'] = 'application/json'
    kwargs['headers']['Accept'] = 'text/plain'

    tmp_path = os.path.join(current_app.root_path, 'control/tmp', secrets.token_hex(8) + '.txt')
    written = 0
    try:
        resp = requests.post(base + '/generate', json={'input': user_input},
                             timeout=GENERATE_TIMEOUT, stream=True, **kwargs)
        if resp.status_code != 200:
            current_app.logger.warning(
                'Provider %s /generate returned HTTP %s; leaving wordlist unchanged.',
                provider.id, resp.status_code)
            return None
        with open(tmp_path, 'wb') as tmp:
            for chunk in resp.iter_content(chunk_size=_STREAM_CHUNK):
                if not chunk:
                    continue
                written += len(chunk)
                if written > MAX_WORDLIST_BYTES:
                    raise ValueError('provider wordlist exceeded %d bytes' % MAX_WORDLIST_BYTES)
                tmp.write(chunk)
    except Exception as exc:  # noqa: BLE001 - never propagate; log + no-op like the crawler
        current_app.logger.warning(
            'Provider %s wordlist generation failed (%s); leaving wordlist unchanged.',
            provider.id, exc)
        _safe_unlink(tmp_path)
        return None

    # Atomic on the same filesystem (control/tmp and control/wordlists are siblings);
    # fall back to a copy+remove move across filesystems.
    try:
        os.replace(tmp_path, dest_path)
    except OSError:
        shutil.move(tmp_path, dest_path)
    return written


def _safe_unlink(path):
    try:
        os.remove(path)
    except OSError:
        pass
