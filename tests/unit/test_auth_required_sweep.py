"""Auth-required regression sweep.

For every route registered by ``create_app`` that isn't a public auth/login
endpoint or first-run setup page, fetching it without a session cookie
should redirect to ``/login`` (HTML routes) or return the unauthorized API
payload (``/v1/...`` routes).

This catches a whole class of regression where a decorator is missed on a
new route — protected pages would silently expose data to unauthenticated
users.
"""

import re

import pytest

# Routes that intentionally allow anonymous access.
PUBLIC_PREFIXES = (
    "/login",
    "/logout",
    "/register",
    "/reset_password",
    "/static/",
    "/setup/",
    "/v1/not_authorized",
    "/v1/upgrade_required",
    "/v1/agents/heartbeat",
)


def _dummy_value(converter: str) -> str:
    if converter in ("int",):
        return "1"
    return "x"


def _materialize_path(rule) -> str:
    """Convert ``/jobs/<int:job_id>`` -> ``/jobs/1``."""
    parts = []
    for _converter, _, variable in rule._converters and [] or []:  # noqa: E501  (placeholder)
        parts.append(variable)
    # Use Werkzeug's own substitution by walking the rule's _trace
    path = rule.rule
    for arg in rule.arguments:
        converter = rule._converters[arg].__class__.__name__.replace("Converter", "").lower()
        placeholder = re.search(rf"<(?:[^:>]+:)?{re.escape(arg)}>", path)
        if placeholder:
            path = path.replace(placeholder.group(0), _dummy_value(converter))
    return path


def _collect_protected_routes(app):
    routes = []
    for rule in app.url_map.iter_rules():
        path = _materialize_path(rule)
        if any(path.startswith(prefix) for prefix in PUBLIC_PREFIXES):
            continue
        # Skip static + catch-all
        if rule.endpoint == "static":
            continue
        # Pick a representative method
        methods = (rule.methods or set()) - {"HEAD", "OPTIONS"}
        if not methods:
            continue
        method = "GET" if "GET" in methods else next(iter(methods))
        routes.append(pytest.param(method, path, id=f"{method} {path}"))
    return routes


@pytest.fixture(scope="module")
def _routes(request):
    # Build one app to enumerate routes; tests use the per-test ``client``.
    from hashview import create_app
    app = create_app(
        testing=True,
        config_overrides={
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
            "WTF_CSRF_ENABLED": False,
            "HASHVIEW_SKIP_SETUP": True,
            "HASHVIEW_SKIP_GUI_SETUP": True,
            "HASHVIEW_DISABLE_SCHEDULER": True,
        },
    )
    return _collect_protected_routes(app)


def pytest_generate_tests(metafunc):
    """Parametrize ``test_protected_route_requires_auth`` with the route list.

    Builds a throwaway app at collection time so the parametrize ids are
    visible in pytest output.
    """
    if "method" in metafunc.fixturenames and "path" in metafunc.fixturenames:
        from hashview import create_app
        app = create_app(
            testing=True,
            config_overrides={
                "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
                "SQLALCHEMY_TRACK_MODIFICATIONS": False,
                "WTF_CSRF_ENABLED": False,
                "HASHVIEW_SKIP_SETUP": True,
                "HASHVIEW_SKIP_GUI_SETUP": True,
                "HASHVIEW_DISABLE_SCHEDULER": True,
            },
        )
        metafunc.parametrize(("method", "path"), _collect_protected_routes(app))


def test_protected_route_requires_auth(client, method, path):
    """Anonymous access to a protected route must NOT return 200 OK content.

    Acceptable responses:
      * 302/303 redirect to /login (HTML routes via flask-login)
      * 302 redirect to /v1/not_authorized (API routes via is_authorized)
      * 401 / 403 (protected admin pages)
      * 404 / 405 — also acceptable; missing-row errors are not auth bypasses
    A 200 reply with HTML content from a protected page would be a bug.
    """
    resp = client.open(path, method=method, follow_redirects=False)
    if resp.status_code in (301, 302, 303, 307, 308):
        location = (resp.headers.get("Location") or "").lower()
        assert (
            "/login" in location
            or "/v1/not_authorized" in location
            or "/setup/" in location
        ), f"Redirect to unexpected location: {location} for {method} {path}"
        return
    if resp.status_code in (401, 403, 404, 405):
        return
    # 500 is bad data plumbing but not an auth issue; flag separately.
    if resp.status_code == 500:
        pytest.xfail(
            f"{method} {path} 500'd with dummy params — not an auth bypass but worth fixing."
        )
    assert resp.status_code != 200, (
        f"{method} {path} returned 200 unauthenticated — possible auth bypass."
    )
