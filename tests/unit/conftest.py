"""Conftest for unit tests.

Overrides the parent (tests/) autouse fixtures `ensure_setup` and
`configure_page`, which require Playwright + a live HTTP server. Unit tests
here use Flask's test_client against an in-memory SQLite app, so those
e2e-specific fixtures must not run (and must not pull in `live_server`,
which `pytest.skip(...)`s without `HASHVIEW_E2E_BASE_URL`).

Also provides shared fixtures for unit tests:

- ``app`` — a Flask app built via ``create_app(testing=True, ...)`` with an
  in-memory SQLite DB, all tables created, CSRF disabled, mail suppressed.
- ``client`` — Flask's test_client for ``app``.
- ``db_session`` — convenience access to the SQLAlchemy session bound to
  ``app``.

When the app's runtime deps (Flask, Flask-SQLAlchemy, …) aren't installed —
e.g. the e2e-only CI venv that only has requirements-dev.txt — the
``collect_ignore_glob`` below skips the entire tests/unit/ tree at
collection time rather than erroring on the ``from hashview import …``
imports inside the fixtures. The e2e CI script already ignores this dir
explicitly; this guard means a stray ``pytest tests/`` against a thin env
still does the right thing.
"""

import importlib.util

import pytest

if importlib.util.find_spec("flask") is None:
    collect_ignore_glob = ["test_*.py"]


@pytest.fixture(autouse=True, scope="session")
def control_dirs():
    """Create the runtime control dirs that setup.py / the Dockerfile guarantee.

    They're gitignored, so a fresh clone lacks them; several units write real
    files there (wordlist storage, backup tmp files, hashfile uploads).
    """
    import os
    from pathlib import Path

    root = Path(__file__).resolve().parents[2] / "hashview" / "control"
    for sub in ("rules", "wordlists", "tmp", "hashes"):
        os.makedirs(root / sub, exist_ok=True)


@pytest.fixture(autouse=True)
def ensure_setup():
    """Override parent autouse so live_server isn't requested for unit tests."""
    return


@pytest.fixture(autouse=True)
def configure_page():
    """Override parent autouse so the Playwright `page` fixture isn't pulled."""
    return


def _build_test_app():
    # Import lazily so this module remains importable in envs without
    # Flask (paired with the ``collect_ignore_glob`` above).
    import os

    from hashview import create_app

    overrides = {
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
        "SQLALCHEMY_ENGINE_OPTIONS": {
            "connect_args": {"check_same_thread": False},
        },
        "WTF_CSRF_ENABLED": False,
        "MAIL_SUPPRESS_SEND": True,
        "SECRET_KEY": "unit-test-secret",
        "SERVER_NAME": "localhost.test",
        "HASHVIEW_SKIP_SETUP": True,
        "HASHVIEW_SKIP_GUI_SETUP": True,
        "HASHVIEW_DISABLE_SCHEDULER": True,
    }

    # CI MySQL/MariaDB parity: when HASHVIEW_TEST_DATABASE_URI is set the test
    # app talks to that database instead of in-memory SQLite. Unset (the local
    # default), behaviour is unchanged. The SQLite-only check_same_thread
    # connect_arg is meaningless to other dialects, so drop it then.
    test_db_uri = os.environ.get("HASHVIEW_TEST_DATABASE_URI")
    if test_db_uri:
        overrides["SQLALCHEMY_DATABASE_URI"] = test_db_uri
        overrides["SQLALCHEMY_ENGINE_OPTIONS"] = {}

    app = create_app(testing=True, config_overrides=overrides)
    return app


@pytest.fixture()
def app():
    from hashview.models import db as _db
    app = _build_test_app()
    with app.app_context():
        _db.create_all()
        yield app
        _db.session.remove()
        _db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def db_session(app):
    from hashview.models import db as _db
    return _db.session
