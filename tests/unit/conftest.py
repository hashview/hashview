"""Conftest for unit tests.

Overrides the parent (tests/) autouse fixtures ``ensure_setup`` and
``configure_page``, which require Playwright + a live HTTP server. Unit tests
here drive Flask's ``test_client`` against an in-memory SQLite app, so those
e2e-specific fixtures must not run (and must not pull in ``live_server``,
which ``pytest.skip(...)``s without ``HASHVIEW_E2E_BASE_URL``).

The app is built by hand rather than via ``hashview.create_app`` because on
this branch ``create_app()`` takes no arguments, hard-loads the MySQL
``config.conf`` and starts the scheduler — none of which a unit test wants.
We register only the blueprint under test on a throwaway Flask app bound to a
single shared in-memory SQLite connection (``StaticPool``).

When Flask isn't installed (e.g. an e2e-only CI venv that only has
requirements-dev.txt) the ``collect_ignore_glob`` below skips the whole
tests/unit/ tree at collection time instead of erroring on imports.
"""

import importlib.util

import pytest


if importlib.util.find_spec("flask") is None:
    collect_ignore_glob = ["test_*.py"]


@pytest.fixture(autouse=True)
def ensure_setup():
    """Override parent autouse so live_server isn't requested for unit tests."""
    return


@pytest.fixture(autouse=True)
def configure_page():
    """Override parent autouse so the Playwright `page` fixture isn't pulled."""
    return


def _build_api_app():
    # Imported lazily so this module stays importable without Flask (paired
    # with the ``collect_ignore_glob`` guard above).
    from flask import Flask
    from sqlalchemy.pool import StaticPool

    from hashview.models import db
    from hashview.api.routes import api

    app = Flask(__name__)
    app.config.update(
        SQLALCHEMY_DATABASE_URI="sqlite://",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        # A single shared connection so the in-memory DB survives across the
        # multiple app contexts a test client request opens.
        SQLALCHEMY_ENGINE_OPTIONS={
            "connect_args": {"check_same_thread": False},
            "poolclass": StaticPool,
        },
        SECRET_KEY="unit-test-secret",
        TESTING=True,
    )
    db.init_app(app)
    app.register_blueprint(api)
    return app


@pytest.fixture()
def app():
    from hashview.models import db

    app = _build_api_app()
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()
