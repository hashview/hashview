"""Conftest for integration tests.

Like ``tests/unit/conftest.py``, this overrides the parent (``tests/``) autouse
fixtures ``ensure_setup`` / ``configure_page`` (which require Playwright + a
live HTTP server) so integration tests can use Flask's test_client / a real DB
session without pulling in the e2e machinery.

The ``mysql``-marked tests here run against a real MySQL/MariaDB backend,
selected via the ``HASHVIEW_TEST_DATABASE_URI`` environment variable (honoured
by ``tests/unit/conftest._build_test_app``). When that env var is unset — the
normal local case — the ``mysql_app`` fixture skips, so ``pytest tests/`` on a
developer box never tries to reach a database that isn't there.

If the app's runtime deps (Flask, Flask-SQLAlchemy, …) aren't installed, the
whole tree is ignored at collection time, mirroring the unit conftest guard.
"""

import importlib.util
import os

import pytest


if importlib.util.find_spec("flask") is None:
    collect_ignore_glob = ["test_*.py"]


@pytest.fixture(autouse=True)
def ensure_setup():
    """Override parent autouse so live_server isn't requested here."""
    return


@pytest.fixture(autouse=True)
def configure_page():
    """Override parent autouse so the Playwright `page` fixture isn't pulled."""
    return


@pytest.fixture()
def mysql_app():
    """A Flask app bound to the MySQL/MariaDB backend under test.

    Skips cleanly when ``HASHVIEW_TEST_DATABASE_URI`` is unset (local dev) so a
    plain ``pytest tests/`` run is unaffected. The schema is assumed to already
    exist (CI runs ``flask db upgrade`` against this database first); we do NOT
    ``create_all``/``drop_all`` here so we exercise the migration-created schema
    rather than the ORM's ``create_all`` view of it.
    """
    db_uri = os.environ.get("HASHVIEW_TEST_DATABASE_URI")
    if not db_uri:
        pytest.skip(
            "HASHVIEW_TEST_DATABASE_URI not set — MySQL integration tests are "
            "CI-only (run against the db-parity workflow's MariaDB service)."
        )

    # Reuse the unit conftest's builder so the env override path is shared and
    # tested in exactly one place.
    from tests.unit.conftest import _build_test_app

    app = _build_test_app()
    yield app


@pytest.fixture()
def mysql_session(mysql_app):
    """A clean SQLAlchemy session on the MySQL app, rolled back after the test.

    Each test runs inside a transaction that is rolled back on teardown, so the
    migration-created schema is never mutated permanently and tests don't leak
    rows into each other.
    """
    from hashview.models import db as _db

    with mysql_app.app_context():
        yield _db.session
        _db.session.rollback()
        _db.session.remove()
