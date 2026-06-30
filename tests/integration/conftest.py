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
    """A clean SQLAlchemy session on the MySQL app, fully reverted after the test.

    Uses the classic SQLAlchemy "connection + outer transaction + SAVEPOINT"
    isolation pattern so that even a test which calls ``session.commit()`` only
    commits *within* the savepoint: on teardown we roll back the outer
    transaction and close the connection, reverting everything. This keeps the
    migration-created schema un-mutated and prevents row leakage between tests.

    Implementation notes:
    * We bind the scoped session to a dedicated connection that owns an explicit
      outer transaction.
    * ``join_transaction_mode="create_savepoint"`` makes the session emit a
      SAVEPOINT for its work, so a ``commit()`` releases the savepoint rather
      than committing the outer transaction.
    """
    from hashview.models import db as _db

    with mysql_app.app_context():
        engine = _db.engine
        connection = engine.connect()
        transaction = connection.begin()

        _db.session.remove()
        _db.session.configure(
            bind=connection,
            join_transaction_mode="create_savepoint",
        )

        try:
            yield _db.session
        finally:
            _db.session.remove()
            if transaction.is_active:
                transaction.rollback()
            connection.close()
            # Restore the session's default binding for any later fixtures/tests.
            _db.session.configure(bind=engine)
