"""Run the real Alembic migration chain to ``head`` against a target database.

Used by the ``db-parity`` CI workflow to execute the production MySQL-only DDL
(``create_foreign_key`` / ``alter_column``) that the SQLite unit suite can never
run — see ``tests/unit/test_migration_smoke.py``'s docstring for the gap this
closes.

The target database comes from ``HASHVIEW_TEST_DATABASE_URI`` (the same env var
the test app honours), so the URL dialect the migrations run under exactly
matches the one the integration tests use. We build the app with
``create_app(testing=True, …)`` so config.conf / scheduler / GUI setup are all
skipped, then call ``flask_migrate.upgrade()`` inside the app context — which is
how the app itself applies migrations (see ``setup_defaults_if_needed`` in
``hashview/__init__.py``). ``migrations/env.py`` reads the engine URL from
``current_app.extensions['migrate'].db.engine.url``, so pointing the app at the
MariaDB service is sufficient.

Exits non-zero on any failure so the CI job fails loudly.
"""

import os
import sys

# Make the repo root importable regardless of the cwd this is invoked from.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask_migrate import upgrade  # noqa: E402

from hashview import create_app  # noqa: E402


def main() -> int:
    db_uri = os.environ.get("HASHVIEW_TEST_DATABASE_URI")
    if not db_uri:
        print(
            "HASHVIEW_TEST_DATABASE_URI must be set to the target database URL.",
            file=sys.stderr,
        )
        return 2

    app = create_app(
        testing=True,
        config_overrides={
            "SQLALCHEMY_DATABASE_URI": db_uri,
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
            "SECRET_KEY": "migration-runner",
            "MAIL_SUPPRESS_SEND": True,
            "HASHVIEW_SKIP_SETUP": True,
            "HASHVIEW_SKIP_GUI_SETUP": True,
            "HASHVIEW_DISABLE_SCHEDULER": True,
        },
    )

    # Absolute path to this repo's migrations/ so the run is cwd-independent.
    migrations_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "migrations"
    )
    with app.app_context():
        upgrade(directory=migrations_dir)

    print(f"Migration upgrade to head succeeded against {app.config['SQLALCHEMY_DATABASE_URI']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
