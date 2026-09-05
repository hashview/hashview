"""Regression: the main->dev migration tail is idempotent under schema drift.

Reproduces the field failure where a database stamped at 8027c2d2b40a already
physically had columns a later migration adds (classic model drift): the blind
`ALTER TABLE hashes ADD COLUMN recovered_at` in a02b6f567b7b aborted with a
duplicate-column error, and because MySQL DDL is non-transactional the whole
upgrade stranded there -- leaving every later dev column (slack_id, byte_size,
loopback, agent_timeout_minutes, ...) uncreated and the app throwing
'Unknown column' on nearly every model.

These tests drive the REAL Alembic tail (8027c2d2b40a -> dev head) against a
SQLite database, so they exercise the actual migration files. Stamping below
the tail while the schema is already at/near head is precisely the drift; a
non-idempotent migration raises 'duplicate column name' here just as MySQL
raised 1060. We stamp at 8027c2d2b40a (not base) so the SQLite-incompatible
early FK/alter migrations below it never run.
"""

from pathlib import Path

from flask_migrate import stamp, upgrade
from sqlalchemy import inspect as sa_inspect
from sqlalchemy import text

MIGRATIONS_DIR = str(Path(__file__).resolve().parents[2] / "migrations")
BASE_REV = "8027c2d2b40a"      # what the drifted field DB was stamped at
DEV_HEAD = "b5c8d9e1f2a4"


def _drifted_app(tmp_path, drop_columns=()):
    """Build a SQLite app whose schema is the full dev model (i.e. ahead of the
    stamped revision), optionally dropping some columns to simulate a main-era
    schema that is missing the dev additions but still carries the drifted
    `recovered_at`. Returns (app, db)."""
    from hashview import create_app
    from hashview.models import db

    db_file = tmp_path / "drift.db"
    app = create_app(testing=True, config_overrides={
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_file}",
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
        "SECRET_KEY": "migration-drift-test",
        "HASHVIEW_SKIP_SETUP": True,
        "HASHVIEW_SKIP_GUI_SETUP": True,
        "HASHVIEW_DISABLE_SCHEDULER": True,
    })
    with app.app_context():
        db.create_all()
        for table, col in drop_columns:
            # A main-era schema missing this column wouldn't carry a dev-head index
            # on it either; SQLite also refuses to drop an indexed column, so drop
            # any dependent index first. The migration tail re-adds both.
            for ix in sa_inspect(db.engine).get_indexes(table):
                if col in ix["column_names"]:
                    db.session.execute(text(f'DROP INDEX IF EXISTS {ix["name"]}'))
            db.session.execute(text(f"ALTER TABLE {table} DROP COLUMN {col}"))
        db.session.commit()
        # Point Alembic below the tail: schema ahead, bookkeeping behind == drift.
        stamp(directory=MIGRATIONS_DIR, revision=BASE_REV)
    return app, db


def _columns(db, table):
    return {c["name"] for c in sa_inspect(db.engine).get_columns(table)}


def _current_rev(db):
    return db.session.execute(text("SELECT version_num FROM alembic_version")).scalar()


def test_upgrade_head_idempotent_when_schema_already_ahead(tmp_path):
    """Full dev schema present but stamped at 8027c2d2b40a: upgrade must skip the
    already-present columns and still reach dev head (pre-fix: a02b6f567b7b
    raised 'duplicate column name: recovered_at' right here)."""
    app, db = _drifted_app(tmp_path)
    with app.app_context():
        assert "recovered_at" in _columns(db, "hashes")   # the drift trigger
        upgrade(directory=MIGRATIONS_DIR)                  # must not raise
        assert _current_rev(db) == DEV_HEAD


def test_upgrade_head_adds_only_the_missing_columns(tmp_path):
    """A main-era-ish schema (dev columns dropped) that still carries the
    drifted `recovered_at`: upgrade skips recovered_at, (re)creates the genuinely
    missing columns from across the tail, and lands at dev head."""
    missing = [("hashes", "task_id"), ("wordlists", "byte_size"),
               ("users", "slack_id"), ("tasks", "loopback"),
               ("settings", "agent_timeout_minutes")]
    app, db = _drifted_app(tmp_path, drop_columns=missing)
    with app.app_context():
        assert "recovered_at" in _columns(db, "hashes")    # kept -> reproduces the crash
        for table, col in missing:
            assert col not in _columns(db, table)
        upgrade(directory=MIGRATIONS_DIR)
        assert _current_rev(db) == DEV_HEAD
        for table, col in missing:
            assert col in _columns(db, table), f"{table}.{col} was not re-created"
