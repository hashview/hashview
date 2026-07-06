"""End-to-end main->dev migration verifier.

Run by tests/run_migration_e2e.sh AFTER the dev app has migrated + backfilled
the DB. Reads two live MySQL databases:
  HASHVIEW_MIGRATED_DB_URI  - the db that went main -> seed -> dev
  HASHVIEW_FRESH_DB_URI     - dev schema built from empty (parity oracle)
"""
import os
import pytest
from sqlalchemy import create_engine, text

from tests.migration.expected_hex import USERNAME_CASES, PLAINTEXT_CASES

DEV_HEAD = "c8b3f0a14d27"

pytestmark = [pytest.mark.mysql, pytest.mark.migration]


def _engine(env):
    uri = os.environ.get(env)
    if not uri:
        pytest.skip(f"{env} not set (run via tests/run_migration_e2e.sh)")
    return create_engine(uri)


@pytest.fixture(scope="module")
def migrated():
    return _engine("HASHVIEW_MIGRATED_DB_URI")


@pytest.fixture(scope="module")
def fresh():
    return _engine("HASHVIEW_FRESH_DB_URI")


def _scalar(engine, sql, **params):
    with engine.connect() as c:
        return c.execute(text(sql), params).scalar()


def test_alembic_at_dev_head(migrated):
    assert _scalar(migrated, "SELECT version_num FROM alembic_version") == DEV_HEAD


def test_passwords_decoded_flag_flipped(migrated):
    assert _scalar(migrated, "SELECT passwords_decoded FROM settings LIMIT 1") == 1


@pytest.mark.parametrize("row_id,marker", [(9001, "u_ascii"), (9002, "u_utf8"),
                                           (9003, "u_nonutf8"), (9004, "u_plaintext")])
def test_username_hex_backfill(migrated, row_id, marker):
    _seeded, expected = USERNAME_CASES[marker]
    got = _scalar(migrated, "SELECT username FROM hashfile_hashes WHERE id=:i", i=row_id)
    assert got == expected


@pytest.mark.parametrize("row_id,marker", [(9001, "p_ascii"), (9002, "p_utf8"),
                                           (9003, "p_nonutf8")])
def test_plaintext_hex_backfill(migrated, row_id, marker):
    _seeded, expected = PLAINTEXT_CASES[marker]
    got = _scalar(migrated, "SELECT plaintext FROM hashes WHERE id=:i", i=row_id)
    assert got == expected


def test_ddl_backfills_on_preexisting_rows(migrated):
    assert _scalar(migrated, "SELECT hex_salt FROM hashfiles WHERE id=900") == 0
    assert _scalar(migrated, "SELECT loopback FROM tasks WHERE id=900") == 0
    # settings columns added on dev exist and carry upgrade-safe defaults
    assert _scalar(migrated, "SELECT pushover_enabled FROM settings LIMIT 1") == 1
    assert _scalar(migrated, "SELECT slack_enabled FROM settings LIMIT 1") == 0
    assert _scalar(migrated, "SELECT agent_timeout_minutes FROM settings LIMIT 1") == 60


def _col(engine, table, col):
    """Return (data_type, character_set_name) for a column. Uses positional
    access -- information_schema column labels don't resolve via SQLAlchemy 1.4
    Row attribute access, and MySQL may vary their case."""
    with engine.connect() as c:
        row = c.execute(text(
            "SELECT data_type, character_set_name "
            "FROM information_schema.columns "
            "WHERE table_schema=DATABASE() AND table_name=:t AND column_name=:c"),
            {"t": table, "c": col}).fetchone()
    return {"data_type": row[0], "character_set_name": row[1]}


def test_explicit_type_assertions(migrated):
    ciphertext = _col(migrated, "hashes", "ciphertext")
    assert ciphertext["data_type"] == "text"
    assert ciphertext["character_set_name"] == "utf8mb4"
    assert _col(migrated, "hashes", "plaintext")["character_set_name"] == "utf8mb4"
    assert _col(migrated, "hashfile_hashes", "username")["character_set_name"] == "utf8mb4"


def _schema_snapshot(engine):
    """Comparable dict of the schema from information_schema."""
    snap = {}
    with engine.connect() as c:
        cols = c.execute(text(
            "SELECT table_name, column_name, ordinal_position, data_type, "
            "character_maximum_length, numeric_precision, numeric_scale, "
            "is_nullable, column_default, character_set_name, collation_name, extra "
            "FROM information_schema.columns WHERE table_schema=DATABASE() "
            "ORDER BY table_name, ordinal_position")).fetchall()
        snap["columns"] = [tuple(r) for r in cols]
        idx = c.execute(text(
            "SELECT table_name, index_name, non_unique, seq_in_index, column_name "
            "FROM information_schema.statistics WHERE table_schema=DATABASE() "
            "ORDER BY table_name, index_name, seq_in_index")).fetchall()
        snap["indexes"] = [tuple(r) for r in idx]
        fks = c.execute(text(
            "SELECT table_name, column_name, referenced_table_name, referenced_column_name "
            "FROM information_schema.key_column_usage WHERE table_schema=DATABASE() "
            "AND referenced_table_name IS NOT NULL "
            "ORDER BY table_name, column_name, referenced_table_name")).fetchall()
        snap["fks"] = [tuple(r) for r in fks]
    return snap


def test_schema_parity_with_fresh_build(migrated, fresh):
    m = _schema_snapshot(migrated)
    f = _schema_snapshot(fresh)
    assert m["columns"] == f["columns"], "column definitions differ (type/charset/collation/default/order)"
    assert m["indexes"] == f["indexes"], "index definitions differ"
    assert m["fks"] == f["fks"], "foreign key definitions differ"
