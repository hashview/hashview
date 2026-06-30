"""MySQL/MariaDB integration smoke tests.

These close the gap left by ``tests/unit/test_migration_smoke.py``: the unit
suite only validates the Alembic chain *structurally* and never runs the
MySQL-only DDL (``create_foreign_key`` / ``alter_column``) that SQLite can't
execute. The db-parity CI workflow runs ``flask db upgrade`` against a real
MariaDB service first, then runs these tests (``-m mysql``) against that
migration-built schema.

They deliberately exercise behaviour that differs between SQLite and MySQL:

* the migration-created tables actually exist with the expected columns
  (proving the MySQL DDL ran, not just ``create_all``),
* default MySQL string collation is case-INSENSITIVE for equality (SQLite's
  default is case-sensitive), so a query that round-trips through the DB
  surfaces the dialect difference, and
* model rows with real FK columns insert and round-trip, and an ORM
  relationship cascade behaves on the live engine.

Every test is marked ``mysql`` and uses the ``mysql_session`` fixture, which
``pytest.skip``s when ``HASHVIEW_TEST_DATABASE_URI`` is unset — so a normal
local ``pytest tests/`` run collects but skips these, unchanged.
"""

from datetime import datetime

import pytest
from sqlalchemy import inspect, text


pytestmark = pytest.mark.mysql


def _make_user(session, email):
    from hashview.models import Users

    user = Users(
        first_name="Smoke",
        last_name="Tester",
        email_address=email,
        password="x" * 60,
        admin=False,
    )
    session.add(user)
    session.flush()  # assign PK without committing
    return user


def test_migration_created_tables_exist(mysql_session):
    """The schema reached by ``flask db upgrade`` contains the expected tables.

    Asserting on the live MySQL schema (not ORM metadata) proves the migration
    chain's MySQL-only DDL executed end-to-end, which is exactly what never
    happens in the SQLite unit suite.
    """
    inspector = inspect(mysql_session.get_bind())
    tables = set(inspector.get_table_names())

    expected = {
        "users",
        "customers",
        "jobs",
        "job_tasks",
        "agents",
        "agent_benchmarks",
        "rules",
        "wordlists",
        "tasks",
        "task_groups",
        "hashfiles",
        "settings",
    }
    missing = expected - tables
    assert not missing, f"Migration-built schema is missing tables: {sorted(missing)}"

    # alembic's own bookkeeping table must be present (proves upgrade ran here).
    assert "alembic_version" in tables, (
        "alembic_version table absent — `flask db upgrade` did not stamp this DB."
    )


def test_string_equality_is_case_insensitive_on_mysql(mysql_session):
    """MySQL's default collation makes string equality case-insensitive.

    Under SQLite (the unit default) this same query would NOT match, so this
    asserts the production dialect's real behaviour — the kind of difference the
    SQLite-only suite can never catch.
    """
    from hashview.models import Users

    collation = mysql_session.execute(text("SELECT @@collation_database")).scalar()
    if collation and (collation.endswith("_bin") or "_cs" in collation):
        pytest.skip(
            f"Database collation {collation!r} is case-sensitive; this test only "
            "holds under a case-insensitive (_ci) collation."
        )

    email = "Case.Sensitive@Example.COM"
    _make_user(mysql_session, email)
    mysql_session.flush()

    hit = (
        mysql_session.query(Users)
        .filter(Users.email_address == "case.sensitive@example.com")
        .first()
    )
    assert hit is not None, (
        "Expected MySQL's default case-insensitive collation to match a "
        "differently-cased email; got no row."
    )
    assert hit.email_address == email


def test_fk_row_roundtrip_and_relationship(mysql_session):
    """Rows with real FK columns insert, round-trip, and the ORM backref works.

    Users.rules is a relationship over Rules.owner_id -> users.id (a FK created
    by the migration chain). Inserting through it and reading it back exercises
    the FK column the MySQL DDL defined.
    """
    from hashview.models import Rules, Users

    user = _make_user(mysql_session, "fk.roundtrip@example.com")

    rule = Rules(
        name="smoke-rule",
        last_updated=datetime.utcnow(),
        owner_id=user.id,
        path="control/rules/smoke.rule",
        size=0,
        checksum="0" * 64,
    )
    mysql_session.add(rule)
    mysql_session.flush()

    fetched = mysql_session.get(Users, user.id)
    assert any(r.name == "smoke-rule" for r in fetched.rules), (
        "Rules backref did not surface the inserted row over the FK."
    )

    # And the FK column actually points back at the user.
    fetched_rule = mysql_session.get(Rules, rule.id)
    assert fetched_rule.owner_id == user.id


def test_foreign_key_constraint_is_enforced(mysql_session):
    """A FK created by the migration chain rejects an orphan reference.

    SQLite does not enforce FKs by default, so this constraint behaviour only
    manifests on MySQL — verifying the migration's ``create_foreign_key`` DDL
    produced an *enforced* constraint, not just a column.
    """
    from sqlalchemy.exc import IntegrityError

    from hashview.models import Rules

    orphan = Rules(
        name="orphan-rule",
        last_updated=datetime.utcnow(),
        owner_id=2_000_000_000,  # no such user
        path="control/rules/orphan.rule",
        size=0,
        checksum="0" * 64,
    )
    mysql_session.add(orphan)
    with pytest.raises(IntegrityError):
        mysql_session.flush()
    mysql_session.rollback()


def test_now_function_returns_db_clock(mysql_session):
    """``SELECT NOW()`` returns a datetime on MySQL.

    The app's nav-count context processor relies on the DB clock (``SELECT
    NOW()``) for agent freshness; this confirms the round-trip works on the
    real backend (SQLite has no NOW()).
    """
    value = mysql_session.execute(text("SELECT NOW()")).scalar()
    assert value is not None
