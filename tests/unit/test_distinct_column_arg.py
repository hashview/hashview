"""``Query.distinct(<column>)`` is PostgreSQL's DISTINCT ON -- issue #373.

Every other backend silently drops the argument and emits a plain
``SELECT DISTINCT``, with a deprecation warning promising a future
``CompileError``. Four queries here were written that way; two had already been
rewritten for unrelated reasons by the time the issue was looked at again, a
fifth was never filed at all because it sat in unreachable code.

Two guards, because one is not enough:

* ``pytest.ini`` escalates ``SADeprecationWarning`` to an error, which catches
  any *executed* occurrence. That is the general guard and it covers the whole
  deprecated surface, not just this construct.
* The static sweep below catches the ones no test executes. The fifth site hid
  in dead code for exactly that long.

The rest of the module pins the shape of the two queries that were fixed. The
point is not that they no longer warn -- it is that they no longer drag every
row of a junction table through the ORM to build a set of usernames.
"""

import ast
import pathlib

import pytest
from sqlalchemy import event

from hashview.models import Customers, HashfileHashes, Users, Wordlists, db
from hashview.utils.utils import update_dynamic_wordlist


def _user():
    user = Users(first_name="t", last_name="u", email_address="t@example.com",
                 password="x" * 60, admin=True)
    db.session.add(user)
    db.session.commit()
    return user


def _wordlist(tmp_path, name):
    path = str(tmp_path / f"{name.replace(' ', '_')}.txt")
    open(path, "w").close()
    wl = Wordlists(name=name, owner_id=1, type="dynamic", path=path,
                   checksum="", size=0)
    db.session.add(wl)
    db.session.commit()
    return wl


def _statements_while(fn):
    """Every SQL statement emitted while fn() runs."""
    seen = []

    def record(conn, cursor, statement, parameters, context, executemany):
        seen.append(" ".join(statement.split()))

    event.listen(db.engine, "before_cursor_execute", record)
    try:
        fn()
    finally:
        event.remove(db.engine, "before_cursor_execute", record)
    return seen


def _select_against(statements, table):
    matches = [s for s in statements
               if s.lower().startswith("select") and f" from {table}" in s.lower()]
    assert len(matches) == 1, f"expected one SELECT against {table}, got {matches}"
    return matches[0]


# --------------------------------------------------------------- static sweep

def test_no_query_passes_a_column_to_distinct():
    """Nothing anywhere calls ``.distinct(<anything>)``.

    Deliberately a source sweep and not a warning check: a warning only fires
    on code that runs, and the instance that survived longest
    (hashview.py's orphaned data_retention_cleanup copy) was never reached by
    anything, test or production.
    """
    offenders = []
    roots = [pathlib.Path("hashview"), pathlib.Path("migrations"),
             pathlib.Path("install")]
    files = [pathlib.Path("hashview.py"), pathlib.Path("setup.py")]
    for root in roots:
        files.extend(root.rglob("*.py"))
    for path in files:
        if not path.exists():
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "distinct"
                    and (node.args or node.keywords)):
                offenders.append(f"{path}:{node.lineno}")
    assert offenders == [], (
        "Query.distinct(<column>) is DISTINCT ON; every backend but PostgreSQL "
        f"drops the argument and warns it will raise one day: {offenders}")


# ------------------------------------------------------- the rewritten queries

def test_the_username_query_fetches_one_column_and_never_dedupes_in_sql(app, tmp_path):
    """One column, no DISTINCT -- and both halves matter.

    The column, because this used to load every hashfile_hashes row as a full
    ORM entity on the agent's download path. No DISTINCT, because
    hashfile_hashes.username is utf8mb4 with no explicit COLLATE: on MySQL 8 it
    inherits a case- and accent-insensitive collation, so a SQL-side DISTINCT
    would fold 'Admin' into 'admin' and quietly shrink the wordlist. The Python
    set that follows dedupes exactly, by codepoint.
    """
    _user()
    wl = _wordlist(tmp_path, "(DYNAMIC) All Usernames")
    for name in ("alice", "Alice", "bob"):
        db.session.add(HashfileHashes(hash_id=1, hashfile_id=1, username=name))
    db.session.commit()

    statements = _statements_while(lambda: update_dynamic_wordlist(wl.id))
    select = _select_against(statements, "hashfile_hashes")

    assert "distinct" not in select.lower(), (
        f"SQL-side DISTINCT folds case variants under MySQL's collation: {select}")
    selected = select.lower().split(" from ")[0]
    assert "username" in selected
    for column in ("hashfile_hashes.id", "hash_id", "hashfile_id"):
        assert column not in selected, (
            f"{column} is being fetched to build a set of usernames: {select}")


def test_username_case_variants_all_survive(app, tmp_path):
    # The behaviour the missing DISTINCT protects. SQLite compares case
    # sensitively so this passes either way here; its MySQL counterpart in
    # tests/integration/test_dynamic_wordlist_mysql.py is the one that bites.
    _user()
    wl = _wordlist(tmp_path, "(DYNAMIC) All Usernames")
    for name in ("admin", "Admin", "ADMIN"):
        db.session.add(HashfileHashes(hash_id=1, hashfile_id=1, username=name))
    db.session.commit()

    update_dynamic_wordlist(wl.id)

    assert set(open(wl.path).read().splitlines()) == {"admin", "Admin", "ADMIN"}


def test_the_customer_query_fetches_one_column(app, tmp_path):
    _user()
    wl = _wordlist(tmp_path, "(DYNAMIC) All Customers")
    db.session.add(Customers(name="AcmeCorp"))
    db.session.commit()

    statements = _statements_while(lambda: update_dynamic_wordlist(wl.id))
    select = _select_against(statements, "customers")

    selected = select.lower().split(" from ")[0]
    assert "customers.name" in selected
    assert "customers.id" not in selected, f"fetching the whole row: {select}"
    assert open(wl.path).read().splitlines() == ["acmecorp"]


# ------------------------------------------------------------ the CI guard

def test_a_deprecated_sqlalchemy_construct_fails_the_suite():
    """pytest.ini escalates SADeprecationWarning, so #373 cannot come back quietly.

    It sat in the warnings summary of every CI run for months. Nothing reads the
    warnings summary.
    """
    import warnings

    from sqlalchemy.exc import SADeprecationWarning

    with pytest.raises(SADeprecationWarning):
        warnings.warn("canary", SADeprecationWarning, stacklevel=1)
