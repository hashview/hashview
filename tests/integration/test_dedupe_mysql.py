"""The duplicate-hash repair, run against a real MySQL/MariaDB backend.

Every query in ``hashview.utils.dedupe`` is raw SQL, and the unit suite runs it
on SQLite, which parses far more than MySQL does. That gap shipped: the count
query aliased a column ``groups``, which SQLite accepts and MySQL 8.0.2+ refuses
outright (GROUPS became reserved for window functions). The script died with a
1064 and the Settings -> Data management repair section vanished, because the
route falls back to a count of zero and the section only renders when a count is
non-zero -- so a broken query looked exactly like a clean table.

Adding MySQL to the parity matrix alone would not have caught that: nothing in
tests/integration touched dedupe, so the job would have gone green. This module
is the companion that gives the matrix something to catch, by running every
dedupe statement -- the reads AND the four writes behind a merge -- on whichever
backend the job is pointed at.

``tests/unit/test_sql_reserved_words.py`` covers the same class statically, with
no database, so a collision fails on a laptop too. This one proves the
statements actually execute.
"""

import pytest

from hashview.utils.dedupe import (
    duplicate_summary,
    find_duplicate_groups,
    group_hashfiles,
    group_rows,
    merge_group,
    orphan_summary,
    orphaned_links,
)

pytestmark = pytest.mark.mysql

NTLM = 1000
CIPHER = "8846f7eaee8fb117ad06bdd830b7586c"
SUB = CIPHER[:32]
# A second, distinct hash -- see the merge test for why it must not collide.
SUB_OTHER = "b4b9b02e6f09a9bd760f388b67351e2b"


def _hashfile(session, owner_id, name):
    from hashview.models import Hashfiles

    hashfile = Hashfiles(name=name, customer_id=1, owner_id=owner_id)
    session.add(hashfile)
    session.flush()
    return hashfile


def _hash_row(session, sub=None, cracked=False, plaintext=None):
    from hashview.models import Hashes

    row = Hashes(ciphertext=CIPHER, sub_ciphertext=sub or SUB, hash_type=NTLM,
                 cracked=cracked, plaintext=plaintext)
    session.add(row)
    session.flush()
    return row


def _link(session, hashfile_id, hash_id, username):
    from hashview.models import HashfileHashes

    link = HashfileHashes(hashfile_id=hashfile_id, hash_id=hash_id,
                          username=username)
    session.add(link)
    session.flush()
    return link


def test_every_dedupe_read_query_executes(mysql_session):
    """The reads must parse and run -- this is what the reserved word broke.

    Asserts shape, not counts: the parity schema is shared and these have to
    hold whatever else a sibling test left behind.
    """
    conn = mysql_session.connection()

    groups, excess = duplicate_summary(conn)
    assert groups >= 0 and excess >= 0

    assert isinstance(find_duplicate_groups(conn), list)
    assert isinstance(find_duplicate_groups(conn, limit=5, offset=0), list)
    assert isinstance(group_rows(conn, NTLM, SUB), list)
    assert isinstance(group_hashfiles(conn, [1, 2]), dict)

    stale_links, stale_alerts = orphan_summary(conn)
    assert stale_links >= 0 and stale_alerts >= 0
    assert isinstance(orphaned_links(conn, limit=5), list)


def test_duplicate_summary_reports_none_under_the_constraint(mysql_session):
    """On a migrated schema there can BE no duplicates -- and that is the point.

    uq_hashes_sub_ciphertext_hash_type makes a duplicate row impossible, so a
    parity database always reports a clean table. The repair exists for
    databases upgraded from before the constraint, where the migration finds
    duplicates, warns, and skips creating it. That is why this module cannot
    manufacture a real duplicate group here, and why the merge test below joins
    two distinct rows instead: what has to be proven on MySQL is that the
    statements execute, not which rows they pick -- the row-choice semantics are
    covered on SQLite in tests/unit/test_duplicate_hash_repair.py.
    """
    assert duplicate_summary(mysql_session.connection()) == (0, 0)


def test_merge_group_runs_end_to_end_on_the_real_engine(mysql_session):
    """All four write statements behind a merge, on MySQL rather than SQLite.

    The collapse step in particular is MySQL-shaped: it wraps its subquery in a
    derived table because MySQL refuses to read the table it is deleting from,
    a constraint SQLite does not have and therefore never checks.

    The two rows differ in sub_ciphertext so the uniqueness constraint is
    satisfied -- merge_group takes the keeper and losers as arguments and never
    requires them to collide, so every statement still runs exactly as it would
    on a real duplicate pair.
    """
    from hashview.models import Hashes, HashfileHashes, Users

    owner = Users(first_name="Dedupe", last_name="Parity",
                  email_address="dedupe-parity@example.com",
                  password="x" * 60, admin=False)
    mysql_session.add(owner)
    mysql_session.flush()

    hashfile = _hashfile(mysql_session, owner.id, "dedupe-parity.txt")

    keeper = _hash_row(mysql_session, sub=SUB)
    loser = _hash_row(mysql_session, sub=SUB_OTHER, cracked=True,
                      plaintext="password")
    # The same account reached through both rows: repointing makes these two
    # links identical, which is what the collapse step has to clean up.
    _link(mysql_session, hashfile.id, keeper.id, "alice")
    _link(mysql_session, hashfile.id, loser.id, "alice")
    _link(mysql_session, hashfile.id, loser.id, "bob")
    mysql_session.flush()

    keeper_id, loser_id = keeper.id, loser.id
    stats = merge_group(mysql_session.connection(), keeper_id, [loser_id])
    # merge_group works in raw SQL behind the session's back, so the identity
    # map still holds the deleted row; expunge before reading it back or the
    # refresh raises ObjectDeletedError instead of returning None.
    mysql_session.expunge_all()

    assert Hashes.query.get(loser_id) is None, "the loser row must be gone"
    survivor = Hashes.query.get(keeper_id)
    assert survivor is not None
    # The keeper was uncracked and the loser was cracked, so the plaintext is
    # promoted onto the survivor rather than lost with the row.
    assert survivor.cracked and survivor.plaintext == "password"
    assert stats["promoted_crack"] is True

    usernames = sorted(
        link.username for link in
        HashfileHashes.query.filter_by(hash_id=keeper_id).all()
    )
    assert usernames == ["alice", "bob"], "links move, and duplicates collapse"


def test_create_unique_constraint_recreates_it_on_the_real_engine(mysql_session):
    """The helper that finishes the repair, exercised as DDL on MySQL.

    This is the step that rescues an operator whose migration skipped the
    constraint: f3b8c1a7d942 is stamped as applied the moment it skips, so no
    later `db upgrade` reattempts, and only this helper -- called by the repair
    script and on every app start -- can still create it.

    DDL auto-commits on MySQL and so escapes the fixture's savepoint isolation,
    which is why the constraint is restored in a finally: the schema this job's
    other tests run against has to end exactly as it started.
    """
    from sqlalchemy import text

    from hashview.utils.dedupe import (
        UNIQUE_CONSTRAINT,
        constraint_present,
        create_unique_constraint,
    )

    conn = mysql_session.connection()
    assert constraint_present(conn), "the migrated schema should already have it"

    try:
        conn.execute(text(f"ALTER TABLE hashes DROP INDEX {UNIQUE_CONSTRAINT}"))
        assert not constraint_present(conn), "precondition: dropped"

        assert create_unique_constraint(conn) is True
        assert constraint_present(conn)
        # Idempotent: startup calls it on every boot until it succeeds once.
        assert create_unique_constraint(conn) is False
    finally:
        if not constraint_present(conn):
            conn.execute(text(
                f"ALTER TABLE hashes ADD CONSTRAINT {UNIQUE_CONSTRAINT} "
                "UNIQUE (sub_ciphertext, hash_type)"))
