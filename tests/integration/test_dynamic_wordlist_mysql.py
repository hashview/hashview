"""Batched recovered-plaintext generation, against a real MySQL/MariaDB.

The unit suite covers the pagination logic on SQLite, but the property that
actually matters here is collation-dependent and SQLite cannot show it. MySQL's
default collation is accent- and case-insensitive, so DISTINCT collapses
'Password'/'password' and orders 'ünïcödé' near 'u' -- while Python compares
codepoints and sorts it after 'z'. A keyset walk that assumed Python's ordering
agreed with the database's would either skip values or refuse to advance, and a
unit test over ASCII on SQLite would never notice. (That is not hypothetical:
an ordering-based loop guard did exactly this and was caught here.)

So this asserts the one invariant worth asserting -- the batched walk returns
exactly what the single query returned -- on the engine whose collation rules
actually apply.
"""

import pytest

from hashview.utils.utils import iter_distinct_recovered_plaintexts

pytestmark = pytest.mark.mysql

# Case variants, accents, CJK, an empty string, a $HEX[] wrapper and a long
# value: everything whose ordering or equality differs between Python and a
# MySQL collation.
AWKWARD = ['Password', 'password', 'PASSWORD', '', ' ', 'ünïcödé', 'Ünïcödé',
           'æøå', '密码', '$HEX[00ff]', 'z' * 200, 'apple', 'Banana', 'cherry']


def _seed(session, values):
    from hashview.models import Hashes

    for index, value in enumerate(values):
        # 'dwl' prefix: this schema is shared with the other mysql-marked
        # modules, and sub_ciphertext carries a uniqueness constraint, so the
        # keys have to be distinctive to this module rather than just unique
        # within it.
        session.add(Hashes(ciphertext=f'dwl-ct{index}',
                           sub_ciphertext=f'dwl{index:029d}',
                           hash_type=1000, cracked=True, plaintext=value))
    session.flush()


@pytest.mark.parametrize('batch_size', [1, 2, 7, 5000])
def test_batched_walk_matches_the_single_query(mysql_session, batch_size):
    from sqlalchemy import text

    _seed(mysql_session, AWKWARD + AWKWARD)     # every value duplicated
    single = [row[0] for row in mysql_session.execute(text(
        'SELECT DISTINCT plaintext FROM hashes '
        ' WHERE cracked = true AND plaintext IS NOT NULL ORDER BY plaintext'))]

    walked = list(iter_distinct_recovered_plaintexts(batch_size=batch_size))

    assert len(walked) == len(set(walked)), 'a value was yielded twice'
    assert walked == single, (
        'the batched walk disagrees with the single query it replaces')


def test_a_null_plaintext_does_not_wedge_the_walk(mysql_session):
    """NULLs must be filtered, and must never become the resume value."""
    from hashview.models import Hashes

    _seed(mysql_session, ['alpha', 'beta'])
    for index in range(3):
        mysql_session.add(Hashes(ciphertext=f'dwl-null{index}',
                                 sub_ciphertext=f'dwlnull{index:025d}',
                                 hash_type=1000, cracked=True, plaintext=None))
    mysql_session.flush()

    walked = list(iter_distinct_recovered_plaintexts(batch_size=1))
    assert None not in walked
    assert 'alpha' in walked and 'beta' in walked


def test_the_batch_query_is_served_by_the_covering_index(mysql_session):
    """EXPLAIN the SQL the WALK ACTUALLY EMITS, not a hand-written lookalike.

    The first version of this test EXPLAINed a query this module wrote by hand
    with `cracked = true`, and passed while the real walk shipped
    `cracked IS true` -- which MySQL cannot use for index range access, because
    IS TRUE is a boolean test operator rather than an equality comparison. The
    walk quietly fell back to scanning ix_hashes_plaintext with a row lookup per
    entry, doing work proportional to every plaintext in the table instead of
    the cracked ones: 1.8s became 129.7s on 4M rows at 25% cracked.

    So this captures the statement the ORM emits and explains THAT, through the
    raw cursor with the same parameters. A test that reconstructs the query it
    is checking cannot catch the query changing.
    """
    from sqlalchemy import event

    _seed(mysql_session, ['alpha', 'bravo', 'charlie'])

    captured = []
    engine = mysql_session.get_bind()

    @event.listens_for(engine, 'before_cursor_execute')
    def _capture(conn, cursor, statement, parameters, context, executemany):
        if 'DISTINCT' in statement and 'hashes' in statement:
            captured.append((statement, parameters))

    try:
        list(iter_distinct_recovered_plaintexts(batch_size=2))
    finally:
        event.remove(engine, 'before_cursor_execute', _capture)

    assert captured, 'the walk emitted no DISTINCT query to explain'
    statement, parameters = captured[-1]

    # IS TRUE is the specific trap; assert on the emitted text as well as the
    # plan, so the reason a plan regressed is legible when this fails.
    assert 'IS true' not in statement and 'IS 1' not in statement, (
        'the walk compares cracked with IS, which cannot use the composite '
        f'index on MySQL: {statement}')

    raw = mysql_session.connection().connection
    cursor = raw.cursor()
    try:
        cursor.execute('EXPLAIN ' + statement, parameters)
        columns = [c[0] for c in cursor.description]
        plan = dict(zip(columns, cursor.fetchone(), strict=True))
    finally:
        cursor.close()

    assert plan['key'] == 'ix_hashes_cracked_plaintext', (
        f"the batch query is not using the covering index, got {plan['key']!r}; "
        f"plan: {plan}")
    assert 'Using temporary' not in (plan['Extra'] or ''), (
        f"the batch query builds a temporary table: {plan['Extra']!r}")
