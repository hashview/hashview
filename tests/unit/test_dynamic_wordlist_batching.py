"""Batched generation must produce exactly what the single query produced.

generate_recovered_password_wordlist used to run one
``SELECT DISTINCT plaintext FROM hashes WHERE cracked = true`` and iterate it.
On a large corpus that built an on-disk temporary table, held the whole result
in the app's memory, and was cut off by net_write_timeout mid-fetch. It now
walks the corpus in keyset-paginated batches instead.

The risk that swap introduces is silent data loss: a pagination bug drops
plaintexts from the wordlist, and nothing fails -- the agent just cracks fewer
hashes with a quietly shorter list. So every test here forces the batch
boundary into awkward places (batch_size of 1, 2, 3 against a corpus with
duplicates, adjacent equal values and edge-case strings) and compares against
the set the database itself reports.
"""

import pytest

from hashview.models import Hashes, db
from hashview.utils.utils import (
    generate_recovered_password_wordlist,
    iter_distinct_recovered_plaintexts,
)


def _add(plaintext, cracked=True):
    db.session.add(Hashes(
        ciphertext=f'c{plaintext!r}{cracked}', sub_ciphertext=f's{abs(hash(plaintext)) % 10**9}',
        hash_type=1000, cracked=cracked, plaintext=plaintext))


def _seed(app, values, uncracked=()):
    with app.app_context():
        for index, value in enumerate(values):
            db.session.add(Hashes(ciphertext=f'ct{index}', sub_ciphertext=f'sub{index:029d}',
                                  hash_type=1000, cracked=True, plaintext=value))
        for index, value in enumerate(uncracked, start=len(values)):
            db.session.add(Hashes(ciphertext=f'ct{index}', sub_ciphertext=f'sub{index:029d}',
                                  hash_type=1000, cracked=False, plaintext=value))
        db.session.commit()


def _expected(app):
    """What the database itself says the distinct cracked plaintexts are."""
    with app.app_context():
        rows = (Hashes.query.filter(Hashes.cracked.is_(True), Hashes.plaintext.isnot(None))
                .with_entities(Hashes.plaintext).distinct().all())
        return sorted({row[0] for row in rows})


@pytest.mark.parametrize('batch_size', [1, 2, 3, 7, 1000])
def test_batching_returns_exactly_the_distinct_set(app, batch_size):
    """Every batch size must agree with the single-query answer.

    batch_size of 1 is the important one: it puts a boundary between every
    single row, so any off-by-one in the keyset shows up as a missing or
    repeated value.
    """
    values = ['alpha', 'bravo', 'bravo', 'charlie', 'alpha', 'delta',
              'echo', 'echo', 'echo', 'foxtrot']
    _seed(app, values, uncracked=['never-cracked'])
    with app.app_context():
        got = list(iter_distinct_recovered_plaintexts(batch_size=batch_size))
        assert got == sorted(got), 'keyset pagination must yield in order'
        assert len(got) == len(set(got)), 'no value may be yielded twice'
        assert got == _expected(app)
        assert 'never-cracked' not in got


def test_a_run_of_identical_values_spanning_batches_is_not_dropped(app):
    """Duplicates crossing a batch edge are where a keyset walk goes wrong.

    With batch_size 2 and three copies of the same plaintext, a batch can be
    filled entirely by values that DISTINCT collapses to one -- the resume
    point has to come from the value, not from a row count.
    """
    _seed(app, ['same', 'same', 'same', 'zulu'])
    with app.app_context():
        assert list(iter_distinct_recovered_plaintexts(batch_size=2)) == ['same', 'zulu']


def test_edge_case_strings_survive_the_round_trip(app):
    """Empty string, whitespace, unicode and $HEX[] wrappers all come back."""
    values = ['', ' ', '  leading', 'trailing  ', 'ünïcödé', '$HEX[00ff]', 'z' * 200]
    _seed(app, values)
    with app.app_context():
        assert list(iter_distinct_recovered_plaintexts(batch_size=2)) == _expected(app)


def test_null_plaintexts_are_skipped(app):
    """A cracked row with no plaintext must not end up as a blank line."""
    _seed(app, ['real'])
    with app.app_context():
        db.session.add(Hashes(ciphertext='ctnull', sub_ciphertext='sub' + '9' * 29,
                              hash_type=1000, cracked=True, plaintext=None))
        db.session.commit()
        assert list(iter_distinct_recovered_plaintexts(batch_size=1)) == ['real']


def test_an_empty_corpus_yields_nothing(app):
    with app.app_context():
        assert list(iter_distinct_recovered_plaintexts(batch_size=5)) == []


def test_the_written_wordlist_matches_the_distinct_set(app, tmp_path):
    """End to end: the file the agent downloads has one line per distinct value."""
    _seed(app, ['alpha', 'alpha', 'bravo', 'charlie'])
    target = tmp_path / 'wordlist.txt'
    with app.app_context():
        generate_recovered_password_wordlist(str(target))
        assert target.read_text(encoding='utf-8').splitlines() == _expected(app)


def test_length_filtering_still_applies_across_batches(app, tmp_path):
    """The length window is applied per value, so batching must not disturb it."""
    _seed(app, ['ab', 'abcd', 'abcdef', 'abcdefgh'])
    target = tmp_path / 'wordlist.txt'
    with app.app_context():
        generate_recovered_password_wordlist(str(target), min_length=4, max_length=6)
        assert sorted(target.read_text(encoding='utf-8').splitlines()) == ['abcd', 'abcdef']


def test_pagination_is_correct_even_when_rows_arrive_out_of_order(app):
    """Seeded in reverse so natural row order disagrees with sorted order.

    Without the ORDER BY the keyset is unsound -- the resume value comes from
    whatever row happened to be last, so already-emitted values reappear and
    later ones are skipped. Seeding in descending order is what makes a missing
    ORDER BY observable; a corpus that is already in order hides it.
    """
    _seed(app, ['zulu', 'yankee', 'xray', 'whiskey', 'alpha', 'bravo'])
    with app.app_context():
        got = list(iter_distinct_recovered_plaintexts(batch_size=2))
        assert got == sorted(got)
        assert len(got) == len(set(got)), 'a value was yielded twice'
        assert got == _expected(app)


def test_a_null_plaintext_can_never_wedge_the_walk(app):
    """The NULL filter is one guard; the sentinel is the other.

    If NULLs ever reach the walk, the resume value would be NULL, which must
    not be mistaken for "no lower bound yet" -- that mistake re-issues the same
    unbounded query forever and grows the output file without end.
    """
    _seed(app, ['alpha'])
    with app.app_context():
        for index in range(3):
            db.session.add(Hashes(ciphertext=f'ctn{index}',
                                  sub_ciphertext=f'subn{index:028d}',
                                  hash_type=1000, cracked=True, plaintext=None))
        db.session.commit()
        assert list(iter_distinct_recovered_plaintexts(batch_size=1)) == ['alpha']


def test_every_batch_query_carries_an_explicit_order_by(app):
    """The ORDER BY is load-bearing, and SQLite cannot demonstrate it.

    Keyset pagination is only sound if each batch is ordered by the column the
    resume value comes from. On MySQL, DISTINCT without ORDER BY is served from
    a temporary table in no defined order, so the resume value would be an
    arbitrary row and values would be skipped and repeated.

    SQLite cannot show that: it implements DISTINCT with a sorted temp B-tree,
    so results come back ordered whether or not ORDER BY was asked for, and
    deleting the clause changes nothing observable here. Rather than leave the
    clause untested until it reaches a production MySQL, assert it is in the
    SQL actually sent.
    """
    from sqlalchemy import event

    statements = []

    with app.app_context():
        engine = db.engine

        @event.listens_for(engine, 'before_cursor_execute')
        def _record(conn, cursor, statement, parameters, context, executemany):
            if statement.lstrip().upper().startswith('SELECT'):
                statements.append(' '.join(statement.split()))

        try:
            _seed(app, ['alpha', 'bravo', 'charlie'])
            list(iter_distinct_recovered_plaintexts(batch_size=2))
        finally:
            event.remove(engine, 'before_cursor_execute', _record)

    walk = [s for s in statements if 'FROM hashes' in s and 'DISTINCT' in s]
    assert walk, 'the walk issued no DISTINCT query over hashes'
    for statement in walk:
        assert 'ORDER BY' in statement.upper(), (
            f'batch query has no ORDER BY, so the keyset is unsound on MySQL: {statement}')


def test_the_walk_compares_cracked_with_equality_not_is(app):
    """`cracked = true`, never `cracked IS true` -- an index-usability trap.

    MySQL treats IS TRUE as a boolean test operator rather than an equality
    comparison, so it cannot drive index range access: `cracked IS true`
    abandons the composite (cracked, plaintext) index and scans the plaintext
    index instead, with a row lookup per entry to test cracked. That is work
    proportional to every plaintext in the table rather than to the cracked
    ones -- 1.8s became 129.7s on a 4M-row table at 25% cracked.

    SQLite cannot show this: it happily uses an index either way, and the test
    corpus here is entirely cracked so a row lookup costs nothing. Assert on the
    emitted SQL, which is where the trap actually lives.
    """
    from sqlalchemy import event

    statements = []
    with app.app_context():
        engine = db.engine

        @event.listens_for(engine, 'before_cursor_execute')
        def _record(conn, cursor, statement, parameters, context, executemany):
            if 'DISTINCT' in statement and 'hashes' in statement:
                statements.append(' '.join(statement.split()))

        try:
            _seed(app, ['alpha', 'bravo'])
            list(iter_distinct_recovered_plaintexts(batch_size=1))
        finally:
            event.remove(engine, 'before_cursor_execute', _record)

    assert statements, 'the walk emitted no DISTINCT query'
    for statement in statements:
        assert 'cracked IS' not in statement, (
            f'IS defeats the composite index on MySQL: {statement}')
        assert 'cracked = ' in statement, (
            f'expected an equality comparison on cracked: {statement}')
