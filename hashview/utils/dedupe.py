"""Find and merge duplicate ``hashes`` rows sharing (sub_ciphertext, hash_type).

Migration ``f3b8c1a7d942`` adds ``uq_hashes_sub_ciphertext_hash_type``. The
import has always deduped on that pair -- it looks a hash up and inserts only
when absent -- but nothing enforced it, so two concurrent imports could both
miss and both insert. The constraint closes that race; these helpers clean up
what it produced before the constraint existed.

Everything here speaks raw SQL against a Connection rather than the ORM, and the
module deliberately imports nothing from Flask or hashview.models. Both matter:
a database that still has duplicates is a database where the migration refused
to finish, so it sits BELOW head while ``hashview.models`` describes head --
querying it through the models would fail on columns that do not exist yet. The
repair has to be able to run in exactly that state.

WHAT A DUPLICATE IS. Same sub_ciphertext AND same hash_type. The same 32-hex
string uploaded once as MD5 and once as NTLM is NOT a duplicate -- it is two
different hashes that happen to share a ciphertext, which is the case the pair
constraint exists to permit. Grouping is left to the database (GROUP BY) rather
than done in Python, so what is detected is exactly what the index will enforce,
including under a case-insensitive collation.

MERGING. Duplicate rows of one pair are the same hash, so merging is a repair,
not a choice: repoint the children, keep any recovered plaintext, drop the extra
rows. Two things make it dangerous enough to be careful about, both because
hashes.id has no foreign key anywhere:

  * a link row left pointing at a deleted hash makes build_hashcat_command raise
    (utils.py, the unguarded Hashes.query.get), which makes the job
    undispatchable; and
  * _hashfile_has_uncracked reads a dangling link as "nothing uncracked left",
    which cancels the job's remaining tasks.

So the children are repointed, never orphaned, and a group is only ever merged
automatically when the data leaves nothing to decide.
"""

from sqlalchemy import bindparam, text

# Two SQL strings here still interpolate a table name with an f-string, which
# bandit reports as B608 (hardcoded_sql_expressions) at Medium severity and LOW
# confidence. Both are false positives: `table` and `group_by` come from
# _CHILD_TABLES below, a module constant of two literal table names and their
# literal column tuples. Nothing operator-supplied reaches the SQL text.
#
# Every variable-length `IN (...)` uses bindparam(expanding=True) instead of a
# generated placeholder list, so SQLAlchemy builds the parameter markers and
# there is no f-string for bandit to flag -- and no hand-rolled ':h0, :h1' to
# get wrong. Both call sites return early on an empty list, which expanding
# bindparams do not accept.

# Tables holding a hashes.id. Neither has a foreign key, so nothing in the
# database will notice -- or stop -- a row being deleted out from under them.
# The second element is what makes two of a survivor's rows redundant.
_CHILD_TABLES = (
    ('hashfile_hashes', ('hashfile_id', 'username')),
    ('hash_notifications', ('owner_id', 'method')),
)


def duplicate_summary(conn):
    """(group_count, excess_rows) over the whole table.

    excess_rows is how many rows would go away: the count the operator cares
    about, and not the same as the group count once a group has three members.
    """
    row = conn.execute(text(
        'SELECT COUNT(*) AS groups, COALESCE(SUM(cnt - 1), 0) AS excess FROM ('
        '  SELECT COUNT(*) AS cnt FROM hashes'
        '  GROUP BY hash_type, sub_ciphertext HAVING COUNT(*) > 1'
        ') AS grouped'
    )).fetchone()
    return int(row[0]), int(row[1])


def find_duplicate_groups(conn, limit=None, offset=0):
    """The duplicate (hash_type, sub_ciphertext) pairs, most-duplicated first."""
    sql = ('SELECT hash_type, sub_ciphertext, COUNT(*) AS cnt FROM hashes '
           'GROUP BY hash_type, sub_ciphertext HAVING COUNT(*) > 1 '
           'ORDER BY cnt DESC, sub_ciphertext ASC')
    params = {}
    if limit is not None:
        sql += ' LIMIT :limit OFFSET :offset'
        params = {'limit': int(limit), 'offset': int(offset)}
    return [{'hash_type': int(r[0]), 'sub_ciphertext': r[1], 'count': int(r[2])}
            for r in conn.execute(text(sql), params).fetchall()]


def group_rows(conn, hash_type, sub_ciphertext):
    """Every row of one duplicate group, with what an operator needs to choose.

    Link and notification counts come from correlated subqueries rather than
    joins: a join would multiply the hash row by its children and the counts
    would be wrong for any hash that is in more than one hashfile.
    """
    rows = conn.execute(text(
        'SELECT h.id, h.ciphertext, h.cracked, h.plaintext, h.recovered_at,'
        '       h.recovered_by, h.task_id,'
        '       (SELECT COUNT(*) FROM hashfile_hashes f WHERE f.hash_id = h.id) AS links,'
        '       (SELECT COUNT(*) FROM hash_notifications n WHERE n.hash_id = h.id) AS notes'
        '  FROM hashes h'
        ' WHERE h.hash_type = :t AND h.sub_ciphertext = :s'
        ' ORDER BY h.id ASC'
    ), {'t': hash_type, 's': sub_ciphertext}).fetchall()
    return [{
        'id': int(r[0]), 'ciphertext': r[1], 'cracked': bool(r[2]),
        'plaintext': r[3], 'recovered_at': r[4], 'recovered_by': r[5],
        'task_id': r[6], 'links': int(r[7]), 'notifications': int(r[8]),
    } for r in rows]


def group_hashfiles(conn, hash_ids):
    """{hash_id: [(hashfile_id, hashfile_name, username), ...]} for context.

    Which files an account appears in is the thing that tells an operator these
    really are the same hash, so it is worth showing even though the merge does
    not depend on it.
    """
    if not hash_ids:
        return {}
    ids = [int(v) for v in hash_ids]
    rows = conn.execute(
        text(
            'SELECT f.hash_id, f.hashfile_id, hf.name, f.username'
            '  FROM hashfile_hashes f'
            '  LEFT JOIN hashfiles hf ON hf.id = f.hashfile_id'
            ' WHERE f.hash_id IN :ids'
            ' ORDER BY f.hash_id, f.hashfile_id'
        ).bindparams(bindparam('ids', expanding=True)),
        {'ids': ids},
    ).fetchall()
    out = {}
    for hash_id, hashfile_id, name, username in rows:
        out.setdefault(int(hash_id), []).append(
            (int(hashfile_id), name, username))
    return out


def classify_group(rows):
    """(kind, keeper_id, reason) -- whether the data decides this group for us.

    'conflict' means a human has to choose, and there are exactly two ways to
    get there:

      * the rows' ciphertexts are not byte-identical. Same sub_ciphertext is
        supposed to mean same ciphertext (it is its md5), so this is either an
        md5 collision or a normalisation bug -- either way these are not
        interchangeable rows and merging them would destroy a real hash. This
        gate is what keeps an automatic merge from ever being wrong.
      * two rows are cracked to DIFFERENT plaintexts. One of them is wrong and
        which one is not a question the data answers.

    Everything else is 'auto': the rows are the same hash, and at most one
    recovered password exists among them.
    """
    if len(rows) < 2:
        return 'auto', (rows[0]['id'] if rows else None), 'no duplicates'

    if len({r['ciphertext'] for r in rows}) > 1:
        return 'conflict', None, (
            'the rows do not share a ciphertext, so they are not the same hash '
            '(an md5 collision, or ciphertext that was normalised differently)')

    plaintexts = {r['plaintext'] for r in rows if r['cracked'] and r['plaintext'] is not None}
    if len(plaintexts) > 1:
        return 'conflict', None, (
            'cracked to different plaintexts: '
            + ', '.join(repr(p) for p in sorted(plaintexts)))

    return 'auto', recommend_keeper(rows), (
        'identical hash, one recovered password at most' if plaintexts
        else 'identical hash, none recovered')


def recommend_keeper(rows):
    """Which row to keep. Cracked first, then earliest recovery, then lowest id.

    Cracked first because a recovered password is the only thing in these rows
    that cannot be recomputed. Lowest id last because it is stable and because
    it is the id already baked into any "hash recovered" notification that was
    sent -- those carry a permanent /searches?hash_id=N link.
    """
    return min(rows, key=lambda r: (
        not r['cracked'],
        r['recovered_at'] or _FAR_FUTURE,
        r['id'],
    ))['id']


class _FarFuture:
    """Sorts after every real datetime, without assuming a datetime type back
    from the driver (SQLite hands back strings unless the column is typed)."""

    def __lt__(self, other):
        return False

    def __gt__(self, other):
        return True

    def __eq__(self, other):
        return isinstance(other, _FarFuture)

    def __le__(self, other):
        return isinstance(other, _FarFuture)

    def __ge__(self, other):
        return True

    def __hash__(self):
        return hash('_FarFuture')


_FAR_FUTURE = _FarFuture()


def orphan_summary(conn):
    """(orphaned_links, orphaned_alerts) -- child rows whose hash is gone.

    Not caused by merging (merge_group repoints rather than deletes), but the
    same absent foreign key lets anything else that removed a hash leave these
    behind, and nothing routinely cleans them up: purge_orphaned_hashes only runs
    when a hashfile or customer is deleted.
    """
    links = conn.execute(text(
        'SELECT COUNT(*) FROM hashfile_hashes f'
        ' WHERE NOT EXISTS (SELECT 1 FROM hashes h WHERE h.id = f.hash_id)')).scalar()
    alerts = conn.execute(text(
        'SELECT COUNT(*) FROM hash_notifications n'
        ' WHERE NOT EXISTS (SELECT 1 FROM hashes h WHERE h.id = n.hash_id)')).scalar()
    return int(links or 0), int(alerts or 0)


def orphaned_links(conn, limit=200):
    """Dangling hashfile_hashes rows, with enough context to judge them.

    Reported rather than deleted: the row is the record that an account existed
    in a hashfile, and that is not recoverable without re-importing the file. It
    is also the actively harmful kind -- build_hashcat_command raises on a
    dangling first link, making the job undispatchable, and
    _hashfile_has_uncracked reads one as "nothing left to crack", which cancels
    the job's remaining tasks.
    """
    rows = conn.execute(text(
        'SELECT f.id, f.hash_id, f.hashfile_id, hf.name, f.username'
        '  FROM hashfile_hashes f'
        '  LEFT JOIN hashfiles hf ON hf.id = f.hashfile_id'
        ' WHERE NOT EXISTS (SELECT 1 FROM hashes h WHERE h.id = f.hash_id)'
        ' ORDER BY f.hashfile_id, f.id'
        ' LIMIT :limit'), {'limit': int(limit)}).fetchall()
    return [{'id': int(r[0]), 'hash_id': int(r[1]), 'hashfile_id': int(r[2]),
             'hashfile_name': r[3], 'username': r[4]} for r in rows]


def delete_orphaned_alerts(conn):
    """Drop hash_notifications rows whose hash is gone. Returns how many.

    Safe, and the only thing that ever clears them outside a hashfile/customer
    delete. Such a row can never fire -- process_recovered_hash_notifications
    looks the hash up, `continue`s when it is missing, and so never reaches the
    delete that would retire it -- while still being re-scanned by a full table
    read on every crack upload and every /v1/hashes/import, forever.

    The caller owns the transaction.
    """
    result = conn.execute(text(
        'DELETE FROM hash_notifications'
        ' WHERE NOT EXISTS (SELECT 1 FROM hashes h WHERE h.id = hash_notifications.hash_id)'))
    return int(result.rowcount or 0)


def merge_group(conn, keeper_id, loser_ids):
    """Fold the losers into the keeper. Returns what it did, for the receipt.

    Order is deliberate: promote the crack first, then repoint the children,
    then collapse what repointing made redundant, and only then delete. At no
    point does a child row point at a hash that is gone -- which is the failure
    that makes jobs undispatchable and silently cancels live cracking.

    The caller owns the transaction.
    """
    loser_ids = [int(i) for i in loser_ids if int(i) != int(keeper_id)]
    if not loser_ids:
        return {'keeper': int(keeper_id), 'deleted': [], 'promoted_crack': False,
                'relinked': {}, 'collapsed': {}}
    params = {'losers': loser_ids, 'keeper': int(keeper_id)}
    stats = {'keeper': int(keeper_id), 'deleted': loser_ids,
             'promoted_crack': False, 'relinked': {}, 'collapsed': {}}

    # 1. Promote a recovered password onto the keeper if it lacks one. Guarded on
    #    the keeper still being uncracked so this can never overwrite a crack.
    promoted = conn.execute(
        text(
            'UPDATE hashes SET cracked = 1,'
            '  plaintext = (SELECT l.plaintext FROM (SELECT * FROM hashes) l'
            '               WHERE l.id IN :losers AND l.cracked = 1'
            '                ORDER BY l.recovered_at IS NULL, l.recovered_at, l.id LIMIT 1),'
            '  recovered_at = (SELECT l.recovered_at FROM (SELECT * FROM hashes) l'
            '                  WHERE l.id IN :losers AND l.cracked = 1'
            '                   ORDER BY l.recovered_at IS NULL, l.recovered_at, l.id LIMIT 1),'
            '  recovered_by = (SELECT l.recovered_by FROM (SELECT * FROM hashes) l'
            '                  WHERE l.id IN :losers AND l.cracked = 1'
            '                   ORDER BY l.recovered_at IS NULL, l.recovered_at, l.id LIMIT 1),'
            '  task_id = (SELECT l.task_id FROM (SELECT * FROM hashes) l'
            '             WHERE l.id IN :losers AND l.cracked = 1'
            '              ORDER BY l.recovered_at IS NULL, l.recovered_at, l.id LIMIT 1)'
            ' WHERE id = :keeper AND cracked = 0'
            '   AND EXISTS (SELECT 1 FROM (SELECT * FROM hashes) x WHERE x.id IN :losers'
            '                 AND x.cracked = 1)'
        ).bindparams(bindparam('losers', expanding=True)),
        params,
    )
    stats['promoted_crack'] = bool(promoted.rowcount)

    for table, redundant_on in _CHILD_TABLES:
        moved = conn.execute(
            text(
                f'UPDATE {table} SET hash_id = :keeper WHERE hash_id IN :losers'  # nosec B608
            ).bindparams(bindparam('losers', expanding=True)),
            params,
        )
        stats['relinked'][table] = int(moved.rowcount or 0)

        # Repointing can leave the keeper holding rows that are now identical --
        # the same account in the same hashfile, or the same alert twice. Neither
        # table has a unique constraint to stop it, so collapse them here. The
        # derived-table wrapper is required: MySQL refuses a subquery that reads
        # the table being deleted from.
        group_by = ', '.join(redundant_on)
        collapsed = conn.execute(text(
            f'DELETE FROM {table} WHERE hash_id = :keeper AND id NOT IN ('  # nosec B608
            f'  SELECT keep_id FROM ('
            f'    SELECT MIN(id) AS keep_id FROM {table} WHERE hash_id = :keeper'
            f'    GROUP BY {group_by}'
            f'  ) AS keepers)'
        ), {'keeper': int(keeper_id)})
        stats['collapsed'][table] = int(collapsed.rowcount or 0)

    conn.execute(
        text('DELETE FROM hashes WHERE id IN :losers')
        .bindparams(bindparam('losers', expanding=True)),
        {'losers': loser_ids},
    )
    return stats
