"""add unique constraint on hashes (sub_ciphertext, hash_type)

Revision ID: f3b8c1a7d942
Revises: a8c4d2e1f5b3
Create Date: 2026-09-09 00:00:00.000000

The hashfile import dedups on (hash_type, sub_ciphertext) -- it looks a hash up
by that pair and inserts only when it is absent -- but nothing enforced the
pair's uniqueness, so the check-then-act was a TOCTOU: two concurrent imports
of the same hash can both miss the lookup and both insert. This composite
unique index closes that race, and it makes the dedup lookup a single-row
`const` access instead of a `ref` probe plus a row fetch to check hash_type.

The pair, not sub_ciphertext alone: sub_ciphertext is md5(ciphertext), and the
same ciphertext can legitimately exist under two hash types -- an NTLM hash and
an MD5 hash are both 32 hex characters.

Column order is (sub_ciphertext, hash_type), not the reverse. Uniqueness,
query plans, probe latency and index size are identical either way -- every
current reader supplies both columns as equality -- but the order decides what
dropping ix_hashes_sub_ciphertext costs. hash_type is the least selective
column in the table (869,228 of 869,232 rows are 1000, three distinct values in
total) while sub_ciphertext is unique, so with hash_type leading a bare
`WHERE sub_ciphertext = ?` would collapse to a full table scan once the old
index is gone. With sub_ciphertext leading, the new index is a leftmost-prefix
superset of the one being dropped, which makes the swap strictly
non-regressive -- including for future or ad-hoc queries the audit below cannot
speak for.

Also drops ix_hashes_sub_ciphertext, which becomes redundant. Audited before
removing it: every reader of sub_ciphertext in the tree filters on hash_type as
well, so all of them are served by the new index --
  hashview/utils/utils.py   the import dedup lookup
  hashview/api/routes.py    the agent-heartbeat cracked-hash ingest
  hashview/api/routes.py    POST /v1/hashes/import
and nothing filters sub_ciphertext on its own today. Dropping it also takes one
130-byte-key index off the insert path
that the batched import exists to speed up. ix_hashes_hash_type is deliberately
left alone: it is a cheap 4-byte key and its other readers were not audited.

Before creating the constraint, checks for pre-existing duplicate pairs, which
would prevent its creation. If any exist this raises RuntimeError listing them,
so the operator can merge them before re-running rather than stranding the
migration mid-apply -- MySQL DDL is non-transactional. Note the losing row's
hashfile_hashes children need repointing, not just deleting, because
hashfile_hashes.hash_id has no foreign key; that is a judgement call for the
operator, which is why this does not attempt it automatically.

Guarded on apply (idempotent under schema drift) using sa.inspect, following
b5c8d9e1f2a4.
"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'f3b8c1a7d942'
down_revision = 'a8c4d2e1f5b3'
branch_labels = None
depends_on = None

_UQ_NAME = 'uq_hashes_sub_ciphertext_hash_type'
_OLD_INDEX = 'ix_hashes_sub_ciphertext'
_COLUMNS = ['sub_ciphertext', 'hash_type']


def _existing_unique_name(insp):
    """Name of an existing unique constraint/index on the pair, or None."""
    for constraint in insp.get_unique_constraints('hashes'):
        if set(constraint['column_names']) == set(_COLUMNS):
            return constraint['name'] or _UQ_NAME
    # MySQL surfaces a unique constraint through get_indexes as well.
    for index in insp.get_indexes('hashes'):
        if index.get('unique') and list(index['column_names']) == _COLUMNS:
            return index['name']
    return None


def upgrade():
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if 'hashes' not in insp.get_table_names():
        return  # Table absent; nothing to do.

    if _existing_unique_name(insp) is None:
        dup_rows = bind.execute(sa.text(
            'SELECT hash_type, sub_ciphertext, COUNT(*) AS cnt FROM hashes '
            'GROUP BY hash_type, sub_ciphertext HAVING COUNT(*) > 1 LIMIT 20'
        )).fetchall()
        if dup_rows:
            pairs = [f'(hash_type={row[0]}, sub_ciphertext={row[1]}, rows={row[2]})'
                     for row in dup_rows]
            raise RuntimeError(
                'Cannot add unique constraint to hashes (hash_type, sub_ciphertext): '
                f'duplicate pairs exist: {pairs} (up to 20 shown). Merge them before '
                're-running this migration, repointing any hashfile_hashes.hash_id '
                'rows that reference the discarded hash -- that column has no foreign '
                'key, so deleting a duplicate hash silently orphans its links.'
            )

        # batch_alter_table: SQLite has no ALTER TABLE ADD CONSTRAINT, so
        # op.create_unique_constraint() raises NotImplementedError there outside
        # batch mode. Batch mode is a passthrough on MySQL and a copy-and-move
        # rebuild on SQLite -- same pattern as b5c8d9e1f2a4.
        with op.batch_alter_table('hashes') as batch_op:
            batch_op.create_unique_constraint(_UQ_NAME, _COLUMNS)

    # Only now that the composite index exists is the single-column one
    # redundant, so this order never leaves the table without an index on
    # sub_ciphertext.
    insp = sa.inspect(bind)
    if any(index['name'] == _OLD_INDEX for index in insp.get_indexes('hashes')):
        op.drop_index(_OLD_INDEX, table_name='hashes')


def downgrade():
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if 'hashes' not in insp.get_table_names():
        return

    # Restore the single-column index first, so the table is never left without
    # an index on sub_ciphertext while the composite one is being dropped.
    if not any(index['name'] == _OLD_INDEX for index in insp.get_indexes('hashes')):
        op.create_index(_OLD_INDEX, 'hashes', ['sub_ciphertext'])

    name = _existing_unique_name(sa.inspect(bind))
    if name:
        with op.batch_alter_table('hashes') as batch_op:
            batch_op.drop_constraint(name, type_='unique')
