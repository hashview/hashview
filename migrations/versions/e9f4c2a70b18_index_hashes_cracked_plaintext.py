"""add index on hashes (cracked, plaintext)

Revision ID: e9f4c2a70b18
Revises: c7e4b8a15d60
Create Date: 2026-09-16 00:00:00.000000

The dynamic "recovered passwords" wordlists are built from

    SELECT DISTINCT plaintext FROM hashes WHERE cracked = true

and no index covered that shape. The existing (cracked, recovered_at) and
(cracked, task_id) indexes narrow to the cracked rows but say nothing about
plaintext, so MySQL filtered on one of them and then built a temporary table to
do the DISTINCT -- on disk, since tmp_table_size defaults to 16 MB. Nothing is
sent to the client until that table is complete.

On an installation with 6.0M cracked rows / 5.9M distinct plaintexts that took
around 50 seconds before the first row moved, and net_write_timeout (default
60s) closed the connection mid-fetch. The agent's wordlist download failed with
"2013 Lost connection to MySQL server during query", which looks like a dead
database and is not one.

(cracked, plaintext) covers the query outright: the leading column selects the
cracked rows and the second supplies plaintext already ordered, so the DISTINCT
is a covering index scan with no temporary table, and rows start flowing at
once. Measured on a 2M-row / 1.9M-distinct copy of this table:

    without the index   10.7s   Extra: Using temporary
    with the index       1.3s   Extra: Using index

It is also what makes the batched generation in
utils.iter_distinct_recovered_plaintexts worth doing rather than harmful: a
50,000-row keyset batch is ~0.05s against this index and ~10.8s without it,
because every batch would otherwise rebuild the whole temporary table.

Guarded on apply so a database that already has the index (or lacks the table)
is left alone, following the pattern in the other additive migrations here.
"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'e9f4c2a70b18'
down_revision = 'c7e4b8a15d60'
branch_labels = None
depends_on = None

_INDEX = 'ix_hashes_cracked_plaintext'
_COLUMNS = ['cracked', 'plaintext']


def _has_index(insp):
    return any(index['name'] == _INDEX for index in insp.get_indexes('hashes'))


def upgrade():
    insp = sa.inspect(op.get_bind())
    if 'hashes' not in insp.get_table_names() or _has_index(insp):
        return
    op.create_index(_INDEX, 'hashes', _COLUMNS)


def downgrade():
    insp = sa.inspect(op.get_bind())
    if 'hashes' in insp.get_table_names() and _has_index(insp):
        op.drop_index(_INDEX, table_name='hashes')
