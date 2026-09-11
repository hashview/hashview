"""widen job_tasks.chunk_mask to VARCHAR(255)

Revision ID: a4c9e7b21f60
Revises: f3b8c1a7d942
Create Date: 2026-09-11 00:00:00.000000

Widens job_tasks.chunk_mask from VARCHAR(64) to VARCHAR(255).

This is defensive, not a live bug: a chunk sub-mask is never longer than the
task mask it came from (chunking._expand_mask replaces a '?x' charset position
with a 1- or 2-character literal), and Tasks.hc_mask is VARCHAR(50), so today
len(chunk_mask) <= 50 < 64 always holds.

The hazard is that this is an undocumented coupling between two column widths
in different tables with only 14 characters of headroom. Widening hc_mask -- a
plausible future request, since the form has no length validator -- would make
the chunker start writing TRUNCATED sub-masks, and a truncated mask is still a
VALID mask: nothing would error, the wrong keyspace would just be cracked.
255 puts the coupling comfortably out of reach. A unit test pins the invariant.

Guarded on apply (idempotent under schema drift) following the pattern in
d3a4a6a7b352: inspect the live column and alter only when it is narrower.
"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'a4c9e7b21f60'
down_revision = 'f3b8c1a7d942'
branch_labels = None
depends_on = None

_TARGET_LENGTH = 255
_PREVIOUS_LENGTH = 64


def _chunk_mask_length(insp):
    """Current VARCHAR length of job_tasks.chunk_mask, or None if absent."""
    if 'job_tasks' not in insp.get_table_names():
        return None
    for col in insp.get_columns('job_tasks'):
        if col['name'] == 'chunk_mask':
            return getattr(col['type'], 'length', None)
    return None


def _resize(target):
    """Alter chunk_mask to ``target`` chars, only when it is not already there.

    batch_alter_table rather than a bare alter_column: SQLite has no
    ALTER COLUMN ... TYPE, so a plain alter_column raises there (the unit tests
    run on SQLite). Batch mode recreates the table on SQLite and emits an
    ordinary ALTER on MySQL.
    """
    insp = sa.inspect(op.get_bind())
    length = _chunk_mask_length(insp)
    if length is None or length == target:
        return
    with op.batch_alter_table('job_tasks') as batch:
        batch.alter_column(
            'chunk_mask',
            type_=sa.String(length=target),
            existing_type=sa.String(length=length),
            existing_nullable=True,
        )


def upgrade():
    _resize(_TARGET_LENGTH)


def downgrade():
    _resize(_PREVIOUS_LENGTH)
