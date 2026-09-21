"""widen tasks.hc_mask to VARCHAR(255)

Revision ID: 8662da4377b9
Revises: e9f4c2a70b18
Create Date: 2026-09-21 00:00:00.000000

Widens tasks.hc_mask from VARCHAR(50) to VARCHAR(255), matching
job_tasks.chunk_mask (already 255, per its own comment).

50 was too tight for the one attack mode where a full mask is actually
required: hashcat modes 27000/27100 (NetNTLMv1/v2 (NT)) crack the captured
NT hash itself, so hashcat forces the "password" to be exactly 32
characters. A full 32-position mask is 64 characters ('?h' x 32), which
TasksForm's db_length validator -- derived straight from this column --
rejected outright with "Field cannot be longer than 50 characters." before
it ever reached hashcat. No mask-attack task against 27000/27100 could be
created through the UI.

The form side is not updated alongside this: hashview/utils/form_limits.py
derives every validator and every rendered maxlength from the column
itself, so the task Add/Edit forms pick up 255 from this migration with no
code change.

Guarded on apply (idempotent under schema drift) and batched rather than a
bare alter_column, following a4c9e7b21f60 / f2a6c9d41b78: SQLite has no
ALTER COLUMN ... TYPE, and the unit tests run on SQLite.

Note on downgrade: narrowing back to 50 after longer masks exist will be
rejected by MySQL in strict mode rather than silently truncating task
records, which is the behaviour to want here.
"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '8662da4377b9'
down_revision = 'e9f4c2a70b18'
branch_labels = None
depends_on = None

_TARGET_LENGTH = 255
_PREVIOUS_LENGTH = 50


def _mask_length(insp):
    """Current VARCHAR length of tasks.hc_mask, or None if absent."""
    if 'tasks' not in insp.get_table_names():
        return None
    for col in insp.get_columns('tasks'):
        if col['name'] == 'hc_mask':
            return getattr(col['type'], 'length', None)
    return None


def _resize(target):
    """Alter tasks.hc_mask to ``target`` chars, only when it is not already there."""
    insp = sa.inspect(op.get_bind())
    length = _mask_length(insp)
    if length is None or length == target:
        return
    with op.batch_alter_table('tasks') as batch:
        batch.alter_column(
            'hc_mask',
            type_=sa.String(length=target),
            existing_type=sa.String(length=length),
            existing_nullable=True,
        )


def upgrade():
    _resize(_TARGET_LENGTH)


def downgrade():
    _resize(_PREVIOUS_LENGTH)
