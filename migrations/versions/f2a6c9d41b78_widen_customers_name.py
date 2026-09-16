"""widen customers.name to VARCHAR(255)

Revision ID: f2a6c9d41b78
Revises: d8b3e5c02a71
Create Date: 2026-09-15 00:00:00.000000

Widens customers.name from VARCHAR(40) to VARCHAR(255).

40 was the tightest bound on any user-typed name in the app -- shorter than
Jobs.name (50), Tasks.name (100) and Hashfiles.name (256) -- and real customer
names (a legal entity plus an engagement qualifier, say) run past it easily.
Until now nothing stopped an over-long one at the form, so it reached MySQL and
came back as a DataError, i.e. a 500 with the typed name lost.

The column is not indexed, so there is no utf8mb4 key-length ceiling to respect
at 255.

The form side is not updated alongside this: hashview/utils/form_limits.py
derives every validator and every rendered maxlength from the column itself, so
the Add/Edit customer modals and the job wizard's "add new customer" field pick
up 255 from this migration with no code change.

Guarded on apply (idempotent under schema drift) and batched rather than a bare
alter_column, following a4c9e7b21f60: SQLite has no ALTER COLUMN ... TYPE, and
the unit tests run on SQLite.

Note on downgrade: narrowing back to 40 after longer names exist will be
rejected by MySQL in strict mode rather than silently truncating customer
records, which is the behaviour to want here.
"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'f2a6c9d41b78'
down_revision = 'd8b3e5c02a71'
branch_labels = None
depends_on = None

_TARGET_LENGTH = 255
_PREVIOUS_LENGTH = 40


def _name_length(insp):
    """Current VARCHAR length of customers.name, or None if absent."""
    if 'customers' not in insp.get_table_names():
        return None
    for col in insp.get_columns('customers'):
        if col['name'] == 'name':
            return getattr(col['type'], 'length', None)
    return None


def _resize(target):
    """Alter customers.name to ``target`` chars, only when it is not already there."""
    insp = sa.inspect(op.get_bind())
    length = _name_length(insp)
    if length is None or length == target:
        return
    with op.batch_alter_table('customers') as batch:
        batch.alter_column(
            'name',
            type_=sa.String(length=target),
            existing_type=sa.String(length=length),
            existing_nullable=False,
        )


def upgrade():
    _resize(_TARGET_LENGTH)


def downgrade():
    _resize(_PREVIOUS_LENGTH)
