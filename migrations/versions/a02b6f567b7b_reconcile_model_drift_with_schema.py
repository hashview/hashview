"""reconcile model drift with schema

Revision ID: a02b6f567b7b
Revises: 8027c2d2b40a
Create Date: 2026-05-27 18:16:35.389246

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'a02b6f567b7b'
down_revision = '8027c2d2b40a'
branch_labels = None
depends_on = None


def _has_column(table, column):
    """True if ``table`` already has ``column`` in the live database.

    These adds are guarded because real-world databases drift: a column this
    migration means to introduce may already exist (e.g. built model-first by
    an earlier deploy), and a blind ``ADD COLUMN`` then aborts the whole
    upgrade with 'Duplicate column name' -- MySQL DDL is non-transactional, so
    the failure strands every later change too. Skipping already-present
    columns makes the upgrade safe to (re-)run on a drifted schema.
    """
    return any(c['name'] == column for c in sa.inspect(op.get_bind()).get_columns(table))


# (table, column-factory) pairs. limit_recovered carries a server_default so
# the NOT NULL add succeeds against a jobs table that already holds rows.
_ADDS = [
    ('hashes', lambda: sa.Column('recovered_at', sa.DateTime(), nullable=True)),
    ('hashes', lambda: sa.Column('task_id', sa.Integer(), nullable=True)),
    ('hashes', lambda: sa.Column('recovered_by', sa.Integer(), nullable=True)),
    ('jobs', lambda: sa.Column('limit_recovered', sa.Boolean(), nullable=False,
                               server_default=sa.text('0'))),
    ('tasks', lambda: sa.Column('wl_id_2', sa.Integer(), nullable=True)),
    ('tasks', lambda: sa.Column('j_rule', sa.String(length=25), nullable=True)),
    ('tasks', lambda: sa.Column('k_rule', sa.String(length=25), nullable=True)),
]


def upgrade():
    for table, make_col in _ADDS:
        if not _has_column(table, make_col().name):
            op.add_column(table, make_col())


def downgrade():
    for table, make_col in reversed(_ADDS):
        if _has_column(table, make_col().name):
            op.drop_column(table, make_col().name)
