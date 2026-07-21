"""add users.theme column

Revision ID: d4e7a1c9f2b8
Revises: c8b3f0a14d27
Create Date: 2026-07-21 00:00:00.000000

Adds a per-user theme preference. Additive DDL only; existing rows backfill to
the server-default 'auto' (follow the OS color-scheme).

Guarded on apply (idempotent under schema drift) so a database that already has
the column -- e.g. re-run after a partial upgrade -- doesn't abort with a
duplicate-column error. Mirrors the guard pattern in the squash delta
(c8b3f0a14d27).
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'd4e7a1c9f2b8'
down_revision = 'c8b3f0a14d27'
branch_labels = None
depends_on = None


def _has_column(table, column):
    return any(c['name'] == column for c in sa.inspect(op.get_bind()).get_columns(table))


def upgrade():
    if not _has_column('users', 'theme'):
        op.add_column(
            'users',
            sa.Column('theme', sa.String(length=16), nullable=False,
                      server_default='auto'),
        )


def downgrade():
    if _has_column('users', 'theme'):
        op.drop_column('users', 'theme')
