"""add users.theme column

Revision ID: d4e7a1c9f2b8
Revises: c8b3f0a14d27
Create Date: 2026-07-21 00:00:00.000000

Adds a per-user theme preference. Additive DDL only; existing rows backfill to
the server-default 'auto' (follow the OS color-scheme).
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'd4e7a1c9f2b8'
down_revision = 'c8b3f0a14d27'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        'users',
        sa.Column('theme', sa.String(length=16), nullable=False,
                  server_default='auto'),
    )


def downgrade():
    op.drop_column('users', 'theme')
