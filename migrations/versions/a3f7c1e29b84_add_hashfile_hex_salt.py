"""add hashfile hex_salt option

Revision ID: a3f7c1e29b84
Revises: dae1c3ac81e6
Create Date: 2026-06-26 00:00:00.000000

Adds ``hashfiles.hex_salt`` -- a per-hashfile flag marking that the supplied
hashes' salts are hex-encoded. When set, the job-creation import validates that
each salted line carries a hex salt and ``build_hashcat_command`` appends
``--hex-salt`` (only for the colon-delimited hash_only / user_hash formats).

NOT NULL with a ``server_default`` of 0 so existing hashfile rows backfill to
"plain salts"; fresh rows rely on the model ``default=False``.
``batch_alter_table`` keeps this SQLite-safe for the migration-smoke test.
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a3f7c1e29b84'
down_revision = 'dae1c3ac81e6'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('hashfiles') as batch_op:
        batch_op.add_column(sa.Column('hex_salt', sa.Boolean(), nullable=False, server_default=sa.text('0')))


def downgrade():
    with op.batch_alter_table('hashfiles') as batch_op:
        batch_op.drop_column('hex_salt')
