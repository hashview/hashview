"""add agent timeout setting + offline-notified flag

Revision ID: c8b3f0a14d27
Revises: d4e7a1b9c602
Create Date: 2026-06-29 00:00:00.000000

Makes the agent-offline cutoff configurable and supports one-shot offline /
recovery admin alerts:
- ``settings.agent_timeout_minutes`` — minutes to wait for an agent check-in
  before it's considered offline. NOT NULL, ``server_default`` of 60 so existing
  rows keep the previously-hardcoded 1-hour cutoff.
- ``agents.offline_notified`` — whether the "agent offline" admin alert has
  already been sent (reset on recovery). NOT NULL, ``server_default`` of 0.

``batch_alter_table`` keeps this SQLite-safe for the migration-smoke test.
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c8b3f0a14d27'
down_revision = 'd4e7a1b9c602'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('settings') as batch_op:
        batch_op.add_column(sa.Column('agent_timeout_minutes', sa.Integer(), nullable=False, server_default=sa.text('60')))

    with op.batch_alter_table('agents') as batch_op:
        batch_op.add_column(sa.Column('offline_notified', sa.Boolean(), nullable=False, server_default=sa.text('0')))


def downgrade():
    with op.batch_alter_table('agents') as batch_op:
        batch_op.drop_column('offline_notified')

    with op.batch_alter_table('settings') as batch_op:
        batch_op.drop_column('agent_timeout_minutes')
