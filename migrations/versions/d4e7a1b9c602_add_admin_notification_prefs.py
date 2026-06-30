"""add administrative-notification preferences

Revision ID: d4e7a1b9c602
Revises: a3f7c1e29b84
Create Date: 2026-06-29 00:00:00.000000

Administrative notifications (agent-error alerts via notify_admins) become
opt-in per admin, with per-channel selection, plus a Slack room for admin
messages:
- ``users.admin_notifications_enabled`` + ``users.admin_notify_email`` /
  ``admin_notify_pushover`` / ``admin_notify_slack`` (per-admin opt-in + channels),
- ``settings.slack_admin_channel`` (the shared room admin Slack alerts post to).

Admins receive these by default on every channel: all four flags are NOT NULL
with a ``server_default`` of 1, so existing rows backfill to "opted in, all
channels on". (Slack only actually sends when Slack is enabled instance-wide and
Settings.slack_admin_channel is set — see notify_admins; the pref defaulting on
just pre-checks the box.) The flags exist on every user but only ``admin=True``
users are notified. ``batch_alter_table`` keeps this SQLite-safe for the
migration-smoke test.
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd4e7a1b9c602'
down_revision = 'a3f7c1e29b84'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('users') as batch_op:
        batch_op.add_column(sa.Column('admin_notifications_enabled', sa.Boolean(), nullable=False, server_default=sa.text('1')))
        batch_op.add_column(sa.Column('admin_notify_email', sa.Boolean(), nullable=False, server_default=sa.text('1')))
        batch_op.add_column(sa.Column('admin_notify_pushover', sa.Boolean(), nullable=False, server_default=sa.text('1')))
        batch_op.add_column(sa.Column('admin_notify_slack', sa.Boolean(), nullable=False, server_default=sa.text('1')))

    with op.batch_alter_table('settings') as batch_op:
        batch_op.add_column(sa.Column('slack_admin_channel', sa.String(length=255), nullable=True))


def downgrade():
    with op.batch_alter_table('settings') as batch_op:
        batch_op.drop_column('slack_admin_channel')

    with op.batch_alter_table('users') as batch_op:
        batch_op.drop_column('admin_notify_slack')
        batch_op.drop_column('admin_notify_pushover')
        batch_op.drop_column('admin_notify_email')
        batch_op.drop_column('admin_notifications_enabled')
