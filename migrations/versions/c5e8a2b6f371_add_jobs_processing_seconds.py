"""add jobs.processing_seconds and jobs.last_counted_at

Revision ID: c5e8a2b6f371
Revises: b3d9f1c47a25
Create Date: 2026-09-21 20:05:00.000000

Settings.max_runtime_jobs was measured as wall-clock since jobs.started_at,
which counts every hour a job spent waiting for an agent as though it had been
cracking. That is not a corner case, it is the ordinary consequence of
priorities: a higher-priority job takes the whole fleet, the lower-priority one
sits untouched, and it blows a cap it was never given the chance to spend.

processing_seconds is the replacement clock. The JOB_RUNTIME sweep credits each
job one sweep interval at a time, and only while at least one of its tasks is
actually running, so time nobody spent working on the job costs it nothing.
last_counted_at is the guard that stops two sweeps inside one interval crediting
it twice.

Existing rows land on 0 rather than a value derived from started_at. That is
deliberate and it is the safe direction: seeding from wall-clock would re-import
exactly the over-counting this replaces, and on a busy instance it would expire
a batch of long-starved jobs the moment the upgrade finished. A job running
across the upgrade gets its full allowance from here.

Guarded on apply (mirrors e5d1c7b3a904) so re-running against a database that
already has the columns is a no-op rather than a duplicate-column abort.
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'c5e8a2b6f371'
down_revision = 'b3d9f1c47a25'
branch_labels = None
depends_on = None

_TABLE = 'jobs'


def _has_column(table, column):
    return any(c['name'] == column for c in sa.inspect(op.get_bind()).get_columns(table))


def upgrade():
    if not _has_column(_TABLE, 'processing_seconds'):
        op.add_column(_TABLE, sa.Column('processing_seconds', sa.Integer(),
                                        nullable=False, server_default='0'))
    if not _has_column(_TABLE, 'last_counted_at'):
        op.add_column(_TABLE, sa.Column('last_counted_at', sa.DateTime(),
                                        nullable=True))


def downgrade():
    for column in ('last_counted_at', 'processing_seconds'):
        if _has_column(_TABLE, column):
            op.drop_column(_TABLE, column)
