"""add job_tasks.ended_at

Revision ID: b3d9f1c47a25
Revises: e9f4c2a70b18
Create Date: 2026-09-21 19:10:00.000000

When a JobTasks row stopped is not recorded anywhere. It has a started_at, and
its status eventually becomes terminal, but the moment of that transition is
lost -- so a finished chunk tells you when it began and nothing else.

That gap is why a job's runtime can only be measured as wall-clock since
Jobs.started_at today. With both ends recorded, the time a job was ACTIVELY
worked is the measure of the union of its rows' [started_at, ended_at]
intervals: overlapping chunks collapse into one interval instead of being
counted twice, and a stretch where a higher-priority job held the whole fleet is
covered by no interval at all and so costs nothing. Neither a sum (double-counts
parallel chunks) nor wall-clock (counts starvation) gets that right.

Nothing reads the column yet. This records the value so the history exists when
something does -- a column added later can only ever describe rows written after
it.

Additive and nullable: every existing row lands on NULL, which is the honest
answer for a row that finished before this shipped. Guarded on apply, mirroring
e5d1c7b3a904, so re-running against a database that already has the column is a
no-op rather than a duplicate-column abort.
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'b3d9f1c47a25'
down_revision = 'e9f4c2a70b18'
branch_labels = None
depends_on = None

_TABLE = 'job_tasks'
_COLUMN = 'ended_at'


def _has_column(table, column):
    return any(c['name'] == column for c in sa.inspect(op.get_bind()).get_columns(table))


def upgrade():
    if not _has_column(_TABLE, _COLUMN):
        op.add_column(_TABLE, sa.Column(_COLUMN, sa.DateTime(), nullable=True))


def downgrade():
    if _has_column(_TABLE, _COLUMN):
        op.drop_column(_TABLE, _COLUMN)
