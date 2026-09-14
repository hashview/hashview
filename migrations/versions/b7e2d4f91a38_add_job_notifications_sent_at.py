"""add job_notifications.sent_at

Revision ID: b7e2d4f91a38
Revises: a4c9e7b21f60
Create Date: 2026-09-14 00:00:00.000000

Job notifications used to be DELETED as they were delivered, which made a job's
notification setup a one-shot. Two consequences, both bad:

  * a premature or mistaken completion destroyed the configuration permanently,
    with no way to tell it had ever existed; and
  * re-running a job notified nobody, silently, because the rows were gone.

The second is a bug on its own. The first becomes materially more dangerous
once job completion is derived from a keyspace cursor, where a transient state
could otherwise burn the rows.

`sent_at` replaces the delete: NULL means "not yet delivered for the current
run", and queueing a job resets it to NULL. Delivery is gated on a conditional
UPDATE of this column (... WHERE id = :id AND sent_at IS NULL), so two agents
completing a job's last two chunks at the same moment cannot double-send.

Additive DDL only, nullable with no server default. Existing rows land on NULL,
which reads as "not yet sent" -- correct, because every row that HAD been sent
was already deleted by the code this replaces. There is nothing to backfill.

Guarded on apply (idempotent under schema drift) so a database that already has
the column doesn't abort with a duplicate-column error, mirroring
e5d1c7b3a904 and the squash delta c8b3f0a14d27. MySQL DDL is non-transactional,
so an unguarded failure here would strand the whole upgrade tail.
"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'b7e2d4f91a38'
down_revision = 'a4c9e7b21f60'
branch_labels = None
depends_on = None

_TABLE = 'job_notifications'
_COLUMN = 'sent_at'


def _has_column(table, column):
    return any(c['name'] == column for c in sa.inspect(op.get_bind()).get_columns(table))


def upgrade():
    if not _has_column(_TABLE, _COLUMN):
        op.add_column(_TABLE, sa.Column(_COLUMN, sa.DateTime(), nullable=True))


def downgrade():
    if _has_column(_TABLE, _COLUMN):
        op.drop_column(_TABLE, _COLUMN)
