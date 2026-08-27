"""add performance indexes on hashes + hash_notifications

Revision ID: f1a2b3c4d5e6
Revises: b9d3f4a1c2e5
Create Date: 2026-08-26 00:00:00.000000

Adds three indexes that turn hot full-table scans / filesorts on the two largest
tables into bounded index access:

  ix_hashes_cracked_recovered_at  hashes(cracked, recovered_at)
      -> dashboard recovery feed (ORDER BY recovered_at DESC LIMIT) and the
         chart's cracked + recovered_at range COUNTs.
  ix_hashes_cracked_task_id       hashes(cracked, task_id)
      -> per-task recovered counts (filter cracked, GROUP BY task_id) used by
         /tasks and several analytics endpoints.
  ix_hash_notifications_hash_id   hash_notifications(hash_id)
      -> the /jobs per-hashfile "has alert hashes" join
         (hash_notifications.hash_id = hashfile_hashes.hash_id).

Each is a composite/leading-equality index chosen to serve both the equality
filter and the range/group that follows it. Guarded on apply so it is idempotent
under schema drift (a fresh create_all already builds these from the models).
"""
from alembic import op

# revision identifiers, used by Alembic.
revision = 'f1a2b3c4d5e6'
down_revision = 'b9d3f4a1c2e5'
branch_labels = None
depends_on = None

# (index name, table, [columns]) -- names match the model declarations so a
# model-built (create_all) schema and this migration agree.
_INDEXES = [
    ('ix_hashes_cracked_recovered_at', 'hashes', ['cracked', 'recovered_at']),
    ('ix_hashes_cracked_task_id', 'hashes', ['cracked', 'task_id']),
    ('ix_hash_notifications_hash_id', 'hash_notifications', ['hash_id']),
]


def _has_index(table, name):
    import sqlalchemy as sa
    insp = sa.inspect(op.get_bind())
    if table not in insp.get_table_names():
        return True  # table absent -> nothing to create; treat as "present" to skip
    return any(ix['name'] == name for ix in insp.get_indexes(table))


def upgrade():
    for name, table, cols in _INDEXES:
        if not _has_index(table, name):
            op.create_index(name, table, cols, unique=False)


def downgrade():
    for name, table, _cols in reversed(_INDEXES):
        if _has_index(table, name):
            op.drop_index(name, table_name=table)
