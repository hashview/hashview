"""add indexes on job_tasks and hashes.task_id

Revision ID: a8c4d2e1f5b3
Revises: b5c8d9e1f2a4
Create Date: 2026-09-05 00:00:00.000000

Adds three indexes that close the remaining index gaps in the job wizard and task-level
queries (issue #422):

  ix_job_tasks_job_id         job_tasks(job_id)
      -> job wizard's SELECT * FROM job_tasks WHERE job_id = ? queries.
  ix_job_tasks_task_id        job_tasks(task_id)
      -> job wizard's SELECT * FROM job_tasks WHERE task_id = ? queries.
  ix_hashes_task_id           hashes(task_id)
      -> per-task hash lookups (WHERE task_id = ?) without relying on the composite
         ix_hashes_cracked_task_id, which requires the leading cracked column.

Note: hash_notifications.hash_id and hashes.cracked were already indexed before this
migration (as documented in migrations/versions/f1a2b3c4d5e6_add_perf_indexes.py and
the Hashes.__table_args__ in models.py), so issue #422's claim about those was stale.
This migration only closes the three genuine gaps.

Each index is guarded on apply so it is idempotent under schema drift (a fresh
create_all already builds these from the models).
"""
from alembic import op

# revision identifiers, used by Alembic.
revision = 'a8c4d2e1f5b3'
down_revision = 'b5c8d9e1f2a4'
branch_labels = None
depends_on = None

# (index name, table, [columns]) -- names match the model declarations so a
# model-built (create_all) schema and this migration agree.
_INDEXES = [
    ('ix_job_tasks_job_id', 'job_tasks', ['job_id']),
    ('ix_job_tasks_task_id', 'job_tasks', ['task_id']),
    ('ix_hashes_task_id', 'hashes', ['task_id']),
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
