"""add job_task_ledger, job_tasks.ledger_id and job_tasks.chunk_keyspace

Revision ID: c3f8a1d47e29
Revises: b7e2d4f91a38
Create Date: 2026-09-14 00:00:00.000000

The ledger is the durable record of one ATTACK on a job, and of where its
keyspace stands. JobTasks rows are dispatch receipts; once chunks are issued on
demand the set of them for a task changes over the life of a run, so everything
previously answered by counting or scanning those rows -- how many attacks a job
has, what order they are in, how far along it is, whether it is finished -- needs
somewhere stable to live.

One row per ASSIGNMENT, not per (job_id, task_id): jobs_assign_task deliberately
permits a dynamic-wordlist task to be assigned to one job more than once, so
(job_id, task_id) is not unique over attacks. (job_id, position) is, and position
is also what replaces the min(JobTasks.id) dispatch ordering -- which stops being
usable once rows are minted lazily, because a task whose first row appears an
hour into a run gets a HIGHER min id than one queued at the start.

Additive DDL only, and deliberately no data migration. Existing job_tasks rows
land on ledger_id NULL, which is the marker for "queued by a pre-ledger server";
those keep dispatching by the old ordering until their job is re-queued. In
particular this must NOT rewrite `command` or `chunk_total` on an existing row:
a row's command already encodes the temp-file key its agent will look for, and
changing the flag without rebuilding the command would silently point the two
halves at different files.

No foreign keys and no altered columns, matching the house style for
job_tasks.job_id/task_id (indexed bare integers; their FKs were dropped by
0fa1e1dc4069) and keeping the chain runnable against SQLite, which
tests/unit/test_migration_drift_idempotency.py drives it over.

Guarded on apply (idempotent under schema drift) so a database that already has
these doesn't abort with a duplicate error -- MySQL DDL is non-transactional, so
an unguarded failure here would strand the whole upgrade tail.
"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'c3f8a1d47e29'
down_revision = 'b7e2d4f91a38'
branch_labels = None
depends_on = None

_JOB_TASK_COLUMNS = (
    ('ledger_id', lambda: sa.Column('ledger_id', sa.Integer(), nullable=True)),
    ('chunk_keyspace', lambda: sa.Column('chunk_keyspace', sa.BigInteger(), nullable=True)),
)


def _inspector():
    return sa.inspect(op.get_bind())


def _has_table(table):
    return table in _inspector().get_table_names()


def _has_column(table, column):
    return any(c['name'] == column for c in _inspector().get_columns(table))


def _has_index(table, name):
    return any(i['name'] == name for i in _inspector().get_indexes(table))


def upgrade():
    if not _has_table('job_task_ledger'):
        op.create_table(
            'job_task_ledger',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('job_id', sa.Integer(), nullable=False),
            sa.Column('task_id', sa.Integer(), nullable=False),
            sa.Column('position', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('state', sa.String(length=16), nullable=False,
                      server_default='Pending'),
            sa.Column('keyspace', sa.BigInteger(), nullable=True),
            sa.Column('keyspace_source', sa.String(length=10), nullable=True),
            sa.Column('keyspace_pos', sa.BigInteger(), nullable=False, server_default='0'),
            sa.Column('amp', sa.BigInteger(), nullable=False, server_default='1'),
            sa.Column('min_slice', sa.BigInteger(), nullable=False, server_default='1'),
            sa.Column('issued_count', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('chunkable', sa.Boolean(), nullable=False, server_default=sa.text('0')),
            sa.Column('hc_major', sa.SmallInteger(), nullable=True),
            sa.Column('measured_by', sa.Integer(), nullable=True),
            sa.Column('measure_expires', sa.DateTime(), nullable=True),
            sa.Column('fingerprint', sa.String(length=64), nullable=True),
            sa.Column('closed_reason', sa.String(length=32), nullable=True),
            sa.Column('rev', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('updated_at', sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint('id'),
            sa.UniqueConstraint('job_id', 'position', name='uix_ledger_job_position'),
        )
        op.create_index('ix_job_task_ledger_job_id', 'job_task_ledger', ['job_id'])
        op.create_index('ix_job_task_ledger_task_id', 'job_task_ledger', ['task_id'])

    for name, column in _JOB_TASK_COLUMNS:
        if not _has_column('job_tasks', name):
            op.add_column('job_tasks', column())
    if not _has_index('job_tasks', 'ix_job_tasks_ledger_id'):
        op.create_index('ix_job_tasks_ledger_id', 'job_tasks', ['ledger_id'])


def downgrade():
    if _has_index('job_tasks', 'ix_job_tasks_ledger_id'):
        op.drop_index('ix_job_tasks_ledger_id', table_name='job_tasks')
    for name, _ in reversed(_JOB_TASK_COLUMNS):
        if _has_column('job_tasks', name):
            op.drop_column('job_tasks', name)
    if _has_table('job_task_ledger'):
        op.drop_table('job_task_ledger')
