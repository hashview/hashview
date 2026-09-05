"""add unique constraint on task_groups.name

Revision ID: b5c8d9e1f2a4
Revises: d3a4a6a7b352
Create Date: 2026-09-05 00:00:00.000000

Adds a unique constraint on task_groups.name to prevent race conditions in
check-then-act patterns in both the UI and API routes. The application layer
currently queries for duplicate names before inserting, but a concurrent insert
can slip between the check and the commit (TOCTOU). A database-level unique
index closes the race.

Before applying the constraint, checks for pre-existing duplicate names (which
would prevent the constraint creation). If duplicates exist, raises RuntimeError
with a list of them, so the operator can manually rename them before re-running
the migration. MySQL DDL is non-transactional, so a constraint violation would
strand mid-apply otherwise.

Guarded on apply (idempotent under schema drift) using sa.inspect so an already-
constrained column or a table that's absent doesn't cause errors.
"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'b5c8d9e1f2a4'
down_revision = 'd3a4a6a7b352'
branch_labels = None
depends_on = None


def upgrade():
    # Check for pre-existing duplicates before creating the constraint.
    # On a real deployment with actual data, a duplicate-name conflict would
    # strand the migration mid-apply (MySQL DDL is non-transactional).
    insp = sa.inspect(op.get_bind())
    if 'task_groups' not in insp.get_table_names():
        return  # Table absent; nothing to do.

    # Query for duplicates: SELECT name, COUNT(*) FROM task_groups
    # GROUP BY name HAVING COUNT(*) > 1
    bind = op.get_bind()
    dup_rows = bind.execute(sa.text(
        'SELECT name, COUNT(*) as cnt FROM task_groups GROUP BY name HAVING COUNT(*) > 1'
    )).fetchall()

    if dup_rows:
        dup_names = [row[0] for row in dup_rows]
        raise RuntimeError(
            f'Cannot add unique constraint to task_groups.name: '
            f'duplicate names exist: {dup_names}. '
            f'Rename them manually before re-running this migration.'
        )

    # Check if the unique constraint already exists (e.g. schema drift or
    # a prior partial run).
    constraint_exists = False
    for constraint in insp.get_unique_constraints('task_groups'):
        if 'name' in constraint['column_names']:
            constraint_exists = True
            break

    if not constraint_exists:
        op.create_unique_constraint('uq_task_groups_name', 'task_groups', ['name'])


def downgrade():
    # On downgrade, drop the unique constraint if it exists.
    insp = sa.inspect(op.get_bind())
    if 'task_groups' not in insp.get_table_names():
        return

    constraint_exists = False
    constraint_name = None
    for constraint in insp.get_unique_constraints('task_groups'):
        if 'name' in constraint['column_names']:
            constraint_exists = True
            constraint_name = constraint['name']
            break

    if constraint_exists:
        op.drop_constraint(constraint_name, 'task_groups', type_='unique')
