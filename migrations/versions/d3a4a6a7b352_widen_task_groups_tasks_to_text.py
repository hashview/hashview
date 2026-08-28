"""widen task_groups.tasks to TEXT

Revision ID: d3a4a6a7b352
Revises: f1a2b3c4d5e6
Create Date: 2026-08-28 00:00:00.000000

Widens task_groups.tasks from VARCHAR(1024) to TEXT. The column holds a
JSON-serialized list of task IDs and may exceed 1024 chars when bulk-creating
task groups (e.g. 40+ four-digit task IDs = ~240+ chars for JSON, plus
delimiters and quotes). Changing to TEXT avoids a silent truncation hazard.

Guarded on apply (idempotent under schema drift) so a database that already has
the column as TEXT or a different size doesn't abort. Uses sa.inspect to
check the live column type before altering, following the pattern established
in commit 706bfeb for drift-safe migrations.
"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'd3a4a6a7b352'
down_revision = 'f1a2b3c4d5e6'
branch_labels = None
depends_on = None


def upgrade():
    # Inspect the live column to see if it's already TEXT or needs conversion.
    # This handles schema drift: the column may be String(256) (from models.py
    # create_all), String(1024) (from the initial migration), or already TEXT
    # (from a prior run).
    insp = sa.inspect(op.get_bind())
    if 'task_groups' in insp.get_table_names():
        for col in insp.get_columns('task_groups'):
            if col['name'] == 'tasks':
                # Check if it's already TEXT. String types report as VARCHAR in
                # inspection, but Text types report as TEXT, LONGTEXT, etc.
                col_type_str = str(col['type'])
                if col_type_str.upper() not in ('TEXT', 'LONGTEXT', 'MEDIUMTEXT'):
                    # It's a String type, alter to Text
                    op.alter_column(
                        'task_groups',
                        'tasks',
                        type_=sa.Text(),
                        existing_type=sa.String(length=1024),
                        existing_nullable=False,
                    )
                break


def downgrade():
    # On downgrade, revert to String(1024) to match the existing initial
    # migration (d6a54eeeaeb9_initial_migration.py:112).
    insp = sa.inspect(op.get_bind())
    if 'task_groups' in insp.get_table_names():
        for col in insp.get_columns('task_groups'):
            if col['name'] == 'tasks':
                col_type_str = str(col['type'])
                if col_type_str.upper() in ('TEXT', 'LONGTEXT', 'MEDIUMTEXT'):
                    # It's a TEXT type, revert to String(1024)
                    op.alter_column(
                        'task_groups',
                        'tasks',
                        type_=sa.String(length=1024),
                        existing_type=sa.Text(),
                        existing_nullable=False,
                    )
                break
