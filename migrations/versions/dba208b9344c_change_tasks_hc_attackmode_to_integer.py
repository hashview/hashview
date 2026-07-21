"""change tasks.hc_attackmode to Integer

Revision ID: dba208b9344c
Revises: a02b6f567b7b
Create Date: 2026-05-28 04:28:34.490020

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = 'dba208b9344c'
down_revision = 'a02b6f567b7b'
branch_labels = None
depends_on = None


def _hc_attackmode_is_text():
    """True only if tasks.hc_attackmode is still a textual column.

    Guards against re-running the text->int normalization on a database where
    the column is ALREADY integer (schema drift: some deploys built the column
    integer from the start). If it were re-run there, the string-literal WHERE
    clauses would be cast to integers by MySQL -- 'dictionary'/'maskmode' both
    become 0 -- rewriting legitimate mode-0 rows to mode 3. Skipping entirely
    when the column is already integer is a safe no-op.
    """
    for c in sa.inspect(op.get_bind()).get_columns('tasks'):
        if c['name'] == 'hc_attackmode':
            return 'CHAR' in str(c['type']).upper() or 'TEXT' in str(c['type']).upper()
    return False


def upgrade():
    if not _hc_attackmode_is_text():
        return  # already Integer -- nothing to normalize or convert

    # Normalize legacy textual values to their numeric equivalents BEFORE the
    # column type change so MySQL's implicit cast can't silently turn them
    # into 0. Mapping comes from hashview/tasks/forms.py choices.
    op.execute("UPDATE tasks SET hc_attackmode = '0' WHERE hc_attackmode = 'dictionary'")
    op.execute("UPDATE tasks SET hc_attackmode = '1' WHERE hc_attackmode = 'combinator'")
    op.execute("UPDATE tasks SET hc_attackmode = '3' WHERE hc_attackmode IN ('maskmode', 'bruteforce')")

    with op.batch_alter_table('tasks', schema=None) as batch_op:
        batch_op.alter_column('hc_attackmode',
               existing_type=mysql.VARCHAR(length=25),
               type_=sa.Integer(),
               existing_nullable=False)


def downgrade():
    with op.batch_alter_table('tasks', schema=None) as batch_op:
        batch_op.alter_column('hc_attackmode',
               existing_type=sa.Integer(),
               type_=mysql.VARCHAR(length=25),
               existing_nullable=False)
