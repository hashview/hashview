"""empty message

Revision ID: 0fa1e1dc4069
Revises: b4a9f18259b9
Create Date: 2022-10-03 16:11:12.708438

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '0fa1e1dc4069'
down_revision = 'b4a9f18259b9'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('task_queues')
    op.drop_constraint('hashfile_hashes_ibfk_2', 'hashfile_hashes', type_='foreignkey')
    op.drop_constraint('hashfile_hashes_ibfk_1', 'hashfile_hashes', type_='foreignkey')
    op.drop_constraint('hashfiles_ibfk_1', 'hashfiles', type_='foreignkey')
    op.drop_constraint('job_tasks_ibfk_2', 'job_tasks', type_='foreignkey')
    op.drop_constraint('job_tasks_ibfk_1', 'job_tasks', type_='foreignkey')
    op.add_column('settings', sa.Column('max_runtime_jobs', sa.Integer(), nullable=True))
    op.add_column('settings', sa.Column('max_runtime_tasks', sa.Integer(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('settings', 'max_runtime_tasks')
    op.drop_column('settings', 'max_runtime_jobs')
    op.create_foreign_key('job_tasks_ibfk_1', 'job_tasks', 'jobs', ['job_id'], ['id'])
    op.create_foreign_key('job_tasks_ibfk_2', 'job_tasks', 'tasks', ['task_id'], ['id'])
    op.create_foreign_key('hashfiles_ibfk_1', 'hashfiles', 'customers', ['customer_id'], ['id'])
    op.create_foreign_key('hashfile_hashes_ibfk_1', 'hashfile_hashes', 'hashes', ['hash_id'], ['id'])
    op.create_foreign_key('hashfile_hashes_ibfk_2', 'hashfile_hashes', 'hashfiles', ['hashfile_id'], ['id'])
    op.create_table('task_queues',
    sa.Column('id', mysql.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('last_updated', mysql.DATETIME(), nullable=False),
    sa.Column('status', mysql.VARCHAR(length=20), nullable=False),
    sa.Column('command', mysql.VARCHAR(length=256), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    mysql_collate='utf8mb4_0900_ai_ci',
    mysql_default_charset='utf8mb4',
    mysql_engine='InnoDB'
    )
    # ### end Alembic commands ###
