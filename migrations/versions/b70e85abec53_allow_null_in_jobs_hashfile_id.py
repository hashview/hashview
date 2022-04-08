"""Allow null in the hashfile_id column in the jobs table

Revision ID: b70e85abec53
Revises: 05ef92815fbd
Create Date: 2020-12-28 13:40:21.506752

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = 'b70e85abec53'
down_revision = '05ef92815fbd'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('jobs', 'hashfile_id',
               existing_type=mysql.INTEGER(display_width=11),
               nullable=True)
    op.drop_constraint('jobs_ibfk_3', 'jobs', type_='foreignkey')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_foreign_key('jobs_ibfk_3', 'jobs', 'hashfiles', ['hashfile_id'], ['id'])
    op.alter_column('jobs', 'hashfile_id',
               existing_type=mysql.INTEGER(display_width=11),
               nullable=False)
    # ### end Alembic commands ###