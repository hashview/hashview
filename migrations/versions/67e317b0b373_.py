"""empty message

Revision ID: 67e317b0b373
Revises: c342cd4bbbdf
Create Date: 2022-10-03 17:17:47.009502

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '67e317b0b373'
down_revision = 'c342cd4bbbdf'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('job_tasks', 'ended_at')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('job_tasks', sa.Column('ended_at', mysql.DATETIME(), nullable=True))
    # ### end Alembic commands ###
