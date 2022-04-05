"""Add the last_login_utc column to the users table

Revision ID: 650b7b3a8086
Revises: 32e2976dcda0
Create Date: 2022-03-29 11:44:55.977718

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '650b7b3a8086'
down_revision = '32e2976dcda0'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('users', sa.Column('last_login_utc', sa.DateTime(), nullable=True))


def downgrade():
    op.drop_column('users', 'last_login_utc')
