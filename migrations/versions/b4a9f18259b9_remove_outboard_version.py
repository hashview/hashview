"""Remove outboard version

Revision ID: b4a9f18259b9
Revises: 650b7b3a8086
Create Date: 2022-05-24 23:18:24.128766

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = 'b4a9f18259b9'
down_revision = '650b7b3a8086'
branch_labels = None
depends_on = None


def upgrade():
    op.drop_column('settings', 'version')


def downgrade():
    op.add_column('settings', sa.Column('version', mysql.VARCHAR(length=10), nullable=True))
    connection = op.get_bind()
    settings_table = sa.Table('settings')
    with open('VERSION.TXT', 'r') as f:
        hashview_version = f.readline().strip('\n')
    connection.execute(settings_table.update().where(settings_table.c.id == '1').values(version=hashview_version))