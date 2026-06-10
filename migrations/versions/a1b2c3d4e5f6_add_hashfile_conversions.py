"""add_hashfile_conversions

Revision ID: a1b2c3d4e5f6
Revises: d4e8b1f3a297
Create Date: 2026-06-09 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a1b2c3d4e5f6'
down_revision = 'd4e8b1f3a297'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'hashfile_conversions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('hashfile_id', sa.Integer(), nullable=False),
        sa.Column('source_type', sa.String(length=20), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('source_path', sa.Text(), nullable=False),
        sa.Column('system_path', sa.Text(), nullable=True),
        sa.Column('conversion_error', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['hashfile_id'], ['hashfiles.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('hashfile_id'),
    )


def downgrade():
    op.drop_table('hashfile_conversions')
