"""add wordlist providers (external wordlist generation services)

Revision ID: f1a2b3c4d5e6
Revises: c8b3f0a14d27
Create Date: 2026-07-21 00:00:00.000000

Additive, guarded DDL (MySQL DDL is non-transactional, so each change is guarded
so a drifted / partially-applied schema still upgrades cleanly):
  * new table ``wordlist_providers``
  * new nullable column ``wordlists.provider_id`` (FK -> wordlist_providers.id)
  * new nullable column ``jobs.provider_input``

No row-data migration: a provider's backing (DYNAMIC) wordlist row is created by
the Settings route when the provider is registered, not here.
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f1a2b3c4d5e6'
down_revision = 'd4e7a1c9f2b8'
branch_labels = None
depends_on = None


def _insp():
    return sa.inspect(op.get_bind())


def _has_table(table):
    return _insp().has_table(table)


def _has_column(table, column):
    return any(c['name'] == column for c in _insp().get_columns(table))


def upgrade():
    if not _has_table('wordlist_providers'):
        op.create_table(
            'wordlist_providers',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('name', sa.String(length=128), nullable=False),
            sa.Column('description', sa.String(length=512), nullable=True),
            sa.Column('base_url', sa.String(length=512), nullable=False),
            sa.Column('auth_type', sa.String(length=10), nullable=False, server_default='bearer'),
            sa.Column('username', sa.String(length=255), nullable=True),
            sa.Column('provider_secret', sa.String(length=512), nullable=True),
            sa.Column('verify_tls', sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column('owner_id', sa.Integer(), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(['owner_id'], ['users.id']),
            sa.PrimaryKeyConstraint('id'),
            sa.UniqueConstraint('name'),
        )

    if not _has_column('wordlists', 'provider_id'):
        op.add_column('wordlists', sa.Column('provider_id', sa.Integer(), nullable=True))
        # Named FK so downgrade can drop it deterministically. Wrapped: SQLite (and
        # some drifted setups) can't ALTER-add a FK; the column itself is what the
        # app needs, so a failed constraint add must not strand the column.
        try:
            op.create_foreign_key(
                'fk_wordlists_provider_id', 'wordlists', 'wordlist_providers',
                ['provider_id'], ['id'])
        except Exception:  # noqa: BLE001
            pass

    if not _has_column('jobs', 'provider_input'):
        op.add_column('jobs', sa.Column('provider_input', sa.String(length=2048), nullable=True))


def downgrade():
    if _has_column('jobs', 'provider_input'):
        op.drop_column('jobs', 'provider_input')

    if _has_column('wordlists', 'provider_id'):
        try:
            op.drop_constraint('fk_wordlists_provider_id', 'wordlists', type_='foreignkey')
        except Exception:  # noqa: BLE001
            pass
        op.drop_column('wordlists', 'provider_id')

    if _has_table('wordlist_providers'):
        op.drop_table('wordlist_providers')
