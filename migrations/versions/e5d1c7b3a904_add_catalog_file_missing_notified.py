"""add rules.file_missing_notified and wordlists.file_missing_notified

Revision ID: e5d1c7b3a904
Revises: f3b8c1a7d942
Create Date: 2026-09-11 00:00:00.000000

One-shot latch for the "catalog file is gone from disk" admin alert (issue
#383), mirroring agents.offline_notified. It records whether the admins have
been TOLD, not whether the file is currently there -- that is computed per
request by utils.rule_file_missing / wordlist_file_missing and never stored.

Additive DDL only. Existing rows land on 0, so the first CATALOG_HEALTH sweep
after the upgrade reports every already-stale row in one aggregated alert.
That is intended: it is the "tell me what is already broken" report.

Note the model default (False) and the server default (0) AGREE here. That is
deliberate, and unlike Settings.passwords_decoded, where they differ on purpose
so fresh installs skip a backfill that existing ones must run. A new row has
genuinely never been alerted on, whether the install is fresh or not.

Guarded on apply (idempotent under schema drift) so a database that already has
the columns doesn't abort with a duplicate-column error. Mirrors the guard
pattern in the squash delta (c8b3f0a14d27).
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'e5d1c7b3a904'
down_revision = 'f3b8c1a7d942'
branch_labels = None
depends_on = None

_TABLES = ('rules', 'wordlists')
_COLUMN = 'file_missing_notified'


def _has_column(table, column):
    return any(c['name'] == column for c in sa.inspect(op.get_bind()).get_columns(table))


def upgrade():
    for table in _TABLES:
        if not _has_column(table, _COLUMN):
            op.add_column(
                table,
                sa.Column(_COLUMN, sa.Boolean(), nullable=False,
                          server_default=sa.text('0')),
            )


def downgrade():
    for table in reversed(_TABLES):
        if _has_column(table, _COLUMN):
            op.drop_column(table, _COLUMN)
