"""add settings.catalog_prune_orphans

Revision ID: b6f21d9c4a83
Revises: a4c9e7b21f60
Create Date: 2026-09-14 00:00:00.000000

Arms the CATALOG_HEALTH sweep's orphan prune (issue #494): a rule/wordlist row
whose file is gone, that no task references, and that the admins were already
told about in an EARLIER sweep, is deleted rather than left as permanent debris.

Additive DDL only. Model default and server default AGREE on 1, so an existing
install upgrades into the same behaviour a fresh one gets. That is the right
default because the rows it removes are unusable by construction -- excluded
from new tasks (8ea8c5d), skipped by the agent (5194dab), and 404 on download --
but it is a switch rather than a constant precisely so an operator who wants to
audit the debris by hand can turn it off. It lives here and not in config.conf
because config.conf is baked at image build time.

Guarded on apply (idempotent under schema drift) so a database that already has
the column doesn't abort with a duplicate-column error, mirroring e5d1c7b3a904.
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'b6f21d9c4a83'
down_revision = 'a4c9e7b21f60'
branch_labels = None
depends_on = None

_TABLE = 'settings'
_COLUMN = 'catalog_prune_orphans'


def _has_column(table, column):
    return any(c['name'] == column for c in sa.inspect(op.get_bind()).get_columns(table))


def upgrade():
    if not _has_column(_TABLE, _COLUMN):
        op.add_column(
            _TABLE,
            sa.Column(_COLUMN, sa.Boolean(), nullable=False,
                      server_default=sa.text('1')),
        )


def downgrade():
    if _has_column(_TABLE, _COLUMN):
        op.drop_column(_TABLE, _COLUMN)
