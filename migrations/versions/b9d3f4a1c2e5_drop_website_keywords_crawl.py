"""drop website-keywords crawl feature (columns + seeded wordlist)

Revision ID: b9d3f4a1c2e5
Revises: d4e7a1c9f2b8
Create Date: 2026-08-25 00:00:00.000000

Removes the "(DYNAMIC) Website Keywords" crawl feature. Drops the Settings
crawl_* columns and Jobs.crawl_url that the squash delta (c8b3f0a14d27) added,
and deletes the seeded "(DYNAMIC) Website Keywords" wordlist row (task rows that
referenced it, if any, are left with a dangling wl_id -- accepted, and there is
no DB-level FK from tasks to wordlists).

Guarded on apply (idempotent under schema drift). Downgrade re-adds the columns
with their former defaults; the deleted wordlist row is not restored.
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'b9d3f4a1c2e5'
down_revision = 'd4e7a1c9f2b8'
branch_labels = None
depends_on = None

# Former default UA, inlined (mirrors the squash delta so downgrade re-adds an
# identical column without importing from the models).
_CRAWL_UA = ('Mozilla/5.0 (compatible; Hashview-Crawler/1.0; '
             '+https://github.com/hashview/hashview)')

# (table, column-factory) for the crawl columns the squash delta added; used to
# drop (upgrade) and re-add (downgrade) them identically.
_CRAWL_COLS = [
    ('settings', lambda: sa.Column('crawl_min_word_length', sa.Integer(), nullable=False, server_default='8')),
    ('settings', lambda: sa.Column('crawl_user_agent', sa.String(length=255), nullable=False, server_default=_CRAWL_UA)),
    ('settings', lambda: sa.Column('crawl_force_lowercase', sa.Boolean(), nullable=False, server_default=sa.text('1'))),
    ('settings', lambda: sa.Column('crawl_depth', sa.Integer(), nullable=False, server_default='2')),
    ('settings', lambda: sa.Column('crawl_threads', sa.Integer(), nullable=False, server_default='5')),
    ('jobs', lambda: sa.Column('crawl_url', sa.String(length=2048), nullable=True)),
]

_WORDLIST_NAME = '(DYNAMIC) Website Keywords'


def _has_column(table, column):
    return any(c['name'] == column for c in sa.inspect(op.get_bind()).get_columns(table))


def upgrade():
    # Purge the seeded wordlist row (no-op if already absent).
    op.execute(sa.text("DELETE FROM wordlists WHERE name = :n").bindparams(n=_WORDLIST_NAME))
    for table, make_col in reversed(_CRAWL_COLS):
        if _has_column(table, make_col().name):
            op.drop_column(table, make_col().name)


def downgrade():
    for table, make_col in _CRAWL_COLS:
        if not _has_column(table, make_col().name):
            op.add_column(table, make_col())
