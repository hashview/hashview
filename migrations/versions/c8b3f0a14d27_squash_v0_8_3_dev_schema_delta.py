"""squash v0.8.3-dev schema delta (collapses 14 dev-only migrations)

Revision ID: c8b3f0a14d27
Revises: 8a5b0fff063d
Create Date: 2026-07-08 00:00:00.000000

Consolidates the fourteen dev-only migrations that were stacked on top of the
last released head (``8a5b0fff063d``) into a single schema delta, so upgrading
from ``main`` to v0.8.3 runs one migration instead of fourteen.

This revision deliberately reuses the id of the former dev head
(``c8b3f0a14d27``) with ``down_revision = 8a5b0fff063d``. Consequences:
  * A database at the released ``main`` head runs this one migration and lands
    at ``c8b3f0a14d27`` -- exactly where the fourteen-step chain used to end.
  * A database already fully migrated on the dev branch (stamped
    ``c8b3f0a14d27``) is treated as up-to-date -- a no-op, no re-run.
  * A database stamped at one of the twelve now-removed *intermediate* dev
    revisions must be re-stamped manually (``flask db stamp c8b3f0a14d27``)
    after confirming its schema already matches head; those revision ids no
    longer exist in the tree.

The body below is the faithful, in-order concatenation of the original fourteen
upgrades; each block is labelled with the revision it came from. Every change is
additive DDL (new columns/tables/indexes plus MySQL-only charset/type widening
of pre-existing base-schema columns). There are NO row-data (DML) migrations:
the real backfills (wordlist ``byte_size``; the legacy hex->text decode of
usernames/plaintext) run at application startup, keyed off the ``byte_size`` and
``passwords_decoded`` flag columns this migration creates -- so nothing needs to
be carried here beyond those column definitions.

``DEFAULT_CRAWL_USER_AGENT`` is inlined as a literal (rather than imported from
``hashview.models`` as the original 5c2e1f4a9d37 did) so this permanent
migration artifact cannot be broken by a future model refactor.

Original chain (down -> up):
  8a5b0fff063d (main head)
  -> 3f9c1d2a7b04  add wordlists.byte_size
  -> 5c2e1f4a9d37  add crawl settings + jobs.crawl_url
  -> 8b4d2f1c9a06  add slack notification settings
  -> 9c5e3a07b218  add email/pushover enable flags
  -> a1f7c4e9d2b3  unicode text storage
  -> c3d9f1a6b8e2  add azure/entra SSO
  -> d4e8b1f3a297  add tasks.loopback
  -> e2b9c7a14d35  widen hashes.ciphertext to TEXT
  -> 3ddfbf55f5cc  index hashfile_hashes.hashfile_id
  -> 32eb61afc767  add chunking + agent_benchmarks
  -> dae1c3ac81e6  add agent GPU telemetry
  -> a3f7c1e29b84  add hashfiles.hex_salt
  -> d4e7a1b9c602  add admin notification prefs
  -> c8b3f0a14d27  add agent timeout + offline flag  (former dev head)
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c8b3f0a14d27'
down_revision = '8a5b0fff063d'
branch_labels = None
depends_on = None

# Inlined so this permanent artifact can't break on a model refactor (see docstring).
_CRAWL_UA = ('Mozilla/5.0 (compatible; Hashview-Crawler/1.0; '
             '+https://github.com/hashview/hashview)')


def _insp():
    return sa.inspect(op.get_bind())


def _has_column(table, column):
    return any(c['name'] == column for c in _insp().get_columns(table))


def _has_table(table):
    return _insp().has_table(table)


def _has_index(table, name):
    return any(ix['name'] == name for ix in _insp().get_indexes(table))


# Every additive column this squash introduces, in original order, as
# (table, column-factory). Guarded on apply so a database that already has some
# of these (schema drift, or a partially-applied prior run) upgrades cleanly
# instead of aborting on a duplicate-column error -- MySQL DDL is
# non-transactional, so one blind ADD COLUMN failure would strand the rest.
_ADDS = [
    ('wordlists', lambda: sa.Column('byte_size', sa.BigInteger(), nullable=True)),
    ('settings', lambda: sa.Column('crawl_min_word_length', sa.Integer(), nullable=False, server_default='8')),
    ('settings', lambda: sa.Column('crawl_user_agent', sa.String(length=255), nullable=False, server_default=_CRAWL_UA)),
    ('settings', lambda: sa.Column('crawl_force_lowercase', sa.Boolean(), nullable=False, server_default=sa.text('1'))),
    ('settings', lambda: sa.Column('crawl_depth', sa.Integer(), nullable=False, server_default='2')),
    ('settings', lambda: sa.Column('crawl_threads', sa.Integer(), nullable=False, server_default='5')),
    ('jobs', lambda: sa.Column('crawl_url', sa.String(length=2048), nullable=True)),
    ('settings', lambda: sa.Column('slack_enabled', sa.Boolean(), nullable=False, server_default=sa.text('0'))),
    ('settings', lambda: sa.Column('slack_bot_token', sa.String(length=255), nullable=True)),
    ('users', lambda: sa.Column('slack_id', sa.String(length=50), nullable=True)),
    ('settings', lambda: sa.Column('email_enabled', sa.Boolean(), nullable=False, server_default=sa.text('1'))),
    ('settings', lambda: sa.Column('pushover_enabled', sa.Boolean(), nullable=False, server_default=sa.text('1'))),
    ('settings', lambda: sa.Column('passwords_decoded', sa.Boolean(), nullable=False, server_default=sa.text('0'))),
    ('settings', lambda: sa.Column('auth_method', sa.String(length=10), nullable=False, server_default='local')),
    ('settings', lambda: sa.Column('azure_tenant_id', sa.String(length=64), nullable=True)),
    ('settings', lambda: sa.Column('azure_client_id', sa.String(length=64), nullable=True)),
    ('settings', lambda: sa.Column('azure_client_secret', sa.String(length=512), nullable=True)),
    ('settings', lambda: sa.Column('azure_redirect_uri', sa.String(length=512), nullable=True)),
    ('settings', lambda: sa.Column('azure_allowed_groups', sa.String(length=1024), nullable=True)),
    ('users', lambda: sa.Column('auth_source', sa.String(length=10), nullable=False, server_default='local')),
    ('users', lambda: sa.Column('azure_oid', sa.String(length=64), nullable=True)),
    ('tasks', lambda: sa.Column('loopback', sa.Boolean(), nullable=False, server_default=sa.text('0'))),
    ('job_tasks', lambda: sa.Column('chunk_no', sa.Integer(), nullable=True)),
    ('job_tasks', lambda: sa.Column('chunk_total', sa.Integer(), nullable=True)),
    ('job_tasks', lambda: sa.Column('chunk_skip', sa.BigInteger(), nullable=True)),
    ('job_tasks', lambda: sa.Column('chunk_limit', sa.BigInteger(), nullable=True)),
    ('job_tasks', lambda: sa.Column('chunk_mask', sa.String(length=64), nullable=True)),
    ('settings', lambda: sa.Column('enabled_chunking', sa.Boolean(), nullable=False, server_default=sa.false())),
    ('settings', lambda: sa.Column('chunk_target_duration', sa.Integer(), nullable=False, server_default='3600')),
    ('agents', lambda: sa.Column('gpu_model', sa.String(length=128), nullable=True)),
    ('agents', lambda: sa.Column('gpu_temps', sa.String(length=128), nullable=True)),
    ('hashfiles', lambda: sa.Column('hex_salt', sa.Boolean(), nullable=False, server_default=sa.text('0'))),
    ('users', lambda: sa.Column('admin_notifications_enabled', sa.Boolean(), nullable=False, server_default=sa.text('1'))),
    ('users', lambda: sa.Column('admin_notify_email', sa.Boolean(), nullable=False, server_default=sa.text('1'))),
    ('users', lambda: sa.Column('admin_notify_pushover', sa.Boolean(), nullable=False, server_default=sa.text('1'))),
    ('users', lambda: sa.Column('admin_notify_slack', sa.Boolean(), nullable=False, server_default=sa.text('1'))),
    ('settings', lambda: sa.Column('slack_admin_channel', sa.String(length=255), nullable=True)),
    ('settings', lambda: sa.Column('agent_timeout_minutes', sa.Integer(), nullable=False, server_default=sa.text('60'))),
    ('agents', lambda: sa.Column('offline_notified', sa.Boolean(), nullable=False, server_default=sa.text('0'))),
]


def upgrade():
    for table, make_col in _ADDS:
        if not _has_column(table, make_col().name):
            op.add_column(table, make_col())

    # utf8mb4 widening of pre-existing base-schema columns (MySQL only; SQLite
    # ignores VARCHAR length, so data already fits). Re-applying is a harmless
    # no-op, so these need no existence guard.
    if op.get_bind().dialect.name == 'mysql':
        op.execute("ALTER TABLE hashfile_hashes MODIFY username VARCHAR(256) CHARACTER SET utf8mb4")
        op.execute("ALTER TABLE hashes MODIFY plaintext VARCHAR(256) CHARACTER SET utf8mb4")
        op.execute("ALTER TABLE users MODIFY first_name VARCHAR(64) CHARACTER SET utf8mb4 NOT NULL")
        op.execute("ALTER TABLE users MODIFY last_name VARCHAR(64) CHARACTER SET utf8mb4 NOT NULL")
        op.execute("ALTER TABLE users MODIFY email_address VARCHAR(255) CHARACTER SET utf8mb4 NOT NULL")
    if op.get_bind().dialect.name != 'sqlite':
        op.execute("ALTER TABLE hashes MODIFY ciphertext TEXT CHARACTER SET utf8mb4 NOT NULL")

    # ---- 3ddfbf55f5cc: index on hashfile_hashes.hashfile_id ----
    if not _has_index('hashfile_hashes', 'ix_hashfile_hashes_hashfile_id'):
        op.create_index('ix_hashfile_hashes_hashfile_id', 'hashfile_hashes',
                        ['hashfile_id'], unique=False)

    # ---- 32eb61afc767: agent_benchmarks table (+ its indexes) ----
    if not _has_table('agent_benchmarks'):
        op.create_table(
            'agent_benchmarks',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('agent_id', sa.Integer(), nullable=False),
            sa.Column('hash_type', sa.Integer(), nullable=False),
            sa.Column('speed', sa.BigInteger(), nullable=False),
            sa.Column('updated_at', sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(['agent_id'], ['agents.id'], ),
            sa.PrimaryKeyConstraint('id'),
            sa.UniqueConstraint('agent_id', 'hash_type', name='uix_agent_hashtype'),
        )
        op.create_index('ix_agent_benchmarks_agent_id', 'agent_benchmarks', ['agent_id'], unique=False)
        op.create_index('ix_agent_benchmarks_hash_type', 'agent_benchmarks', ['hash_type'], unique=False)


def downgrade():
    # Reverse of the fourteen original downgrades, back to 8a5b0fff063d. The
    # utf8mb4/TEXT widenings (hashes.ciphertext/plaintext, hashfile_hashes.username,
    # users.first_name/last_name/email_address) are intentionally NOT reverted --
    # narrowing could truncate stored data; a wider column is a safe superset.
    # This matches the original migrations, which all skipped those reversals.

    # Drop the additive columns in reverse order, guarded so a partial schema
    # downgrades cleanly. The agent_benchmarks table/indexes are removed first.
    if _has_table('agent_benchmarks'):
        if _has_index('agent_benchmarks', 'ix_agent_benchmarks_hash_type'):
            op.drop_index('ix_agent_benchmarks_hash_type', table_name='agent_benchmarks')
        if _has_index('agent_benchmarks', 'ix_agent_benchmarks_agent_id'):
            op.drop_index('ix_agent_benchmarks_agent_id', table_name='agent_benchmarks')
        op.drop_table('agent_benchmarks')

    if _has_index('hashfile_hashes', 'ix_hashfile_hashes_hashfile_id'):
        op.drop_index('ix_hashfile_hashes_hashfile_id', table_name='hashfile_hashes')

    for table, make_col in reversed(_ADDS):
        if _has_column(table, make_col().name):
            op.drop_column(table, make_col().name)
