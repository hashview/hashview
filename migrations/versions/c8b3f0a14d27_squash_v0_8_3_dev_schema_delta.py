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


def upgrade():
    # ---- 3f9c1d2a7b04: wordlists.byte_size (backfilled at app startup) ----
    with op.batch_alter_table('wordlists') as batch_op:
        batch_op.add_column(sa.Column('byte_size', sa.BigInteger(), nullable=True))

    # ---- 5c2e1f4a9d37: website-crawler settings + jobs.crawl_url ----
    # DEFAULT_CRAWL_USER_AGENT literal inlined (see module docstring).
    with op.batch_alter_table('settings') as batch_op:
        batch_op.add_column(sa.Column('crawl_min_word_length', sa.Integer(), nullable=False, server_default='8'))
        batch_op.add_column(sa.Column('crawl_user_agent', sa.String(length=255), nullable=False, server_default='Mozilla/5.0 (compatible; Hashview-Crawler/1.0; +https://github.com/hashview/hashview)'))
        batch_op.add_column(sa.Column('crawl_force_lowercase', sa.Boolean(), nullable=False, server_default=sa.text('1')))
        batch_op.add_column(sa.Column('crawl_depth', sa.Integer(), nullable=False, server_default='2'))
        batch_op.add_column(sa.Column('crawl_threads', sa.Integer(), nullable=False, server_default='5'))

    with op.batch_alter_table('jobs') as batch_op:
        batch_op.add_column(sa.Column('crawl_url', sa.String(length=2048), nullable=True))

    # ---- 8b4d2f1c9a06: Slack notification settings ----
    with op.batch_alter_table('settings') as batch_op:
        batch_op.add_column(sa.Column('slack_enabled', sa.Boolean(), nullable=False, server_default=sa.text('0')))
        batch_op.add_column(sa.Column('slack_bot_token', sa.String(length=255), nullable=True))

    with op.batch_alter_table('users') as batch_op:
        batch_op.add_column(sa.Column('slack_id', sa.String(length=50), nullable=True))

    # ---- 9c5e3a07b218: email/pushover master switches ----
    with op.batch_alter_table('settings') as batch_op:
        batch_op.add_column(sa.Column('email_enabled', sa.Boolean(), nullable=False, server_default=sa.text('1')))
        batch_op.add_column(sa.Column('pushover_enabled', sa.Boolean(), nullable=False, server_default=sa.text('1')))

    # ---- a1f7c4e9d2b3: unicode text storage flag + utf8mb4 widening ----
    with op.batch_alter_table('settings') as batch_op:
        batch_op.add_column(sa.Column('passwords_decoded', sa.Boolean(), nullable=False, server_default=sa.text('0')))

    if op.get_bind().dialect.name == 'mysql':
        op.execute("ALTER TABLE hashfile_hashes MODIFY username VARCHAR(256) CHARACTER SET utf8mb4")
        op.execute("ALTER TABLE hashes MODIFY plaintext VARCHAR(256) CHARACTER SET utf8mb4")

    # ---- c3d9f1a6b8e2: Azure/Entra OIDC SSO ----
    with op.batch_alter_table('settings') as batch_op:
        batch_op.add_column(sa.Column('auth_method', sa.String(length=10), nullable=False, server_default='local'))
        batch_op.add_column(sa.Column('azure_tenant_id', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('azure_client_id', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('azure_client_secret', sa.String(length=512), nullable=True))
        batch_op.add_column(sa.Column('azure_redirect_uri', sa.String(length=512), nullable=True))
        batch_op.add_column(sa.Column('azure_allowed_groups', sa.String(length=1024), nullable=True))

    with op.batch_alter_table('users') as batch_op:
        batch_op.add_column(sa.Column('auth_source', sa.String(length=10), nullable=False, server_default='local'))
        batch_op.add_column(sa.Column('azure_oid', sa.String(length=64), nullable=True))

    # Widen the user text columns for JIT-provisioned Entra identities. MySQL only;
    # SQLite ignores VARCHAR length, so existing data already fits.
    if op.get_bind().dialect.name == 'mysql':
        op.execute("ALTER TABLE users MODIFY first_name VARCHAR(64) CHARACTER SET utf8mb4 NOT NULL")
        op.execute("ALTER TABLE users MODIFY last_name VARCHAR(64) CHARACTER SET utf8mb4 NOT NULL")
        op.execute("ALTER TABLE users MODIFY email_address VARCHAR(255) CHARACTER SET utf8mb4 NOT NULL")

    # ---- d4e8b1f3a297: tasks.loopback ----
    with op.batch_alter_table('tasks') as batch_op:
        batch_op.add_column(sa.Column('loopback', sa.Boolean(), nullable=False, server_default=sa.text('0')))

    # ---- e2b9c7a14d35: widen hashes.ciphertext to TEXT utf8mb4 ----
    if op.get_bind().dialect.name != 'sqlite':
        op.execute("ALTER TABLE hashes MODIFY ciphertext TEXT CHARACTER SET utf8mb4 NOT NULL")

    # ---- 3ddfbf55f5cc: index on hashfile_hashes.hashfile_id ----
    op.create_index(
        'ix_hashfile_hashes_hashfile_id',
        'hashfile_hashes', ['hashfile_id'], unique=False)

    # ---- 32eb61afc767: agent_benchmarks table + job_tasks chunk_* + settings chunking ----
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

    op.add_column('job_tasks', sa.Column('chunk_no', sa.Integer(), nullable=True))
    op.add_column('job_tasks', sa.Column('chunk_total', sa.Integer(), nullable=True))
    op.add_column('job_tasks', sa.Column('chunk_skip', sa.BigInteger(), nullable=True))
    op.add_column('job_tasks', sa.Column('chunk_limit', sa.BigInteger(), nullable=True))
    op.add_column('job_tasks', sa.Column('chunk_mask', sa.String(length=64), nullable=True))

    op.add_column('settings', sa.Column(
        'enabled_chunking', sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column('settings', sa.Column(
        'chunk_target_duration', sa.Integer(), nullable=False, server_default='3600'))

    # ---- dae1c3ac81e6: agents GPU telemetry ----
    op.add_column('agents', sa.Column('gpu_model', sa.String(length=128), nullable=True))
    op.add_column('agents', sa.Column('gpu_temps', sa.String(length=128), nullable=True))

    # ---- a3f7c1e29b84: hashfiles.hex_salt ----
    with op.batch_alter_table('hashfiles') as batch_op:
        batch_op.add_column(sa.Column('hex_salt', sa.Boolean(), nullable=False, server_default=sa.text('0')))

    # ---- d4e7a1b9c602: admin notification prefs + settings.slack_admin_channel ----
    with op.batch_alter_table('users') as batch_op:
        batch_op.add_column(sa.Column('admin_notifications_enabled', sa.Boolean(), nullable=False, server_default=sa.text('1')))
        batch_op.add_column(sa.Column('admin_notify_email', sa.Boolean(), nullable=False, server_default=sa.text('1')))
        batch_op.add_column(sa.Column('admin_notify_pushover', sa.Boolean(), nullable=False, server_default=sa.text('1')))
        batch_op.add_column(sa.Column('admin_notify_slack', sa.Boolean(), nullable=False, server_default=sa.text('1')))

    with op.batch_alter_table('settings') as batch_op:
        batch_op.add_column(sa.Column('slack_admin_channel', sa.String(length=255), nullable=True))

    # ---- c8b3f0a14d27: agent timeout + offline flag ----
    with op.batch_alter_table('settings') as batch_op:
        batch_op.add_column(sa.Column('agent_timeout_minutes', sa.Integer(), nullable=False, server_default=sa.text('60')))

    with op.batch_alter_table('agents') as batch_op:
        batch_op.add_column(sa.Column('offline_notified', sa.Boolean(), nullable=False, server_default=sa.text('0')))


def downgrade():
    # Reverse of the fourteen original downgrades, back to 8a5b0fff063d. The
    # utf8mb4/TEXT widenings (hashes.ciphertext/plaintext, hashfile_hashes.username,
    # users.first_name/last_name/email_address) are intentionally NOT reverted --
    # narrowing could truncate stored data; a wider column is a safe superset.
    # This matches the original migrations, which all skipped those reversals.

    # ---- reverse of c8b3f0a14d27 ----
    with op.batch_alter_table('agents') as batch_op:
        batch_op.drop_column('offline_notified')

    with op.batch_alter_table('settings') as batch_op:
        batch_op.drop_column('agent_timeout_minutes')

    # ---- reverse of d4e7a1b9c602 ----
    with op.batch_alter_table('settings') as batch_op:
        batch_op.drop_column('slack_admin_channel')

    with op.batch_alter_table('users') as batch_op:
        batch_op.drop_column('admin_notify_slack')
        batch_op.drop_column('admin_notify_pushover')
        batch_op.drop_column('admin_notify_email')
        batch_op.drop_column('admin_notifications_enabled')

    # ---- reverse of a3f7c1e29b84 ----
    with op.batch_alter_table('hashfiles') as batch_op:
        batch_op.drop_column('hex_salt')

    # ---- reverse of dae1c3ac81e6 ----
    op.drop_column('agents', 'gpu_temps')
    op.drop_column('agents', 'gpu_model')

    # ---- reverse of 32eb61afc767 ----
    op.drop_column('settings', 'chunk_target_duration')
    op.drop_column('settings', 'enabled_chunking')

    op.drop_column('job_tasks', 'chunk_mask')
    op.drop_column('job_tasks', 'chunk_limit')
    op.drop_column('job_tasks', 'chunk_skip')
    op.drop_column('job_tasks', 'chunk_total')
    op.drop_column('job_tasks', 'chunk_no')

    op.drop_index('ix_agent_benchmarks_hash_type', table_name='agent_benchmarks')
    op.drop_index('ix_agent_benchmarks_agent_id', table_name='agent_benchmarks')
    op.drop_table('agent_benchmarks')

    # ---- reverse of 3ddfbf55f5cc ----
    op.drop_index('ix_hashfile_hashes_hashfile_id', table_name='hashfile_hashes')

    # ---- reverse of e2b9c7a14d35: ciphertext TEXT widening intentionally not reverted ----

    # ---- reverse of d4e8b1f3a297 ----
    with op.batch_alter_table('tasks') as batch_op:
        batch_op.drop_column('loopback')

    # ---- reverse of c3d9f1a6b8e2 (users column widening intentionally not reverted) ----
    with op.batch_alter_table('users') as batch_op:
        batch_op.drop_column('azure_oid')
        batch_op.drop_column('auth_source')

    with op.batch_alter_table('settings') as batch_op:
        batch_op.drop_column('azure_allowed_groups')
        batch_op.drop_column('azure_redirect_uri')
        batch_op.drop_column('azure_client_secret')
        batch_op.drop_column('azure_client_id')
        batch_op.drop_column('azure_tenant_id')
        batch_op.drop_column('auth_method')

    # ---- reverse of a1f7c4e9d2b3 (username/plaintext widening intentionally not reverted) ----
    with op.batch_alter_table('settings') as batch_op:
        batch_op.drop_column('passwords_decoded')

    # ---- reverse of 9c5e3a07b218 ----
    with op.batch_alter_table('settings') as batch_op:
        batch_op.drop_column('pushover_enabled')
        batch_op.drop_column('email_enabled')

    # ---- reverse of 8b4d2f1c9a06 ----
    with op.batch_alter_table('users') as batch_op:
        batch_op.drop_column('slack_id')

    with op.batch_alter_table('settings') as batch_op:
        batch_op.drop_column('slack_bot_token')
        batch_op.drop_column('slack_enabled')

    # ---- reverse of 5c2e1f4a9d37 ----
    with op.batch_alter_table('jobs') as batch_op:
        batch_op.drop_column('crawl_url')

    with op.batch_alter_table('settings') as batch_op:
        batch_op.drop_column('crawl_threads')
        batch_op.drop_column('crawl_depth')
        batch_op.drop_column('crawl_force_lowercase')
        batch_op.drop_column('crawl_user_agent')
        batch_op.drop_column('crawl_min_word_length')

    # ---- reverse of 3f9c1d2a7b04 ----
    with op.batch_alter_table('wordlists') as batch_op:
        batch_op.drop_column('byte_size')
