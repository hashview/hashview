"""create hashes (sub_ciphertext, hash_type) unique constraint if still missing

Revision ID: c7e4b8a15d60
Revises: f2a6c9d41b78
Create Date: 2026-09-16 00:00:00.000000

f3b8c1a7d942 creates uq_hashes_sub_ciphertext_hash_type, but when it finds
duplicate rows it logs a warning, SKIPS the constraint, and returns normally --
so Alembic stamps that revision as applied. A later `flask db upgrade` begins
from a revision above it and never reattempts, which makes that migration's own
advice ("Re-run the upgrade afterwards to create the constraint") do nothing at
all. An operator who followed it merged their duplicates, ran the upgrade, saw
success, and still had no constraint and no indication of it.

This runs once for every database in that state: duplicates since merged,
constraint still absent. It also drops ix_hashes_sub_ciphertext, which
f3b8c1a7d942 returns before reaching on an affected database, so the superseded
single-column index is still there.

A database that still has duplicates when this runs is left alone with the same
warning -- but it is not stranded the way it was before, because
scripts/repair_duplicate_hashes.py --apply now creates the constraint itself as
soon as the last duplicate is merged. That path, not a migration, is what makes
the fix reachable at any point.
"""
import logging

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'c7e4b8a15d60'
# Re-parented onto f2a6c9d41b78 (widen customers.name), which landed on the dev
# line first. Both were written against d8b3e5c02a71, and two revisions sharing
# a parent is two Alembic heads -- which `flask db upgrade` refuses to resolve
# and tests/unit/test_migration_smoke.py fails on. The two are unrelated (a
# customers column width and a hashes constraint), so the order between them
# carries no meaning; this one simply goes last.
down_revision = 'f2a6c9d41b78'
branch_labels = None
depends_on = None

_UQ_NAME = 'uq_hashes_sub_ciphertext_hash_type'
_OLD_INDEX = 'ix_hashes_sub_ciphertext'
_COLUMNS = ['sub_ciphertext', 'hash_type']


def _has_unique(insp):
    """Whether the pair already carries a uniqueness constraint."""
    for constraint in insp.get_unique_constraints('hashes'):
        if set(constraint['column_names']) == set(_COLUMNS):
            return True
    # MySQL surfaces a unique constraint through get_indexes as well.
    return any(index.get('unique') and list(index['column_names']) == _COLUMNS
               for index in insp.get_indexes('hashes'))


def upgrade():
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if 'hashes' not in insp.get_table_names() or _has_unique(insp):
        return

    duplicates = bind.execute(sa.text(
        'SELECT COUNT(*) FROM ('
        '  SELECT 1 FROM hashes GROUP BY hash_type, sub_ciphertext'
        '  HAVING COUNT(*) > 1) AS grouped'
    )).scalar()
    if duplicates:
        logging.getLogger('alembic.runtime.migration').warning(
            '%s is still missing because hashes holds %s duplicate '
            '(sub_ciphertext, hash_type) pair(s). Merge them with  '
            'python scripts/repair_duplicate_hashes.py --apply  (or from the web '
            'UI under Settings -> Data management), which creates the constraint '
            'itself once the last one is gone. Re-running this upgrade will NOT '
            'create it.', _UQ_NAME, duplicates)
        return

    # batch_alter_table: SQLite has no ALTER TABLE ADD CONSTRAINT, so
    # create_unique_constraint raises there outside batch mode. Batch mode is a
    # passthrough on MySQL and a copy-and-move rebuild on SQLite.
    with op.batch_alter_table('hashes') as batch_op:
        batch_op.create_unique_constraint(_UQ_NAME, _COLUMNS)

    # Only now that the composite index exists is the single-column one
    # redundant, so this order never leaves the table without an index on
    # sub_ciphertext.
    if any(index['name'] == _OLD_INDEX for index in sa.inspect(bind).get_indexes('hashes')):
        op.drop_index(_OLD_INDEX, table_name='hashes')


def downgrade():
    """Deliberately a no-op.

    The constraint belongs to f3b8c1a7d942; this revision only finishes a job
    that one left undone. Dropping it here would undo that revision's work from
    under it and re-open the import race, and downgrading past f3b8c1a7d942
    removes it properly anyway.
    """
