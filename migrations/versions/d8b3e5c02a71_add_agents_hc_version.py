"""add agents.hc_version and agents.hc_major

Revision ID: d8b3e5c02a71
Revises: c3f8a1d47e29
Create Date: 2026-09-14 00:00:00.000000

The server has never recorded which hashcat an agent runs, and it now has to.

hashcat 7 redefines BOTH `--keyspace` and `--skip`/`--limit` to whole-run units.
That is self-consistent within a version -- a slice computed from one and applied
with the other still tiles correctly -- and silently mis-covering across one: a
keyspace measured on 6.x, sliced, and run on 7.x addresses a completely different
space, with no error, no warning, and no symptom other than hashes that were
never actually tried.

So a measured keyspace is only usable by an agent running the same hashcat MAJOR
as the agent that measured it. Majors, not full versions: 6.2.6 and 6.2.7 are
identical for these three flags, and comparing full strings would stall a whole
fleet over a patch bump.

hc_version keeps the raw string for diagnostics; hc_major is the comparison. Both
nullable -- an agent that has not yet reported (or whose `hashcat --version`
could not be parsed) simply never receives a measured slice, and runs whole
attacks instead, which emit no --skip/--limit and are correct under any unit.

Additive DDL only, guarded on apply so a drifted schema does not abort the tail.
"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'd8b3e5c02a71'
down_revision = 'c3f8a1d47e29'
branch_labels = None
depends_on = None

_COLUMNS = (
    ('hc_version', lambda: sa.Column('hc_version', sa.String(length=32), nullable=True)),
    ('hc_major', lambda: sa.Column('hc_major', sa.SmallInteger(), nullable=True)),
)


def _has_column(table, column):
    return any(c['name'] == column for c in sa.inspect(op.get_bind()).get_columns(table))


def upgrade():
    for name, column in _COLUMNS:
        if not _has_column('agents', name):
            op.add_column('agents', column())


def downgrade():
    for name, _ in reversed(_COLUMNS):
        if _has_column('agents', name):
            op.drop_column('agents', name)
