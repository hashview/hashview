"""Migration chain smoke test.

Validates that the Alembic migration chain is structurally intact — a single
linear chain from one base to exactly one head, with every ``down_revision``
resolving to a known revision. This catches the bad-merge incident class (a
merge that drops version scripts, leaving an orphaned/forked chain) before it
ships.

It deliberately does NOT execute ``upgrade head`` against SQLite: several early
migrations use ``op.create_foreign_key`` / ``op.alter_column`` which SQLite
cannot ALTER in place (they run fine against the production MySQL database, and
``render_as_batch`` does not rewrite already-written direct ops at runtime —
verified). Structural validation via alembic's ScriptDirectory verifies chain
integrity on any backend without running constraint ALTERs.
"""

from pathlib import Path

import pytest
from alembic.config import Config as AlembicConfig
from alembic.script import ScriptDirectory

REPO_ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS_DIR = REPO_ROOT / "migrations"


def _downs(down_revision):
    """Normalise a down_revision (None | str | tuple) to a tuple of ids."""
    if down_revision is None:
        return ()
    if isinstance(down_revision, tuple | list):
        return tuple(down_revision)
    return (down_revision,)


@pytest.mark.security
def test_alembic_upgrade_head_on_empty_sqlite():
    """The migration chain is a single contiguous line to exactly one head.

    (Name kept for history; now validates the chain structurally rather than
    executing it on SQLite — see module docstring.)
    """
    if not MIGRATIONS_DIR.exists():
        pytest.skip("migrations/ directory missing — already a regression caught.")

    version_files = list((MIGRATIONS_DIR / "versions").glob("*.py"))
    assert len(version_files) >= 40, (
        f"Expected 40+ migration scripts; found only {len(version_files)}. "
        "Did a merge drop them?"
    )

    cfg = AlembicConfig(str(MIGRATIONS_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    script = ScriptDirectory.from_config(cfg)

    # walk_revisions() raises if the chain can't be resolved (e.g. a dropped
    # migration left a dangling parent) — that alone is a meaningful failure.
    revisions = list(script.walk_revisions())
    rev_ids = {r.revision for r in revisions}

    # Exactly one head and one base => a single, unforked, complete chain.
    heads = script.get_heads()
    assert len(heads) == 1, f"Expected exactly one migration head; found {heads}"
    bases = script.get_bases()
    assert len(bases) == 1, f"Expected exactly one base revision; found {bases}"

    # Every down_revision must resolve to a revision that is actually present;
    # a dropped migration file shows up here as a dangling parent id.
    for rev in revisions:
        for parent in _downs(rev.down_revision):
            assert parent in rev_ids, (
                f"Revision {rev.revision} points at unknown down_revision "
                f"{parent!r} — the chain is broken (a migration may have been "
                "dropped)."
            )

    # The number of resolvable revisions matches the number of version files
    # (each migration file defines exactly one revision).
    assert len(rev_ids) == len(version_files), (
        f"{len(version_files)} version files but {len(rev_ids)} resolvable "
        "revisions — a file may be unparsable or duplicate a revision id."
    )
