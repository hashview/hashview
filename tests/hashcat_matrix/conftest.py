"""Neutralise the repo-root autouse e2e fixtures for this directory.

tests/conftest.py declares an autouse ensure_setup(page, live_server, request),
so every test under tests/ otherwise requests Playwright's `page` and the
`live_server` fixture -- and `live_server` skips the test when
HASHVIEW_E2E_BASE_URL is unset. These live hashcat tests need neither. Without
these overrides the module skips even with HASHCAT_BIN set, turning the CI gate
into a no-op that always reports success. tests/agent_unit/conftest.py does the
same thing for the same reason.
"""
import importlib.util
import os

import pytest

# test_mask_chunk_coverage.py alone in this directory imports from hashview
# (the chunk planner and the argv assembler, so it exercises the REAL ones
# rather than a copy) and therefore needs the server runtime deps. When those
# aren't installed -- the e2e job builds a venv from requirements-dev.txt only,
# because the app itself runs in Docker -- skip collection of this file so
# pytest doesn't fail importing hashview. The e2e run does not --ignore this
# directory, and `-m e2e` filters AFTER collection, so the import happens
# regardless of the marker. hashcat-matrix.yml installs requirements.txt, so
# the guard is inert in the job that actually runs these. Mirrors
# tests/agent_unit/conftest.py and tests/unit/conftest.py.
# Gated on HASHCAT_BIN being unset: hashcat-matrix.yml sets it for both runs and
# then greps the output for "skipped" to prove the gate was not a no-op. A
# collect_ignore is invisible to that grep -- it produces no output at all -- so
# an unconditional guard would let this file vanish silently and still report
# green. Inside the gate, a missing runtime dep must surface as a collection
# ERROR. Outside it, this keeps a stray `pytest tests/` on a thin env working.
if os.environ.get("HASHCAT_BIN") is None and importlib.util.find_spec("flask") is None:
    collect_ignore = ["test_mask_chunk_coverage.py"]


@pytest.fixture(autouse=True)
def ensure_setup():
    """Override the parent autouse fixture so live_server is never requested."""
    return


@pytest.fixture(autouse=True)
def configure_page():
    """Override the parent autouse fixture so the Playwright page is never built."""
    return
