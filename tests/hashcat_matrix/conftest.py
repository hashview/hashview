"""Neutralise the repo-root autouse e2e fixtures for this directory.

tests/conftest.py declares an autouse ensure_setup(page, live_server, request),
so every test under tests/ otherwise requests Playwright's `page` and the
`live_server` fixture -- and `live_server` skips the test when
HASHVIEW_E2E_BASE_URL is unset. These live hashcat tests need neither. Without
these overrides the module skips even with HASHCAT_BIN set, turning the CI gate
into a no-op that always reports success. tests/agent_unit/conftest.py does the
same thing for the same reason.
"""
import pytest


@pytest.fixture(autouse=True)
def ensure_setup():
    """Override the parent autouse fixture so live_server is never requested."""
    return


@pytest.fixture(autouse=True)
def configure_page():
    """Override the parent autouse fixture so the Playwright page is never built."""
    return
