"""Local conftest for the crack e2e test.

The root tests/conftest.py defines autouse fixtures (`ensure_setup`,
`configure_page`) that depend on Playwright's `page` and the `live_server`
fixture — which skips unless HASHVIEW_E2E_BASE_URL is set. The crack test talks
to the stack via `docker compose exec`, not a browser, so we override those
autouse fixtures with no-ops here to fully decouple it from Playwright.
"""
import pytest


@pytest.fixture(autouse=True)
def ensure_setup():
    return


@pytest.fixture(autouse=True)
def configure_page():
    return
