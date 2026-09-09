"""Neutralise the repo-root autouse e2e fixtures for this directory.

tests/conftest.py declares an autouse ensure_setup(page, live_server, request),
so every test under tests/ otherwise requests Playwright's `page` and the
`live_server` fixture -- and `live_server` skips the test when
HASHVIEW_E2E_BASE_URL is unset. These live hashcat interop tests need neither:
they drive the real hashcat binary directly via HASHCAT_BIN, not a live
Hashview server. Without these overrides the module skips even with
HASHCAT_BIN set, turning the CI gate into a no-op that always reports success.
tests/agent_unit/conftest.py does the same thing for the same reason.
"""
import importlib.util

import pytest

# pytest.ini sets testpaths = tests, so a plain `pytest tests` (e.g. the e2e
# job) collects this directory too. test_kerberos_aes_interop.py imports from
# hashview.utils.utils for the normalize_kerberos_hash round-trip assertion,
# which pulls in Flask -- but the e2e job only installs requirements-dev.txt
# (it drives the app over HTTP inside Docker and never imports hashview.*), so
# collection dies with ModuleNotFoundError: No module named 'flask'.
#
# This is the same problem #429 hit and solved with a directory-level
# collect_ignore; same pattern here, adapted to this module's filename.
#
# This is not a hole in the no-skip gate: our own kerberos-hashcat-interop.yml
# workflow installs requirements.txt, so Flask is present there and all 26
# tests collect and run normally. If Flask were ever missing in THAT job,
# collect_ignore would yield zero collected tests, pytest would exit 5 (no
# tests collected), and the step would fail through the pipefail shell -- so
# the gate still cannot pass while proving nothing.
if importlib.util.find_spec("flask") is None:
    collect_ignore = ["test_kerberos_aes_interop.py"]


@pytest.fixture(autouse=True)
def ensure_setup():
    """Override the parent autouse fixture so live_server is never requested."""
    return


@pytest.fixture(autouse=True)
def configure_page():
    """Override the parent autouse fixture so the Playwright page is never built."""
    return
