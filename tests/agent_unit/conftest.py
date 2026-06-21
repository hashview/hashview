"""Unit tests for the hashview agent (install/hashview-agent).

The agent is shipped as a script tree, not an installed package, so we add
its root to sys.path. Its only side-effectful dependency is agent.http.http,
which tests monkeypatch — no live server, no hashcat.

Importing the agent package has a side effect: agent/__init__.py (and
agent/http/http.py) do ``from agent.config import Config``, and
agent/config.py reads ``agent/config.conf`` relative to the CWD at class
definition time, raising KeyError when the file is absent. We pre-seed
sys.modules with a stub agent.config so the real module is never imported.
"""
import sys
import types
from pathlib import Path

AGENT_ROOT = Path(__file__).resolve().parents[2] / "install" / "hashview-agent"
if str(AGENT_ROOT) not in sys.path:
    sys.path.insert(0, str(AGENT_ROOT))

if "agent.config" not in sys.modules:
    _config_stub = types.ModuleType("agent.config")

    class Config:
        HASHVIEW_SERVER = "127.0.0.1"
        HASHVIEW_PORT = "8443"
        USE_SSL = "True"
        NAME = "test-agent"
        UUID = "00000000-0000-0000-0000-000000000000"
        HC_BIN_PATH = "/usr/bin/hashcat"
        HC_EXTRA_ARGS = ""

    _config_stub.Config = Config
    sys.modules["agent.config"] = _config_stub

import pytest


@pytest.fixture(autouse=True)
def ensure_setup():
    """Override parent autouse so live_server isn't requested."""
    return


@pytest.fixture(autouse=True)
def configure_page():
    """Override parent autouse so the Playwright page fixture isn't pulled."""
    return
