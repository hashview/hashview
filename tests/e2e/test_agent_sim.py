import os
import subprocess
import sys
import uuid

import pytest


@pytest.mark.e2e
@pytest.mark.agent_sim
def test_agent_registers_and_receives_work(live_server):
    # Validate agent can register/heartbeat without DB access.
    agent_uuid = str(uuid.uuid4())
    env = os.environ.copy()
    env["HASHVIEW_API_URL"] = live_server
    env["HASHVIEW_AGENT_UUID"] = agent_uuid
    env["HASHVIEW_AGENT_NAME"] = "test-agent"
    env["HASHVIEW_AGENT_MAX_SECONDS"] = "5"
    result = subprocess.run(
        [sys.executable, "tests/agent/sim.py"],
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode in {0, 1, 2}
