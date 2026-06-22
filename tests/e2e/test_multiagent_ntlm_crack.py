import json
import os
import shlex
import subprocess
import time

import pytest

POLL_SECONDS = 5
DEADLINE_SECONDS = 240


def _verify(compose, job_name):
    """Run the in-container verifier and return its parsed JSON state."""
    cmd = shlex.split(compose) + [
        "exec", "-T", "-e", "PYTHONPATH=/", "-w", "/", "app",
        "python", "/tmp/verify_crack.py", job_name,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    # The verifier prints exactly one JSON line on stdout.
    line = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
    if not line:
        raise AssertionError(f"verifier produced no output: {proc.stderr}")
    return json.loads(line)


@pytest.mark.e2e_crack
def test_two_agents_really_crack_ntlm_job():
    manifest_path = os.getenv("HASHVIEW_E2E_CRACK_MANIFEST")
    compose = os.getenv("HASHVIEW_E2E_CRACK_COMPOSE")
    if not manifest_path or not compose:
        pytest.skip("Run via tests/run_e2e_crack_compose.sh (sets manifest + compose env).")

    manifest = json.loads(open(manifest_path).read())
    job_name = manifest["job_name"]
    expected_plaintexts = {pt for t in manifest["tasks"] for pt in t["target_plaintexts"]}

    state = None
    deadline = time.time() + DEADLINE_SECONDS
    while time.time() < deadline:
        state = _verify(compose, job_name)
        done = (state["job_status"] == "Completed"
                and state["hashes"]
                and all(h["cracked"] for h in state["hashes"]))
        if done:
            break
        time.sleep(POLL_SECONDS)

    assert state is not None, "verifier never returned state"

    # 1. Every target hash recovered with the EXACT chosen plaintext.
    cracked = {h["plaintext"] for h in state["hashes"] if h["cracked"]}
    assert cracked == expected_plaintexts, (
        f"recovered {cracked!r}, expected {expected_plaintexts!r}; state={state}")

    # 2. Job + both job_tasks Completed.
    assert state["job_status"] == "Completed", state
    assert len(state["job_tasks"]) == 2, state
    assert all(jt["status"] == "Completed" for jt in state["job_tasks"]), state

    # 3. Real concurrent distribution: two DISTINCT agents, neither None.
    agent_ids = {jt["agent_id"] for jt in state["job_tasks"]}
    assert len(agent_ids) == 2 and None not in agent_ids, (
        f"expected two distinct agent_ids, got {agent_ids}; state={state}")

    # 4. Per-task attribution: each task's targets recovered under that task's id.
    task_ids = {jt["task_id"] for jt in state["job_tasks"]}
    recovered_task_ids = {h["task_id"] for h in state["hashes"] if h["cracked"]}
    assert recovered_task_ids == task_ids, (
        f"recovered task_ids {recovered_task_ids} != job task_ids {task_ids}; state={state}")
