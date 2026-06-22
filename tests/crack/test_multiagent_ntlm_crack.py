import json
import os
import shlex
import subprocess
import time

import pytest

POLL_SECONDS = 1
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

    # Poll until the job completes, recording which agent each job_task was
    # assigned to WHILE it runs. The server nulls JobTasks.agent_id on
    # completion, so the assignment is only observable transiently — capture it
    # during the run rather than reading it after the fact.
    state = None
    observed = {}  # job_task id -> set of non-None agent_ids seen while running
    deadline = time.time() + DEADLINE_SECONDS
    while time.time() < deadline:
        state = _verify(compose, job_name)
        for jt in state["job_tasks"]:
            if jt["agent_id"] is not None:
                observed.setdefault(jt["id"], set()).add(jt["agent_id"])
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

    # 3. Real concurrent distribution: both job_tasks were observed assigned to
    #    agents, and the two were handled by two DISTINCT agents.
    assert len(observed) == 2, f"both job_tasks should have been assigned; saw {observed}"
    distinct_agents = {aid for seen in observed.values() for aid in seen}
    assert len(distinct_agents) == 2, (
        f"expected two distinct agents across the job_tasks, saw {observed}")

    # 4. Per-task attribution: each task's targets recovered under that task's id.
    task_ids = {jt["task_id"] for jt in state["job_tasks"]}
    recovered_task_ids = {h["task_id"] for h in state["hashes"] if h["cracked"]}
    assert recovered_task_ids == task_ids, (
        f"recovered task_ids {recovered_task_ids} != job task_ids {task_ids}; state={state}")
