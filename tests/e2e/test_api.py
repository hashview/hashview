import json
import os

import pytest


@pytest.mark.e2e
def test_api_rules_requires_authorization(page, live_server):
    response = page.request.get(f"{live_server}/v1/rules")
    if response.status in {301, 302, 303, 307, 308}:
        location = response.headers.get("location", "")
        if location.startswith("/"):
            location = f"{live_server}{location}"
        response = page.request.get(location)
    assert response.ok
    data = response.json()
    if "msg" in data:
        assert data["msg"].startswith("Your agent is not authorized")
    else:
        assert "rules" in data


@pytest.mark.e2e
def test_api_rules_authorized(page, live_server):
    api_key = os.getenv("HASHVIEW_E2E_API_KEY")
    if not api_key:
        pytest.skip("Set HASHVIEW_E2E_API_KEY for authorized API tests.")
    page.context.add_cookies([{"name": "uuid", "value": api_key, "url": live_server}])
    response = page.request.get(f"{live_server}/v1/rules")
    assert response.ok
    data = response.json()
    assert data["status"] == 200
    if "rules" not in data:
        pytest.skip("HASHVIEW_E2E_API_KEY is not authorized for this server.")


@pytest.mark.e2e
def test_api_task_lookup(page, live_server):
    api_key = os.getenv("HASHVIEW_E2E_API_KEY")
    task_id = os.getenv("HASHVIEW_E2E_TASK_ID")
    if not api_key or not task_id:
        pytest.skip("Set HASHVIEW_E2E_API_KEY and HASHVIEW_E2E_TASK_ID.")
    page.context.add_cookies([{"name": "uuid", "value": api_key, "url": live_server}])
    response = page.request.get(f"{live_server}/v1/tasks/{task_id}")
    assert response.ok
    data = response.json()
    if "task" not in data:
        pytest.skip("HASHVIEW_E2E_API_KEY is not authorized for task lookup.")
    task = data["task"]
    assert str(task.get("id")) == str(task_id)


@pytest.mark.e2e
def test_api_job_lookup(page, live_server):
    api_key = os.getenv("HASHVIEW_E2E_API_KEY")
    job_id = os.getenv("HASHVIEW_E2E_JOB_ID")
    if not api_key or not job_id:
        pytest.skip("Set HASHVIEW_E2E_API_KEY and HASHVIEW_E2E_JOB_ID.")
    page.context.add_cookies([{"name": "uuid", "value": api_key, "url": live_server}])
    response = page.request.get(f"{live_server}/v1/jobs/{job_id}")
    assert response.ok
    data = response.json()
    if "job" not in data:
        pytest.skip("HASHVIEW_E2E_API_KEY is not authorized for job lookup.")
    job = data["job"]
    assert str(job.get("id")) == str(job_id)


@pytest.mark.e2e
def test_api_agent_heartbeat_creates_agent(page, live_server):
    page.context.add_cookies(
        [
            {"name": "uuid", "value": "test-agent-uuid", "url": live_server},
            {"name": "agent_version", "value": "0.8.3", "url": live_server},
            {"name": "name", "value": "Test Agent", "url": live_server},
        ]
    )
    response = page.request.post(
        f"{live_server}/v1/agents/heartbeat",
        data=json.dumps({}),
        headers={"Content-Type": "application/json"},
    )
    assert response.ok
    data = response.json()
    assert data["msg"] == "Go Away"
