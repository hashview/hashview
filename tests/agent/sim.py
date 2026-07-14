import os
import time
import uuid as uuid_lib

import requests


def main() -> int:
    api_url = os.getenv("HASHVIEW_API_URL", "http://localhost:5000")
    agent_uuid = os.getenv("HASHVIEW_AGENT_UUID", str(uuid_lib.uuid4()))
    agent_name = os.getenv("HASHVIEW_AGENT_NAME", "test-agent")
    agent_version = os.getenv("HASHVIEW_AGENT_VERSION", "0.8.3")
    poll_interval = float(os.getenv("HASHVIEW_AGENT_POLL_INTERVAL", "1.0"))
    max_seconds = float(os.getenv("HASHVIEW_AGENT_MAX_SECONDS", "30"))

    session = requests.Session()
    session.cookies.set("uuid", agent_uuid)
    session.cookies.set("agent_version", agent_version)
    session.cookies.set("name", agent_name)

    deadline = time.time() + max_seconds
    while time.time() < deadline:
        response = session.post(
            f"{api_url}/v1/agents/heartbeat",
            json={"agent_status": "Idle", "hc_status": ""},
            timeout=10,
        )
        if response.status_code == 426:
            print("UPGRADE_REQUIRED")
            return 2
        data = response.json()
        msg = data.get("msg")
        if msg == "START":
            print(f"START {data.get('job_task_id')}")
            return 0
        time.sleep(poll_interval)

    print("TIMEOUT")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
