"""Unit tests for install/hashview-agent/agent/api/api.py.

Every function in api.py gets a happy-path test, and every function with a
426 (agent version older than server) branch gets a SystemExit test. The
agent's HTTP layer is monkeypatched on the agent.http.http module object,
which is the same object api.py bound via ``from agent.http import http``.
"""
import json

import pytest
from agent.api import api
from agent.bench import parse_benchmark_speed
from agent.http import http

VERSION_MISMATCH = {"type": "message", "status": 426}


# ---------------------------------------------------------------------------
# heartbeat
# ---------------------------------------------------------------------------

def test_heartbeat_returns_decoded_response_on_200(monkeypatch):
    payload = {"type": "message", "status": 200, "msg": "OK"}
    captured = {}

    def fake_post(path, body):
        captured["path"] = path
        captured["body"] = body
        return json.dumps(payload)

    monkeypatch.setattr(http, "post", fake_post)
    assert api.heartbeat("idle", "stopped") == payload
    assert captured["path"] == "/v1/agents/heartbeat"
    assert captured["body"] == {"agent_status": "idle", "hc_status": "stopped"}


def test_heartbeat_exits_on_426_version_mismatch(monkeypatch):
    monkeypatch.setattr(http, "post", lambda path, body: json.dumps(VERSION_MISMATCH))
    with pytest.raises(SystemExit):
        api.heartbeat("idle", "stopped")


def test_heartbeat_returns_none_on_unexpected_type(monkeypatch):
    # Pins actual behavior: non-message types fall through and return None.
    payload = {"type": "unexpected", "status": 200}
    monkeypatch.setattr(http, "post", lambda path, body: json.dumps(payload))
    assert api.heartbeat("idle", "stopped") is None


def test_heartbeat_no_op_when_server_returns_no_body(monkeypatch):
    # http.post returns None for a non-200 (e.g. the server is mid-reboot / 500).
    # heartbeat must NOT crash on json.loads(None); it returns a safe sentinel so
    # the agent's cycle continues and retries next beat (callers read ['msg']).
    monkeypatch.setattr(http, "post", lambda path, body: None)
    resp = api.heartbeat("Working", "")
    assert resp == {"type": "message", "status": 200, "msg": None}
    assert resp["msg"] != "Canceled"


def test_heartbeat_no_op_when_server_returns_non_json(monkeypatch):
    # A non-JSON body (e.g. an HTML 500 page) is likewise treated as a no-op.
    monkeypatch.setattr(http, "post", lambda path, body: "<html>500</html>")
    assert api.heartbeat("Working", "")["msg"] is None


# ---------------------------------------------------------------------------
# server_settings
# ---------------------------------------------------------------------------

def test_server_settings_unwraps_settings_key(monkeypatch):
    settings = {"max_runtime_jobs": 4, "db_version": "0.8.3"}
    payload = {"status": 200, "settings": settings}
    monkeypatch.setattr(http, "get", lambda path: json.dumps(payload))
    assert api.server_settings() == settings


def test_server_settings_exits_on_426(monkeypatch):
    monkeypatch.setattr(http, "get", lambda path: json.dumps(VERSION_MISMATCH))
    with pytest.raises(SystemExit):
        api.server_settings()


# ---------------------------------------------------------------------------
# rules_list
# ---------------------------------------------------------------------------

def test_rules_list_unwraps_rules_key(monkeypatch):
    rules = [{"id": 1, "name": "best64", "checksum": "abc"}]
    payload = {"status": 200, "rules": rules}
    monkeypatch.setattr(http, "get", lambda path: json.dumps(payload))
    assert api.rules_list() == rules


def test_rules_list_exits_on_426(monkeypatch):
    monkeypatch.setattr(http, "get", lambda path: json.dumps(VERSION_MISMATCH))
    with pytest.raises(SystemExit):
        api.rules_list()


# ---------------------------------------------------------------------------
# get_rules_file (passthrough)
# ---------------------------------------------------------------------------

def test_get_rules_file_passes_through_http_get(monkeypatch):
    captured = {}

    def fake_get(path):
        captured["path"] = path
        return b"rule-file-bytes"

    monkeypatch.setattr(http, "get", fake_get)
    assert api.get_rules_file(7) == b"rule-file-bytes"
    assert captured["path"] == "/v1/rules/7"


# ---------------------------------------------------------------------------
# getWordlists
# ---------------------------------------------------------------------------

def test_getwordlists_unwraps_wordlists_key(monkeypatch):
    wordlists = [{"id": 2, "name": "rockyou", "checksum": "def"}]
    payload = {"status": 200, "wordlists": wordlists}
    monkeypatch.setattr(http, "get", lambda path: json.dumps(payload))
    assert api.getWordlists() == wordlists


def test_getwordlists_exits_on_426(monkeypatch):
    monkeypatch.setattr(http, "get", lambda path: json.dumps(VERSION_MISMATCH))
    with pytest.raises(SystemExit):
        api.getWordlists()


# ---------------------------------------------------------------------------
# get_wordlists_file (passthrough)
# ---------------------------------------------------------------------------

def test_get_wordlists_file_passes_through_http_get(monkeypatch):
    captured = {}

    def fake_get(path):
        captured["path"] = path
        return b"wordlist-bytes"

    monkeypatch.setattr(http, "get", fake_get)
    assert api.get_wordlists_file(3) == b"wordlist-bytes"
    assert captured["path"] == "/v1/wordlists/3"


# ---------------------------------------------------------------------------
# jobTasks (payload value is itself JSON-encoded)
# ---------------------------------------------------------------------------

def test_jobtasks_double_decodes_job_task(monkeypatch):
    job_task = {"id": 11, "job_id": 5, "task_id": 9, "status": "Queued"}
    payload = {"status": 200, "job_task": json.dumps(job_task)}
    monkeypatch.setattr(http, "get", lambda path: json.dumps(payload))
    assert api.jobTasks(11) == job_task


def test_jobtasks_exits_on_426(monkeypatch):
    monkeypatch.setattr(http, "get", lambda path: json.dumps(VERSION_MISMATCH))
    with pytest.raises(SystemExit):
        api.jobTasks(11)


# ---------------------------------------------------------------------------
# jobs (payload value is itself JSON-encoded)
# ---------------------------------------------------------------------------

def test_jobs_double_decodes_job(monkeypatch):
    job = {"id": 5, "name": "test job", "hashfile_id": 2}
    payload = {"status": 200, "job": json.dumps(job)}
    monkeypatch.setattr(http, "get", lambda path: json.dumps(payload))
    assert api.jobs(5) == job


def test_jobs_exits_on_426(monkeypatch):
    monkeypatch.setattr(http, "get", lambda path: json.dumps(VERSION_MISMATCH))
    with pytest.raises(SystemExit):
        api.jobs(5)


# ---------------------------------------------------------------------------
# tasks (payload value is itself JSON-encoded)
# ---------------------------------------------------------------------------

def test_tasks_double_decodes_task(monkeypatch):
    task = {"id": 9, "name": "rockyou + best64", "hc_attackmode": "dictionary"}
    payload = {"status": 200, "task": json.dumps(task)}
    monkeypatch.setattr(http, "get", lambda path: json.dumps(payload))
    assert api.tasks(9) == task


def test_tasks_exits_on_426(monkeypatch):
    monkeypatch.setattr(http, "get", lambda path: json.dumps(VERSION_MISMATCH))
    with pytest.raises(SystemExit):
        api.tasks(9)


# ---------------------------------------------------------------------------
# updateDynamicWordlists
# ---------------------------------------------------------------------------

def test_updatedynamicwordlists_returns_decoded_response_on_200(monkeypatch):
    payload = {"type": "message", "status": 200, "msg": "updated"}
    captured = {}

    def fake_get(path):
        captured["path"] = path
        return json.dumps(payload)

    monkeypatch.setattr(http, "get", fake_get)
    assert api.updateDynamicWordlists(4) == payload
    assert captured["path"] == "/v1/updateWordlist/4"


def test_updatedynamicwordlists_exits_on_426(monkeypatch):
    monkeypatch.setattr(http, "get", lambda path: json.dumps(VERSION_MISMATCH))
    with pytest.raises(SystemExit):
        api.updateDynamicWordlists(4)


# ---------------------------------------------------------------------------
# get_hashfile (passthrough)
# ---------------------------------------------------------------------------

def test_get_hashfile_passes_through_http_get(monkeypatch):
    captured = {}

    def fake_get(path):
        captured["path"] = path
        return b"hashfile-bytes"

    monkeypatch.setattr(http, "get", fake_get)
    assert api.get_hashfile(6) == b"hashfile-bytes"
    assert captured["path"] == "/v1/hashfiles/6"


# ---------------------------------------------------------------------------
# uploadCrackFile
# ---------------------------------------------------------------------------

def test_uploadcrackfile_posts_file_contents_and_returns_response(monkeypatch, tmp_path):
    crack_file = tmp_path / "hc_cracked_11.txt"
    crack_file.write_text("8846f7eaee8fb117ad06bdd830b7586c:password\n")

    payload = {"type": "message", "status": 200, "msg": "OK"}
    captured = {}

    def fake_post(path, data):
        captured["path"] = path
        captured["data"] = data
        return json.dumps(payload)

    monkeypatch.setattr(http, "post", fake_post)
    assert api.uploadCrackFile(str(crack_file), 11) == payload
    assert captured["path"] == "/v1/uploadCrackFile/11"
    assert captured["data"] == {"file": "8846f7eaee8fb117ad06bdd830b7586c:password\n"}


def test_uploadcrackfile_exits_on_426(monkeypatch, tmp_path):
    crack_file = tmp_path / "hc_cracked_11.txt"
    crack_file.write_text("hash:plain\n")
    monkeypatch.setattr(http, "post", lambda path, data: json.dumps(VERSION_MISMATCH))
    with pytest.raises(SystemExit):
        api.uploadCrackFile(str(crack_file), 11)


# ---------------------------------------------------------------------------
# getHashType
# ---------------------------------------------------------------------------

def test_gethashtype_returns_decoded_response_on_200(monkeypatch):
    payload = {"type": "message", "status": 200, "hash_type": "1000"}
    captured = {}

    def fake_get(path):
        captured["path"] = path
        return json.dumps(payload)

    monkeypatch.setattr(http, "get", fake_get)
    assert api.getHashType(2) == payload
    assert captured["path"] == "/v1/getHashType/2"


def test_gethashtype_exits_on_426(monkeypatch):
    monkeypatch.setattr(http, "get", lambda path: json.dumps(VERSION_MISMATCH))
    with pytest.raises(SystemExit):
        api.getHashType(2)


# ---------------------------------------------------------------------------
# updateJobTask
# ---------------------------------------------------------------------------

def test_updatejobtask_returns_decoded_response_on_200(monkeypatch):
    payload = {"type": "message", "status": 200, "msg": "OK"}
    captured = {}

    def fake_post(path, body):
        captured["path"] = path
        captured["body"] = body
        return json.dumps(payload)

    monkeypatch.setattr(http, "post", fake_post)
    assert api.updateJobTask(11, "Running") == payload
    assert captured["path"] == "/v1/jobtask/status"
    assert captured["body"] == {"task_status": "Running", "job_task_id": 11}


def test_updatejobtask_exits_on_426(monkeypatch):
    monkeypatch.setattr(http, "post", lambda path, body: json.dumps(VERSION_MISMATCH))
    with pytest.raises(SystemExit):
        api.updateJobTask(11, "Running")


def test_updatejobtask_returns_decoded_response_on_unexpected_status(monkeypatch):
    # Pins actual behavior: unlike heartbeat, the fallthrough branch here
    # returns the decoded response instead of None.
    payload = {"type": "message", "status": 500}
    monkeypatch.setattr(http, "post", lambda path, body: json.dumps(payload))
    assert api.updateJobTask(11, "Running") == payload


# ---------------------------------------------------------------------------
# sendError
# ---------------------------------------------------------------------------

def test_senderror_returns_decoded_response_on_200(monkeypatch):
    payload = {"type": "message", "status": 200, "msg": "OK"}
    captured = {}

    def fake_post(path, body):
        captured["path"] = path
        captured["body"] = body
        return json.dumps(payload)

    monkeypatch.setattr(http, "post", fake_post)
    assert api.sendError("hashcat exploded") == payload
    assert captured["path"] == "/v1/error"
    assert captured["body"] == {"error": "hashcat exploded"}


def test_senderror_exits_on_426(monkeypatch):
    monkeypatch.setattr(http, "post", lambda path, body: json.dumps(VERSION_MISMATCH))
    with pytest.raises(SystemExit):
        api.sendError("hashcat exploded")


# ---------------------------------------------------------------------------
# report_benchmark
# ---------------------------------------------------------------------------

def test_report_benchmark_posts_results(monkeypatch):
    payload = {"type": "message", "status": 200, "msg": "OK"}
    captured = {}

    def fake_post(path, body):
        captured["path"] = path
        captured["body"] = body
        return json.dumps(payload)

    monkeypatch.setattr(http, "post", fake_post)
    results = {"1000": 28460000000, "1800": 95000}
    assert api.report_benchmark(results) == payload
    assert captured["path"] == "/v1/agents/benchmark"
    assert captured["body"] == {"benchmark_results": results}


def test_report_benchmark_exits_on_426_version_mismatch(monkeypatch):
    monkeypatch.setattr(http, "post", lambda path, body: json.dumps(VERSION_MISMATCH))
    with pytest.raises(SystemExit):
        api.report_benchmark({"1000": 1})


# ---------------------------------------------------------------------------
# parse_benchmark_speed (agent.bench)
# ---------------------------------------------------------------------------

def test_parse_benchmark_speed_sums_devices_and_units():
    out = ("Speed.#1.........:  1000 H/s (1.0ms)\n"
           "Speed.#2.........:  2.5 kH/s (1.0ms)\n")
    assert parse_benchmark_speed(out) == 1000 + 2500


def test_parse_benchmark_speed_excludes_aggregate_star_line():
    out = ("Speed.#1.........:  1.0 GH/s\n"
           "Speed.#2.........:  1.0 GH/s\n"
           "Speed.#*.........:  2.0 GH/s\n")   # aggregate must not be added
    assert parse_benchmark_speed(out) == 2 * 10**9


def test_parse_benchmark_speed_none_when_absent():
    assert parse_benchmark_speed("no speed lines here") is None


def test_parse_benchmark_speed_zero_is_reported():
    assert parse_benchmark_speed("Speed.#1.........:  0 H/s") == 0


# ---------------------------------------------------------------------------
# parse_device_info / _short_gpu_name (agent.bench)
# ---------------------------------------------------------------------------

def test_short_gpu_name_trims_vendor_prefix():
    from agent.bench import _short_gpu_name
    assert _short_gpu_name("NVIDIA GeForce RTX 4090") == "RTX 4090"
    assert _short_gpu_name("NVIDIA RTX A6000") == "RTX A6000"
    assert _short_gpu_name("AMD Radeon RX 6900 XT") == "RX 6900 XT"
    assert _short_gpu_name("Tesla A100") == "Tesla A100"   # no known prefix
    assert _short_gpu_name("") == ""


def test_parse_device_info_extracts_count_model_temps():
    from agent.bench import parse_device_info
    status = {"devices": [
        {"device_id": 1, "device_type": "GPU", "device_name": "NVIDIA GeForce RTX 4090", "speed": 1, "temp": 71},
        {"device_id": 2, "device_type": "GPU", "device_name": "NVIDIA GeForce RTX 4090", "speed": 1, "temp": 70},
        {"device_id": 3, "device_type": "CPU", "device_name": "Intel", "speed": 0, "temp": 55},
    ]}
    count, model, temps = parse_device_info(status)
    assert count == 2                 # GPUs only (CPU excluded)
    assert model == "RTX 4090"
    assert temps == "71,70"


def test_parse_device_info_falls_back_to_all_devices_when_untyped():
    from agent.bench import parse_device_info
    status = {"devices": [
        {"device_id": 1, "device_name": "NVIDIA GeForce RTX 3090", "speed": 1, "temp": 60},
    ]}
    count, model, temps = parse_device_info(status)
    assert count == 1 and model == "RTX 3090" and temps == "60"


def test_parse_device_info_empty():
    from agent.bench import parse_device_info
    assert parse_device_info({}) == (0, "", "")
    assert parse_device_info({"devices": []}) == (0, "", "")


# ---------------------------------------------------------------------------
# http._scheme (use_ssl interpretation)
# ---------------------------------------------------------------------------

def test_scheme_treats_yes_ish_values_as_https(monkeypatch):
    from agent.config import Config
    from agent.http import http as httpmod
    for val in ("True", "true", "TRUE", "yes", "Yes", "y", "Y", "1", "on", " true "):
        monkeypatch.setattr(Config, "USE_SSL", val)
        assert httpmod._scheme() == "https://", val


def test_scheme_defaults_to_http_for_falsey(monkeypatch):
    from agent.config import Config
    from agent.http import http as httpmod
    for val in ("False", "false", "no", "n", "0", "", None):
        monkeypatch.setattr(Config, "USE_SSL", val)
        assert httpmod._scheme() == "http://", val


# ---------------------------------------------------------------------------
# retry policy (ride out a server restart)
# ---------------------------------------------------------------------------

def test_retry_policy_retries_posts_and_transient_statuses():
    # POSTs must be retried, not just idempotent GETs: a RemoteDisconnected on a
    # heartbeat/upload POST while the server restarts must be ridden out, else the
    # monitor loop dies and orphans the running hashcat (the reported bug).
    from agent.http import http as httpmod
    assert httpmod.retries.allowed_methods is None      # None => retry every method
    assert 503 in httpmod.retries.status_forcelist      # server not-yet-ready gateway
    assert httpmod.retries.total and httpmod.retries.total >= 1
