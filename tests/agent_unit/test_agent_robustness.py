"""Regression tests for issue #280 — agent HTTP/API layer robustness.

These pin the fixed behaviour so the opaque TypeErrors don't come back:
  - http.get/post return None (not raise) on a non-200 or a connection error.
  - api.* return None (not TypeError) on a None body, a non-JSON body, or a 200
    reply whose shape is wrong (e.g. the server's authorized-but-Error body).
  - the hashview-agent.py call sites tolerate a None api result.
  - agent/config.py exits with a clear message on a missing file/section/key.

The api/http tests monkeypatch at the agent.http.http boundary (the same object
api.py bound). The main-script tests load hashview-agent.py the same way the
issue-xfail suite does (argv/config/psutil stubbed). The config test loads the
REAL agent/config.py by path, since conftest stubs agent.config in sys.modules.
"""
import builtins
import importlib.util
import json
import os
import sys
import types
from pathlib import Path
from unittest import mock

import pytest
import requests
from agent.api import api
from agent.http import http

AGENT_ROOT = Path(__file__).resolve().parents[2] / "install" / "hashview-agent"


# ---------------------------------------------------------------------------
# http.py — fail soft (return None), never bubble a raw exception / non-200
# ---------------------------------------------------------------------------
class _FakeResponse:
    def __init__(self, status_code, text="", content=b""):
        self.status_code = status_code
        self.text = text
        self.content = content


@pytest.fixture
def _http_env(monkeypatch):
    # get()/post() open VERSION.TXT relative to CWD and read builtins.state.
    monkeypatch.chdir(AGENT_ROOT)
    monkeypatch.setattr(builtins, "state", "normal", raising=False)


def test_http_get_returns_none_on_non_200(_http_env, monkeypatch):
    monkeypatch.setattr(http.http, "get", lambda *a, **k: _FakeResponse(500, text="boom"))
    assert http.get("/v1/rules") is None


def test_http_get_returns_none_on_connection_error(_http_env, monkeypatch):
    def boom(*a, **k):
        raise requests.exceptions.ConnectionError("connection refused")
    monkeypatch.setattr(http.http, "get", boom)
    assert http.get("/v1/rules") is None


def test_http_post_returns_none_on_non_200(_http_env, monkeypatch):
    monkeypatch.setattr(http.http, "post", lambda *a, **k: _FakeResponse(503, text="unavailable"))
    assert http.post("/v1/agents/heartbeat", {"agent_status": "Idle"}) is None


def test_http_post_returns_none_on_connection_error(_http_env, monkeypatch):
    def boom(*a, **k):
        raise requests.exceptions.ConnectionError("connection refused")
    monkeypatch.setattr(http.http, "post", boom)
    assert http.post("/v1/error", {"error": "x"}) is None


# ---------------------------------------------------------------------------
# api.py — every function is None-safe (issue's problems A and C at the source)
# ---------------------------------------------------------------------------
ERROR_SHAPE_200 = json.dumps({"status": 200, "type": "Error", "msg": "not authorized"})

_EXTRACT_CALLS = [
    lambda: api.server_settings(),
    lambda: api.rules_list(),
    lambda: api.getWordlists(),
    lambda: api.jobTasks(1),
    lambda: api.jobs(1),
    lambda: api.tasks(1),
]


@pytest.mark.parametrize("body", [None, "<html>500</html>", ERROR_SHAPE_200])
def test_extract_family_returns_none_on_bad_response(monkeypatch, body):
    # None (non-200), non-JSON, and a 200 Error-shape (missing the data key) all
    # degrade to None instead of TypeError/KeyError.
    monkeypatch.setattr(http, "get", lambda path: body)
    for call in _EXTRACT_CALLS:
        assert call() is None


# A None body (non-200) and a non-JSON body are the #280-A crash cases: json.loads
# on them used to TypeError. Every envelope function must now yield None instead.
# (A 200 with a wrong *shape* is handled per-function and pinned in test_agent_api.py:
# report_benchmark/updateJobTask/sendError return the decoded dict on that fallthrough,
# so it is deliberately not asserted as None here.)
@pytest.mark.parametrize("body", [None, "<html>500</html>"])
def test_envelope_family_returns_none_on_bad_response(monkeypatch, body):
    monkeypatch.setattr(http, "get", lambda path: body)
    monkeypatch.setattr(http, "post", lambda path, data: body)
    assert api.report_benchmark({}) is None
    assert api.updateJobTask(1, "Running") is None
    assert api.sendError("x") is None
    assert api.getHashType(1) is None
    assert api.updateDynamicWordlists(1) is None


@pytest.mark.parametrize("body", [None, "<html>500</html>"])
def test_heartbeat_returns_safe_sentinel_on_bad_response(monkeypatch, body):
    # heartbeat is special: it returns a no-op dict (not None) so handle_heartbeat
    # can read ['msg'] and simply find nothing to do this beat.
    monkeypatch.setattr(http, "post", lambda path, data: body)
    assert api.heartbeat("Idle", "") == {"type": "message", "status": 200, "msg": None}


def test_uploadcrackfile_returns_none_on_bad_response(monkeypatch, tmp_path):
    crack = tmp_path / "cracks.txt"
    crack.write_text("hash:plain\n")
    monkeypatch.setattr(http, "post", lambda path, data: None)
    assert api.uploadCrackFile(str(crack), 11) is None


# ---------------------------------------------------------------------------
# hashview-agent.py call sites — tolerate a None api result (problem C)
# ---------------------------------------------------------------------------
def _load_agent_main():
    if "psutil" not in sys.modules:
        stub = types.ModuleType("psutil")

        class _PsutilError(Exception):
            pass

        stub.Error = _PsutilError
        stub.NoSuchProcess = type("NoSuchProcess", (_PsutilError,), {})
        stub.AccessDenied = type("AccessDenied", (_PsutilError,), {})
        stub.ZombieProcess = type("ZombieProcess", (_PsutilError,), {})
        stub.process_iter = lambda *a, **k: []
        sys.modules["psutil"] = stub

    real_exists = os.path.exists
    path = AGENT_ROOT / "hashview-agent.py"
    with mock.patch.object(sys, "argv", ["hashview-agent.py"]), \
         mock.patch(
             "os.path.exists",
             side_effect=lambda p: True if str(p).endswith("agent/config.conf") else real_exists(p),
         ):
        spec = importlib.util.spec_from_file_location("hashview_agent_main_robustness", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    return mod


agent_main = _load_agent_main()


def test_run_assigned_task_aborts_when_jobtask_missing(monkeypatch):
    # jobTasks() -> None must abort before hashcat is ever built/launched.
    monkeypatch.setattr(agent_main, "sync_rules", lambda: None)
    monkeypatch.setattr(agent_main, "sync_wordlists", lambda: None)
    monkeypatch.setattr(agent_main, "jobTasks", lambda job_task_id: None)

    def _boom(*a, **k):
        raise AssertionError("hashcat argv must not be built when the fetch failed")
    monkeypatch.setattr(agent_main, "build_hashcat_argv", _boom)

    agent_main.run_assigned_task(42)   # must return cleanly, no TypeError, no launch


def test_upload_cracks_defers_when_hashtype_missing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "control" / "outfiles").mkdir(parents=True)
    (tmp_path / "control" / "outfiles" / "hc_cracked_1_9.txt").write_text("h:p\n")
    monkeypatch.setattr(agent_main, "getHashType", lambda hashfile_id: None)

    def _boom(*a, **k):
        raise AssertionError("must not upload when the hash type couldn't be confirmed")
    monkeypatch.setattr(agent_main, "uploadCrackFile", _boom)

    agent_main.upload_cracks({"id": 1, "hashfile_id": 2}, {"id": 5, "task_id": 9})   # no raise


def test_maybe_update_dynamic_wordlist_handles_none(monkeypatch):
    monkeypatch.setattr(agent_main, "getWordlists",
                        lambda: [{"id": 3, "type": "dynamic"}])
    monkeypatch.setattr(agent_main, "updateDynamicWordlists", lambda wid: None)
    monkeypatch.setattr(agent_main, "sync_wordlists", lambda: None)
    agent_main.maybe_update_dynamic_wordlist({"wl_id": 3})   # no None['msg'] -> TypeError


# ---------------------------------------------------------------------------
# config.py — clear, fatal message on a missing file/section/key (problem D)
# ---------------------------------------------------------------------------
def _load_real_config():
    # conftest stubs agent.config in sys.modules, so load the real module by path
    # under a throwaway name. Its class body runs on import and may sys.exit().
    path = AGENT_ROOT / "agent" / "config.py"
    spec = importlib.util.spec_from_file_location("hv_agent_config_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_config_exits_on_missing_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)   # no agent/config.conf present
    with pytest.raises(SystemExit):
        _load_real_config()


def test_config_exits_on_missing_key(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "agent").mkdir()
    # [HASHVIEW] present but missing use_ssl, and no [AGENT] section at all.
    (tmp_path / "agent" / "config.conf").write_text(
        "[HASHVIEW]\nserver = 1.2.3.4\nport = 8443\n")
    with pytest.raises(SystemExit):
        _load_real_config()


def test_config_loads_a_complete_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "agent").mkdir()
    (tmp_path / "agent" / "config.conf").write_text(
        "[HASHVIEW]\nserver = 1.2.3.4\nport = 8443\nuse_ssl = True\n\n"
        "[AGENT]\nname = a\nuuid = u\nHC_BIN_PATH = /usr/bin/hashcat\n")
    mod = _load_real_config()
    assert mod.Config.HASHVIEW_SERVER == "1.2.3.4"
    assert mod.Config.HC_EXTRA_ARGS == ""   # optional key defaults cleanly
