"""xfail tests pinning the agent robustness bugs from issues #280 and #281.

Each test asserts the DESIRED behavior, which currently fails because the bug
is present, so it is marked ``@pytest.mark.xfail(strict=True)``. When a bug is
fixed the test starts passing and strict-xfail turns the unexpected pass into a
failure — a built-in reminder to drop the marker.

#280 — agent HTTP/API layer not robust to non-200 / unexpected responses:
  A. api.* call json.loads() on the None that http.get/post return on non-200.
  B. download-to-disk call sites write that None straight to a file.
  C. callers index (`['msg']`) an api result that can be None even on a 200.
  A/B/C are now FIXED — the tests below are regression guards, not xfails (see
  also tests/agent_unit/test_agent_robustness.py for the wider coverage).

#281 — agent process-control reliability:
  D. the hashcat runner treats ANY stderr as fatal and SIGINTs the agent (the
     logic moved from the old shell-based run_command to run_hashcat(argv)).
  E. getHashcatPid aborts its whole scan on the first inaccessible process.

The api/http modules import cleanly (agent.config is stubbed by conftest). The
functions in hashview-agent.py need the script imported; it parses argv and has
an interactive first-run gate at import time, and imports psutil, so we load it
once below with argv/os.path.exists patched and a psutil stub installed.
"""
import importlib.util
import os
import sys
import types
from pathlib import Path
from unittest import mock

import pytest
from agent.api import api
from agent.http import http

AGENT_ROOT = Path(__file__).resolve().parents[2] / "install" / "hashview-agent"


def _load_agent_main():
    # The real agent imports psutil (not a test dependency). A stub both removes
    # the dependency and lets the getHashcatPid test drive process_iter.
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
        spec = importlib.util.spec_from_file_location("hashview_agent_main", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    return mod


agent_main = _load_agent_main()


# ---------------------------------------------------------------------------
# #280 A — api.* must not crash with a raw TypeError on a non-200 (None) reply
# ---------------------------------------------------------------------------
def test_heartbeat_handles_non_200_without_typeerror(monkeypatch):
    # #280 A is FIXED on this dev line: heartbeat() now guards json.loads(None)
    # (http.post returns None on a non-200) and returns a graceful sentinel
    # instead of raising TypeError. This is now a regression guard, not an xfail.
    monkeypatch.setattr(http, "post", lambda path, body: None)   # non-200 -> None
    result = api.heartbeat("Idle", "")   # must not raise
    # Graceful sentinel carries no actionable message.
    assert result is None or result.get("msg") is None


# ---------------------------------------------------------------------------
# #280 B — a failed download must not be written to disk as None (FIXED)
# ---------------------------------------------------------------------------
def test_download_hashfile_handles_failed_download(tmp_path, monkeypatch):
    # #280 B FIXED: a failed download (get_hashfile -> None) is not written to
    # disk; download_hashfile returns False so the caller skips the run. Now a
    # regression guard, not an xfail.
    monkeypatch.chdir(tmp_path)
    (tmp_path / "control" / "hashes").mkdir(parents=True)
    monkeypatch.setattr(agent_main.api, "get_hashfile", lambda hashfile_id: None)
    assert agent_main.download_hashfile(1, 2, 3) is False   # handled, no write(None) -> TypeError
    assert not (tmp_path / "control" / "hashes" / "hashfile_1_2.txt").exists()


# ---------------------------------------------------------------------------
# #280 C — callers must not index a response that can be None (FIXED)
# ---------------------------------------------------------------------------
def test_handle_heartbeat_handles_none_response(monkeypatch):
    # #280 C FIXED: handle_heartbeat tolerates a None reply from send_heartbeat
    # (getHashcatPid() runs first; the default psutil stub yields no processes).
    # Now a regression guard, not an xfail.
    monkeypatch.setattr(agent_main, "send_heartbeat", lambda *a, **k: None)
    agent_main.handle_heartbeat()   # must not raise (was None['msg'] -> TypeError)


# ---------------------------------------------------------------------------
# #281 D — benign hashcat stderr must not make the agent SIGINT itself
# ---------------------------------------------------------------------------
@pytest.mark.xfail(strict=True,
                   reason="#281 D: run_hashcat treats any stderr as fatal and "
                          "os.kill(SIGINT)s the agent on benign hashcat warnings")
def test_run_hashcat_does_not_selfkill_on_benign_stderr(tmp_path, monkeypatch):
    killed = []
    monkeypatch.setattr(agent_main.os, "kill", lambda pid, sig: killed.append((pid, sig)))
    monkeypatch.setattr(agent_main.api, "sendError", lambda msg: None)

    class FakeProc:
        returncode = 0

        def communicate(self):
            # Real hashcat emits benign notices to stderr (OpenCL/CUDA/driver).
            return (b"", b"oclHashcat: benign device warning\n")

    monkeypatch.setattr(agent_main.subprocess, "Popen", lambda *a, **k: FakeProc())
    # run_hashcat is the only process-spawning path left (the shell-based
    # run_command sink is gone), so the fatal-stderr handling lives here now.
    agent_main.run_hashcat(["/usr/bin/hashcat", "-m", "1000"],
                           str(tmp_path / "hc_status.json"))
    assert killed == [], "agent self-killed on benign hashcat stderr"


# ---------------------------------------------------------------------------
# #281 E — getHashcatPid must skip an inaccessible process, not abort the scan
# ---------------------------------------------------------------------------
@pytest.mark.xfail(strict=True,
                   reason="#281 E: getHashcatPid's `except: return False` is inside "
                          "the loop, so one inaccessible process ends the scan")
def test_gethashcatpid_skips_inaccessible_processes(monkeypatch):
    class Bad:
        def as_dict(self, attrs=None):
            raise agent_main.psutil.AccessDenied()

    class Good:
        def as_dict(self, attrs=None):
            return {"pid": 4242, "name": "hashcat",
                    "cmdline": ["hashcat", "--outfile", "control/outfiles/hc_cracked_1_2.txt"]}

    monkeypatch.setattr(agent_main.psutil, "process_iter", lambda *a, **k: [Bad(), Good()])
    assert agent_main.getHashcatPid() == 4242   # desired: skip Bad, find Good
