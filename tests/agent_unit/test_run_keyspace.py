"""The agent's keyspace probe.

The server cannot compute a mask attack's keyspace: hashcat splits a mask between
its base loop -- which is what --skip/--limit index -- and its own device-side
loop, based on the hash mode and on -S, not on the mask alone. So an agent runs
`hashcat --keyspace` and posts the integer back.

Every failure path here reports NOTHING. An attack the server has no usable
measurement for keeps running whole, which emits no --skip/--limit and is correct
whatever the unit turns out to be -- so staying quiet is the safe answer, and
guessing would not be.
"""
import importlib.util
import json
import os
import sys
import types
from pathlib import Path
from unittest import mock

AGENT_ROOT = Path(__file__).resolve().parents[2] / "install" / "hashview-agent"


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
        spec = importlib.util.spec_from_file_location("hashview_agent_main_keyspace", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    return mod


agent_main = _load_agent_main()

COMMAND = json.dumps(['@HASHCATBINPATH@', '-O', '-w', '3', '-m', '0', '-a', '3',
                      '?a?a?a?a?a?a', '--keyspace'])


def _proc(stdout=b"", stderr=b""):
    p = mock.MagicMock()
    p.stdout, p.stderr = stdout, stderr
    return p


def test_runs_the_server_argv_and_reports_the_integer(monkeypatch):
    runs, reported = [], []
    monkeypatch.setattr(agent_main.subprocess, "run",
                        lambda argv, **kw: runs.append(argv) or _proc(b"81450625\n"))
    monkeypatch.setattr(agent_main.api, "report_keyspace",
                        lambda ledger_id, keyspace: reported.append((ledger_id, keyspace)))

    agent_main.run_keyspace(7, COMMAND)

    assert reported == [(7, 81450625)]
    argv = runs[0]
    assert argv[-1] == "--keyspace"
    assert "?a?a?a?a?a?a" in argv
    assert not any(str(a).startswith("control/hashes/") for a in argv), (
        "--keyspace takes no hashfile positional; passing one is a usage error")


def test_an_unparseable_answer_reports_nothing(monkeypatch):
    reported = []
    monkeypatch.setattr(agent_main.subprocess, "run",
                        lambda argv, **kw: _proc(b"", b"clGetPlatformIDs(): CL_PLATFORM_NOT_FOUND\n"))
    monkeypatch.setattr(agent_main.api, "report_keyspace",
                        lambda ledger_id, keyspace: reported.append((ledger_id, keyspace)))

    agent_main.run_keyspace(7, COMMAND)

    assert reported == [], "silence leaves the attack running whole, which is safe"


def test_a_crashing_hashcat_reports_nothing(monkeypatch):
    reported = []

    def boom(argv, **kw):
        raise OSError("no such binary")

    monkeypatch.setattr(agent_main.subprocess, "run", boom)
    monkeypatch.setattr(agent_main.api, "report_keyspace",
                        lambda ledger_id, keyspace: reported.append((ledger_id, keyspace)))

    agent_main.run_keyspace(7, COMMAND)
    assert reported == []


def test_a_missing_command_reports_nothing(monkeypatch):
    reported = []
    monkeypatch.setattr(agent_main.api, "report_keyspace",
                        lambda ledger_id, keyspace: reported.append((ledger_id, keyspace)))
    agent_main.run_keyspace(7, None)
    agent_main.run_keyspace(None, COMMAND)
    assert reported == []


def test_a_warning_before_the_number_is_still_parsed(monkeypatch):
    """Some builds emit OpenCL or deprecation noise before the answer."""
    reported = []
    monkeypatch.setattr(agent_main.subprocess, "run",
                        lambda argv, **kw: _proc(b"clWaitForEvents(): CL_OUT_OF_RESOURCES\n\n81450625\n"))
    monkeypatch.setattr(agent_main.api, "report_keyspace",
                        lambda ledger_id, keyspace: reported.append((ledger_id, keyspace)))

    agent_main.run_keyspace(7, COMMAND)
    assert reported == [(7, 81450625)]


def test_the_heartbeat_dispatches_a_keyspace_reply(monkeypatch):
    """KEYSPACE slots into the same elif chain as BENCHMARK: the server asks the
    agent a question instead of giving it work."""
    calls = []
    monkeypatch.setattr(agent_main, "getHashcatPid", lambda: None)
    monkeypatch.setattr(agent_main, "send_heartbeat",
                        lambda status, hc: {"msg": "KEYSPACE", "ledger_id": 3,
                                            "command": COMMAND})
    monkeypatch.setattr(agent_main, "run_keyspace",
                        lambda ledger_id, command: calls.append((ledger_id, command)))

    agent_main.handle_heartbeat()
    assert calls == [(3, COMMAND)]


def test_the_heartbeat_reports_the_hashcat_version(monkeypatch):
    """The server gates measured slices on the agent's hashcat MAJOR."""
    sent = {}
    agent_main._HC_VERSION = None
    monkeypatch.setattr(agent_main.subprocess, "run",
                        lambda argv, **kw: _proc(b"hashcat (v6.2.6) starting\n"))
    monkeypatch.setattr(agent_main.api, "heartbeat",
                        lambda status, hc, hc_version=None: sent.update(v=hc_version))

    agent_main.send_heartbeat("Idle", "")
    assert sent["v"] == "v6.2.6"
    agent_main._HC_VERSION = None


def test_an_unprobeable_hashcat_reports_no_version(monkeypatch):
    """NULL is safe: the server then never sends this agent a measured slice."""
    sent = {}
    agent_main._HC_VERSION = None

    def boom(argv, **kw):
        raise OSError("nope")

    monkeypatch.setattr(agent_main.subprocess, "run", boom)
    monkeypatch.setattr(agent_main.api, "heartbeat",
                        lambda status, hc, hc_version=None: sent.update(v=hc_version))

    agent_main.send_heartbeat("Idle", "")
    assert sent["v"] is None
    agent_main._HC_VERSION = None
