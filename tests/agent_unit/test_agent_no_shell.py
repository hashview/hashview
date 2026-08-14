"""Agent-side half of the CWE-78 fix (install/hashview-agent/hashview-agent.py).

The server now validates and ``shlex.quote``s task masks/rules, but the string it
stores on ``JobTasks.command`` is only safe if the agent stops handing it to a
shell. These tests pin the agent end of that contract:

  * ``run_command`` / ``run_hashcat`` spawn with ``shell=False`` on an argv list.
  * a quoted argument built by the server survives ``shlex.split`` as ONE argv
    entry (the round trip that makes server-side quoting meaningful).
  * the rule/wordlist sync no longer shells out to ``gunzip``/``mv`` at all, so a
    server-supplied filename carrying shell metacharacters is just a filename.
  * no call anywhere in the script passes a truthy ``shell=``.
"""
import ast
import gzip
import importlib.util
import json
import os
import shlex
import sys
import types
from pathlib import Path
from unittest import mock

import pytest

AGENT_ROOT = Path(__file__).resolve().parents[2] / "install" / "hashview-agent"
AGENT_SCRIPT = AGENT_ROOT / "hashview-agent.py"


def _load_agent_main():
    """Import hashview-agent.py as a module.

    At import it parses argv, builds a Config from agent/config.conf and imports
    psutil, so argv is stubbed, os.path.exists is patched to claim the config
    file exists, and psutil is stubbed if the host lacks it.
    """
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
    with mock.patch.object(sys, "argv", ["hashview-agent.py"]), \
         mock.patch(
             "os.path.exists",
             side_effect=lambda p: True if str(p).endswith("agent/config.conf") else real_exists(p),
         ):
        spec = importlib.util.spec_from_file_location("hashview_agent_main_no_shell", AGENT_SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    return mod


agent_main = _load_agent_main()


class _FakeProc:
    """Stands in for a Popen handle; records nothing itself."""

    def __init__(self, stdout=b"", stderr=b""):
        self._stdout = stdout
        self.stdout = _Reader(stdout)
        self.stderr = _Reader(stderr)

    def communicate(self):
        return self._stdout, b""

    def wait(self):
        return 0


class _Reader:
    def __init__(self, data):
        self._data = data
        self._done = False

    def read(self, size=-1):
        if self._done:
            return b""
        self._done = True
        return self._data


@pytest.fixture()
def spawns(monkeypatch):
    """Capture every Popen call instead of running it."""
    calls = []

    def fake_popen(argv, **kwargs):
        calls.append((argv, kwargs))
        return _FakeProc()

    monkeypatch.setattr(agent_main.subprocess, "Popen", fake_popen)
    return calls


# --------------------------------------------------------------------------- #
# run_command: argv, never a shell string                                     #
# --------------------------------------------------------------------------- #


def test_run_command_spawns_argv_without_a_shell(spawns):
    agent_main.run_command("gunzip control/tmp/abc.gz")

    (argv, kwargs), = spawns
    assert argv == ["gunzip", "control/tmp/abc.gz"]
    assert kwargs["shell"] is False


def test_run_command_does_not_interpret_shell_metacharacters(spawns):
    """The payload becomes literal argv entries; there is no shell to run it."""
    agent_main.run_command("gunzip 'evil; touch pwned' `id`")

    (argv, kwargs), = spawns
    assert kwargs["shell"] is False
    assert argv == ["gunzip", "evil; touch pwned", "`id`"]
    assert not os.path.exists("pwned")


def test_run_command_passes_a_list_through_unchanged(spawns):
    agent_main.run_command(["mv", "a b", "c;d"])

    (argv, kwargs), = spawns
    assert argv == ["mv", "a b", "c;d"]
    assert kwargs["shell"] is False


# --------------------------------------------------------------------------- #
# run_hashcat: the sink for the server-built command string                    #
# --------------------------------------------------------------------------- #


def test_run_hashcat_spawns_argv_without_a_shell(spawns, tmp_path):
    status = tmp_path / "status.json"
    agent_main.run_hashcat("@HASHCATBINPATH@ -m 1000 -a 3 hashes.txt '?l?l ?d'", str(status))

    (argv, kwargs), = spawns
    assert kwargs["shell"] is False
    assert argv[0] == "/usr/bin/hashcat"      # from the stubbed Config
    assert argv[-1] == "--status-json"


def test_run_hashcat_keeps_a_server_quoted_mask_as_one_argument(spawns, tmp_path):
    """The other half of the server's ``shlex.quote``.

    ``build_hashcat_command`` quotes hc_mask, so a mask containing a space
    arrives as ``'?l?l ?d?d'``. shlex.split must hand hashcat exactly one
    positional argument — and an injection payload, had one been stored by a
    pre-fix server, arrives as inert text rather than a command.
    """
    status = tmp_path / "status.json"
    mask = "?l?l ?d?d"
    payload = "?a;touch pwned;#"
    command = (
        "@HASHCATBINPATH@ -m 1000 -a 3 hashes.txt "
        + shlex.quote(mask) + " " + shlex.quote(payload)
    )

    agent_main.run_hashcat(command, str(status))

    (argv, _kwargs), = spawns
    assert mask in argv
    assert payload in argv                    # one inert token, not a command
    assert not os.path.exists("pwned")


# --------------------------------------------------------------------------- #
# sync_rules / sync_wordlists: no gunzip/mv subprocesses at all                #
# --------------------------------------------------------------------------- #

RULE_BODY = b":\nu\nl\n"


def _sha256(data):
    import hashlib

    return hashlib.sha256(data).hexdigest()


@pytest.fixture()
def agent_cwd(tmp_path, monkeypatch):
    """A throwaway agent working tree with fresh, empty manifests."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "control" / "rules").mkdir(parents=True)
    (tmp_path / "control" / "wordlists").mkdir()
    (tmp_path / "control" / "tmp").mkdir()
    monkeypatch.setattr(agent_main, "rules_manifest",
                        agent_main.Manifest(str(tmp_path / "control" / "rules_manifest.json")))
    return tmp_path


@pytest.fixture()
def no_spawn(monkeypatch):
    """Any attempt to spawn a process during a sync is a hard failure."""
    def forbidden(*args, **kwargs):
        raise AssertionError(f"sync spawned a process: {args!r} {kwargs!r}")

    monkeypatch.setattr(agent_main.subprocess, "Popen", forbidden)
    monkeypatch.setattr(agent_main.os, "system", forbidden, raising=False)


def _serve_one_rule(monkeypatch, path, body=RULE_BODY, checksum=None):
    """Stub the server side: one rule whose file is the gzip of ``body``."""
    entry = {"id": 7, "path": path, "checksum": checksum or _sha256(body)}
    monkeypatch.setattr(agent_main.api, "rules_list", lambda: json.dumps([entry]))
    monkeypatch.setattr(agent_main.api, "get_rules_file", lambda rule_id: gzip.compress(body))
    return entry


def test_rules_sync_installs_a_rule_without_spawning_anything(agent_cwd, no_spawn, monkeypatch):
    _serve_one_rule(monkeypatch, "control/rules/best64.rule")

    agent_main.sync_rules()

    assert (agent_cwd / "control" / "rules" / "best64.rule").read_bytes() == RULE_BODY
    assert agent_main.rules_manifest.data["7"]["filename"] == "best64.rule"
    # the temp download is consumed, not left behind in control/tmp
    assert list((agent_cwd / "control" / "tmp").iterdir()) == []


def test_rules_sync_treats_shell_metacharacters_as_a_literal_filename(agent_cwd, no_spawn,
                                                                     monkeypatch):
    """``mv {tmp_file} {dest}`` under shell=True ran the server-supplied path.

    With no shell in the loop the payload can only ever be an (ugly) filename.
    """
    payload = "evil; touch pwned #`id`$(id)"
    _serve_one_rule(monkeypatch, f"control/rules/{payload}")

    agent_main.sync_rules()

    rules_dir = agent_cwd / "control" / "rules"
    assert (rules_dir / payload).read_bytes() == RULE_BODY
    assert not (agent_cwd / "pwned").exists()
    assert not (rules_dir / "pwned").exists()


def test_rules_sync_discards_a_checksum_mismatch(agent_cwd, no_spawn, monkeypatch):
    _serve_one_rule(monkeypatch, "control/rules/abc123", checksum="0" * 64)

    agent_main.sync_rules()

    assert agent_main.rules_manifest.data == {}
    assert list((agent_cwd / "control" / "rules").iterdir()) == []
    assert list((agent_cwd / "control" / "tmp").iterdir()) == []


# --------------------------------------------------------------------------- #
# _gunzip_file replaced `run_command(f'gunzip {tmp_gz}')`                      #
# --------------------------------------------------------------------------- #


def test_gunzip_file_decompresses_in_process_and_removes_the_archive(tmp_path, no_spawn):
    gz_path = tmp_path / "payload.gz"
    gz_path.write_bytes(gzip.compress(RULE_BODY))

    out_path = agent_main._gunzip_file(str(gz_path))

    assert Path(out_path) == tmp_path / "payload"
    assert Path(out_path).read_bytes() == RULE_BODY
    assert not gz_path.exists()


def test_gunzip_file_handles_a_name_with_shell_metacharacters(tmp_path, no_spawn):
    """A filename that would have been a command substitution under the old
    ``gunzip {tmp_gz}`` is now just a path."""
    gz_path = tmp_path / "a b;`id`.gz"
    gz_path.write_bytes(gzip.compress(RULE_BODY))

    out_path = agent_main._gunzip_file(str(gz_path))

    assert Path(out_path).read_bytes() == RULE_BODY
    assert not (tmp_path / "pwned").exists()


def test_gunzip_file_raises_on_a_corrupt_archive(tmp_path, no_spawn):
    """The failure is a normal exception, not an unnoticed non-zero exit code
    from a shelled-out gunzip."""
    gz_path = tmp_path / "corrupt.gz"
    gz_path.write_bytes(b"not gzip at all")

    with pytest.raises(gzip.BadGzipFile):
        agent_main._gunzip_file(str(gz_path))


# --------------------------------------------------------------------------- #
# Nothing may re-add a shell                                                  #
# --------------------------------------------------------------------------- #


def test_agent_script_never_passes_shell_true():
    """Checked via the AST rather than a substring so prose about the old
    behaviour in comments/docstrings doesn't trip it."""
    tree = ast.parse(AGENT_SCRIPT.read_text())
    shell_calls = [
        ast.dump(node) for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        for kw in node.keywords
        if kw.arg == "shell" and not (isinstance(kw.value, ast.Constant) and not kw.value.value)
    ]
    assert shell_calls == [], f"agent spawns a process through a shell: {shell_calls!r}"


def test_agent_script_does_not_call_os_system():
    tree = ast.parse(AGENT_SCRIPT.read_text())
    os_system_calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "system"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "os"
    ]
    assert os_system_calls == [], "agent uses os.system (a shell) to spawn a process"
