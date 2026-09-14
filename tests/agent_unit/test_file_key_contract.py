"""The agent's half of the temp-file key contract.

The server names a job task's target hashfile, crack outfile and potfile after
that row's own id and bakes those paths into ``JobTasks.command``. The agent has
to arrive at the same key on its own. Until 0.8.4 it did that by re-running the
server's conditional from memory -- and a disagreement was silent, because both
sides just used their own path and neither checked the other's.

``job_task_file_key`` replaces that with three tiers, and these tests pin each
one plus the precedence between them. The tier that matters most is tier 2:
reading the key back out of the command makes agreement STRUCTURAL rather than a
convention two repositories have to maintain in step, and it is what protects the
newer-agent-against-older-server direction -- ``versionCheck`` only turns away
agents OLDER than the server, so a fleet upgraded ahead of the server is allowed.
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
        spec = importlib.util.spec_from_file_location("hashview_agent_main_filekey", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    return mod


agent_main = _load_agent_main()


def _command(job_id, key):
    """An argv shaped exactly as build_hashcat_command emits it."""
    return json.dumps([
        '@HASHCATBINPATH@', '-m', '1000', '-a', '0', '-O', '-w', '3',
        '--potfile-path', f'control/outfiles/hc_potfile_{job_id}_{key}.pot',
        '--outfile', f'control/outfiles/hc_cracked_{job_id}_{key}.txt',
        '--outfile-format', '1,3', '--status', '--status-timer=15',
        f'control/hashes/hashfile_{job_id}_{key}.txt',
        'control/wordlists/abc.gz', '-r', 'control/rules/best64.rule',
    ])


def test_tier1_explicit_file_key_wins():
    """A server that states the key outright is believed over everything else."""
    job_task = {'id': 42, 'task_id': 9, 'chunk_total': 3,
                'command': _command(7, 42), 'file_key': 99}
    assert agent_main.job_task_file_key(job_task) == 99


def test_tier2_reads_the_key_out_of_the_command():
    """With no file_key, the command itself is authoritative."""
    job_task = {'id': 42, 'task_id': 9, 'chunk_total': -1, 'command': _command(7, 42)}
    assert str(agent_main.job_task_file_key(job_task)) == '42'


def test_tier2_beats_a_disagreeing_chunk_total():
    """The command wins even when the legacy flag would say otherwise.

    This is the case that used to corrupt: chunk_total says "whole task, key on
    task_id" while hashcat was actually told to write to _42. The old agent would
    have looked for cracks in hc_cracked_7_9.txt, found nothing, and uploaded
    nothing -- forever, silently.
    """
    job_task = {'id': 42, 'task_id': 9, 'chunk_total': None, 'command': _command(7, 42)}
    assert str(agent_main.job_task_file_key(job_task)) == '42'


def test_tier3_falls_back_to_the_legacy_rule_for_an_older_server():
    """No file_key and no parseable command: behave exactly as 0.8.3 did."""
    whole = {'id': 42, 'task_id': 9, 'chunk_total': None, 'command': None}
    chunk = {'id': 42, 'task_id': 9, 'chunk_total': 5, 'command': None}
    assert agent_main.job_task_file_key(whole) == 9
    assert agent_main.job_task_file_key(chunk) == 42


def test_tier3_survives_a_command_it_cannot_parse():
    """A command with no crack file must not raise -- fall through to tier 3."""
    job_task = {'id': 42, 'task_id': 9, 'chunk_total': None,
                'command': json.dumps(['@HASHCATBINPATH@', '--version'])}
    assert agent_main.job_task_file_key(job_task) == 9


def test_key_matches_every_path_in_the_command():
    """All three paths share one key, and that is the key the agent returns."""
    job_task = {'id': 42, 'task_id': 9, 'chunk_total': -1, 'command': _command(7, 42)}
    key = str(agent_main.job_task_file_key(job_task))
    argv = json.loads(job_task['command'])
    assert argv[argv.index('--outfile') + 1].endswith(f'_{key}.txt')
    assert argv[argv.index('--potfile-path') + 1].endswith(f'_{key}.pot')
    assert [a for a in argv if a.startswith('control/hashes/')][0].endswith(f'_{key}.txt')
