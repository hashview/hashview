"""The agent's half of the temp-file key contract.

The server names a job task's target hashfile, crack outfile and potfile after
that row's own id and bakes those paths into ``JobTasks.command``. The agent has
to arrive at the same key on its own. Until 0.8.4 it did that by re-running the
server's conditional from memory -- and a disagreement was silent, because both
sides just used their own path and neither checked the other's.

``job_task_file_key`` replaces that with three tiers, and these tests pin each
one plus the precedence between them. Tier 1 is the command: hashcat is handed
--outfile and --potfile-path explicitly, so the command does not hint at the key,
it IS the key -- whatever the agent names its files, hashcat reads and writes the
paths in there. That makes agreement STRUCTURAL rather than a convention two
repositories maintain in step, and it protects the newer-agent-against-older-server
direction -- ``versionCheck`` only turns away agents OLDER than the server, so a
fleet upgraded ahead of the server is allowed.

The wire ``file_key`` sits BELOW the command deliberately. It led briefly, and
that inversion broke CI: a command built without an explicit job_task_id keys on
the task id, the wire field said the row id, and the agent believed the field --
saving the hashfile under a name hashcat was never told to open. The server now
derives that field from this same command, so it is a second chance at one
answer, never a competing one.
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


def test_the_command_outranks_a_disagreeing_file_key():
    """THE regression: when the two disagree, the command wins.

    This is the exact shape that broke the e2e-crack CI job. The command was built
    without an explicit job_task_id, so it keyed on the task id (42 here stands in
    for whichever key the command actually carries), while the wire field asserted
    the row id. Believing the field made the agent download the hashfile to a path
    hashcat was never told to open -- FileNotFoundError for the target, and for the
    outfile, nothing at all: hashcat wrote its cracks where we never looked.
    """
    job_task = {'id': 42, 'task_id': 9, 'chunk_total': 3,
                'command': _command(7, 42), 'file_key': 99}
    assert str(agent_main.job_task_file_key(job_task)) == '42'


def test_tier1_reads_the_key_out_of_the_command():
    """With no file_key at all, the command is still the answer."""
    job_task = {'id': 42, 'task_id': 9, 'chunk_total': -1, 'command': _command(7, 42)}
    assert str(agent_main.job_task_file_key(job_task)) == '42'


def test_tier1_beats_a_disagreeing_chunk_total():
    """The command wins even when the legacy flag would say otherwise.

    This is the case that used to corrupt: chunk_total says "whole task, key on
    task_id" while hashcat was actually told to write to _42. The old agent would
    have looked for cracks in hc_cracked_7_9.txt, found nothing, and uploaded
    nothing -- forever, silently.
    """
    job_task = {'id': 42, 'task_id': 9, 'chunk_total': None, 'command': _command(7, 42)}
    assert str(agent_main.job_task_file_key(job_task)) == '42'


def test_a_mask_literal_cannot_hijack_the_key():
    """A task field that looks like a crack filename must not be mistaken for one.

    The mask, and the j/k rules, are literal argv elements carrying operator text.
    Scanning the whole command for the first hc_cracked_ match would read an
    attacker- or accident-supplied mask as the key; indexing --outfile cannot.
    Today every free-form field lands after --outfile so a scan is also correct,
    but by argv ordering rather than by construction -- pin the stronger rule.
    """
    argv = json.loads(_command(7, 42))
    argv.insert(1, 'hc_cracked_9_999.txt')      # ahead of --outfile
    argv.append('?l?l?lhc_cracked_8_888.txt')   # and behind it
    assert str(agent_main.job_task_file_key(
        {'id': 42, 'task_id': 9, 'chunk_total': -1, 'command': json.dumps(argv)})) == '42'


def test_tier2_uses_the_wire_key_when_the_command_cannot_be_parsed():
    """No --outfile in the command: fall through to the server's stated key.

    The server reads its file_key out of this same command, so when it HAS one and
    we cannot parse one, its answer is strictly better than re-deriving ours.
    """
    job_task = {'id': 42, 'task_id': 9, 'chunk_total': None,
                'command': json.dumps(['@HASHCATBINPATH@', '--version']),
                'file_key': 99}
    assert agent_main.job_task_file_key(job_task) == 99


def test_tier3_falls_back_to_the_legacy_rule_for_an_older_server():
    """Neither a parseable command nor a file_key: behave exactly as 0.8.3 did."""
    whole = {'id': 42, 'task_id': 9, 'chunk_total': None, 'command': None}
    chunk = {'id': 42, 'task_id': 9, 'chunk_total': 5, 'command': None}
    assert agent_main.job_task_file_key(whole) == 9
    assert agent_main.job_task_file_key(chunk) == 42


def test_tier3_survives_a_command_it_cannot_parse():
    """A command with no crack file and no file_key must not raise."""
    job_task = {'id': 42, 'task_id': 9, 'chunk_total': None,
                'command': json.dumps(['@HASHCATBINPATH@', '--version'])}
    assert agent_main.job_task_file_key(job_task) == 9


def test_a_non_json_command_still_yields_its_key():
    """A row whose command is not a JSON argv list falls back to a plain scan."""
    job_task = {'id': 42, 'task_id': 9, 'chunk_total': None,
                'command': 'hashcat --outfile control/outfiles/hc_cracked_7_42.txt'}
    assert str(agent_main.job_task_file_key(job_task)) == '42'


def test_key_matches_every_path_in_the_command():
    """All three paths share one key, and that is the key the agent returns."""
    job_task = {'id': 42, 'task_id': 9, 'chunk_total': -1, 'command': _command(7, 42)}
    key = str(agent_main.job_task_file_key(job_task))
    argv = json.loads(job_task['command'])
    assert argv[argv.index('--outfile') + 1].endswith(f'_{key}.txt')
    assert argv[argv.index('--potfile-path') + 1].endswith(f'_{key}.pot')
    assert [a for a in argv if a.startswith('control/hashes/')][0].endswith(f'_{key}.txt')
