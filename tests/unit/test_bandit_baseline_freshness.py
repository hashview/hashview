"""The committed bandit baseline must contain only findings that still reproduce.

Bandit matches a finding to a baseline entry on (filename, test_id, issue_text)
and ignores the line number. An entry whose code has since been fixed therefore
does not become inert — it stays a file-scoped exemption for that test ID, and a
later regression of the same class inside that file passes the gate silently.
See issue #426.

The heavy end-to-end check (actually rerunning bandit) lives in CI as
`scripts/check_bandit_baseline.py`. These tests cover that script's matching
logic without paying for a scan, plus a cheap structural assertion on the
committed baseline itself.
"""

import importlib.util
import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BASELINE_PATH = REPO_ROOT / '.bandit-baseline.json'
CHECKER_PATH = REPO_ROOT / 'scripts' / 'check_bandit_baseline.py'


def _load_checker():
    """Import the CI script by path; it lives outside any importable package."""
    spec = importlib.util.spec_from_file_location('check_bandit_baseline', CHECKER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CHECKER = _load_checker()


def _finding(filename, test_id, text, line=1):
    return {
        'filename': filename,
        'test_id': test_id,
        'issue_text': text,
        'line_number': line,
    }


def test_checker_script_exists():
    """CI references the script by path; a rename must break a test, not the gate."""
    assert CHECKER_PATH.is_file()


def test_finding_key_ignores_line_number():
    """Bandit matches on file/test/message only, so the key must not include the line.

    This is the exact property that makes a stale entry dangerous, so the
    detector has to model it rather than compare whole records.
    """
    moved = _finding('a.py', 'B605', 'Starting a process with a shell', line=166)
    same = _finding('a.py', 'B605', 'Starting a process with a shell', line=243)
    assert CHECKER.finding_key(moved) == CHECKER.finding_key(same)


def test_finding_key_separates_test_ids_and_files():
    base = _finding('a.py', 'B605', 'msg')
    assert CHECKER.finding_key(base) != CHECKER.finding_key(_finding('b.py', 'B605', 'msg'))
    assert CHECKER.finding_key(base) != CHECKER.finding_key(_finding('a.py', 'B607', 'msg'))


def test_stale_entry_is_detected():
    """An entry with no live counterpart is stale even though nothing else changed."""
    committed = [
        _finding('agent.py', 'B602', 'subprocess call with shell=True identified'),
        _finding('backup.py', 'B603', 'subprocess call - check for execution'),
    ]
    live_keys = {CHECKER.finding_key(committed[1])}
    stale = [r for r in committed if CHECKER.finding_key(r) not in live_keys]
    assert [r['test_id'] for r in stale] == ['B602']


def test_baseline_holds_no_high_severity_findings():
    """HIGH findings belong in a fix or a tracked issue, never silently in the baseline."""
    results = json.loads(BASELINE_PATH.read_text())['results']
    high = [
        f"{r['test_id']} {r['filename']}:{r['line_number']}"
        for r in results
        if r.get('issue_severity') == 'HIGH'
    ]
    assert not high, f'HIGH-severity findings baselined: {high}'


def test_no_nosec_comment_carries_trailing_prose():
    """`# nosec BXXX - prose` makes bandit warn once per word; keep the prose on its own line.

    Bandit splits everything after `# nosec` on whitespace and commas and tries
    to resolve each token as a test ID, so explanatory text produces a wall of
    "Test in comment" warnings that hide real ones.
    """
    pattern = re.compile(r'#\s*nosec\s+B\d+\s*[-,]\s*\S')
    scanned = ['hashview', 'install/hashview-agent', 'scripts']
    offenders = []
    for target in scanned:
        for path in (REPO_ROOT / target).rglob('*.py'):
            for number, line in enumerate(path.read_text(errors='replace').splitlines(), 1):
                if pattern.search(line):
                    offenders.append(f'{path.relative_to(REPO_ROOT)}:{number}')
    assert not offenders, 'nosec comments with trailing prose: ' + ', '.join(offenders)
