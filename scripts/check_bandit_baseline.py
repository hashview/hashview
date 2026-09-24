#!/usr/bin/env python3
"""Fail when .bandit-baseline.json holds findings that no longer reproduce.

Bandit matches a finding to a baseline entry on (filename, test_id, issue_text)
and deliberately ignores the line number, so an entry whose code has since been
fixed does not simply become inert: it lingers as a standing, file-scoped
exemption for that test ID. Reintroducing the same class of defect anywhere in
that file would match the dead entry and pass the gate silently.

This check makes the staleness self-correcting. It reruns bandit with no
baseline, compares the live findings against the committed ones, and exits
non-zero if any committed entry is unmatched — the fix being to regenerate the
baseline, which is exactly what should happen when a finding is resolved.

Usage:
    python scripts/check_bandit_baseline.py [--baseline PATH] [--] [paths...]

B404/B603 are suppressed below because shelling out to bandit is this
script's entire purpose: the argv is assembled here from constants and the
parsed arguments, and runs with shell=False.
"""

import argparse
import json
import subprocess  # nosec B404
import sys
from pathlib import Path

DEFAULT_TARGETS = ['hashview', 'install/hashview-agent']
DEFAULT_BASELINE = '.bandit-baseline.json'

REGEN_HINT = (
    'Regenerate it with:\n'
    '    bandit -r {targets} -c pyproject.toml -f json -o {baseline}\n'
    'and commit the result.'
)


def finding_key(result):
    """The tuple bandit itself uses to match a finding against the baseline.

    Identical calls on adjacent lines legitimately share a key (three
    subprocess calls in a row, say). Matching is therefore set membership, not
    a count: if any live finding still carries the key, the committed entry is
    considered to reproduce. That mirrors bandit's own behaviour, whose
    exemption is file-scoped regardless of how many sites remain.
    """
    return (result['filename'], result['test_id'], result['issue_text'])


def load_results(path):
    with open(path, encoding='utf-8') as handle:
        return json.load(handle).get('results', [])


def scan(targets, config):
    """Run bandit with no baseline and return its findings."""
    argv = ['bandit', '-r', *targets, '-c', config, '-f', 'json', '-q']
    # B603: fixed argv assembled here (no shell, no caller-supplied binary).
    proc = subprocess.run(argv, capture_output=True, text=True, check=False)  # nosec B603
    if not proc.stdout.strip():
        sys.stderr.write(proc.stderr)
        raise SystemExit('bandit produced no JSON output; see stderr above.')
    return json.loads(proc.stdout).get('results', [])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', default=DEFAULT_BASELINE)
    parser.add_argument('--config', default='pyproject.toml')
    parser.add_argument('targets', nargs='*', default=None)
    args = parser.parse_args(argv)
    targets = args.targets or DEFAULT_TARGETS

    if not Path(args.baseline).exists():
        raise SystemExit(f'Baseline not found: {args.baseline}')

    committed = load_results(args.baseline)
    live_keys = {finding_key(r) for r in scan(targets, args.config)}

    stale = [r for r in committed if finding_key(r) not in live_keys]
    if not stale:
        print(f'bandit baseline is current: all {len(committed)} entries still reproduce.')
        return 0

    print(
        f'{len(stale)} of {len(committed)} baseline entries no longer reproduce.\n'
        'Each one is a standing file-scoped exemption for its test ID, so a\n'
        'regression of that kind would pass this gate silently.\n'
    )
    for result in sorted(stale, key=finding_key):
        print(f"  {result['test_id']}  {result['filename']}:{result['line_number']}")
        print(f"      {result['issue_text']}")
    print()
    print(REGEN_HINT.format(targets=' '.join(targets), baseline=args.baseline))
    return 1


if __name__ == '__main__':
    sys.exit(main())
