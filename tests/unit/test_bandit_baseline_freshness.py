"""Guard the shape of the `# nosec` suppressions bandit reads.

Bandit splits everything following `# nosec` on whitespace and commas and tries
to resolve each token as a test ID, so a justification written inline produces
one "Test in comment" warning per word. Those warnings are indistinguishable
from real ones at a glance, which is how a stale baseline went unnoticed. See
issue #426.
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


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
