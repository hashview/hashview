"""One clock: every recorded timestamp is UTC, and the browser does the rest.

Hashview used to stamp timestamps three ways -- ``datetime.now()`` (app-local),
``func.now()`` (the database's clock), and ``datetime.utcnow()`` -- with nothing
in the schema saying which column was which. Each family was internally
consistent, so nothing looked wrong until a comparison crossed between them.

``func.now()`` is the one worth remembering: SQLAlchemy renders it as ``now()``
on MySQL, which is session-local, and as ``CURRENT_TIMESTAMP`` on SQLite, which
is always UTC. One expression, two clocks, depending on the backend -- which is
also why the SQLite unit suite could never see the problem.

These tests pin the invariant rather than any individual call site: the point is
not that ``jobs.started_at`` uses ``utcnow()``, it is that NOTHING reaches for a
second clock. A new route that writes ``datetime.now()`` is the regression, and
the source sweeps below are what catch it -- no behavioural test can, because on
a UTC-configured CI box the two clocks agree and every assertion passes.
"""
import pathlib
import re
from datetime import UTC, datetime, timedelta

import pytest

from hashview.utils.clock import to_utc_iso, utcnow
from hashview.utils.timefmt import FORMATS, template_localtime

APP = pathlib.Path('hashview')

# Modules allowed to name a raw clock, and why.
CLOCK_EXEMPT = {
    'hashview/utils/clock.py',        # defines it
    'hashview/logs/routes.py',        # parses tz-AWARE audit stamps; see below
    'hashview/models.py',             # JWT iat needs an aware datetime, see below
}


def _python_files():
    return [p for p in APP.rglob('*.py') if 'control' not in p.parts]


TESTS = pathlib.Path('tests')

# This file compares the two clocks against each other, so naming the local one
# is the whole point here and nowhere else under tests/.
TEST_CLOCK_EXEMPT = {'tests/unit/test_utc_timestamps.py'}


# --- the clock itself --------------------------------------------------------

def test_utcnow_is_naive_utc():
    """Naive, because every DateTime column is naive; UTC, because that is the
    whole point. An aware value here would raise on comparison with a stored
    one -- loudly, at least, but still broken."""
    now = utcnow()
    assert now.tzinfo is None
    assert abs((now - datetime.now(UTC).replace(tzinfo=None)).total_seconds()) < 2


def test_utcnow_does_not_follow_the_process_timezone(monkeypatch):
    """The bug in one assertion.

    ``datetime.now()`` moves with TZ; ``utcnow()` must not, or a server in
    America/New_York writes timestamps four hours off one in UTC and the two
    disagree about when the same job started.
    """
    import os
    import time

    before = utcnow()
    monkeypatch.setenv('TZ', 'America/New_York')
    time.tzset()
    try:
        during = utcnow()
        local = datetime.now()
        assert abs((during - before).total_seconds()) < 5, (
            'utcnow moved with the process timezone')
        # And prove the test has teeth: the LOCAL clock really did shift.
        assert abs((local - during).total_seconds()) > 3000, (
            'TZ did not take effect, so this test proves nothing')
    finally:
        monkeypatch.delenv('TZ', raising=False)
        time.tzset()
        os.environ.pop('TZ', None)


# --- nothing reaches for a second clock --------------------------------------

def test_no_module_writes_a_timestamp_from_the_local_clock():
    """The regression guard, and the only kind that can work.

    A behavioural test cannot catch a new ``datetime.now()``: CI runs in UTC, so
    the wrong clock and the right one return the same value and everything
    passes. This reads the source instead.
    """
    offenders = []
    for path in _python_files():
        if str(path) in CLOCK_EXEMPT:
            continue
        source = path.read_text(encoding='utf-8')
        code = '\n'.join(re.sub(r'#.*$', '', line) for line in source.splitlines())
        code = re.sub(r'"""(?:.|\n)*?"""', '', code)          # drop docstrings
        for pattern in (r'\bdatetime\.now\(\s*\)', r'\bdatetime\.utcnow\(', r'\bdatetime\.today\('):
            for m in re.finditer(pattern, code):
                line = code[:m.start()].count('\n') + 1
                offenders.append(f'{path}:{line} {m.group(0)}')
    assert not offenders, (
        'these read a clock that is not utcnow(), so their timestamps follow the '
        'process timezone:\n  ' + '\n  '.join(offenders))


def test_no_test_seeds_a_timestamp_from_the_local_clock():
    """The same guard, pointed at the suite itself.

    Every DateTime column is naive UTC and the app compares against utcnow(), so
    a test that seeds datetime.now() only agrees with the code it tests on a
    machine set to UTC. CI runs UTC, which is precisely why this rots: the suite
    stays green here and fails on a contributor's laptop, and the further from
    UTC the worse it gets. Thirty-four seeds had drifted this way before anyone
    noticed, because nothing was watching.

    Only the LOCAL-clock spellings, unlike the app-side guard above.
    ``datetime.utcnow()`` is deprecated but still naive UTC, so a test using it
    is untidy rather than wrong, and folding that into this assertion would
    bury a real timezone bug in a pile of deprecation cleanup.
    """
    offenders = []
    for path in sorted(TESTS.rglob('*.py')):
        if str(path) in TEST_CLOCK_EXEMPT:
            continue
        source = path.read_text(encoding='utf-8')
        code = '\n'.join(re.sub(r'#.*$', '', line) for line in source.splitlines())
        code = re.sub(r'"""(?:.|\n)*?"""', '', code)          # drop docstrings
        for pattern in (r'\bdatetime\.now\(\s*\)', r'\bdatetime\.today\('):
            for m in re.finditer(pattern, code):
                line = code[:m.start()].count('\n') + 1
                offenders.append(f'{path}:{line} {m.group(0)}')
    assert not offenders, (
        'these seed a test timestamp from the local clock, so they only pass on '
        'a machine set to UTC -- use utcnow():\n  ' + '\n  '.join(offenders))


def test_the_local_clock_guards_are_actually_looking_at_something():
    """Both guards walk a directory tree and assert an empty list. A wrong root,
    a renamed folder or a bad glob would make them pass having read no files at
    all, which is the one failure mode a green assertion cannot show you."""
    assert len(_python_files()) > 20, 'the app-side guard found almost no files'
    assert len(list(TESTS.rglob('*.py'))) > 20, 'the test-side guard found almost no files'
    assert all(p.exists() for p in map(pathlib.Path, CLOCK_EXEMPT | TEST_CLOCK_EXEMPT)), (
        'an exemption names a file that no longer exists, so it silently covers nothing')


def test_no_column_is_stamped_from_the_database_clock():
    """``func.now()`` is not one clock -- it is session-local on MySQL and UTC on
    SQLite. Any column written with it is in a different domain from the rest of
    the schema, and which domain depends on the backend."""
    offenders = []
    for path in _python_files():
        code = '\n'.join(re.sub(r'#.*$', '', line)
                         for line in path.read_text(encoding='utf-8').splitlines())
        code = re.sub(r'"""(?:.|\n)*?"""', '', code)
        if re.search(r'func\.now\(\)|func\.current_timestamp\(\)', code):
            offenders.append(str(path))
    assert not offenders, f'still stamping from the DB clock: {offenders}'


def test_every_datetime_column_defaults_to_the_one_clock():
    """A column default is a write site that no grep of the routes will find."""
    source = pathlib.Path('hashview/models.py').read_text(encoding='utf-8')
    bad = re.findall(r'default=(datetime\.\w+)', source)
    assert not bad, f'model defaults bypassing utcnow: {bad}'
    assert 'default=utcnow' in source


def test_the_agent_timeout_no_longer_negotiates_a_clock():
    """#404. The fallback compared Python UTC against a DB-local column, so when
    ``SELECT NOW()`` failed on a database behind UTC the cutoff landed hours
    ahead of every check-in and the whole fleet was declared offline at once --
    from one failed query, at the moment the database was already unhealthy.

    With one clock there is nothing to fall back to, so the whole construct is
    gone rather than corrected.
    """
    for path in ('hashview/scheduler.py', 'hashview/__init__.py',
                 'hashview/agents/routes.py'):
        code = '\n'.join(re.sub(r'#.*$', '', line)
                         for line in pathlib.Path(path).read_text(encoding='utf-8').splitlines())
        code = re.sub(r'"""(?:.|\n)*?"""', '', code)
        assert 'SELECT NOW()' not in code, f'{path} still reads the DB clock'


# --- the display contract ----------------------------------------------------

def test_localtime_emits_an_instant_the_browser_can_localise():
    out = str(template_localtime(datetime(2026, 9, 22, 20, 6, 6)))
    assert 'datetime="2026-09-22T20:06:06Z"' in out, out
    assert out.startswith('<time class="hv-time"')


def test_the_iso_carries_an_explicit_zone():
    """Without the Z most browsers parse the string as LOCAL, which would shift
    an already-correct instant by the viewer's offset -- this whole change,
    undone at the last step."""
    assert to_utc_iso(datetime(2026, 1, 2, 3, 4, 5)).endswith('Z')


def test_an_aware_value_is_converted_rather_than_truncated():
    aware = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC) + timedelta(hours=5)
    assert to_utc_iso(aware) == '2026-01-02T08:04:05Z'


def test_the_no_js_fallback_names_its_timezone():
    """A viewer without JS gets UTC either way. Saying so is the difference
    between a timestamp they can reason about and one that silently looks
    local."""
    assert 'UTC' in str(template_localtime(datetime(2026, 9, 22, 20, 6, 6)))


@pytest.mark.parametrize('fmt', sorted(FORMATS))
def test_every_server_format_has_a_browser_counterpart(fmt):
    """The two vocabularies must not drift: a format the server renders but the
    browser cannot is a cell that silently stays UTC."""
    js = pathlib.Path('hashview/templates/layout.html.j2').read_text(encoding='utf-8')
    assert f"'{fmt}'" in js or fmt == 'rel', (
        f"format '{fmt}' has no case in hvLocalizeTimes")


def test_a_missing_timestamp_renders_the_placeholder_not_an_error():
    assert 'hv-time-empty' in str(template_localtime(None))
    assert 'never' in str(template_localtime(None, empty='never'))


def test_the_format_name_cannot_inject_markup():
    out = str(template_localtime(datetime(2026, 1, 1), '"><script>alert(1)</script>'))
    assert '<script>' not in out


# --- no template may read a clock --------------------------------------------

def test_no_template_computes_a_time_itself():
    """_dash_jobs.html.j2 used to do ``datetime.now() - job.started_at``.

    The moment started_at became UTC that turned into a local-vs-UTC
    subtraction -- wrong by the host's offset, on the elapsed counter that is
    the most-read number on the dashboard. A template cannot know the right
    clock; the view passes it a number.
    """
    offenders = []
    for path in pathlib.Path('hashview/templates').rglob('*.j2'):
        text = path.read_text(encoding='utf-8')
        for pattern in ('datetime.now(', 'datetime.utcnow(', 'datetime.today('):
            if pattern in text:
                offenders.append(f'{path}: {pattern}')
    assert not offenders, f'templates reading a clock: {offenders}'


def test_no_template_renders_a_bare_datetime():
    """``{{ job.started_at }}`` prints a datetime's repr -- and now prints UTC
    while looking exactly like a local time. Every one must go through
    localtime()."""
    columns = ('created_at', 'updated_at', 'started_at', 'ended_at', 'queued_at',
               'uploaded_at', 'last_updated', 'last_checkin', 'recovered_at',
               'last_login_utc')
    pattern = re.compile(r'\{\{\s*[\w.]+\.(' + '|'.join(columns) + r')\s*(\|[^}]*)?\}\}')
    offenders = []
    for path in pathlib.Path('hashview/templates').rglob('*.j2'):
        for m in pattern.finditer(path.read_text(encoding='utf-8')):
            offenders.append(f'{path}: {m.group(0)}')
    assert not offenders, (
        'rendered without localtime(), so they display UTC as though it were '
        f'local: {offenders}')


def test_every_poller_relocalises_what_it_swaps_in():
    """The dashboard replaces whole panels by innerHTML every few seconds.
    Markup injected that way has never been through the localiser, so without a
    re-run those cells keep the UTC fallback while the rest of the page is
    local."""
    home = pathlib.Path('hashview/templates/home.html.j2').read_text(encoding='utf-8')
    swaps = re.findall(r'\.innerHTML = html', home)
    calls = re.findall(r'hvLocalizeTimes\(', home)
    assert len(calls) >= len(swaps), (
        f'{len(swaps)} partial swaps but only {len(calls)} re-localisations')


def test_the_localiser_is_loaded_for_every_page():
    """It lives in the shared layout, outside the authenticated branch, so the
    login page localises too."""
    layout = pathlib.Path('hashview/templates/layout.html.j2').read_text(encoding='utf-8')
    assert 'window.hvLocalizeTimes' in layout
    assert 'data-hv-utc' in layout, 'the SVG/chart escape hatch is missing'


# --- the places a browser cannot reach ---------------------------------------

def test_output_that_cannot_run_javascript_names_its_timezone():
    """Email, Slack, Pushover and CSV get no localiser, so they say UTC.

    The alternative is bare digits that a reader will reasonably assume are
    local -- an admin paged at 02:00 about an agent "last seen 14:32" cannot
    tell whether that was twenty minutes ago or most of a day.
    """
    checks = [
        ('hashview/utils/utils.py', 'Canceled:', 'job-cancellation email'),
        ('hashview/scheduler.py', 'considered offline', 'agent-offline notification'),
        ('hashview/searches/routes.py', 'Recovered At (UTC)', 'search CSV export'),
    ]
    for path, needle, what in checks:
        text = pathlib.Path(path).read_text(encoding='utf-8')
        line = next((line for line in text.splitlines() if needle in line), None)
        assert line is not None, f'{what}: anchor {needle!r} not found in {path}'
        assert 'UTC' in line, f'{what} emits a timestamp without naming its zone: {line.strip()}'


def test_the_agent_logs_in_utc_too():
    """Two halves of one investigation.

    An agent log line and a server log line for the same incident are read
    together; in different zones, with neither labelled, they are worse than
    useless. The agent is outside hashview/, so the source sweep above does not
    reach it.
    """
    agent = pathlib.Path('install/hashview-agent/hashview-agent.py').read_text(encoding='utf-8')
    assert 'logging.Formatter.converter = time.gmtime' in agent, (
        'the agent is logging in its own local time again')


def test_the_logs_page_does_not_mix_renderings_of_one_event():
    """The row cell and the detail header describe the same event; one showing
    local and the other UTC is the confusing half of a half-done conversion."""
    template = pathlib.Path('hashview/templates/logs.html.j2').read_text(encoding='utf-8')
    assert '{{ r.ts }}' not in template, (
        'the detail header renders the raw stamp while the row beside it is localised')


def test_a_timezone_aware_value_localises_consistently():
    """The <time> attribute and its no-JS text must describe the same instant.

    They did not: the attribute was converted and the visible text was not, so
    an aware input rendered its original wall clock labelled 'UTC'. The audit
    log is the caller that passes aware values, and its older entries carry the
    writing host's offset -- exactly where a wrong label does the most damage.
    """
    aware = datetime.fromisoformat('2026-09-22T09:00:00-05:00')
    out = str(template_localtime(aware, 'time'))
    assert 'datetime="2026-09-22T14:00:00Z"' in out, out
    assert '>14:00:00 UTC<' in out, f'fallback text disagrees with the instant: {out}'


def test_neither_log_search_haystack_contains_markup():
    """Both decorators build a client-side search string. Only one was fixed
    when the time became an element, so on the Errors tab every row matched
    'hv', 'utc', 'class' and 'fmt'."""
    source = pathlib.Path('hashview/logs/routes.py').read_text(encoding='utf-8')
    haystacks = re.findall(r"search = ' '\.join\(str\(x\) for x in \(\s*([^,]+),", source)
    assert len(haystacks) == 2, f'expected two search builders, found {len(haystacks)}'
    for first in haystacks:
        assert 't' != first.strip(), (
            'a search haystack starts with the rendered <time> element again')
