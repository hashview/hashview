"""Render a stored UTC timestamp as an element the browser localises.

Hashview stores every timestamp in UTC (see utils/clock.py). That is the right
thing to store and the wrong thing to show: the server has no idea what timezone
the person reading the page is in, and guessing from the server's own TZ is how
a dashboard ends up claiming a job started at 3am to someone sitting next to the
rig at 8pm.

So the server emits the instant and the browser formats it:

    {{ localtime(job.started_at) }}

    <time class="hv-time" datetime="2026-09-22T20:06:06Z"
          data-fmt="datetime">2026-09-22 20:06 UTC</time>

``hvLocalizeTimes`` (layout.html.j2) rewrites the text content in the viewer's
zone. Three details in that markup are load-bearing:

  * the ``Z``. Without an offset most browsers parse a bare
    "2026-09-22 20:06:06" as LOCAL time, which would shift an already-correct
    value by the viewer's offset -- the exact bug this change removes,
    reintroduced at the last step.
  * the text between the tags is the no-JS fallback, and it says UTC out loud.
    Rendering bare local-looking digits that are actually UTC is worse than
    showing the offset, because nothing tells the reader to doubt it.
  * a real ``<time datetime=...>`` element, so the machine-readable instant
    survives copy-paste, screen readers and Reader Mode.

The format names are deliberately a small closed vocabulary rather than
strftime strings: the browser formats with Intl, which does not speak strftime,
and every caller picking its own pattern is how the UI drifts.
"""
from datetime import UTC

from markupsafe import Markup, escape

from hashview.utils.clock import to_utc_iso

# name -> (strftime for the no-JS fallback, what the browser renders)
# Chosen to match the formats the templates already used, so this change moves
# the timezone and nothing else about how the UI looks.
FORMATS = {
    'datetime': '%b %d %H:%M',        # "Sep 22 20:06"      -- the common case
    'datetime-sec': '%b %d %H:%M:%S',
    'datetime-full': '%b %d, %Y %H:%M',
    'date': '%Y-%m-%d',               # "2026-09-22"
    'time': '%H:%M:%S',               # "20:06:06"          -- logs
    'short': '%m/%d %H:%M',           # "09/22 20:06"       -- chart labels
    'rel': '%b %d %H:%M',             # "5m ago", fallback to absolute
}

DEFAULT_FORMAT = 'datetime'


def template_localtime(value, fmt=DEFAULT_FORMAT, empty='—'):
    """A <time> element for ``value``, localised client-side.

    ``empty`` is what a missing timestamp renders as, so callers stop
    hand-writing ``{{ x.strftime(...) if x else '—' }}`` at every site and
    getting the fallback subtly different each time.
    """
    if value is None:
        return Markup('<span class="hv-time-empty">%s</span>') % empty

    pattern = FORMATS.get(fmt, FORMATS[DEFAULT_FORMAT])

    # Normalise FIRST, then derive both the attribute and the visible text from
    # the same value. Deriving the fallback from the caller's `value` instead
    # meant an AWARE input got a correctly-converted datetime= attribute beside
    # visible text still showing the original wall clock -- and labelled UTC.
    # A fallback that asserts a zone it is not in is worse than no label: the
    # audit log is the one caller that passes aware values, and its stamps
    # written before this change carry the writing host's offset.
    if value.tzinfo is not None:
        value = value.astimezone(UTC).replace(tzinfo=None)
    iso = to_utc_iso(value)
    # Says UTC because that is what it is. A viewer without JS gets a timestamp
    # they can reason about rather than one that silently looks local.
    fallback = value.strftime(pattern) + ' UTC'
    return Markup(
        '<time class="hv-time" datetime="%s" data-fmt="%s">%s</time>'
    ) % (escape(iso), escape(fmt), escape(fallback))
