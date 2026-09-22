"""The one clock. Every timestamp Hashview records is UTC, and this is where it
comes from.

Hashview used to stamp timestamps from three different sources, and nothing in
the schema said which column belonged to which:

  * ``datetime.now()`` -- the app process's local time. Jobs.started_at /
    ended_at / queued_at, JobTasks.started_at, and most of the rest.
  * ``func.now()`` -- the DATABASE's clock, for Agents.last_checkin. Worse than
    it looks: SQLAlchemy renders that as ``now()`` on MySQL, which is
    session-local, but as ``CURRENT_TIMESTAMP`` on SQLite, which is always UTC.
    One expression, two domains, depending on the backend.
  * ``datetime.utcnow()`` -- UTC, for Users.last_login_utc and the audit log.
    The only one that was self-describing, because the column says so in its
    name.

Each family was internally consistent, so nothing was visibly wrong until a
comparison crossed between them -- which the agent-timeout fallback did (#404):
when ``SELECT NOW()`` failed it compared Python UTC against a DB-local column,
so on a database behind UTC the cutoff landed hours ahead of every stored
check-in and the entire fleet was declared offline at once, from one failed
query, at exactly the moment the database was already unhealthy.

Naive UTC, not timezone-aware
-----------------------------
Every DateTime column in models.py is naive (``db.DateTime``, no
``timezone=True``). Storing aware datetimes would mean a MySQL schema change and
touching every comparison, for no gain the display layer cannot get from an
explicit "this is UTC" contract. So: naive, and universally UTC, which makes any
two timestamps in the schema directly comparable.

Not ``datetime.utcnow()``
-------------------------
That is deprecated from Python 3.12 and scheduled for removal, which is why the
test suite prints a wall of DeprecationWarnings. ``datetime.now(timezone.utc)``
is the supported spelling; the ``.replace(tzinfo=None)`` drops the offset back
off to match the columns.

No dependencies on purpose
--------------------------
models.py imports this for its column defaults, and utils.py imports models, so
anything this module imported would risk a cycle. Keep it standard-library.
"""
from datetime import UTC, datetime

__all__ = ['utcnow', 'to_utc_iso']


def utcnow():
    """Current UTC time, naive -- the value every recorded timestamp uses."""
    return datetime.now(UTC).replace(tzinfo=None)


def to_utc_iso(value):
    """A stored timestamp as an ISO-8601 string the browser can localise.

    Emits an explicit ``Z``. Without an offset, ``new Date(s)`` parses a
    space-separated string as LOCAL time in most browsers, so a value that is
    already correct would be shifted again by the viewer's offset -- the bug
    this whole change exists to remove, reintroduced in the last step.

    Returns None for None, so a template can fall back to an em dash.
    """
    if value is None:
        return None
    if value.tzinfo is not None:
        value = value.astimezone(UTC).replace(tzinfo=None)
    return value.strftime('%Y-%m-%dT%H:%M:%SZ')
