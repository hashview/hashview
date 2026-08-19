"""Clock-domain integration tests (issue #404).

Hashview stamps timestamps from two different clocks, and nothing in the schema
marks which column belongs to which:

* **Database clock** — ``Agents.last_checkin`` is written with ``func.now()``
  (``hashview/api/routes.py:162``, and ``:297`` on registration). This is
  deliberate: the comment at ``routes.py:157-161`` explains that the heartbeat
  writer and the dashboard renderer can run in different process timezones, so
  both the write and the offline cutoff go through the single DB clock.
* **App-process clock** — ``Jobs.started_at`` / ``ended_at`` / ``queued_at`` and
  ``JobTasks.started_at`` / ``updated_at`` are written with ``datetime.now()``
  (``hashview/utils/utils.py:1263``, ``:1277``; ``hashview/api/routes.py:382``,
  ``:495``, ``:568``, ``:572``, ``:1136``; ``hashview/jobs/routes.py:908``).

The SQLite unit suite cannot see any of this. SQLite has no ``NOW()``, so
``SELECT NOW()`` always raises there and ``tests/unit/test_agent_health_check.py``
only ever exercises the ``datetime.utcnow()`` *fallback* — against fixtures that
are themselves stamped with ``utcnow()``. Both sides agree by construction, so
the domain split is invisible. These tests run on a real MySQL/MariaDB backend
where ``NOW()`` exists and the session timezone can be moved off UTC, which is
what makes the two clocks distinguishable.

Every test is marked ``mysql`` and uses ``mysql_session``, which skips when
``HASHVIEW_TEST_DATABASE_URI`` is unset — a plain local ``pytest tests/`` run
collects and skips these, unchanged.
"""

from contextlib import contextmanager
from datetime import datetime, timedelta

import pytest
from sqlalchemy import func, text

pytestmark = pytest.mark.mysql

# Offsets chosen to be unambiguous: far enough from UTC that a real skew can
# never be confused with clock jitter, and on both sides of zero because the two
# directions produce opposite failures (see the fallback tests below).
WEST_OFFSET_HOURS = 8    # '-08:00' — DB behind UTC
EAST_OFFSET_HOURS = 9    # '+09:00' — DB ahead of UTC
TOLERANCE = timedelta(seconds=30)


@contextmanager
def db_timezone(session, offset):
    """Run the block with the MySQL *session* timezone set to ``offset``.

    Always restores the previous value. ``mysql_session`` hands back a pooled
    connection on teardown, so leaking ``SET time_zone`` here would silently
    re-time every later test that reused it.
    """
    previous = session.execute(text("SELECT @@session.time_zone")).scalar()
    session.execute(text("SET time_zone = :tz"), {"tz": offset})
    try:
        yield
    finally:
        # '@@session.time_zone' reads back as SYSTEM when never explicitly set;
        # assigning that literal string is valid and restores the default.
        session.execute(text("SET time_zone = :tz"), {"tz": previous})


@pytest.fixture()
def job_owner(mysql_session):
    """A (user, customer) pair to satisfy the ``jobs`` FK constraints.

    The db-parity schema is migration-built and empty, so ``owner_id=1`` /
    ``customer_id=1`` don't exist; both rows are rolled back with the fixture's
    outer transaction.
    """
    from hashview.models import Customers, Users

    user = Users(
        first_name="Clock",
        last_name="Domain",
        email_address="clock-domain@example.com",
        password="x" * 60,
        admin=False,
    )
    customer = Customers(name="clock-domain-customer")
    mysql_session.add_all([user, customer])
    mysql_session.flush()
    return user, customer


def _agent(session, name, last_checkin=None, offline_notified=False):
    from hashview.models import Agents

    agent = Agents(
        name=name,
        src_ip="127.0.0.1",
        uuid="u-" + name,
        status="Idle",
        last_checkin=last_checkin,
        offline_notified=offline_notified,
    )
    session.add(agent)
    session.flush()
    return agent


# ---------------------------------------------------------------------------
# The documented invariant: last_checkin lives in the DB clock domain
# ---------------------------------------------------------------------------
def test_last_checkin_is_written_in_the_db_clock_domain(mysql_session):
    """``func.now()`` stamps the DB clock, not the Python process clock.

    Locks the contract that ``hashview/api/routes.py:157-162`` relies on. With
    the session timezone pushed 9 hours off UTC, a DB-clock write and a Python
    ``utcnow()`` are ~9 hours apart, so this distinguishes the two rather than
    passing trivially the way it would on a UTC box.
    """
    with db_timezone(mysql_session, f"+{EAST_OFFSET_HOURS:02d}:00"):
        agent = _agent(mysql_session, "clock-domain-1")
        agent.last_checkin = func.now()
        mysql_session.flush()
        mysql_session.refresh(agent)

        db_now = mysql_session.execute(text("SELECT NOW()")).scalar()
        assert abs(agent.last_checkin - db_now) < TOLERANCE, (
            "last_checkin must agree with the DB clock it was stamped from"
        )

        # ...and must NOT be interpretable as a Python UTC timestamp.
        drift_from_utc = abs(agent.last_checkin - datetime.utcnow())
        assert drift_from_utc > timedelta(hours=EAST_OFFSET_HOURS - 1), (
            "last_checkin should be in the DB's timezone, not Python UTC; if "
            "this fails the heartbeat write has silently changed clock domains"
        )


def test_agent_health_cutoff_tracks_db_clock_under_non_utc_tz(mysql_app, mysql_session, monkeypatch):
    """A freshly checked-in agent is not offline, whatever the DB timezone.

    This is the primary (``SELECT NOW()``) path of ``_agent_health_check_inner``.
    Both the cutoff and ``last_checkin`` come from the DB clock, so a non-UTC
    server must make no difference.
    """
    import logging

    from hashview.models import Settings, db
    from hashview.scheduler import _agent_health_check_inner
    from hashview.utils import utils as utils_mod

    calls = []
    monkeypatch.setattr(utils_mod, "notify_admins", lambda subj, msg: calls.append(subj))

    settings = Settings.query.first() or Settings(
        retention_period=1, max_runtime_jobs=0, max_runtime_tasks=0
    )
    settings.agent_timeout_minutes = 10
    mysql_session.add(settings)
    mysql_session.flush()

    with db_timezone(mysql_session, f"-{WEST_OFFSET_HOURS:02d}:00"):
        agent = _agent(mysql_session, "clock-domain-2")
        agent.last_checkin = func.now()      # fresh check-in, DB clock
        mysql_session.flush()

        _agent_health_check_inner(db, logging.getLogger("test-clock-domains"))

        assert calls == [], (
            f"a just-checked-in agent was reported offline under a non-UTC DB "
            f"timezone: {calls}"
        )
        assert agent.offline_notified is False


# ---------------------------------------------------------------------------
# #404 — the utcnow() fallback crosses clock domains
# ---------------------------------------------------------------------------
@contextmanager
def broken_db_clock(monkeypatch, session):
    """Make ``SELECT NOW()`` raise, leaving every other query working.

    Mirrors the real failure the ``except Exception`` in
    ``hashview/scheduler.py:252-256`` exists to absorb, without breaking the
    queries the health check needs to actually run.
    """
    original = session.execute

    def _execute(statement, *args, **kwargs):
        if "SELECT NOW()" in str(statement):
            raise RuntimeError("simulated DB clock read failure")
        return original(statement, *args, **kwargs)

    monkeypatch.setattr(session, "execute", _execute)
    try:
        yield
    finally:
        monkeypatch.undo()


@pytest.mark.xfail(
    reason="issue #404: when SELECT NOW() fails, hashview/scheduler.py:257 falls "
           "back to datetime.utcnow() while last_checkin is still in the DB's "
           "local timezone. On a DB behind UTC the cutoff lands hours ahead of "
           "every stored check-in, so the whole fleet is declared offline at "
           "once — triggered by one failed query, at exactly the moment the DB "
           "is already unhealthy",
    strict=False,
)
def test_fallback_does_not_declare_live_agents_offline(mysql_app, mysql_session, monkeypatch):
    """The fallback cutoff must not misjudge a fresh agent on a non-UTC DB.

    Desired behaviour: an agent that checked in seconds ago is never offline,
    even when the DB clock read fails. Today the fallback switches to Python UTC
    while ``last_checkin`` stays DB-local, so on a DB behind UTC the comparison
    at ``scheduler.py:260`` flags it — and every other agent — as offline.
    """
    import logging

    from hashview.models import Settings, db
    from hashview.scheduler import _agent_health_check_inner
    from hashview.utils import utils as utils_mod

    calls = []
    monkeypatch.setattr(utils_mod, "notify_admins", lambda subj, msg: calls.append(subj))

    settings = Settings.query.first() or Settings(
        retention_period=1, max_runtime_jobs=0, max_runtime_tasks=0
    )
    settings.agent_timeout_minutes = 10
    mysql_session.add(settings)
    mysql_session.flush()

    with db_timezone(mysql_session, f"-{WEST_OFFSET_HOURS:02d}:00"):
        _agent(mysql_session, "clock-domain-3").last_checkin = func.now()
        mysql_session.flush()

        with broken_db_clock(monkeypatch, mysql_session):
            _agent_health_check_inner(db, logging.getLogger("test-clock-domains"))

    assert calls == [], (
        f"fallback path declared a live agent offline on a DB behind UTC: {calls}"
    )


@pytest.mark.xfail(
    reason="issue #404: the same utcnow() fallback fails the other way on a DB "
           "ahead of UTC — stored check-ins sit hours in the future relative to "
           "the cutoff, so genuinely dead agents keep reading as online and the "
           "offline alert never fires",
    strict=False,
)
def test_fallback_still_detects_a_genuinely_dead_agent(mysql_app, mysql_session, monkeypatch):
    """A long-dead agent must still be detected when the DB clock read fails.

    The mirror image of the test above: with the DB ahead of UTC, the Python-UTC
    cutoff sits *behind* every DB-local check-in, so nothing ever looks stale.
    """
    import logging

    from hashview.models import Settings, db
    from hashview.scheduler import _agent_health_check_inner
    from hashview.utils import utils as utils_mod

    calls = []
    monkeypatch.setattr(utils_mod, "notify_admins", lambda subj, msg: calls.append(subj))

    settings = Settings.query.first() or Settings(
        retention_period=1, max_runtime_jobs=0, max_runtime_tasks=0
    )
    settings.agent_timeout_minutes = 10
    mysql_session.add(settings)
    mysql_session.flush()

    with db_timezone(mysql_session, f"+{EAST_OFFSET_HOURS:02d}:00"):
        # Two hours stale against a 10-minute timeout: unambiguously offline.
        stale = mysql_session.execute(
            text("SELECT NOW() - INTERVAL 2 HOUR")
        ).scalar()
        _agent(mysql_session, "clock-domain-4").last_checkin = stale
        mysql_session.flush()

        with broken_db_clock(monkeypatch, mysql_session):
            _agent_health_check_inner(db, logging.getLogger("test-clock-domains"))

    assert len(calls) == 1 and calls[0].startswith("Agent offline"), (
        "a two-hour-stale agent went undetected because the fallback cutoff was "
        f"computed in a different clock domain: {calls}"
    )


# ---------------------------------------------------------------------------
# The other domain: job timestamps are app-clock, and the runtime caps match
# ---------------------------------------------------------------------------
def test_job_timestamps_are_app_clock_not_db_clock(mysql_session, job_owner):
    """``Jobs.started_at`` is stamped from the app process, not the DB.

    The runtime caps at ``hashview/api/routes.py:249`` and ``:376`` compare
    ``started_at`` against ``datetime.now()``, so both sides must stay in the
    app-process domain. This pins that: if a future change moves ``started_at``
    to ``func.now()`` those caps silently skew by the DB's UTC offset, which is
    the latent half of #404.
    """
    from hashview.models import Jobs

    user, customer = job_owner
    with db_timezone(mysql_session, f"+{EAST_OFFSET_HOURS:02d}:00"):
        job = Jobs(name="clock-domain-job", owner_id=user.id,
                   customer_id=customer.id, status="Queued")
        job.started_at = datetime.now()          # the production idiom
        mysql_session.add(job)
        mysql_session.flush()
        mysql_session.refresh(job)

        assert abs(job.started_at - datetime.now()) < TOLERANCE, (
            "started_at must round-trip in the app-process clock domain"
        )

        db_now = mysql_session.execute(text("SELECT NOW()")).scalar()
        assert abs(job.started_at - db_now) > timedelta(hours=EAST_OFFSET_HOURS - 1), (
            "started_at unexpectedly matches the DB clock; the runtime caps in "
            "api/routes.py compare it against datetime.now() and would now skew"
        )


def test_runtime_cap_is_self_consistent_under_non_utc_db(mysql_session, job_owner):
    """The max-runtime comparison stays correct whatever the DB timezone.

    Both operands are app-clock, so this is a regression lock rather than a bug
    reproduction — it fails only if one side is moved to the DB clock.
    """
    from hashview.models import Jobs

    user, customer = job_owner
    max_hours = 4
    with db_timezone(mysql_session, f"-{WEST_OFFSET_HOURS:02d}:00"):
        fresh = Jobs(name="cap-fresh", owner_id=user.id,
                     customer_id=customer.id, status="Running")
        fresh.started_at = datetime.now() - timedelta(hours=max_hours - 1)
        expired = Jobs(name="cap-expired", owner_id=user.id,
                       customer_id=customer.id, status="Running")
        expired.started_at = datetime.now() - timedelta(hours=max_hours + 1)
        mysql_session.add_all([fresh, expired])
        mysql_session.flush()
        mysql_session.refresh(fresh)
        mysql_session.refresh(expired)

        def over_cap(job):
            # The expression from hashview/api/routes.py:249.
            return job.started_at + timedelta(hours=max_hours) < datetime.now()

        assert over_cap(fresh) is False, "a job inside its runtime cap was expired early"
        assert over_cap(expired) is True, "a job past its runtime cap was not expired"
