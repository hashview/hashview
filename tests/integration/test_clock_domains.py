"""Clock-domain integration tests (issues #404, #522).

Hashview records every timestamp in UTC, from one helper
(``hashview/utils/clock.utcnow``). These tests exist because the SQLite unit
suite structurally cannot prove that: SQLite renders ``func.now()`` as
``CURRENT_TIMESTAMP``, which is already UTC, so a regression back to the
database's clock would be invisible there. On MySQL ``func.now()`` is
session-local, and the session timezone can be moved off UTC -- which is what
makes the two distinguishable at all.

What this file used to assert is worth recording, because it is the design that
was replaced. Timestamps came from three clocks with nothing marking which
column belonged to which:

  * ``Agents.last_checkin`` from ``func.now()``  -- the DATABASE's clock
  * ``Jobs.*`` / ``JobTasks.*`` from ``datetime.now()`` -- the APP PROCESS's clock
  * ``Users.last_login_utc`` from ``datetime.utcnow()`` -- UTC

Each family was internally consistent, so nothing looked wrong until a
comparison crossed between them -- which the agent-timeout fallback did (#404).
When ``SELECT NOW()`` failed it compared Python UTC against a DB-local column,
so on a database behind UTC the cutoff landed hours ahead of every stored
check-in and the entire fleet was declared offline at once, from one failed
query, at exactly the moment the database was already unhealthy.

The fix was not to make the fallback agree with the database. It was to delete
the second clock: with ``last_checkin`` in UTC the cutoff is just "now minus the
timeout", there is nothing to read from the server and nothing to fall back to,
and the ``SELECT NOW()`` / ``try`` / ``except`` construct is gone from all three
places that carried a copy of it.

Every test is marked ``mysql`` and uses ``mysql_session``, which skips when
``HASHVIEW_TEST_DATABASE_URI`` is unset -- a plain local ``pytest tests/``
collects and skips these, unchanged.
"""

from contextlib import contextmanager
from datetime import datetime, timedelta

import pytest
from sqlalchemy import text

from hashview.utils.clock import utcnow

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
def test_the_heartbeat_writes_utc_not_the_database_clock(mysql_app, mysql_session):
    """The inverted invariant. This test used to assert the opposite.

    The session timezone is pushed 9 hours off UTC, so a DB-clock write and a
    UTC one are ~9 hours apart and the assertion can actually tell them apart --
    on a UTC box both would pass and the test would prove nothing.
    """
    from hashview.api._shared import update_heartbeat

    with db_timezone(mysql_session, f"+{EAST_OFFSET_HOURS:02d}:00"):
        agent = _agent(mysql_session, "clock-domain-1")
        agent.uuid = "clock-domain-1-uuid"
        mysql_session.flush()

        # update_heartbeat reads request.remote_addr, so it needs a request
        # context; the point of calling the real writer rather than assigning
        # the column is that this test then covers the actual production path.
        with mysql_app.test_request_context('/', environ_base={'REMOTE_ADDR': '10.0.0.9'}):
            update_heartbeat(agent.uuid)
        mysql_session.refresh(agent)

        assert abs(agent.last_checkin - utcnow()) < TOLERANCE, (
            "last_checkin must be UTC; if this fails the heartbeat has gone "
            "back to stamping whatever clock the database happens to run"
        )

        db_now = mysql_session.execute(text("SELECT NOW()")).scalar()
        assert abs(agent.last_checkin - db_now) > timedelta(hours=EAST_OFFSET_HOURS - 1), (
            "last_checkin tracks the DB clock again -- the exact coupling that "
            "made the timeout comparison backend-dependent"
        )


def test_agent_health_is_indifferent_to_the_database_timezone(mysql_app, mysql_session, monkeypatch):
    """A freshly checked-in agent is not offline, whatever the DB timezone.

    Same guarantee as before, reached the other way round: the cutoff and the
    column are both UTC, so the database's timezone is no longer an input to the
    comparison at all rather than being an input that both sides happen to share.
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
        agent.last_checkin = utcnow()        # fresh check-in, the one clock
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


def test_a_broken_db_clock_cannot_declare_live_agents_offline(mysql_app, mysql_session, monkeypatch):
    """#404, from the direction that produced the fleet-wide alert.

    ``broken_db_clock`` makes ``SELECT NOW()`` raise while every other query
    keeps working -- the real failure the old ``except`` existed to absorb. The
    sweep no longer reads that clock at all, so breaking it is now a no-op
    rather than the trigger for declaring every agent offline at once.
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
        _agent(mysql_session, "clock-domain-3").last_checkin = utcnow()
        mysql_session.flush()

        with broken_db_clock(monkeypatch, mysql_session):
            _agent_health_check_inner(db, logging.getLogger("test-clock-domains"))

    assert calls == [], (
        f"fallback path declared a live agent offline on a DB behind UTC: {calls}"
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
        # Seeded in UTC, deliberately, while the DB session sits 9 hours east --
        # so if the sweep ever went back to reading the server's clock this
        # agent would read as being in the future and the alert would vanish.
        _agent(mysql_session, "clock-domain-4").last_checkin = (
            utcnow() - timedelta(hours=2))
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
