"""xfail regression tests for the dashboard ETA defects in issue #427.

#427 has three parts. This file covers the two that are self-contained and can
land without the per-chunk-keyspace work:

  * The ``_eta_seconds`` comparator (hashview/main/routes.py:176) knows only
    ``d/h/m/s``. The agent's ``time_difference``
    (install/hashview-agent/hashview-agent.py:533-571) emits the largest *two*
    non-zero components drawn from year/month/day/hour/minute/second, so
    ``year`` is dropped entirely and ``month`` collides with the ``m`` key and
    scores as minutes. A year-long ETA therefore sorts below a three-minute one
    and can never win the ``max()`` that produces the parent-task ETA.

  * ``_eta_text`` (hashview/main/routes.py:169) returns whatever sits between
    the first parentheses, so the agent's non-duration sentinels — "The
    specified time is in the past." and "The specified time is very close to
    now." — are rendered verbatim in the ETA column
    (hashview/templates/_dash_jobs.html.j2:87,103) and score 0 seconds.

NOT covered here: the headline #427 defect, that the parent ETA is a ``max()``
over running chunks only and ignores queued ones. Not for lack of data --
``JobTasks.chunk_limit``/``chunk_mask``, ``Rules.size``, ``Wordlists.size`` and
``AgentBenchmarks.speed`` are all persisted, and ``plan_chunks`` already sizes
each chunk to ~``Settings.chunk_target_duration`` on the slowest agent -- but
because the *formula* is still an open design question (see #427: whether to
reconstruct keyspace or derive from the chunk count, how to avoid double
counting in-flight chunks, what to do when agents are shared across jobs).
Pinning a number before that is settled would just pin one of the candidates.

Overlap with PR #407 / branch test/agent-eta-clamp: that branch pins the
*agent* side, clamping ``estimated_stop`` at the source so the sentinel is
never emitted. These tests pin the *server* side, which must stay defensive
regardless — an upgraded server still talks to not-yet-upgraded agents, and
``Agents.hc_status`` rows already persisted in the DB still carry the sentence.
The two are complementary, not duplicates.

Each test asserts the *correct* (post-fix) behavior and is
``@pytest.mark.xfail(strict=True)``, so it XFAILs today and turns into a hard
XPASS failure the moment the bug is fixed — the signal to drop the marker.
"""

import json

import pytest

from hashview.main.routes import _agents_ctx, _eta_seconds, _eta_text, _job_task_groups
from hashview.models import (
    Agents,
    Customers,
    Hashfiles,
    Jobs,
    JobTasks,
    Tasks,
    Users,
    db,
)

# The agent's own arithmetic: years = days // 365, months = (days % 365) // 30
# (hashview-agent.py:544-545). Any fix should use the same definitions.
YEAR = 365 * 86400
MONTH = 30 * 86400

PAST = "The specified time is in the past."
NEAR = "The specified time is very close to now."


def _seed_job_with_chunks(chunk_etas):
    """A running job with one chunked task, one Running chunk per given ETA.

    ``chunk_etas`` are raw ``Time_Estimated`` payload strings as the agent
    stores them (already parenthesised).
    """
    user = Users(first_name="A", last_name="D", email_address="own@e.com",
                 password="x" * 60, admin=True)
    db.session.add(user)
    db.session.commit()
    cust = Customers(name="Acme")
    db.session.add(cust)
    db.session.commit()
    hf = Hashfiles(name="hf", customer_id=cust.id, owner_id=user.id)
    db.session.add(hf)
    db.session.commit()
    job = Jobs(name="Q2 Pentest", owner_id=user.id, customer_id=cust.id,
               hashfile_id=hf.id, status="Running", priority=3)
    db.session.add(job)
    db.session.commit()

    task = Tasks(name="wordlist + rule", owner_id=user.id, hc_attackmode=0,
                 wl_id=1, rule_id=1)
    db.session.add(task)
    db.session.commit()

    total = len(chunk_etas) + 2                      # + 2 still queued
    for i, eta in enumerate(chunk_etas, start=1):
        agent = Agents(name=f"rig-{i}", src_ip=f"1.1.1.{i}", uuid=f"u-{i}",
                       status="Working", benchmark="100 GH/s",
                       hc_status=json.dumps({"Speed #": "100 GH/s",
                                             "Recovered": "7/100",
                                             "Time_Estimated": eta}))
        db.session.add(agent)
        db.session.commit()
        db.session.add(JobTasks(job_id=job.id, task_id=task.id, status="Running",
                                chunk_no=i, chunk_total=total, agent_id=agent.id))
    for i in range(len(chunk_etas) + 1, total + 1):
        db.session.add(JobTasks(job_id=job.id, task_id=task.id, status="Queued",
                                chunk_no=i, chunk_total=total))
    db.session.commit()
    return job, task


def _group(job, task):
    ac = _agents_ctx()
    dash = _job_task_groups(
        [job], JobTasks.query.all(),
        {t.id: t for t in Tasks.query.all()},
        {a.id: a for a in ac['agents']},
        ac['recovered_list'], ac['time_estimated_list'],
    )[job.id]
    return {g['task_id']: g for g in dash['groups']}[task.id]


# --------------------------------------------------------------------------
# #427, defect 2: _eta_seconds cannot parse the units the agent emits
# --------------------------------------------------------------------------


@pytest.mark.security
def test_eta_seconds_still_parses_the_units_it_already_handles():
    """Guard rail, not an xfail: a fix must not regress d/h/m/s parsing."""
    assert _eta_seconds("52 minutes, 22 seconds") == 52 * 60 + 22
    assert _eta_seconds("2 days, 3 hours") == 2 * 86400 + 3 * 3600
    assert _eta_seconds("") == 0


@pytest.mark.security
@pytest.mark.xfail(strict=True, reason="#427: _eta_seconds has no 'year' unit, so years are dropped")
def test_eta_seconds_parses_years():
    assert _eta_seconds("1 year") == YEAR


@pytest.mark.security
@pytest.mark.xfail(strict=True, reason="#427: 'month' matches the 'm' key and is scored as minutes")
def test_eta_seconds_does_not_read_months_as_minutes():
    assert _eta_seconds("3 months") == 3 * MONTH


@pytest.mark.security
@pytest.mark.xfail(strict=True, reason="#427: '1 year, 2 months' scores 120s and loses to any longer duration")
def test_a_year_long_eta_outranks_a_few_minutes():
    # The ordering consequence, which is what the max() at routes.py:270 relies on.
    assert _eta_seconds("1 year, 2 months") > _eta_seconds("3 minutes, 6 seconds")


@pytest.mark.security
@pytest.mark.xfail(strict=True, reason="#427: the year-long chunk scores 120s, so the 3-minute chunk wins the max()")
def test_parent_eta_reports_the_longest_running_chunk(app, db_session):
    job, task = _seed_job_with_chunks(["x (1 year, 2 months)",
                                       "y (3 minutes, 6 seconds)"])
    assert _group(job, task)['eta'] == "1 year, 2 months"


# --------------------------------------------------------------------------
# #427, defect 3: non-duration sentinels reach the ETA column
# --------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.xfail(strict=True, reason="#427: _eta_text passes the agent's error sentence straight through")
@pytest.mark.parametrize("sentinel", [PAST, NEAR])
def test_eta_text_does_not_emit_a_sentence_as_an_eta(sentinel):
    # Deliberately not pinning a replacement string -- '0 secs', '' and a
    # distinct 'stalled' marker are all defensible. Only that prose does not
    # reach a column the operator reads as a duration.
    assert _eta_text(f"Mon Aug 24 10:26:00 2026 ({sentinel})") != sentinel


@pytest.mark.security
@pytest.mark.xfail(strict=True, reason="#427: a task whose only running chunk is stalled shows the error sentence as its ETA")
def test_parent_eta_of_a_stalled_task_is_not_an_error_sentence(app, db_session):
    job, task = _seed_job_with_chunks([f"Mon Aug 24 10:26:00 2026 ({PAST})"])
    assert _group(job, task)['eta'] != PAST


@pytest.mark.security
@pytest.mark.xfail(strict=True, reason="#427: the stalled chunk's own row renders the sentence verbatim")
def test_stalled_chunk_row_is_not_labelled_with_the_error_sentence(app, db_session):
    job, task = _seed_job_with_chunks([f"Mon Aug 24 10:26:00 2026 ({PAST})",
                                       "y (3 minutes, 6 seconds)"])
    etas = [c['eta'] for c in _group(job, task)['active_chunks']]
    assert PAST not in etas
