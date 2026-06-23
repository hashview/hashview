"""Regression tests for agents routes/helpers (function-coverage batch)."""

from hashview.models import AgentBenchmarks, Agents, JobTasks, db
from tests.unit.helpers import login, make_admin, make_user


def _agent(name="ag", status="Pending", uuid="u1"):
    a = Agents(name=name, src_ip="127.0.0.1", uuid=uuid, status=status)
    db.session.add(a)
    db.session.commit()
    return a


def test_fmt_age_buckets():
    from hashview.agents.routes import _fmt_age
    assert _fmt_age(0) == "now"
    assert _fmt_age(30) == "30s ago"
    assert _fmt_age(120) == "2m ago"
    assert _fmt_age(3600) == "1h ago"
    assert _fmt_age(3660) == "1h 1m ago"
    assert _fmt_age(86400) == "1d ago"


def test_agent_ages_returns_mapping(app):
    from hashview.agents.routes import _agent_ages
    a = _agent()
    ages = _agent_ages([a])
    assert a.id in ages  # value may be None (no last_checkin), key must exist


def test_agents_list_renders_for_admin(app, client):
    admin = make_admin()
    login(client, admin)
    _agent(name="VisibleAgent")
    resp = client.get("/agents")
    assert resp.status_code == 200
    assert b"VisibleAgent" in resp.data


def test_agents_list_forbidden_for_non_admin(app, client):
    user = make_user()
    login(client, user)
    resp = client.get("/agents")
    assert resp.status_code == 403


def test_agents_authorize_sets_status(app, client):
    admin = make_admin()
    login(client, admin)
    a = _agent(status="Pending")
    resp = client.get(f"/agents/{a.id}/authorize", follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert Agents.query.get(a.id).status == "Authorized"


def test_agents_deauthorize_sets_pending(app, client):
    admin = make_admin()
    login(client, admin)
    a = _agent(status="Authorized")
    resp = client.get(f"/agents/{a.id}/deauthorize", follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert Agents.query.get(a.id).status == "Pending"


def test_agents_benchmark_all_flushes_for_admin(app, client):
    admin = make_admin()
    login(client, admin)
    a = _agent(status="Idle", uuid="bench-flush-u")
    db.session.add(AgentBenchmarks(agent_id=a.id, hash_type=1000, speed=123))
    db.session.commit()
    assert AgentBenchmarks.query.count() == 1

    resp = client.post("/agents/benchmark", follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert AgentBenchmarks.query.count() == 0   # all benchmarks flushed


def test_agents_benchmark_all_forbidden_for_non_admin(app, client):
    user = make_user()
    login(client, user)
    resp = client.post("/agents/benchmark", follow_redirects=False)
    assert resp.status_code == 403


def test_fmt_speed_units():
    from hashview.agents.routes import _fmt_speed
    assert _fmt_speed(0) == "0 H/s"
    assert _fmt_speed(999) == "999 H/s"
    assert _fmt_speed(2500) == "2.50 kH/s"
    assert _fmt_speed(28460000000) == "28.46 GH/s"


def test_agents_info_modal_shows_benchmarks(app, client):
    admin = make_admin()
    login(client, admin)
    a = _agent(name="InfoAgent", status="Idle", uuid="info-u")
    db.session.add(AgentBenchmarks(agent_id=a.id, hash_type=1000, speed=28460000000))
    db.session.commit()
    resp = client.get("/agents")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert f'id="info-{a.id}"' in html      # the per-agent info modal is rendered
    assert "28.46 GH/s" in html             # benchmark speed, human-formatted
    assert "NTLM" in html                   # hash mode labeled by name


def test_agents_info_modal_no_benchmarks_message(app, client):
    admin = make_admin()
    login(client, admin)
    a = _agent(name="BareAgent", status="Idle", uuid="bare-u")
    resp = client.get("/agents")
    html = resp.get_data(as_text=True)
    assert f'id="info-{a.id}"' in html
    assert "No benchmarks recorded yet" in html


def test_agents_delete_removes_agent_and_all_references(app, client):
    """Deleting an agent also clears every agent_id reference (job_tasks +
    agent_benchmarks) and re-queues any chunk it was running, so the delete can't
    be blocked by a foreign key and leave the agent showing in the list."""
    admin = make_admin()
    login(client, admin)
    a = _agent(name="DelRig", status="Working", uuid="del-u")
    db.session.add(AgentBenchmarks(agent_id=a.id, hash_type=1000, speed=123))
    jt = JobTasks(job_id=1, task_id=1, status="Running", priority=3, agent_id=a.id)
    db.session.add(jt)
    db.session.commit()
    a_id, jt_id = a.id, jt.id

    resp = client.post(f"/agents/delete/{a_id}", follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert Agents.query.get(a_id) is None                                 # actually gone
    assert AgentBenchmarks.query.filter_by(agent_id=a_id).count() == 0    # benchmarks removed
    jt2 = JobTasks.query.get(jt_id)
    assert jt2.agent_id is None                                           # reference cleared
    assert jt2.status == "Queued"                                         # running chunk re-queued


def test_agents_delete_forbidden_for_non_admin(app, client):
    user = make_user()
    login(client, user)
    a = _agent(uuid="del-nonadmin")
    resp = client.post(f"/agents/delete/{a.id}", follow_redirects=False)
    assert resp.status_code == 403
    assert Agents.query.get(a.id) is not None


def test_agents_benchmark_all_commit_failure_flashes(app, client):
    """If the benchmark flush can't commit, the route flashes an error and
    redirects rather than silently dropping the request."""
    from unittest.mock import patch
    admin = make_admin()
    login(client, admin)
    a = _agent(status="Idle", uuid="bench-fail-u")
    db.session.add(AgentBenchmarks(agent_id=a.id, hash_type=1000, speed=123))
    db.session.commit()

    with patch("hashview.agents.routes.try_commit", return_value=False):
        resp = client.post("/agents/benchmark", follow_redirects=True)
    assert resp.status_code == 200
    assert b"Could not reset benchmarks" in resp.data


def test_agents_delete_commit_failure_flashes(app, client):
    """If the agent delete can't commit, the route flashes an error rather than
    silently dropping the request."""
    from unittest.mock import patch
    admin = make_admin()
    login(client, admin)
    a = _agent(name="StuckRig", status="Idle", uuid="del-fail-u")

    with patch("hashview.agents.routes.try_commit", return_value=False):
        resp = client.post(f"/agents/delete/{a.id}", follow_redirects=True)
    assert resp.status_code == 200
    assert b"Agent could not be deleted" in resp.data
