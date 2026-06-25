"""Flask routes to handle Agents"""
import os

from flask import (
    Blueprint,
    abort,
    flash,
    redirect,
    render_template,
    send_from_directory,
    url_for,
)
from flask_login import current_user, login_required
from flask_wtf import FlaskForm
from sqlalchemy import text

import hashview
from hashview.agents.forms import AgentsForm
from hashview.models import AgentBenchmarks, Agents, JobTasks, db
from hashview.utils.hashcat_modes import (
    HASH_TYPE_CHOICES,
    KERBEROS_HASH_TYPE_CHOICES,
    NETNTLM_HASH_TYPE_CHOICES,
    SHADOW_HASH_TYPE_CHOICES,
)
from hashview.utils.utils import agent_telemetry, fmt_hps, try_commit

agents = Blueprint('agents', __name__)

# Hash mode (int) -> human label, e.g. 1000 -> "(1000) NTLM". Built once from the
# canonical hashcat_modes lists so the agent-info modal can name each benchmark.
_MODE_NAMES = {}
for _choices in (HASH_TYPE_CHOICES, KERBEROS_HASH_TYPE_CHOICES,
                 NETNTLM_HASH_TYPE_CHOICES, SHADOW_HASH_TYPE_CHOICES):
    for _mode, _label in _choices:
        try:
            _MODE_NAMES[int(_mode)] = _label
        except (TypeError, ValueError):
            pass

def _agent_benchmarks(agents_):
    """agent.id -> list of {hash_type, name, speed, updated_at} for the modal.

    Every agent is present; agents with no benchmarks map to [].
    """
    by_agent = {a.id: [] for a in agents_}
    if not by_agent:
        return by_agent          # no agents -> skip the empty-IN() query
    rows = (AgentBenchmarks.query
            .filter(AgentBenchmarks.agent_id.in_(by_agent))
            .order_by(AgentBenchmarks.hash_type)
            .all())
    for row in rows:
        by_agent[row.agent_id].append({
            'hash_type': row.hash_type,
            'name': _MODE_NAMES.get(row.hash_type, ''),
            'speed': fmt_hps(row.speed, places=2),
            'updated_at': row.updated_at,
        })
    return by_agent


def _fmt_age(seconds):
    """Relative 'last heartbeat' label: now, 5s ago, 14m ago, 1h 14m ago, 1d 1h ago."""
    s = max(0, int(seconds))
    if s < 1:
        return 'now'
    if s < 60:
        return '%ds ago' % s
    m = s // 60
    if m < 60:
        return '%dm ago' % m
    h, rm = m // 60, m % 60
    if h < 24:
        return ('%dh %dm ago' % (h, rm)) if rm else ('%dh ago' % h)
    dy, rh = h // 24, h % 24
    return ('%dd %dh ago' % (dy, rh)) if rh else ('%dd ago' % dy)


def _agent_ages(agents):
    """Static relative 'last heartbeat' string per agent, measured against the DATABASE
    clock (last_checkin is stamped with func.now()), so it's independent of this process's
    timezone. The agents page isn't realtime, so this is computed once at render and shown
    as a static value — it does not tick."""
    try:
        db_now = db.session.execute(text("SELECT NOW()")).scalar()
    except Exception:
        db_now = None
    out = {}
    for a in agents:
        try:
            if a.last_checkin and db_now:
                out[a.id] = _fmt_age((db_now - a.last_checkin).total_seconds())
            else:
                out[a.id] = None
        except Exception:
            out[a.id] = None
    return out

@agents.route("/agents", methods=['GET', 'POST'])
@login_required
def agents_list():
    """Function to list agents"""
    if current_user.admin:
        agents_form = AgentsForm()

        if agents_form.validate_on_submit():
            agent_name = agents_form.name.data
            agent_id = agents_form.id.data

            agent = Agents.get(agent_id)
            agent.name = agent_name
            db.session.commit()

            flash('Updated Agents Name', 'success')
            return redirect(url_for('agents.agents_list'))
        else:
            agents = Agents.query.all()
            return render_template('agents.html.j2', title='agents', agents=agents,
                                   agent_age=_agent_ages(agents),
                                   agent_benchmarks=_agent_benchmarks(agents),
                                   telemetry=agent_telemetry(agents),
                                   agentsForm=agents_form)
    else:
        abort(403)

@agents.route("/agents/benchmark", methods=['POST'])
@login_required
def agents_benchmark_all():
    """Flush all stored per-(agent, hashtype) benchmarks.

    With benchmark-first dispatch, every agent re-runs `hashcat -b` for the
    in-use hash types on its next idle check-in, refreshing the data the chunk
    planner sizes from. Admin-only + CSRF-protected.
    """
    if not current_user.admin:
        abort(403)
    if not FlaskForm().validate_on_submit():
        flash('Security check failed (invalid or missing CSRF token).', 'danger')
        return redirect(url_for('agents.agents_list'))

    AgentBenchmarks.query.delete()
    if not try_commit('flush agent benchmarks'):
        flash('Could not reset benchmarks; please try again.', 'danger')
        return redirect(url_for('agents.agents_list'))

    flash('Benchmarks reset — agents will re-benchmark on their next check-in.', 'success')
    return redirect(url_for('agents.agents_list'))

@agents.route("/agents/edit/<int:agent_id>", methods=['GET', 'POST'])
@login_required
def agents_edit(agent_id):
    """Function to edit agents"""
    agent = Agents.query.get(agent_id)
    if agent is None:
        flash('Agent not found — it may have already been deleted.', 'warning')
        return redirect(url_for('agents.agents_list'))
    if not current_user.admin:
        flash('You are unauthorized to edit agent data.', 'danger')
        return redirect(url_for('agents.agents_list'))

    agents_form = AgentsForm()
    if agents_form.validate_on_submit():
        agent.name = agents_form.name.data
        db.session.commit()
        flash('Updated Agents Name', 'success')
        return redirect(url_for('agents.agents_list'))
    return render_template('agents_edit.html.j2', title='agents', agent=agent, agentsForm=agents_form)

@agents.route("/agents/<int:agent_id>/authorize", methods=['GET'])
@login_required
def agents_authorize(agent_id):
    """Function to authorize agents"""
    if current_user.admin:
        agent = Agents.query.get(agent_id)

        agent.status = 'Authorized'
        db.session.commit()

        flash('Agent Authorized', 'success')
        return redirect(url_for('agents.agents_list'))
    else:
        abort(403)

@agents.route("/agents/<int:agent_id>/deauthorize", methods=['GET'])
@login_required
def agents_deauthorize(agent_id):
    """Function to deauthorize agents"""
    if current_user.admin:
        agent = Agents.query.get(agent_id)

        if agent.status == 'Working':
            flash('Agent was working. The active task was not stopped and you will not receive the results.', 'warning')

        agent.status = 'Pending'
        db.session.commit()

        flash('Agent Deauthorized', 'success')
        return redirect(url_for('agents.agents_list'))
    else:
        abort(403)


@agents.route("/agents/delete/<int:agent_id>", methods=['GET', 'POST'])
@login_required
def agents_delete(agent_id):
    """Function to delete agent"""
    agent = Agents.query.get(agent_id)
    if agent is None:
        flash('Agent not found — it may have already been deleted.', 'warning')
        return redirect(url_for('agents.agents_list'))
    if not current_user.admin:
        abort(403)

    # Remove every reference to this agent BEFORE deleting it. Two foreign keys
    # point at agents.id — job_tasks.agent_id and agent_benchmarks.agent_id — and
    # either one blocks the delete (the commit rolls back, so the agent silently
    # reappears). Re-queue any chunk it was actively running (so the work isn't
    # orphaned), clear agent_id on all of its job_tasks, and drop its stored
    # per-hashtype benchmarks.
    for jt in JobTasks.query.filter_by(agent_id=agent_id).all():
        if jt.status == 'Running':
            jt.status = 'Queued'
        jt.agent_id = None
    AgentBenchmarks.query.filter_by(agent_id=agent_id).delete(synchronize_session=False)

    db.session.delete(agent)
    if not try_commit(f'delete agent {agent_id}'):
        flash('Agent could not be deleted — please try again.', 'danger')
        return redirect(url_for('agents.agents_list'))
    flash('Agent removed', 'success')
    return redirect(url_for('agents.agents_list'))

@agents.route("/agents/download", methods=['GET'])
@login_required
def agents_download():
    """Function to download agent"""
    version = hashview.__version__
    filename = 'hashview-agent.' + version + '.tgz'
    cmd = 'tar -czf hashview/control/tmp/' + filename + ' -C install hashview-agent'
    os.system(cmd)

    return send_from_directory('control/tmp', filename, as_attachment=True)
