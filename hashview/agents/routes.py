from flask import Blueprint, render_template, abort, flash, redirect, url_for, send_from_directory
from flask_login import login_required, current_user
from hashview.agents.forms import AgentsForm
from hashview.models import Agents, JobTasks
from hashview.utils.utils import getHashviewVersion
from hashview import db
import os

agents = Blueprint('agents', __name__)

@agents.route("/agents", methods=['GET', 'POST'])
@login_required
def agents_list():
    if current_user.admin:
        agentsForm = AgentsForm()

        if agentsForm.validate_on_submit():
            agent_name = agentsForm.name.data
            agent_id = agentsForm.id.data

            agent = Agents.get(agent_id)
            agent.name = agent_name
            db.session.commit()

            flash('Updated Agents Name', 'success')
            return redirect(url_for('agents.agents_list'))
        else:
            agents = Agents.query.all()
            return render_template('agents.html', title='agents', agents=agents, agentsForm=agentsForm)
    else:
        abort(403)

@agents.route("/agents/edit/<int:agent_id>", methods=['GET', 'POST'])
@login_required
def agents_edit(agent_id):
    if current_user.admin:
        agentsForm = AgentsForm()

        if agentsForm.validate_on_submit():
            agent_name = agentsForm.name.data
            agent_id = agentsForm.id.data

            agent = Agents.query.get(agent_id)
            agent.name = agent_name
            db.session.commit()

            flash('Updated Agents Name', 'success')
            return redirect(url_for('agents.agents_list'))
        else:
            agent = Agents.query.get(agent_id)
            return render_template('agents_edit.html', title='agents', agent=agent, agentsForm=agentsForm)
    else:
        flash('You are unauthorized to edit agent data.', 'danger')
    redirect(url_for('agents.agents_list'))

@agents.route("/agents/<int:agent_id>/authorize", methods=['GET'])
@login_required
def agents_authorize(agent_id):
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
    if current_user.admin:
        jobtasks = JobTasks.query.filter_by(agent_id = agent_id).count()
        if jobtasks > 0:
            flash('Error: Agent is active with a task.', 'danger')
        else:
            agent = Agents.query.get(agent_id)
            db.session.delete(agent)
            db.session.commit()
            flash('Agent removed', 'success')
        return redirect(url_for('agents.agents_list'))
    else:
        abort(403)

@agents.route("/agents/download", methods=['GET'])
@login_required
def agents_download():
    version = getHashviewVersion()
    filename = 'hashview-agent.' + version + '.tgz'
    cmd = 'tar -czf hashview/control/tmp/' + filename + ' install/hashview-agent/*'
    os.system(cmd)

    return send_from_directory('control/tmp', filename, as_attachment=True)