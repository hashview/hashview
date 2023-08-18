import json

from flask import Blueprint, render_template, redirect, flash
from flask_login import login_required, current_user
from sqlalchemy import or_

from hashview.models import Jobs, JobTasks, Users, Customers, Tasks, Agents
from hashview.utils.utils import update_job_task_status


main = Blueprint('main', __name__)

@main.route("/")
@login_required
def home():
    jobs = Jobs.query.filter(or_((Jobs.status.like('Running')),(Jobs.status.like('Queued'))))
    running_jobs = Jobs.query.filter_by(status = 'Running').order_by(Jobs.priority.desc(), Jobs.queued_at.asc()).all()
    queued_jobs = Jobs.query.filter_by(status = 'Queued').order_by(Jobs.priority.desc(), Jobs.queued_at.asc()).all()
    users = Users.query.all()
    customers = Customers.query.all()
    job_tasks = JobTasks.query.all()
    tasks = Tasks.query.all()
    agents = Agents.query.all()

    recovered_list = {}
    time_estimated_list = {}

    # Create Agent Progress
    for agent in agents:
        if agent.hc_status:
            recovered_list[agent.id] = json.loads(agent.hc_status)['Recovered']
            time_estimated_list[agent.id] = json.loads(agent.hc_status)['Time_Estimated']

    collapse_all = ""
    for job in jobs:
        collapse_all = (collapse_all + "collapse" + str(job.id) + " ")

    return render_template('home.html', jobs=jobs, running_jobs=running_jobs, queued_jobs=queued_jobs, users=users, customers=customers, job_tasks=job_tasks, tasks=tasks, agents=agents, recovered_list=recovered_list, time_estimated_list=time_estimated_list, collapse_all=collapse_all)

@main.route("/job_task/stop/<int:job_task_id>")
@login_required
def stop_job_task(job_task_id):
    job_task = JobTasks.query.get(job_task_id)
    job = Jobs.query.get(job_task.job_id)

    if job_task and job:
        if current_user.admin or job.owner_id == current_user.id:
            update_job_task_status(job_task.id, 'Canceled')
        else:
            flash('You are unauthorized to stop this task', 'danger')

    return redirect("/")


