from flask import Blueprint, render_template, redirect
from flask_login import login_required, current_user
from hashview.models import Jobs, JobTasks, Users, Customers, Tasks, Agents
from hashview.utils.utils import update_job_task_status
import json
from hashview import db, scheduler
from sqlalchemy import or_


main = Blueprint('main', __name__)

@main.route("/")
@login_required
def home():
    jobs = Jobs.query.filter(or_((Jobs.status.like('Running')),(Jobs.status.like('Queued'))))
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

    # These are going to have to be put into an array :(
    #fig1_cracked_cnt = db.session.query(Hashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '1').filter(HashfileHashes.hashfile_id==hashfile_id).count()
    #fig1_uncracked_cnt = db.session.query(Hashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '0').filter(HashfileHashes.hashfile_id==hashfile_id).count()

    return render_template('home.html', jobs=jobs, users=users, customers=customers, job_tasks=job_tasks, tasks=tasks, agents=agents, recovered_list=recovered_list, time_estimated_list=time_estimated_list)

@main.route("/job_task/stop/<int:job_task_id>")
@login_required
def stop_job_task(job_task_id):
    job_task = JobTasks.query.get(job_task_id)
    job = Jobs.query.get(job_task.job_id)

    if job_task and job:
        if current_user.admin or job.owner_id == current_user.id:
            update_job_task_status(job_task.id, 'Canceled')

    return redirect("/")


            