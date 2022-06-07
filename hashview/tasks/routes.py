from flask import Blueprint, render_template, redirect, url_for, flash, abort
from flask_login import login_required, current_user
from hashview.tasks.forms import TasksForm
from hashview.models import TaskGroups, Tasks, Wordlists, Rules, Users, Jobs, JobTasks
from hashview.models import db

tasks = Blueprint('tasks', __name__)

@tasks.route("/tasks", methods=['GET', 'POST'])
@login_required
def tasks_list():
    tasks = Tasks.query.all()
    users = Users.query.all()
    jobs = Jobs.query.all()
    job_tasks = JobTasks.query.all()
    wordlists = Wordlists.query.all()
    task_groups = TaskGroups.query.all()
    return render_template('tasks.html', title='tasks', tasks=tasks, users=users, jobs=jobs, job_tasks=job_tasks, wordlists=wordlists, task_groups=task_groups)

@tasks.route("/tasks/add", methods=['GET', 'POST'])
@login_required
def tasks_add():
    tasksForm = TasksForm()
    if tasksForm.validate_on_submit():
        wordlist_id = tasksForm.wl_id.data.id
        if tasksForm.rule_id.data == None:
            rule_id = None
        else:
            rule_id = tasksForm.rule_id.data.id

        if tasksForm.hc_attackmode.data == 'dictionary':
            task = Tasks(   name=tasksForm.name.data,
                            owner_id=current_user.id,
                            wl_id=wordlist_id,
                            rule_id=rule_id,
                            hc_attackmode=tasksForm.hc_attackmode.data
            )
            db.session.add(task)
            db.session.commit()
            flash(f'Task {tasksForm.name.data} created!', 'success')
        elif tasksForm.hc_attackmode.data == 'maskmode':
            task = Tasks(   name=tasksForm.name.data,
                            owner_id=current_user.id,
                            wl_id=None,
                            rule_id=None,
                            hc_attackmode=tasksForm.hc_attackmode.data,
                            hc_mask=tasksForm.mask.data,
            )
            db.session.add(task)
            db.session.commit()
            flash(f'Task {tasksForm.name.data} created!', 'success')
        else:
            flash('Attack Mode not supported... yet...', 'danger')
        return redirect(url_for('tasks.tasks_list'))
    return render_template('tasks_add.html', title='Tasks Add', tasksForm=tasksForm)

@tasks.route("/tasks/delete/<int:task_id>", methods=['POST'])
@login_required
def tasks_delete(task_id):
    task = Tasks.query.get(task_id)
    task_groups = TaskGroups.query.all()
    if current_user.admin or task.owner_id == current_user.id:

        # Check if associated with JobTask (which implies its associated with a job)
        jobtasks = JobTasks.query.all()
        for jobtask in jobtasks:
            if jobtask.task_id == task_id:
                flash('Can not delete. Task is associated to one or more jobs.', 'danger')
                return redirect(url_for('tasks.tasks_list'))

        for task_group in task_groups:
            if str(task_id) in task_group.tasks:
                flash('Can not delete. The Task is associated to one or more Task Groups.', 'danger')
                return redirect(url_for('tasks.tasks_list'))


        db.session.delete(task)
        db.session.commit()
        flash('Task has been deleted!', 'success')
        return redirect(url_for('tasks.tasks_list'))
    else:
        abort(403)