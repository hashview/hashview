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

    # clear select field for wordlists and rules
    tasksForm.rule_id.choices = []
    tasksForm.wl_id.choices = []

    wordlists = Wordlists.query.all()
    rules = Rules.query.all()

    for wordlist in wordlists:
        tasksForm.wl_id.choices += [(wordlist.id, wordlist.name)]
    
    tasksForm.rule_id.choices = [('None', 'None')]
    for rule in rules:
        tasksForm.rule_id.choices += [(rule.id, rule.name)]

    if tasksForm.validate_on_submit():

        if tasksForm.rule_id.data == 'None':
            rule_id = None
        else:
            rule_id = tasksForm.rule_id.data

        if tasksForm.hc_attackmode.data == 'dictionary':
            task = Tasks(   name=tasksForm.name.data,
                            owner_id=current_user.id,
                            wl_id=tasksForm.wl_id.data,
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
                            hc_mask=tasksForm.mask.data
            )
            db.session.add(task)
            db.session.commit()
            flash(f'Task {tasksForm.name.data} created!', 'success')
        else:
            flash('Attack Mode not supported... yet...', 'danger')
        return redirect(url_for('tasks.tasks_list'))
    return render_template('tasks_add.html', title='Tasks Add', tasksForm=tasksForm)

@tasks.route("/tasks/edit/<int:task_id>", methods=['GET', 'POST'])
@login_required
def task_edit(task_id):
    task = Tasks.query.get(task_id)

    # Check if task is currently assigned to a job. 
    # We probably dont care if its assigned to a task group though
    affected_jobs = JobTasks.query.filter_by(task_id=task_id).all()
    if affected_jobs:
        flash('Can not edit this task. It is currently associated to one or more jobs.', 'danger')
        return redirect(url_for('tasks.tasks_list'))

    if current_user.admin or task.owner_id == current_user.id:
        tasksForm = TasksForm()

        # clear select field for wordlists and rules
        tasksForm.rule_id.choices = []
        tasksForm.wl_id.choices = []

        wordlists = Wordlists.query.all()
        # Add the current value for wordlist.
        if task.hc_attackmode == 'dictionary':
            edit_task_wl = Wordlists.query.get(task.wl_id)
            if edit_task_wl:
                tasksForm.wl_id.choices.append((edit_task_wl.id, edit_task_wl.name))
        rules = Rules.query.all()
        # Check if the current value for rule is an integer.
        if isinstance(task.rule_id, int):
            edit_task_rl = Rules.query.get(task.rule_id)
            if edit_task_rl:
                tasksForm.rule_id.choices.append((edit_task_rl.id, edit_task_rl.name))
                tasksForm.rule_id.choices.append(('None', 'None'))
        else:
            # If it's not an integer, set rule_id and rule_name to 'None'.
            tasksForm.rule_id.choices.append(('None', 'None'))

        # Populate the choices for wordlists excluding the current value.
        tasksForm.wl_id.choices += [(wordlist.id, wordlist.name) for wordlist in wordlists if wordlist.id != task.wl_id]
        
        # Populate the choices for rules excluding the current value.
        tasksForm.rule_id.choices += [(rule.id, rule.name) for rule in rules if rule.id != task.rule_id]
        
        tasksForm.submit.label.text = 'Update'

        if tasksForm.validate_on_submit():
            wordlist_id = tasksForm.wl_id.data
            rule_id = tasksForm.rule_id.data

            if tasksForm.rule_id.data == 'None':
                tasksForm.rule_id.data = None

            if tasksForm.hc_attackmode.data == 'dictionary':
                task.name = tasksForm.name.data
                task.wl_id = tasksForm.wl_id.data
                task.rule_id = tasksForm.rule_id.data
                task.hc_attackmode = tasksForm.hc_attackmode.data
                hc_mask = None

                db.session.add(task)
                db.session.commit()
                flash(f'Task {tasksForm.name.data} updated!', 'success')
            elif tasksForm.hc_attackmode.data == 'maskmode':

                task.name = tasksForm.name.data
                task.wl_id = None
                task.rule_id = None
                task.hc_attackmode = tasksForm.hc_attackmode.data
                task.hc_mask = tasksForm.mask.data

                db.session.add(task)
                db.session.commit()
                flash(f'Task {tasksForm.name.data} updated!', 'success')
            else:
                flash('Attack Mode not supported... yet...', 'danger')
            return redirect(url_for('tasks.tasks_list'))
        else:
            tasksForm.name.data = task.name
            tasksForm.hc_attackmode.data = task.hc_attackmode
            tasksForm.wl_id.data = (task.wl_id, 'Rockyou.txt')
            tasksForm.rule_id.data = (task.rule_id, 'bar')
            tasksForm.mask.data = task.hc_mask

        return render_template('tasks_edit.html', title='Tasks Edit', tasksForm=tasksForm, task=task, wordlists=wordlists, rules=rules)
    else:
        flash('You are unauthorized to edit this task.', 'danger')
        return redirect(url_for('tasks.tasks_list'))
    
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
        flash('You are unauthorized to delete this task.', 'danger')
        return redirect(url_for('tasks.tasks_list'))
