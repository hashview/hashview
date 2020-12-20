from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required
from hashview.tasks.forms import TasksForm
from hashview.models import Tasks, Wordlists, Rules

tasks = Blueprint('tasks', __name__)

#############################################
# Tasks
#############################################

@tasks.route("/tasks", methods=['GET', 'POST'])
@login_required
def tasks_list():
    tasks = Tasks.query.all()
    return render_template('tasks.html', title='tasks', tasks=tasks) 

@tasks.route("/tasks/add", methods=['GET', 'POST'])
@login_required
def tasks_add():
    tasksForm = TasksForm()
    if tasksForm.validate_on_submit():
        if tasksForm.hc_attackmode.data == 'dictionary':
            task = Tasks(name=tasksForm.name.data, wl_id=tasksForm.wl_id.data, rule_id=tasksForm.rule_id.data)
            db.session.add(task)
            db.session.commit()
            flash(f'Task {tasksForm.name.data} created!', 'success')
        elif tasksForm.hc_attackmode.data == 'maskmode':
            task = Tasks(fname=tasksForm.name.data, hc_mask=tasksForm.mask.data)
            db.session.add(task)
            db.session.commit() 
            flash(f'Task {tasksForm.name.data} created!', 'success')           
        else:
            flash('Attack Mode not supported... yet...', 'danger')
        return redirect(url_for('tasks.tasks_list'))  
    return render_template('tasks_add.html', title='Tasks Add', tasksForm=tasksForm)   