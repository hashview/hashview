from flask import Blueprint, render_template, redirect, url_for, flash, abort
from flask_login import login_required, current_user
from hashview.tasks.forms import TasksForm
from hashview.models import Tasks, Wordlists, Rules
from hashview import db
from hashview.utils.utils import get_keyspace

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
        wordlist_id = tasksForm.wl_id.data.id
        rule_id = tasksForm.rule_id.data.id
 
        if tasksForm.hc_attackmode.data == 'dictionary':
            task = Tasks(   name=tasksForm.name.data, 
                            wl_id=wordlist_id,
                            rule_id=rule_id, 
                            hc_attackmode=tasksForm.hc_attackmode.data,
                            keyspace=get_keyspace(  method=tasksForm.hc_attackmode.data, 
                                                    wordlist_id = rule_id, 
                                                    rule_id=rule_id,
                                                    mask=None
                            )
            )             
            db.session.add(task)
            db.session.commit()
            flash(f'Task {tasksForm.name.data} created!', 'success')
        elif tasksForm.hc_attackmode.data == 'maskmode':
            task = Tasks(   name=tasksForm.name.data, 
                            wl_id=None,
                            rule_id=None, 
                            hc_attackmode=tasksForm.hc_attackmode.data,
                            keyspace=get_keyspace(  method=tasksForm.hc_attackmode.data, 
                                                    wordlist_id = None, 
                                                    rule_id=None,
                                                    mask=tasksForm.mask.data
                )
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
    if current_user.admin:
        # Confirm not already in active task group or job
        task = Tasks.query.get_or_404(task_id)
        db.session.delete(task)
        db.session.commit()
        flash('Task has been deleted!', 'success')
        return redirect(url_for('tasks.tasks_list'))
    else:
        abort(403)