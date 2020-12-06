from flask import Blueprint, render_template, redirect, url_for
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
    form = TasksForm()
    wordlists = Wordlists.query.all()
    rules = Rules.query.all()
    if form.validate_on_submit():
        # Check if name exists
        #if form.rules.data:
        #   rules_path = os.path.join(current_app.root_path, save_file('control/rules', form.rules.data))
        #    
        #    rule = Rules(name=form.name.data, 
        #                        path=rules_path,
        #                        size=get_linecount(rules_path),
        #                        checksum=get_filehash(rules_path))
        #    db.session.add(rule)
        #    db.session.commit()
        #    flash(f'Rules File created!', 'success')
            return redirect(url_for('tasks.tasks_list'))  
    return render_template('tasks_add.html', title='Tasks Add', form=form)   