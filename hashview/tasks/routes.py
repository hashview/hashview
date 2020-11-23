from flask import Blueprint, render_template
from flask_login import login_required
from hashview.models import Tasks

tasks = Blueprint('tasks', __name__)

#############################################
# Tasks
#############################################

@tasks.route("/tasks", methods=['GET', 'POST'])
@login_required
def tasks_list():
    tasks = Tasks.query.all()
    return render_template('tasks.html', title='tasks', tasks=tasks) 