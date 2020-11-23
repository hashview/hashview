from flask import Blueprint, render_template
from flask_login import login_required
from hashview.models import TaskGroups

taskgroups = Blueprint('taskgroups', __name__)

#############################################
# Task Groups
#############################################

@taskgroups.route("/taskgroups", methods=['GET', 'POST'])
@login_required
def taskgroups_list():
    taskgroups = Taskgroups.query.all()
    return render_template('taskgroups.html', title='taskgroups', taskgroups=taskgroups)   
