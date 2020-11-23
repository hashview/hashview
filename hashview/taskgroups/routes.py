from flask import Blueprint

taskgroups = Blueprint('taskgroups', __name__)

#############################################
# Task Groups
#############################################

@taskgroups.route("/taskgroups", methods=['GET', 'POST'])
@login_required
def taskgroups():
    taskgroups = Taskgroups.query.all()
    return render_template('taskgroups.html', title='taskgroups', taskgroups=taskgroups)   
