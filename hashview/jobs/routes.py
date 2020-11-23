from flask import Blueprint, render_template
from flask_login import login_required
from hashview.models import Jobs

jobs = Blueprint('jobs', __name__)

#############################################
# Jobs
#############################################

@jobs.route("/jobs", methods=['GET', 'POST'])
@login_required
def jobs_list():
    jobs = Jobs.query.all()
    return render_template('jobs.html', title='jobs', jobs=jobs)