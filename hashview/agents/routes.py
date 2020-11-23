from flask import Blueprint, render_template, abort
from flask_login import login_required, current_user
from hashview.models import Agents

agents = Blueprint('agents', __name__)

@agents.route("/agents", methods=['GET', 'POST'])
@login_required
def agents_list():
    if current_user.admin:
        agents = Agents.query.all()
        return render_template('agents.html', title='agents', agents=agents)
    else:
        abort(403)
