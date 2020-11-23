from flask import Blueprint, render_template, abort
from flask_login import login_required, current_user
from hashview.settings.forms import SettingsForm
from hashview.models import Settings

settings = Blueprint('settings', __name__)


#############################################
# Settings
#############################################

@settings.route("/settings", methods=['GET', 'POST'])
@login_required
def settings_list():
    if current_user.admin:
        form = SettingsForm()
        settings = Settings.query.all()
        return render_template('settings.html', title='settings', settings=settings, form=form)
    else:
        abort(403)
