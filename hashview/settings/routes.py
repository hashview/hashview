from flask import Blueprint, render_template, abort, url_for, flash, request, redirect
from flask_login import login_required, current_user
from hashview.settings.forms import HashviewSettingsForm
from hashview.models import Settings
from hashview import db
import os

settings = Blueprint('settings', __name__)


#############################################
# Settings
#############################################

@settings.route("/settings", methods=['GET', 'POST'])
@login_required
def settings_list():
    if current_user.admin:
        HashviewForm = HashviewSettingsForm()
        settings = Settings.query.first()

        tmp_folder_size = 0
        for file in os.scandir('hashview/control/tmp/'):
            tmp_folder_size += os.stat(file).st_size

        if HashviewForm.validate_on_submit():
            settings.retention_period = HashviewForm.retention_period.data
            db.session.commit()
            flash('Updated Hashview settings!', 'success')
            return redirect(url_for('settings.settings_list'))
        elif request.method == 'GET':
            HashviewForm.retention_period.data = settings.retention_period

        return render_template('settings.html', title='settings', settings=settings, HashviewForm=HashviewForm, tmp_folder_size=tmp_folder_size)
    else:
        abort(403)

@settings.route('/settings/clear_temp')
@login_required
def clear_temp_folder():
    if current_user.admin:
        for file in os.scandir('hashview/control/tmp/'):
            os.remove(file.path)
        return redirect(url_for('settings.settings_list'))
    else:
        abort(403)