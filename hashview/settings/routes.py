from flask import Blueprint, render_template, abort, url_for, flash, request, redirect
from flask_login import login_required, current_user
from hashview.settings.forms import HashviewSettingsForm
from hashview.models import Settings
from hashview import db

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

        if HashviewForm.validate_on_submit():
            settings.retention_period = HashviewForm.retention_period.data
            settings.hashcat_path = HashviewForm.hashcat_path.data
            db.session.commit()
            flash('Updated Hashview settings!', 'success')
            return redirect(url_for('settings.settings_list'))
        elif request.method == 'GET':
            HashviewForm.retention_period.data = settings.retention_period
            HashviewForm.hashcat_path.data = settings.hashcat_path
        
        return render_template('settings.html', title='settings', settings=settings, HashviewForm=HashviewForm)
    else:
        abort(403)
