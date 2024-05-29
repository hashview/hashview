"""Flask routes to handle Settings"""
import os
from flask import Blueprint, render_template, abort, url_for, flash, request, redirect
from flask_login import login_required, current_user
import hashview
from hashview.settings.forms import HashviewSettingsForm
from hashview.models import Settings
from hashview.models import db


settings = Blueprint('settings', __name__)


#############################################
# Settings
#############################################

@settings.route("/settings", methods=['GET', 'POST'])
@login_required
def settings_list():
    """Function to return list of Settings"""

    if current_user.admin:
        hashview_form = HashviewSettingsForm()
        settings = Settings.query.first()

        tmp_folder_size = 0
        for file in os.scandir('hashview/control/tmp/'):
            tmp_folder_size += os.stat(file).st_size

        if hashview_form.validate_on_submit():
            settings.retention_period = hashview_form.retention_period.data
            settings.max_runtime_jobs = hashview_form.max_runtime_jobs.data
            settings.max_runtime_tasks = hashview_form.max_runtime_tasks.data
            settings.enabled_job_weights = hashview_form.enabled_job_weights.data
            db.session.commit()
            flash('Updated Hashview settings!', 'success')
            return redirect(url_for('settings.settings_list'))
        elif request.method == 'GET':
            hashview_form.retention_period.data = settings.retention_period
            hashview_form.max_runtime_jobs.data = settings.max_runtime_jobs
            hashview_form.max_runtime_tasks.data = settings.max_runtime_tasks
            hashview_form.enabled_job_weights.data = settings.enabled_job_weights

        try:
            database_version = db.session.execute('SELECT version_num FROM alembic_version LIMIT 1;').scalar()
        except:
            database_version = 'error'

        return render_template(
            'settings.html',
            title               = 'settings',
            settings            = settings,
            hashview_form        = hashview_form,
            tmp_folder_size     = tmp_folder_size,
            application_version = hashview.__version__,
            database_version    = database_version,
        )

    abort(403)

@settings.route('/settings/clear_temp')
@login_required
def clear_temp_folder():
    """Function to clear temp folder"""
    if current_user.admin:
        for file in os.scandir('hashview/control/tmp/'):
            os.remove(file.path)
        return redirect(url_for('settings.settings_list'))

    abort(403)
