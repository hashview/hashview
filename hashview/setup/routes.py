"""Flask routes to handle Setup"""

from flask import Blueprint, current_app, flash, redirect, render_template, url_for
from flask_login import login_user

from hashview.models import Settings, Users, db
from hashview.setup import admin_pass_needs_changed, settings_needs_added
from hashview.users.routes import bcrypt
from hashview.utils.clock import utcnow

from .forms import SetupAdminPassForm, SetupSettingsForm

blueprint = Blueprint('setup', __name__)


@blueprint.route('/setup/admin-pass', methods=['GET'])
def admin_pass_get():
    """Function to get admin password setup"""

    if not admin_pass_needs_changed(db, bcrypt):
        return redirect(url_for('main.home'))

    admin_user = db.session.query(Users).filter_by(id=1).first()

    login_user(admin_user, remember=False)
    admin_user.last_login_utc = utcnow()
    db.session.commit()

    form = SetupAdminPassForm()
    form.first_name.data    = admin_user.first_name
    form.last_name.data     = admin_user.last_name
    form.email_address.data = admin_user.email_address
    return render_template('setup_admin_pass.html.j2', form=form)


@blueprint.route('/setup/admin-pass', methods=['POST'])
def admin_pass_post():
    """Function to set admin password setup"""

    logger = current_app.logger

    if not admin_pass_needs_changed(db, bcrypt):
        logger.info('%s: Admin pass does not need changed.', admin_pass_post.__name__)
        return redirect(url_for('main.home'))

    form = SetupAdminPassForm()
    if not form.is_submitted():
        logger.info('%s: Form was not submitted.', admin_pass_post.__name__)
        return redirect(url_for('main.home'))

    if not form.validate():
        logger.info('%s: Form was not valid.', admin_pass_post.__name__)
        return render_template('setup_admin_pass.html.j2', form=form)

    admin_user = db.session.query(Users).filter_by(id=1).first()
    admin_user.first_name    = form.first_name.data
    admin_user.last_name     = form.last_name.data
    admin_user.email_address = form.email_address.data
    admin_user.password      = bcrypt.generate_password_hash(form.password.data)
    db.session.commit()
    flash('Admin password changed!', 'success')
    return redirect(url_for('setup.settings_get'))


@blueprint.route('/setup/settings', methods=['GET'])
def settings_get():
    """Function to get settings setup"""

    if not settings_needs_added(db):
        return redirect(url_for('main.home'))

    form = SetupSettingsForm()
    form.retention_period.data  = 1
    form.max_runtime_tasks.data = 0
    form.max_runtime_jobs.data  = 0
    return render_template('setup_settings.html.j2', form=form)


@blueprint.route('/setup/settings', methods=['POST'])
def settings_post():
    """Function to set settings setup"""

    logger = current_app.logger

    if not settings_needs_added(db):
        logger.info('%s: Settings do not need added.', settings_post.__name__)
        return redirect(url_for('main.home'))

    form = SetupSettingsForm()
    if not form.is_submitted():
        logger.info('%s: Form was not submitted.', settings_post.__name__)
        return redirect(url_for('main.home'))

    if not form.validate():
        logger.info('%s: Form was not valid.', settings_post.__name__)
        return render_template('setup_settings.html.j2', form=form)

    settings = Settings(
        retention_period  = form.retention_period.data,
        max_runtime_tasks = form.max_runtime_tasks.data,
        max_runtime_jobs  = form.max_runtime_jobs.data
    )
    db.session.add(settings)
    db.session.commit()
    flash('Settings added!', 'success')
    return redirect(url_for('main.home'))
