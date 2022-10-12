from textwrap import dedent
from datetime import datetime

from flask import Blueprint, render_template, url_for, flash, abort, redirect, request, current_app
from flask_login import login_required, logout_user, current_user, login_user
from flask_login import LoginManager
from flask_bcrypt import Bcrypt

from hashview.models import db
from hashview.models import Users, Jobs, Wordlists, Rules, TaskGroups, Tasks
from hashview.users.forms import LoginForm, UsersForm, ProfileForm, RequestResetForm, ResetPasswordForm
from hashview.utils.utils import send_email, send_pushover

import uuid

bcrypt = Bcrypt()


login_manager = LoginManager()
login_manager.login_view = 'users.login_get'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


users = Blueprint('users', __name__)


@users.route("/login", methods=['GET'])
def login_get():
    form = LoginForm()
    return render_template('login.html', title='Login', form=form)

@users.route("/login", methods=['POST'])
def login_post():
    def failed():
        flash('Login Unsuccessful. Please check email and password', 'danger')
        return render_template('login.html', title='Login', form=form)

    form = LoginForm()
    if not form.validate_on_submit():
        current_app.logger.info('Login is Complete with Failure(Form Validation).')
        return failed()

    user = Users.query.filter_by(email_address=form.email.data).first()
    if not user:
        current_app.logger.info('Login is Complete with Failure(Invalid User from Email:%s).', form.email.data)
        return failed()

    if not bcrypt.check_password_hash(user.password, form.password.data):
        current_app.logger.info('Login is Complete with Failure(Invalid Password).')
        return failed()

    else:
        login_user(user, remember=form.remember.data)
        user.last_login_utc = datetime.utcnow()
        db.session.commit()
        current_app.logger.info('Login is Complete with Success(User:%s).', user.email_address)
        return redirect(
            request.args.get("next", url_for('main.home'))
        )

@users.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('main.home'))

@users.route("/users", methods=['GET', 'POST'])
@login_required
def users_list():
    users = Users.query.all()
    jobs = Jobs.query.all()
    wordlists = Wordlists.query.all()
    rules = Rules.query.all()
    tasks = Tasks.query.all()
    task_groups = TaskGroups.query.all()
    return render_template('users.html', title='Users', users=users, jobs=jobs, wordlists=wordlists, rules=rules, tasks=tasks, task_groups=task_groups)

@users.route("/users/add", methods=['GET', 'POST'])
@login_required
def users_add():
    if current_user.admin:
        form = UsersForm()
        if form.validate_on_submit():
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('latin-1')
            if form.pushover_app_id.data and form.pushover_user_key.data:
                user = Users(first_name=form.first_name.data, last_name=form.last_name.data, email_address=form.email.data, admin=form.is_admin.data, password=hashed_password, pushover_app_id=form.pushover_app_id.data, pushover_user_key=form.pushover_user_key.data)
            else:
                user = Users(first_name=form.first_name.data, last_name=form.last_name.data, email_address=form.email.data, admin=form.is_admin.data, password=hashed_password)
            db.session.add(user)
            db.session.commit()
            flash(f'Account created for {form.email.data}!', 'success')
            return redirect(url_for('users.users_list'))
        return render_template('users_add.html', title='User Add', form=form)
    else:
        abort(403)

@users.route("/users/delete/<int:user_id>", methods=['POST'])
@login_required
def users_delete(user_id):
    if current_user.admin:
        user = Users.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        flash('User has been deleted!', 'success')
        return redirect(url_for('users.users_list'))
    else:
        abort(403)

@users.route("/profile", methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm()
    if form.validate_on_submit():
        current_user.first_name = form.first_name.data
        current_user.last_name = form.last_name.data
        if form.pushover_user_key.data:
            current_user.pushover_user_key = form.pushover_user_key.data
        if form.pushover_app_id.data:
            current_user.pushover_app_id = form.pushover_app_id.data
        db.session.commit()
        flash('Profile Updated!', 'success')
        return redirect(url_for('users.profile'))
    elif request.method == 'GET':
        form.first_name.data = current_user.first_name
        form.last_name.data = current_user.last_name
    return render_template('profile.html', title='Profile', form=form, current_user=current_user)

@users.route("/profile/send_test_pushover", methods=['GET'])
@login_required
def send_test_pushover():
    user = Users.query.get(current_user.id)
    send_pushover(user, 'Test Message From Hashview', 'This is a test pushover message from hashview')
    flash('Pushover Sent', 'success')
    return redirect(url_for('users.profile'))

@users.route("/profile/generate_api_key", methods=['GET'])
@login_required
def generate_api_key():
    user = Users.query.get(current_user.id)
    user.api_key = str(uuid.uuid4())
    db.session.commit()
    flash('New API Key Set', 'success')
    return redirect(url_for('users.profile'))

@users.route("/reset_password", methods=['GET', 'POST'])
def reset_request():

    form = RequestResetForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email_address=form.email.data).first()
        if user:
            token = user.get_reset_token()
            subject = 'Password Reset Request.'
            message = f'''To reset your password, vist the following link:
    {url_for('users.reset_token', user_id=user.id, token=token, _external=True)}

    If you did not make this request... then something phishy is going on.
    '''
            send_email(user, subject, message)
        flash('An email has been sent to '+  form.email.data, 'info')
        return redirect(url_for('users.login_get'))
    return render_template('reset_request.html', title='Reset Password', form=form)

@users.route("/admin_reset_password/<int:user_id>", methods=['GET', 'POST'])
@login_required
def admin_reset(user_id):
    if not current_user.admin:
        flash('Unauthorized to reset users account.', 'danger')
        return redirect(url_for('users.users_list'))

    else:
        user = Users.query.get(user_id)
        token = user.get_reset_token()
        subject = 'Password Reset Request.'
        message = dedent(f'''\
            To reset your password, vist the following link:
            {url_for('users.reset_token', user_id=user_id, token=token, _external=True)}

            If you did not make this request... then something phishy is going on.
            ''')
        send_email(user, subject, message)
        flash('An email has been sent to '+  user.email_address, 'info')
        return redirect(url_for('users.users_list'))


@users.route("/reset_password/<int:user_id>/<string:token>", methods=['GET', 'POST'])
def reset_token(user_id :int, token :str):
    user = Users.query.get(user_id)
    if not user:
        flash('Invalid User Id!', 'warning')
        return redirect(url_for('main.home'))

    if not user.verify_reset_token(token):
        flash('Invalid or Expired Token!', 'warning')
        return redirect(url_for('main.home'))

    form = ResetPasswordForm()
    if not form.validate_on_submit():
        return render_template('reset_token.html', title='Reset Password', form=form)

    else:
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated! You are now able to login.', 'success')
        return redirect(url_for('users.login_get'))
