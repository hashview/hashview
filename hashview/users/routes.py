from flask import Blueprint, render_template, url_for, flash, abort, redirect, request
from flask_login import login_required, logout_user, current_user, login_user
from hashview.users.forms import LoginForm, UsersForm, ProfileForm, RequestResetForm, ResetPasswordForm
from hashview.utils.utils import send_email, send_pushover
from hashview.models import Users
from hashview import db, bcrypt

users = Blueprint('users', __name__)

@users.route("/login", methods=['GET', 'POST'])
def login(): 
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email_address=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            if request.args.get("next"):
                return redirect(request.args.get("next"))
            else:
                return redirect(url_for('main.home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)  

@users.route("/logout")
def logout(): 
    logout_user()
    return redirect(url_for('main.home'))

@users.route("/users", methods=['GET', 'POST'])
@login_required
def users_list():
    users = Users.query.all()
    return render_template('users.html', title='Users', users=users)

@users.route("/users/add", methods=['GET', 'POST'])
@login_required
def users_add():
    if current_user.admin:
        form = UsersForm()
        if form.validate_on_submit():
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            if form.pushover_id.data and form.pushover_key.data:
                user = Users(first_name=form.first_name.data, last_name=form.last_name.data, email_address=form.email.data, admin=form.is_admin.data, password=hashed_password, pushover_id=form.pushover_id.data, pushover_key=form.pushover_key.data)
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
        if form.pushover_id.data:
            current_user.pushover_id = form.pushover_id.data 
        if form.pushover_key.data:
            current_user.pushover_key = form.pushover_key.data 
        db.session.commit()
        flash('Profile Updated!', 'success')
        return redirect(url_for('users.profile'))
    elif request.method == 'GET':
        form.first_name.data = current_user.first_name
        form.last_name.data = current_user.last_name
        form.pushover_id.data = current_user.pushover_id
        form.pushover_key.data = current_user.pushover_key
    return render_template('profile.html', title='Profile', form=form)

@users.route("/profile/send_test_pushover", methods=['GET'])
@login_required
def send_test_pushover():
    user = Users.query.get(current_user.id)
    send_pushover(user, 'Test Message From Hashview', 'This is a test pushover message from hashview')
    flash('Pushover Sent', 'success')
    return redirect(url_for('users.profile'))

@users.route("/reset_password", methods=['GET', 'POST'])
def reset_request():

    form = RequestResetForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email_address=form.email.data).first()
        token = user.get_reset_token()
        subject = 'Password Reset Request.'
        message = f'''To reset your password, vist the following link:
{url_for('users.reset_token', token=token, _external=True)}

If you did not make this request... then something phishy is going on.
'''
        send_email(user, subject, message)
        flash('An email has been sent to '+  form.email.data, 'info')
        return redirect(url_for('users.login')) 
    return render_template('reset_request.html', title='Reset Password', form=form)

@users.route("/admin_reset_password/<int:user_id>", methods=['GET', 'POST'])
@login_required
def admin_reset(user_id):
    if current_user.admin:
        user = Users.query.get(user_id)
        token = user.get_reset_token()
        subject = 'Password Reset Request.'
        message = f'''To reset your password, vist the following link:
{url_for('users.reset_token', token=token, _external=True)}

If you did not make this request... then something phishy is going on.
'''
        send_email(user, subject, message)
        flash('An email has been sent to '+  user.email_address, 'info')
        return redirect(url_for('users.users_list'))
    else:
        flash('Unauthorized to reset users account.', 'danger')
        return redirect(url_for('users.users_list'))


@users.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    user = Users.verify_reset_token(token)
    if user is None:
        flash('Invalid or Expired Token!', 'warning')
        return redirect(url_for('main.home'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated! You are now able to login.', 'success')
        return redirect(url_for('users.login'))
    return render_template('reset_token.html', title='Reset Password', form=form)
