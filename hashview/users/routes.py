from flask import Blueprint, render_template, url_for, flash, abort, redirect, request
from flask_login import login_required, logout_user, current_user, login_user
from hashview.users.forms import LoginForm, UsersForm, ProfileForm
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
                user = Users(first_name=form.first_name.data, last_name=form.last_name.data, email_address=form.email.data, password=hashed_password, pushover_id=form.pushover_id.data, pushover_key=form.pushover_key.data)
            else:
                user = Users(first_name=form.first_name.data, last_name=form.last_name.data, email_address=form.email.data, password=hashed_password)
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
        #if post.author != current_user:  #confirm if admin
        #    abort(403)
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
        return redirect(url_for('user.profile'))
    elif request.method == 'GET':
        form.first_name.data = current_user.first_name
        form.last_name.data = current_user.last_name
        form.pushover_id.data = current_user.pushover_id
        form.pushover_key.data = current_user.pushover_key
    return render_template('profile.html', title='Profile', form=form)