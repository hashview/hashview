import os
import secrets
import hashlib
from flask import render_template, url_for, flash, redirect, request, abort
from hashview import app, db, bcrypt
from hashview.forms import UsersForm, LoginForm, ProfileForm, SettingsForm, WordlistsForm, RulesForm
from hashview.models import Users, Customers, Hashfiles, Jobs, Settings, Tasks, TaskGroups, TaskQueues, Wordlists, Rules
from flask_login import login_user, current_user, logout_user, login_required


#############################################
# Common Functions
#############################################

def save_file(path, form_file):
    random_hex = secrets.token_hex(8)
    file_name = random_hex + os.path.split(form_file.filename)[0] + '.txt'
    file_path = os.path.join(app.root_path, path, file_name)
    form_file.save(file_path)
    return file_path

def get_linecount(filepath):
    return sum(1 for line in open(filepath))

def get_filehash(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath,"rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096),b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

#############################################
# Main
#############################################

@app.route("/")
@login_required
def home():
    return render_template('home.html')

@app.route("/login", methods=['GET', 'POST'])
def login(): 
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email_address=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)  

@app.route("/logout")
def logout(): 
    logout_user()
    return redirect(url_for('home'))

@app.route("/users", methods=['GET', 'POST'])
@login_required
def users():
    users = Users.query.all()
    return render_template('users.html', title='Users', users=users)

@app.route("/users/add", methods=['GET', 'POST'])
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
            return redirect(url_for('users'))
        return render_template('users_add.html', title='User Add', form=form)   
    else:
        abort(403)

@app.route("/users/delete/<int:user_id>", methods=['POST'])
@login_required
def users_delete(user_id):
    if current_user.admin:
        user = Users.query.get_or_404(user_id)
        #if post.author != current_user:  #confirm if admin
        #    abort(403)
        db.session.delete(user)
        db.session.commit()
        flash('User has been deleted!', 'success')
        return redirect(url_for('users'))
    else:
        abort(403)

@app.route("/profile", methods=['GET', 'POST'])
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
        return redirect(url_for('profile'))
    elif request.method == 'GET':
        form.first_name.data = current_user.first_name
        form.last_name.data = current_user.last_name
        form.pushover_id.data = current_user.pushover_id
        form.pushover_key.data = current_user.pushover_key
    return render_template('profile.html', title='Profile', form=form)

#############################################
# Customers
#############################################

@app.route("/customers", methods=['GET'])
@login_required
def customers():
    customers = Customers.query.all()
    return render_template('customers.html', title='Cusomters', customers=customers)

@app.route("/customers/add", methods=['GET', 'POST'])
@login_required
def customers_add():
    form = CustomersForm()
    if form.validate_on_submit():
        customer = Customers(name=form.name.data)
        db.session.add(customer)
        db.session.commit()
        flash(f'Customer created!', 'success')
        return redirect(url_for('customers'))  # will need to do a conditional return if this was reated during a job creation
    return render_template('cusomers_add.html', title='Customer Add', form=form)   

@app.route("/customers/delete/<int:customer_id>", methods=['POST'])
@login_required
def customers_delete(customer_id):
    customer = Customers.query.get_or_404(customer_id)
    #if post.author != current_user:  #confirm if admin
    #    abort(403)
    db.session.delete(customer)
    db.session.commit()
    flash('Customer has been deleted!', 'success')
    return redirect(url_for('customers'))

#############################################
# Hashfiles
#############################################

@app.route("/hashfiles", methods=['GET', 'POST'])
@login_required
def hashfiles():
    hashfiles = Hashfiles.query.all()
    return render_template('hashfiles.html', title='Hashfiles', hashfiles=hashfiles)

@app.route("/hashfiles/delete/<int:hashfile_id>", methods=['POST'])
@login_required
def hashfiles_delete(hashfile_id):
    # TODO
    # Remove dynamic wordlists
    hashfile = hashfiles.query.get_or_404(hashfile_id)
    # TODO
    #if post.author != current_user:  #confirm if admin
    #    abort(403)
    db.session.delete(hashfile) # Probably need to do more, comfirm with old hashview code
    db.session.commit()
    flash('Hashfile has been deleted!', 'success')
    return redirect(url_for('hashfiles'))

#############################################
# Jobs
#############################################

@app.route("/jobs", methods=['GET', 'POST'])
@login_required
def jobs():
    jobs = Jobs.query.all()
    return render_template('jobs.html', title='jobs', jobs=jobs)

#############################################
# Agents
#############################################

@app.route("/agents", methods=['GET', 'POST'])
@login_required
def agents():
    if current_user.admin:
        agents = Agents.query.all()
        return render_template('agents.html', title='agents', agents=agents)
    else:
        abort(403)

#############################################
# Settings
#############################################

@app.route("/settings", methods=['GET', 'POST'])
@login_required
def settings():
    if current_user.admin:
        form = SettingsForm()
        settings = Settings.query.all()
        return render_template('settings.html', title='settings', settings=settings, form=form)
    else:
        abort(403)

#############################################
# Tasks
#############################################

@app.route("/tasks", methods=['GET', 'POST'])
@login_required
def tasks():
    tasks = Tasks.query.all()
    return render_template('tasks.html', title='tasks', tasks=tasks) 

#############################################
# Task Groups
#############################################

@app.route("/taskgroups", methods=['GET', 'POST'])
@login_required
def taskgroups():
    taskgroups = Taskgroups.query.all()
    return render_template('taskgroups.html', title='taskgroups', taskgroups=taskgroups)   

#############################################
# Wordlists
#############################################

@app.route("/wordlists", methods=['GET'])
@login_required
def wordlists():
    static_wordlists = Wordlists.query.filter_by(type='static').all()
    dynamic_wordlists = Wordlists.query.filter_by(type='dynamic').all()
    return render_template('wordlists.html', title='Wordlists', static_wordlists=static_wordlists, dynamic_wordlists=dynamic_wordlists) 

@app.route("/wordlists/add", methods=['GET', 'POST'])
@login_required
def wordlists_add():
    form = WordlistsForm()
    if form.validate_on_submit():
        if form.wordlist.data:
            wordlist_path = os.path.join(app.root_path, save_file('control/wordlists', form.wordlist.data))
            
            wordlist = Wordlists(name=form.name.data, 
                                type='static', 
                                path=wordlist_path,
                                checksum=get_filehash(wordlist_path),
                                size=get_linecount(wordlist_path))
            db.session.add(wordlist)
            db.session.commit()
            flash(f'Wordlist created!', 'success')
            return redirect(url_for('wordlists'))  
    return render_template('wordlists_add.html', title='Wordlist Add', form=form)   

@app.route("/wordlist/delete/<int:wordlist_id>", methods=['POST'])
@login_required
def wordlists_delete(wordlist_id):
    wordlist = Wordlists.query.get_or_404(wordlist_id)
    # TODO
    #if post.author != current_user:  #confirm if admin
    #    abort(403)
    #if wordlist.type == 'dynamic': # prevent deltion of dynamic list
    #   abort(403)
    db.session.delete(wordlist)
    db.session.commit()
    flash('Wordlist has been deleted!', 'success')
    return redirect(url_for('wordlists'))

#############################################
# Rules
#############################################

@app.route("/rules", methods=['GET'])
@login_required
def rules():
    rules = Rules.query.all()
    return render_template('rules.html', title='Rules', rules=rules) 

@app.route("/rules/add", methods=['GET', 'POST'])
@login_required
def rules_add():
    form = RulesForm()
    if form.validate_on_submit():
        if form.rules.data:
            rules_path = os.path.join(app.root_path, save_file('control/rules', form.rules.data))
            
            rule = Rules(name=form.name.data, 
                                path=rules_path,
                                size=get_linecount(rules_path),
                                checksum=get_filehash(rules_path))
            db.session.add(rule)
            db.session.commit()
            flash(f'Rules File created!', 'success')
            return redirect(url_for('rules'))  
    return render_template('rules_add.html', title='Rules Add', form=form)   

@app.route("/rules/delete/<int:rule_id>", methods=['GET', 'POST'])
@login_required
def rules_delete(rule_id):
    rule = Rules.query.get_or_404(rule_id)
    # TODO
    #if post.author != current_user:  #confirm if admin
    #    abort(403)
    #if wordlist.type == 'dynamic': # prevent deltion of dynamic list
    #   abort(403)
    db.session.delete(rule)
    db.session.commit()
    flash('Rule file has been deleted!', 'success')
    return redirect(url_for('rules'))