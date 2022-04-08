from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required, current_user
from hashview.wordlists.forms import WordlistsForm
from hashview.models import Tasks, Wordlists, Users
from hashview import db
from hashview.utils.utils import save_file, get_linecount, get_filehash, update_dynamic_wordlist

wordlists = Blueprint('wordlists', __name__)

@wordlists.route("/wordlists", methods=['GET'])
@login_required
def wordlists_list():
    static_wordlists = Wordlists.query.filter_by(type='static').all()
    dynamic_wordlists = Wordlists.query.filter_by(type='dynamic').all()
    wordlists = Wordlists.query.all()
    tasks = Tasks.query.all()
    users = Users.query.all()
    return render_template('wordlists.html', title='Wordlists', static_wordlists=static_wordlists, dynamic_wordlists=dynamic_wordlists, wordlists=wordlists, tasks=tasks, users=users) 

@wordlists.route("/wordlists/add", methods=['GET', 'POST'])
@login_required
def wordlists_add():
    form = WordlistsForm()
    if form.validate_on_submit():
        if form.wordlist.data:
            #wordlist_path = os.path.join(current_app.root_path, save_file('control/wordlists', form.wordlist.data))
            wordlist_path = save_file('control/wordlists', form.wordlist.data)
            print('File saved')
            wordlist = Wordlists(name=form.name.data,
                                owner_id=current_user.id, 
                                type='static', 
                                path=wordlist_path,
                                checksum=get_filehash(wordlist_path),
                                size=get_linecount(wordlist_path))
            db.session.add(wordlist)
            db.session.commit()
            flash(f'Wordlist created!', 'success')
            return redirect(url_for('wordlists.wordlists_list'))  
    return render_template('wordlists_add.html', title='Wordlist Add', form=form)   

@wordlists.route("/wordlists/delete/<int:wordlist_id>", methods=['POST'])
@login_required
def wordlists_delete(wordlist_id):
    wordlist = Wordlists.query.get(wordlist_id)
    if current_user.admin or wordlist.owner_id == current_user.id:

        # prevent deltion of dynamic list
        if wordlist.type == 'dynamic': 
            flash('Dynamic Wordlists can not be deleted.', 'danger')
            redirect(url_for('wordlists.wordlists_list'))

        # Check if associated with a Task 
        tasks = Tasks.query.all()
        for task in tasks:
            if task.wl_id == wordlist_id:
                flash('Failed. Wordlist is associated to one or more tasks', 'danger')
                return redirect(url_for('wordlists.wordlists_list'))

        db.session.delete(wordlist)
        db.session.commit()
        flash('Wordlist has been deleted!', 'success')
    else:
        flash('Unauthorized Action!', 'danger')
    return redirect(url_for('wordlists.wordlists_list'))


@wordlists.route("/wordlists/update/<int:wordlist_id>", methods=['GET'])
@login_required
def dynamicwordlist_update(wordlist_id):
    wordlist = Wordlists.query.get(wordlist_id)
    if wordlist.type == 'dynamic':
        update_dynamic_wordlist(wordlist_id)
        flash('Updated Dynamic Wordlist', 'succes')
    else:
        flash('Invalid wordlist', 'danger')
    return redirect(url_for('wordlists.wordlists_list'))
    