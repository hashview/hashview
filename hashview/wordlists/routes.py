import os
from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required
from hashview.wordlists.forms import WordlistsForm
from hashview.models import Wordlists

wordlists = Blueprint('wordlists', __name__)

#############################################
# Wordlists
#############################################

@wordlists.route("/wordlists", methods=['GET'])
@login_required
def wordlists():
    static_wordlists = Wordlists.query.filter_by(type='static').all()
    dynamic_wordlists = Wordlists.query.filter_by(type='dynamic').all()
    return render_template('wordlists.html', title='Wordlists', static_wordlists=static_wordlists, dynamic_wordlists=dynamic_wordlists) 

@wordlists.route("/wordlists/add", methods=['GET', 'POST'])
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

@wordlists.route("/wordlist/delete/<int:wordlist_id>", methods=['POST'])
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
