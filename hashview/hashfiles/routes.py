from flask import Blueprint, render_template, url_for, redirect, flash
from flask_login import login_required
from hashview.models import Hashfiles
from hashview import db

hashfiles = Blueprint('hashfiles', __name__)


@hashfiles.route("/hashfiles", methods=['GET', 'POST'])
@login_required
def hashfiles_list():
    hashfiles = Hashfiles.query.all()
    return render_template('hashfiles.html', title='Hashfiles', hashfiles=hashfiles)

@hashfiles.route("/hashfiles/delete/<int:hashfile_id>", methods=['POST'])
@login_required
def hashfiles_delete(hashfile_id):
    # TODO
    # Remove dynamic wordlists
    hashfile = Hashfiles.query.get_or_404(hashfile_id)
    # TODO
    #if post.author != current_user:  #confirm if admin
    #    abort(403)
    db.session.delete(hashfile) # Probably need to do more, comfirm with old hashview code
    db.session.commit()
    flash('Hashfile has been deleted!', 'success')
    return redirect(url_for('hashfiles.hashfiles_list'))
