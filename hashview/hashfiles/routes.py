from flask import Blueprint, render_template, url_for, redirect, flash
from flask_login import login_required, current_user
from hashview.models import Hashfiles, Customers, Jobs, HashfileHashes, HashNotifications, Hashes
from hashview import db

hashfiles = Blueprint('hashfiles', __name__)


@hashfiles.route("/hashfiles", methods=['GET', 'POST'])
@login_required
def hashfiles_list():
    hashfiles = Hashfiles.query.all()
    customers = Customers.query.all()
    return render_template('hashfiles.html', title='Hashfiles', hashfiles=hashfiles, customers=customers)

@hashfiles.route("/hashfiles/delete/<int:hashfile_id>", methods=['GET'])
@login_required
def hashfiles_delete(hashfile_id):
    hashfile = Hashfiles.query.get_or_404(hashfile_id)
    jobs = Jobs.query.filter_by(hashfile_id = hashfile_id).first()
    hashfile_hashes = HashfileHashes.query.filter_by(hashfile_id = hashfile_id).all()

    if hashfile:
        if current_user.admin or hashfile.owner_id == current_user.id:
            if jobs:
                flash('Error: Hashfile currently associated with a job.', 'danger')
                return redirect(url_for('hashfiles.hashfiles_list'))
            else:
                hashfile_hashes = HashfileHashes.query.filter_by(hashfile_id = hashfile_id).all()
                for hashfile_hash in hashfile_hashes:
                    HashNotifications.query.filter_by(hash_id=hashfile_hash.hash_id).delete()
                    Hashes.query.filter_by(id=hashfile_hash.id, cracked=0).delete()
                    db.session.delete(hashfile_hash)
                db.session.delete(hashfile)
                db.session.commit()
                flash('Hashfile has been deleted!', 'success')
                return redirect(url_for('hashfiles.hashfiles_list'))
        else:
            flash('You do not have rights to delete this hashfile!', 'danger')
            return redirect(url_for('hashfiles.hashfiles_list'))
    else:
        flash('Error in deleteing hashfile', 'danger')
        return redirect(url_for('hashfiles.hashfiles_list'))

