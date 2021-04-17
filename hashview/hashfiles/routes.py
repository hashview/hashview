from flask import Blueprint, render_template, url_for, redirect, flash
from flask_login import login_required, current_user
from hashview.models import Hashfiles, Customers, Jobs, HashfileHashes
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

    # TODO
    # remove uncracked hashes for hashes db where no hashfile_hash is associated
    # HVDB.run('DELETE h FROM hashes h LEFT JOIN hashfilehashes a ON h.id = a.hash_id WHERE(a.hashfile_id is NULL AND h.cracked = 0)')


    # TODO
    # Remove dynamic wordlists from options for being deleted
    hashfile = Hashfiles.query.get_or_404(hashfile_id)
    jobs = Jobs.query.filter_by(hashfile_id = hashfile_id).first()
    hashfile_hashes = HashfileHashes.query.filter_by(hashfile_id = hashfile_id).first()

    if hashfile:
        if current_user.admin:
            if jobs:
                flash('Error: Hashfile currently associated with a job.', 'danger')
                return redirect(url_for('hashfiles.hashfiles_list'))
            else:
                if hashfile_hashes:
                    db.session.delete(hashfile_hashes)
                    db.session.commit()
                db.session.delete(hashfile)
                db.session.commit()
                #if hashfile_hashes:
                #    db.session.delete(hashfile_hashes)
                #    db.session.commit()
                flash('Hashfile has been deleted!', 'success')
                return redirect(url_for('hashfiles.hashfiles_list'))
        else:
            flash('You do not have rights to delete this hashfile!', 'danger')
            return redirect(url_for('hashfiles.hashfiles_list'))
    else:
        flash('Error in deleteing hashfile', 'danger')
        return redirect(url_for('hashfiles.hashfiles_list'))

