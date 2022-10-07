from flask import Blueprint, render_template, url_for, redirect, flash
from flask_login import login_required, current_user
from hashview.models import Hashfiles, Customers, Jobs, HashfileHashes, HashNotifications, Hashes
from hashview.models import db
from sqlalchemy.sql import exists
from sqlalchemy import delete

hashfiles = Blueprint('hashfiles', __name__)

@hashfiles.route("/hashfiles", methods=['GET', 'POST'])
@login_required

def hashfiles_list():
    hashfiles = Hashfiles.query.order_by(Hashfiles.uploaded_at.desc()).all()
    # customers = Customers.query.order_by(Customers.name).all()
    customers = Customers.query.filter(exists().where(Customers.id == Hashfiles.customer_id)).all()
    # Hashes.query.filter(~ exists().where(Hashes.id==HashfileHashes.hash_id)).filter_by(cracked = '0')
    # select * from customers where id in (select customer_id from hashfiles);
    jobs = Jobs.query.all()

    cracked_rate = {}
    hash_type_dict = {}

    for hashfile in hashfiles:
        cracked_cnt = db.session.query(Hashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '1').filter(HashfileHashes.hashfile_id==hashfile.id).count()
        hash_cnt = db.session.query(Hashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(HashfileHashes.hashfile_id==hashfile.id).count()
        cracked_rate[hashfile.id] = "(" + str(cracked_cnt) + "/" + str(hash_cnt) + ")"
        if db.session.query(Hashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(HashfileHashes.hashfile_id==hashfile.id).first():
            hash_type_dict[hashfile.id] = db.session.query(Hashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(HashfileHashes.hashfile_id==hashfile.id).first().hash_type
        else:
            hash_type_dict[hashfile.id] = 'UNKNOWN'
            

    return render_template('hashfiles.html', title='Hashfiles', hashfiles=hashfiles, customers=customers, cracked_rate=cracked_rate, jobs=jobs, hash_type_dict=hash_type_dict)

@hashfiles.route("/hashfiles/delete/<int:hashfile_id>", methods=['GET', 'POST'])
@login_required
def hashfiles_delete(hashfile_id):
    hashfile = Hashfiles.query.get_or_404(hashfile_id)
    jobs = Jobs.query.filter_by(hashfile_id = hashfile_id).first()

    if hashfile:
        if current_user.admin or hashfile.owner_id == current_user.id:
            if jobs:
                flash('Error: Hashfile currently associated with a job.', 'danger')
                return redirect(url_for('hashfiles.hashfiles_list'))
            else:
                HashfileHashes.query.filter_by(hashfile_id = hashfile_id).delete()
                Hashfiles.query.filter_by(id = hashfile_id).delete()
                Hashes.query.filter().where(~exists().where(Hashes.id == HashfileHashes.hash_id)).where(Hashes.cracked == 0).delete(synchronize_session='fetch')
                HashNotifications.query.filter(~exists().where(HashNotifications.hash_id == HashfileHashes.hash_id)).filter(Hashes.cracked == 0).delete(synchronize_session='fetch')
                db.session.commit()
                flash('Hashfile has been deleted!', 'success')
                return redirect(url_for('hashfiles.hashfiles_list'))
        else:
            flash('You do not have rights to delete this hashfile!', 'danger')
            return redirect(url_for('hashfiles.hashfiles_list'))
    else:
        flash('Error in deleteing hashfile', 'danger')
        return redirect(url_for('hashfiles.hashfiles_list'))

