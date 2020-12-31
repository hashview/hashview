from flask import Blueprint, render_template, redirect, abort, flash, url_for, current_app
from flask_login import login_required, current_user
from hashview.jobs.forms import JobsForm, JobsNewHashFileForm
from hashview.models import Jobs, Customers, Hashfiles, Users
from hashview.utils.utils import save_file, get_filehash, import_hashfilehashes
from hashview import db
import os

jobs = Blueprint('jobs', __name__)

@jobs.route("/jobs", methods=['GET', 'POST'])
@login_required
def jobs_list():
    jobs = Jobs.query.all()
    customers = Customers.query.all()
    users = Users.query.all()
    return render_template('jobs.html', title='Jobs', jobs=jobs, customers=customers, users=users)

@jobs.route("/jobs/add", methods=['GET', 'POST'])
@login_required
def jobs_add():
    jobs = Jobs.query.all()
    customers = Customers.query.all()
    jobsForm = JobsForm()
    if jobsForm.validate_on_submit():
        customer_id = jobsForm.customer_id.data
        if jobsForm.customer_id.data == 'add_new':
            customer = Customers(name=jobsForm.customer_name.data)
            db.session.add(customer)
            db.session.commit()
            customer_id = customer.id

        job = Jobs( name = jobsForm.name.data,
                    status = 'Incomplete',
                    customer_id = customer_id,
                    owner_id = current_user.id)
        db.session.add(job)
        db.session.commit()
        return redirect(str(job.id)+"/assigned_hashfile/")
    return render_template('jobs_add.html', title='Jobs', jobs=jobs, customers=customers, jobsForm=jobsForm)

@jobs.route("/jobs/<int:job_id>/assigned_hashfile/", methods=['GET', 'POST'])
@login_required
def jobs_assigned_hashfiles(job_id):
    job = Jobs.query.get(job_id)
    hashfiles = Hashfiles.query.filter_by(customer_id=job.customer_id)
    jobsNewHashFileForm = JobsNewHashFileForm()

    if jobsNewHashFileForm.validate_on_submit():
        
        if jobsNewHashFileForm.hashfile.data:
            
            # User submitted a file upload
            hashfile_path = os.path.join(current_app.root_path, save_file('control/tmp', jobsNewHashFileForm.hashfile.data))

            hashfile = Hashfiles(name=jobsNewHashFileForm.hashfile.name, customer_id=job.customer_id)
            db.session.add(hashfile)
            db.session.commit()
            
            # Parse Hashfile
            if not import_hashfilehashes(   hashfile_id=hashfile.id, 
                                            hashfile_path=hashfile_path, 
                                            file_type=jobsNewHashFileForm.file_type.data, 
                                            hash_type=jobsNewHashFileForm.hash_type.data
                                            ):
                return ('Something went wrong')

            # Delete hashfile
            # TODO

            return redirect(str(hashfile.id))
            #return redirect(url_for('wordlists.wordlists_list'))  
        elif jobsNewHashFileForm.hashfilehashes:
            # User submitted copied/pasted hashes

            hashfile_path = os.path.join(current_app.root_path, save_file('control/tmp', jobsNewHashFileForm.hashfilehashes.data))

            hashfile = Hashfiles(name=jobsNewHashFileForm.name, customer_id=job.customer_id)
            db.session.add(hashfile)
            db.session.commit()
            

                        # Delete hashfile
            # TODO
    else:
        for error in jobsNewHashFileForm.name.errors:
            print(str(error))
        for error in jobsNewHashFileForm.file_type.errors:        
            print(str(error))
        for error in jobsNewHashFileForm.hash_type.errors:        
            print(str(error))
        for error in jobsNewHashFileForm.hashfile.errors:        
            print(str(error))
        for error in jobsNewHashFileForm.hashfilehashes.errors:        
            print(str(error))
        for error in jobsNewHashFileForm.submit.errors:        
            print(str(error))
        

 
    return render_template('jobs_assigned_hashfiles.html', title='Jobs Assigned Hashfiles', hashfiles=hashfiles, job=job, jobsNewHashFileForm=jobsNewHashFileForm)

@jobs.route("/jobs/<int:job_id>/assigned_hashfile/<int:hashfile_id>", methods=['GET'])
@login_required
def jobs_assigned_hashfiles_cracked(job_id, hashfile_id):
    job = Jobs.query.get(job_id)
    hashfile = Hashfiles.query.get(hashfile_id)
    # Oppertunity for either a stored procedure or for some fancy queries.

 
    return render_template('jobs_assigned_hashfiles_cracked.html', title='Jobs Assigned Hashfiles Cracked', hashfile=hashfile, job=job)

@jobs.route("/jobs/delete/<int:job_id>", methods=['GET', 'POST'])
@login_required
def jobs_delete(job_id):
    job = Jobs.query.get(job_id)
    if current_user.admin or job.owner_id == current_user.id:
        db.session.delete(job)
        db.session.commit()
        flash('Job has been deleted!', 'success')
        return redirect(url_for('jobs.jobs_list'))
    else:
        abort(403)