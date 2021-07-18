from flask import Blueprint, render_template, redirect, abort, flash, url_for, current_app, request
from flask_login import login_required, current_user
from hashview.jobs.forms import JobsForm, JobsNewHashFileForm, JobsNotificationsForm, JobSummaryForm
from hashview.models import Jobs, Customers, Hashfiles, Users, HashfileHashes, Hashes, JobTasks, Tasks
from hashview.utils.utils import save_file, get_filehash, import_hashfilehashes, build_hashcat_command
from hashview import db
import os

jobs = Blueprint('jobs', __name__)

@jobs.route("/jobs", methods=['GET', 'POST'])
@login_required
def jobs_list():
    jobs = Jobs.query.all()
    customers = Customers.query.all()
    users = Users.query.all()
    hashfiles = Hashfiles.query.all()
    return render_template('jobs.html', title='Jobs', jobs=jobs, customers=customers, users=users, hashfiles=hashfiles)

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
def jobs_assigned_hashfile(job_id):
    job = Jobs.query.get(job_id)
    hashfiles = Hashfiles.query.filter_by(customer_id=job.customer_id)
    jobsNewHashFileForm = JobsNewHashFileForm()

    hashfile_cracked_rate = {}

    for hashfile in hashfiles:
        cracked_cnt = db.session.query(Hashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '1').filter(HashfileHashes.hashfile_id==hashfile.id).count()
        total = db.session.query(Hashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(HashfileHashes.hashfile_id==hashfile.id).count()
        hashfile_cracked_rate[hashfile.id] = "(" + str(cracked_cnt) + "/" + str(total) + ")"

    if jobsNewHashFileForm.validate_on_submit():
        
        if jobsNewHashFileForm.hashfile.data:
            
            # User submitted a file upload
            hashfile_path = os.path.join(current_app.root_path, save_file('control/tmp', jobsNewHashFileForm.hashfile.data))

            hashfile = Hashfiles(name=jobsNewHashFileForm.hashfile.data.filename, customer_id=job.customer_id)
            db.session.add(hashfile)
            db.session.commit()
            
            # Parse Hashfile
            if not import_hashfilehashes(   hashfile_id=hashfile.id, 
                                            hashfile_path=hashfile_path, 
                                            file_type=jobsNewHashFileForm.file_type.data, 
                                            hash_type=jobsNewHashFileForm.hash_type.data
                                            ):
                return ('Something went wrong')

            # Delete hashfile file on disk
            # TODO
            job.hashfile_id = hashfile.id
            db.session.commit()

            return redirect(str(hashfile.id))
  
        elif jobsNewHashFileForm.hashfilehashes.data:
            # User submitted copied/pasted hashes
            # Going to have to save a file manually instead of using save_file since save_file requires form data to be passed and we're not collecting that object for this tab

            hashfile_path = os.path.join(current_app.root_path, save_file('control/tmp', jobsNewHashFileForm.name.data))

            hashfile = Hashfiles(name=jobsNewHashFileForm.name, customer_id=job.customer_id)
            db.session.add(hashfile)
            db.session.commit()
            
            # Delete hashfile
            # TODO
    # This is janky af, we should really have this be a wtf form
    # however, since we want to add addition text to the options in the list, im not sure if thats possible
    # so instead we're just processing this as a regular form post
    elif request.method == 'POST' and request.form['hashfile_id']:
        job.hashfile_id = request.form['hashfile_id']
        db.session.commit()
        return redirect("/jobs/" + str(job.id)+"/tasks")

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
        
    return render_template('jobs_assigned_hashfiles.html', title='Jobs Assigned Hashfiles', hashfiles=hashfiles, job=job, jobsNewHashFileForm=jobsNewHashFileForm, hashfile_cracked_rate=hashfile_cracked_rate)

@jobs.route("/jobs/<int:job_id>/assigned_hashfile/<int:hashfile_id>", methods=['GET'])
@login_required
def jobs_assigned_hashfile_cracked(job_id, hashfile_id):
    job = Jobs.query.get(job_id)
    hashfile = Hashfiles.query.get(hashfile_id)
    # Can be optimized to only return the hash and plaintext
    cracked_hashfiles_hashes = db.session.query(Hashes, HashfileHashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '1').filter(HashfileHashes.hashfile_id==hashfile.id).all()
    # Oppertunity for either a stored procedure or for some fancy queries.
 
    return render_template('jobs_assigned_hashfiles_cracked.html', title='Jobs Assigned Hashfiles Cracked', hashfile=hashfile, job=job, cracked_hashfiles_hashes=cracked_hashfiles_hashes)

@jobs.route("/jobs/<int:job_id>/tasks", methods=['GET'])
@login_required
def jobs_list_tasks(job_id):
    job = Jobs.query.get(job_id)
    tasks = Tasks.query.all()
    job_tasks = JobTasks.query.filter_by(job_id=job_id)
    # Right now wer're doing nested loops in the template, this could probably be solved with a left/join select

    return render_template('jobs_assigned_tasks.html', title='Jobs Assigned Tasks', job=job, tasks=tasks, job_tasks=job_tasks)

@jobs.route("/jobs/<int:job_id>/assign_task/<int:task_id>", methods=['GET'])
@login_required
def jobs_assigned_task(job_id, task_id):
    task = Tasks.query.get(task_id)
    # TODO
    #exists = JobTasks.query.filter_by(job_id=job_id, task_id=task_id)
    #if exists:
    #    flash('Task already assigned to the job.', 'warning')
    #else:
    job_task = JobTasks(job_id=job_id, task_id=task_id, status='Not Started')
    db.session.add(job_task)
    db.session.commit()

    return redirect("/jobs/"+str(job_id)+"/tasks")

@jobs.route("/jobs/<int:job_id>/move_task_up/<int:task_id>", methods=['GET'])
@login_required
def jobs_move_task_up(job_id, task_id):
    job = Jobs.query.get(job_id)
    job_tasks = JobTasks.query.filter_by(job_id=job_id).all()
    tasks = Tasks.query.all()
    
    # We create an array of all related jobtasks, remove existing jobtasks, re-arrange, and create new jobtasks (this way we dont have to worry about non-contigous jobtasks ids)
    temp_jobtasks = []
    new_jobtasks = []

    for entry in job_tasks:
        temp_jobtasks.append(str(entry.task_id))

    if temp_jobtasks[0] == str(task_id):
        flash('Task is already at the top', 'warning')
        return redirect("/jobs/"+str(job_id)+"/tasks")
    else:
        setLength = len(temp_jobtasks) - 1
        elementIndex = temp_jobtasks.index(str(task_id))
        temp_value = temp_jobtasks[elementIndex - 1]
        temp_jobtasks[elementIndex - 1] = str(task_id)
        temp_jobtasks[elementIndex] = str(temp_value)
            
    new_jobtasks = temp_jobtasks

    JobTasks.query.filter_by(job_id=job_id).delete()
    db.session.commit()

    for entry in new_jobtasks:
        keyspace = 0
        for task in tasks:
            if task.id == entry:
                keyspace = task.keyspace
        job_task = JobTasks(job_id=job_id, task_id=entry, status='Not Started')
        db.session.add(job_task)
        db.session.commit()

    return redirect("/jobs/"+str(job_id)+"/tasks")

@jobs.route("/jobs/<int:job_id>/move_task_down/<int:task_id>", methods=['GET'])
@login_required
def jobs_move_task_down(job_id, task_id):
    job = Jobs.query.get(job_id)
    job_tasks = JobTasks.query.filter_by(job_id=job_id).all()
    tasks = Tasks.query.all()
    
    # We create an array of all related jobtasks, remove existing jobtasks, re-arrange, and create new jobtasks (this way we dont have to worry about non-contigous jobtasks ids)
    temp_jobtasks = []
    new_jobtasks = []

    for entry in job_tasks:
        temp_jobtasks.append(str(entry.task_id))

    if temp_jobtasks[-1] == str(task_id):
        flash('Task is already at the bottom', 'warning')
        return redirect("/jobs/"+str(job_id)+"/tasks")
    else:
        for index in range(len(temp_jobtasks)):
            if int(index+1) <= len(temp_jobtasks):
                if  temp_jobtasks[int(index)] == str(task_id):
                    new_jobtasks.append(temp_jobtasks[int(index+1)])
                    new_jobtasks.append(str(task_id))
                    del temp_jobtasks[int(index+1)]
                else:
                    new_jobtasks.append(temp_jobtasks[int(index)])
    
    JobTasks.query.filter_by(job_id=job_id).delete()
    db.session.commit()

    for entry in new_jobtasks:
        keyspace = 0
        for task in tasks:
            if task.id == entry:
                keyspace = task.keyspace
        job_task = JobTasks(job_id=job_id, task_id=entry, status='Not Started', keyspace_pos=0, keyspace=keyspace)
        db.session.add(job_task)
        db.session.commit()

    return redirect("/jobs/"+str(job_id)+"/tasks")

@jobs.route("/jobs/<int:job_id>/remove_task/<int:task_id>", methods=['GET'])
@login_required
def jobs_remove_task(job_id, task_id):
    job_task = JobTasks.query.filter_by(job_id=job_id, task_id=task_id).first()
    db.session.delete(job_task)
    db.session.commit()

    return redirect("/jobs/"+str(job_id)+"/tasks")

@jobs.route("/jobs/<int:job_id>/notifications", methods=['GET', 'POST'])
@login_required
def jobs_assign_notifications(job_id):
    form = JobsNotificationsForm()
    job = Jobs.query.get(job_id)

    # populate the forms dynamically with the choices in the database
    form.hashes.choices = [(str(c[0].id), c[0].ciphertext) for c in db.session.query(Hashes, HashfileHashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '0').filter(HashfileHashes.hashfile_id==job.hashfile_id).all()]
    
    if form.validate_on_submit():
        if form.job_completion.data:
            if form.job_completion.data == 'email':
                # Do something
                print('user wants an email')
            if form.job_completion.data == 'push':
                # Do another thing
                print('user wants a push')
        if form.hash_completion.data:
            if form.hash_completion.data == 'email':
                print( 'user wants an email')
            if form.hash_completion.data == 'push':
                print('user wants a push')
        
        return redirect("/jobs/"+str(job_id)+"/summary")
    else:
        return render_template('jobs_assigned_notifications.html', title='Jobs Assigned Notifications', job=job, form=form)


@jobs.route("/jobs/delete/<int:job_id>", methods=['GET', 'POST'])
@login_required
def jobs_delete(job_id):
    job = Jobs.query.get(job_id)
    if current_user.admin or job.owner_id == current_user.id:
        JobTasks.query.filter_by(job_id=job_id).delete()
        # Do we need to commit this twice?
        # db.session.commit()

        db.session.delete(job)
        db.session.commit()
        flash('Job has been deleted!', 'success')
        return redirect(url_for('jobs.jobs_list'))
    else:
        flash('You do not have rights to delete this job!', 'danger')
        return redirect(url_for('jobs.jobs_list'))


@jobs.route("/jobs/<int:job_id>/summary", methods=['GET', 'POST'])
@login_required
def jobs_summary(job_id):
    job = Jobs.query.get(job_id)
    form = JobSummaryForm()
    job_tasks = JobTasks.query.filter_by(job_id=job_id).all()

    if form.validate_on_submit():
        for job_task in job_tasks:
            job_task.status = 'Ready'
        
        job.status = 'Ready'
        db.session.commit()

        flash('Job successfully created', 'sucess')

        return redirect(url_for('jobs.jobs_list'))
    else:
        return render_template('jobs_summary.html', title='Job Summary', job=job, form=form)

@jobs.route("/jobs/start/<int:job_id>", methods=['GET'])
@login_required
def jobs_start(job_id):
    job = Jobs.query.get(job_id)
    job_tasks = JobTasks.query.filter_by(job_id = job_id).all()

    if job and job_tasks:
        if current_user.admin or job.owner_id == current_user.id:
            job.status = 'Queued'
            for job_task in job_tasks:
                job_task.status = 'Queued'
                job_task.command = build_hashcat_command(job.id, job_task.task_id)
                job_task.key_pos = 0

            db.session.commit()
            flash('Job has been Started!', 'success')
            return redirect(url_for('jobs.jobs_list'))
        else:
            flash('You do not have rights to start this job!', 'danger')
            return redirect(url_for('jobs.jobs_list'))
    else:
        flash('Error in starting job', 'danger')
        return redirect(url_for('jobs.jobs_list'))

@jobs.route("/jobs/stop/<int:job_id>", methods=['GET'])
@login_required
def jobs_stop(job_id):
    job = Jobs.query.get(job_id)
    job_tasks = JobTasks.query.filter_by(job_id = job_id).all()


    if job:
        if current_user.admin or job.owner_id == current_user.id:

            flash('Job has been stopped!', 'success')
            return redirect(url_for('jobs.jobs_list'))
        else:
            flash('You do not have rights to stop this job!', 'danger')
            return redirect(url_for('jobs.jobs_list'))
    else:
        flash('Error in stopping job', 'danger')
        return redirect(url_for('jobs.jobs_list'))
