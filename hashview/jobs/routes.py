import json
import os
import secrets
from datetime import datetime

from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required
from sqlalchemy import case, func

from hashview.jobs.forms import (
    JobsForm,
    JobsNewHashFileForm,
    JobsNotificationsForm,
    JobSummaryForm,
    JobWebsiteKeywordsForm,
)
from hashview.models import (
    Customers,
    Hashes,
    HashfileHashes,
    Hashfiles,
    HashNotifications,
    JobNotifications,
    Jobs,
    JobTasks,
    Settings,
    TaskGroups,
    Tasks,
    Users,
    Wordlists,
    db,
)
from hashview.utils.audit import log_event
from hashview.utils.utils import (
    build_hashcat_command,
    import_hashfilehashes,
    save_file,
    try_commit,
    validate_hash_only_hashfile,
    validate_kerberos_hashfile,
    validate_netntlm_hashfile,
    validate_pwdump_hashfile,
    validate_shadow_hashfile,
    validate_user_hash_hashfile,
)

jobs = Blueprint('jobs', __name__)


def _job_uses_website_keywords(job_id):
    """True if any task assigned to this job uses the (DYNAMIC) Website Keywords
    wordlist (as primary or combinator-secondary wordlist)."""
    return db.session.query(JobTasks.id).join(
        Tasks, JobTasks.task_id == Tasks.id
    ).join(
        Wordlists, (Wordlists.id == Tasks.wl_id) | (Wordlists.id == Tasks.wl_id_2)
    ).filter(
        JobTasks.job_id == job_id,
        Wordlists.type == 'dynamic',
        Wordlists.name.like('%Website Keywords%'),
    ).first() is not None


def _job_has_alert_hashes(job):
    """True if the job's hashfile has any per-hash alert notifications (drives
    the conditional "Alert Hashes" wizard step)."""
    if not job or not job.hashfile_id:
        return False
    return db.session.query(HashNotifications).join(
        HashfileHashes, HashNotifications.hash_id == HashfileHashes.hash_id
    ).filter(HashfileHashes.hashfile_id == job.hashfile_id).first() is not None


@jobs.route("/jobs", methods=['GET', 'POST'])
@login_required
def jobs_list():
    # Add pagination to reduce load time when many jobs exist
    page = request.args.get('page', 1, type=int)
    per_page = 20  # Adjust as needed

    # Check if filtering by current user
    show_only_mine = request.args.get('show_only_mine', 'false')

    # Build query based on filter
    if show_only_mine == 'true':
        pagination = Jobs.query.filter_by(owner_id=current_user.id).order_by(Jobs.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    else:
        pagination = Jobs.query.order_by(Jobs.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)

    jobs = pagination.items

    customers = Customers.query.all()
    users = Users.query.all()
    hashfiles = Hashfiles.query.all()
    job_tasks = JobTasks.query.all()
    tasks = Tasks.query.all()

    # Per-job cracked progress: cracked / total hashes in the job's hashfile.
    # Cached per hashfile_id so jobs sharing a hashfile are only queried once.
    job_cracked = {}
    _hf_cracked = {}
    for job in jobs:
        hfid = job.hashfile_id
        if not hfid:
            job_cracked[job.id] = {'cracked': 0, 'total': 0, 'pct': 0}
            continue
        if hfid not in _hf_cracked:
            agg = db.session.query(
                func.count(Hashes.id),
                func.coalesce(func.sum(case((Hashes.cracked == True, 1), else_=0)), 0)
            ).join(HashfileHashes, Hashes.id == HashfileHashes.hash_id) \
             .filter(HashfileHashes.hashfile_id == hfid).first()
            total = agg[0] or 0
            cracked = int(agg[1] or 0)
            _hf_cracked[hfid] = {
                'cracked': cracked,
                'total': total,
                'pct': round((cracked / total * 100), 1) if total else 0,
            }
        job_cracked[job.id] = _hf_cracked[hfid]

    # --- per-job info-modal data: hash type, runtime, task count, notifications ---
    hash_type_names = {}
    try:
        _f = JobsNewHashFileForm()
        for _sel in (_f.hash_type, _f.pwdump_hash_type, _f.netntlm_hash_type,
                     _f.kerberos_hash_type, _f.shadow_hash_type):
            for _v, _lab in _sel.choices:
                if _v is not None and str(_v) not in hash_type_names:
                    _nm = _lab.split(') ', 1)[1] if ') ' in _lab else _lab
                    hash_type_names[str(_v)] = _nm.split(' / ')[0].split(',')[0].strip()
    except Exception:  # pragma: no cover - defensive
        hash_type_names = {}

    job_task_count = {}
    for jt in job_tasks:
        job_task_count[jt.job_id] = job_task_count.get(jt.job_id, 0) + 1

    jn_by_job = {}
    for n in JobNotifications.query.all():
        jn_by_job.setdefault(n.job_id, set()).add(n.method)

    job_hash_type = {}
    job_runtime = {}
    job_notifs = {}
    _hf_type = {}
    _hf_perhash = {}
    for job in jobs:
        # runtime: started -> ended (or now if running); total run time even if canceled;
        # '-' when the job never started (e.g. still queued)
        if job.started_at:
            end = job.ended_at or datetime.now()
            secs = (end - job.started_at).total_seconds()
            secs = secs if secs > 0 else 0
            job_runtime[job.id] = '%dh %dm' % (int(secs // 3600), int((secs % 3600) // 60))
        else:
            job_runtime[job.id] = '-'
        if job.hashfile_id:
            if job.hashfile_id not in _hf_type:
                mode = db.session.query(func.min(Hashes.hash_type)).join(HashfileHashes, Hashes.id == HashfileHashes.hash_id).filter(HashfileHashes.hashfile_id == job.hashfile_id).scalar()
                _hf_type[job.hashfile_id] = hash_type_names.get(str(mode), str(mode)) if mode is not None else None
            job_hash_type[job.id] = _hf_type[job.hashfile_id]
            if job.hashfile_id not in _hf_perhash:
                _hf_perhash[job.hashfile_id] = db.session.query(HashNotifications).join(HashfileHashes, HashNotifications.hash_id == HashfileHashes.hash_id).filter(HashfileHashes.hashfile_id == job.hashfile_id).first() is not None
            per_hash = _hf_perhash[job.hashfile_id]
        else:
            job_hash_type[job.id] = None
            per_hash = False
        methods = jn_by_job.get(job.id, set())
        job_notifs[job.id] = {'email': 'email' in methods, 'pushover': 'push' in methods, 'per_hash': per_hash}

    return render_template(
        'jobs.html.j2',
        title='Jobs',
        jobs=jobs,
        customers=customers,
        users=users,
        hashfiles=hashfiles,
        job_tasks=job_tasks,
        tasks=tasks,
        job_cracked=job_cracked,
        job_hash_type=job_hash_type,
        job_runtime=job_runtime,
        job_task_count=job_task_count,
        job_notifs=job_notifs,
        pagination=pagination,
        show_only_mine=show_only_mine
    )

@jobs.route("/jobs/add", methods=['GET', 'POST'])
@login_required
def jobs_add():
    """Function to manage adding of new job"""
    jobs = Jobs.query.all()
    customers = Customers.query.order_by(Customers.name).all()
    jobs_form = JobsForm()
    settings = Settings.query.first()
    if jobs_form.validate_on_submit():
        customer_id = jobs_form.customer_id.data
        if jobs_form.customer_id.data == 'add_new':
            customer = Customers(name=jobs_form.customer_name.data)
            db.session.add(customer)
            db.session.commit()
            customer_id = customer.id

        if settings.enabled_job_weights:
            if int(jobs_form.priority.data) >= 1 and int(jobs_form.priority.data) <=5:
                job_priority = jobs_form.priority.data
            else:
                job_priority = 3
        else:
            job_priority = 3

        job = Jobs( name = jobs_form.name.data,
                    priority = job_priority,
                    status = 'Incomplete',
                    customer_id = customer_id,
                    owner_id = current_user.id,
                    limit_recovered = jobs_form.limit_recovered.data)
        db.session.add(job)
        db.session.commit()
        log_event('job.create', target=f'job:{job.id} {job.name!r}')
        return redirect(str(job.id)+"/assigned_hashfile/")
    return render_template('jobs_add.html.j2', title='Jobs', jobs=jobs, customers=customers, jobsForm=jobs_form, settings=settings)

@jobs.route("/jobs/<int:job_id>/assigned_hashfile/", methods=['GET', 'POST'])
@login_required
def jobs_assigned_hashfile(job_id):
    """Function to manage assigning hashfile to job"""

    job = Jobs.query.get(job_id)
    hashfiles = Hashfiles.query.filter_by(customer_id=job.customer_id)
    jobs_new_hashfile_form = JobsNewHashFileForm()
    # The import-progress modal posts the upload/paste form via XHR (so it can
    # show live upload + import status) and sets this header; for those requests
    # we answer with JSON instead of flash+redirect. A plain (no-JS) form post
    # still falls through to the original flash/redirect behaviour.
    is_ajax = request.headers.get('X-Requested-With') == 'fetch'
    hashfile_cracked_rate = {}
    hashfile_info = {}

    # Reverse-map hashcat modes -> concise friendly names from the form's own choices.
    # Keep the FIRST label seen for a mode (deterministic). A mode can map to several
    # schemes, so the numeric mode is ALSO shown in the UI; the name is only a hint and
    # never stands alone for an ambiguous mode.
    hash_type_names = {}
    for _sel in (jobs_new_hashfile_form.hash_type, jobs_new_hashfile_form.pwdump_hash_type,
                 jobs_new_hashfile_form.netntlm_hash_type, jobs_new_hashfile_form.kerberos_hash_type,
                 jobs_new_hashfile_form.shadow_hash_type):
        for _val, _label in _sel.choices:
            if _val and str(_val) not in hash_type_names:
                _name = _label.split(') ', 1)[1] if ') ' in _label else _label
                hash_type_names[str(_val)] = _name.split(' / ')[0].split(',')[0].strip()

    if job.status == 'Running' or job.status == 'Queued':
        flash('You can not edit a running or queued job. First stop and remove job from queue before editing.', 'danger')
        return redirect(url_for('jobs.jobs_list'))

    for hashfile in hashfiles:
        # one aggregated query per hashfile: total hashes, cracked count, representative mode
        agg = db.session.query(
            func.count(Hashes.id),
            func.coalesce(func.sum(case((Hashes.cracked == True, 1), else_=0)), 0),
            func.min(Hashes.hash_type)
        ).join(HashfileHashes, Hashes.id == HashfileHashes.hash_id) \
         .filter(HashfileHashes.hashfile_id == hashfile.id).first()
        total = agg[0] or 0
        cracked_cnt = int(agg[1] or 0)
        ht = str(agg[2]) if agg[2] is not None else ''
        hashfile_cracked_rate[hashfile.id] = "(" + str(cracked_cnt) + "/" + str(total) + ")"
        if total:
            _pct = (cracked_cnt / total) * 100
            pct_str = '<1%' if 0 < _pct < 1 else ('%d%%' % round(_pct))
        else:
            pct_str = '0%'
        hashfile_info[hashfile.id] = {
            'mode': ht,
            'type': hash_type_names.get(ht, ''),
            'total': total,
            'cracked': cracked_cnt,
            'pct_str': pct_str,
        }

    if jobs_new_hashfile_form.validate_on_submit():

        hashfile_path = ""
        hashfile_name = ""
        if jobs_new_hashfile_form.hashfile.data:
            # User submitted a file upload
            hashfile_path = os.path.join(current_app.root_path, save_file('control/tmp', jobs_new_hashfile_form.hashfile.data))
            hashfile_name = jobs_new_hashfile_form.hashfile.data.filename
        elif jobs_new_hashfile_form.hashfilehashes.data:
            # User submitted copied/pasted hashes
            # Going to have to save a file manually instead of using save_file since save_file requires form data to be passed and we're not collecting that object for this tab

            if len(jobs_new_hashfile_form.name.data) == 0:
                if is_ajax:
                    return jsonify({'status': 'error', 'msg': 'You must assign a name to the hashfile.'}), 400
                flash('You must assign a name to the hashfile', 'danger')
                return redirect(url_for('jobs.jobs_assigned_hashfile', job_id=job_id))
            else:
                hashfile_name = jobs_new_hashfile_form.name.data

            random_hex = secrets.token_hex(8)
            # Absolute path rooted at the app (the upload branch above does the
            # same via save_file); a CWD-relative path breaks when the process
            # isn't launched from the repo root.
            hashfile_path = os.path.join(current_app.root_path, 'control/tmp', random_hex)
            with open(hashfile_path, 'w+') as hashfilehashes_file:
                hashfilehashes_file.write(jobs_new_hashfile_form.hashfilehashes.data)

        if len(hashfile_path) > 0:
            try:
                if jobs_new_hashfile_form.file_type.data == 'pwdump':
                    has_problem = validate_pwdump_hashfile(hashfile_path, jobs_new_hashfile_form.pwdump_hash_type.data)
                    hash_type = jobs_new_hashfile_form.pwdump_hash_type.data
                elif jobs_new_hashfile_form.file_type.data == 'NetNTLM':
                    has_problem = validate_netntlm_hashfile(hashfile_path, jobs_new_hashfile_form.netntlm_hash_type.data)
                    hash_type = jobs_new_hashfile_form.netntlm_hash_type.data
                elif jobs_new_hashfile_form.file_type.data == 'kerberos':
                    has_problem = validate_kerberos_hashfile(hashfile_path, jobs_new_hashfile_form.kerberos_hash_type.data)
                    hash_type = jobs_new_hashfile_form.kerberos_hash_type.data
                elif jobs_new_hashfile_form.file_type.data == 'shadow':
                    has_problem = validate_shadow_hashfile(hashfile_path, jobs_new_hashfile_form.shadow_hash_type.data)
                    hash_type = jobs_new_hashfile_form.shadow_hash_type.data
                elif jobs_new_hashfile_form.file_type.data == 'user_hash':
                    has_problem = validate_user_hash_hashfile(hashfile_path)
                    hash_type = jobs_new_hashfile_form.hash_type.data
                elif jobs_new_hashfile_form.file_type.data == 'hash_only':
                    has_problem = validate_hash_only_hashfile(hashfile_path, jobs_new_hashfile_form.hash_type.data)
                    hash_type = jobs_new_hashfile_form.hash_type.data
                else:
                    has_problem = 'Invalid File Format'

                if has_problem:
                    if is_ajax:
                        return jsonify({'status': 'error', 'msg': has_problem}), 400
                    flash(has_problem, 'danger')
                    return redirect(url_for('jobs.jobs_assigned_hashfile', job_id=job_id))
                else:
                    hashfile = Hashfiles(name=hashfile_name, customer_id=job.customer_id, owner_id=current_user.id)
                    db.session.add(hashfile)
                    db.session.commit()

                    # Parse Hashfile
                    if not import_hashfilehashes(   hashfile_id=hashfile.id,
                                                    hashfile_path=hashfile_path,
                                                    file_type=jobs_new_hashfile_form.file_type.data,
                                                    hash_type=hash_type
                                                    ):
                        msg = 'Something went wrong. Check the filetype / hashtype and try again.'
                        if is_ajax:
                            return jsonify({'status': 'error', 'msg': msg}), 400
                        flash(msg, 'danger')
                        return redirect(url_for('jobs.jobs_assigned_hashfile', job_id=job_id))

                    hashfile_hashes_cnt = db.session.query(HashfileHashes).filter_by(hashfile_id=hashfile.id).count()
                    if hashfile_hashes_cnt == 0:
                        db.session.delete(hashfile)
                        db.session.commit()
                        if is_ajax:
                            return jsonify({'status': 'error', 'msg': 'No valid hashes found in the hashfile. Hashfile not added.'}), 400
                        flash('No valid hashes found in the hashfile. Hashfile not added.', 'danger')
                        return redirect(url_for('jobs.jobs_assigned_hashfile', job_id=job_id))

                    job.hashfile_id = hashfile.id
                    db.session.commit()
                    log_event('hashfile.create',
                              target=f'hashfile:{hashfile.id} {hashfile.name!r}',
                              detail=f'hashes={hashfile_hashes_cnt}')

                if is_ajax:
                    return jsonify({
                        'status': 'ok',
                        'msg': f'{hashfile_hashes_cnt:,} hashes imported.',
                        'redirect': url_for('jobs.jobs_assigned_hashfile_cracked',
                                            job_id=job_id, hashfile_id=hashfile.id),
                    })
                return redirect(str(hashfile.id))
            finally:
                # Implements the long-standing "delete hashfile on disk" TODO:
                # the validators + import have already read the temp file, so
                # remove it on every exit path (success or error) — otherwise
                # control/tmp accumulates one file per submission. Best-effort.
                try:
                    if os.path.exists(hashfile_path):
                        os.remove(hashfile_path)
                except OSError:
                    pass

    elif request.method == 'POST' and request.form.get('hashfile_id'):
        # User selected an existing hashfile
        job.hashfile_id = request.form['hashfile_id']
        db.session.commit()
        return redirect("/jobs/" + str(job.id)+"/notifications")

    else:
        if is_ajax:
            # Validation failed (missing file format/hash type, bad CSRF, …):
            # answer the XHR with the collected errors so the modal can show
            # them instead of receiving the full HTML page.
            msgs = []
            for _field in (jobs_new_hashfile_form.name, jobs_new_hashfile_form.file_type,
                           jobs_new_hashfile_form.hash_type, jobs_new_hashfile_form.hashfile,
                           jobs_new_hashfile_form.hashfilehashes):
                msgs.extend(str(m) for m in _field.errors)
            return jsonify({'status': 'error',
                            'msg': '; '.join(msgs) or 'Invalid upload request.'}), 400
        for error in jobs_new_hashfile_form.name.errors:
            print(str(error))
        for error in jobs_new_hashfile_form.file_type.errors:
            print(str(error))
        for error in jobs_new_hashfile_form.hash_type.errors:
            print(str(error))
        for error in jobs_new_hashfile_form.hashfile.errors:
            print(str(error))
        for error in jobs_new_hashfile_form.hashfilehashes.errors:
            print(str(error))
        for error in jobs_new_hashfile_form.submit.errors:
            print(str(error))

    return render_template('jobs_assigned_hashfiles.html.j2', title='Jobs Assigned Hashfiles', hashfiles=hashfiles, job=job, jobsNewHashFileForm=jobs_new_hashfile_form, hashfile_cracked_rate=hashfile_cracked_rate, hashfile_info=hashfile_info)

@jobs.route("/jobs/<int:job_id>/assigned_hashfile/<int:hashfile_id>", methods=['GET'])
@login_required
def jobs_assigned_hashfile_cracked(job_id, hashfile_id):
    """Function to show instacrack results"""

    job = Jobs.query.get(job_id)
    hashfile = Hashfiles.query.get(hashfile_id)
    # Can be optimized to only return the hash and plaintext
    cracked_hashfiles_hashes = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '1').filter(HashfileHashes.hashfile_id==hashfile.id).all()
    cracked_hashfiles_hashes_cnt = db.session.query(Hashes).join(HashfileHashes, Hashes.id == HashfileHashes.hash_id).filter(Hashes.cracked == '1').filter(HashfileHashes.hashfile_id==hashfile.id).count()
    if cracked_hashfiles_hashes_cnt > 0:
        flash(f"{cracked_hashfiles_hashes_cnt:,} instacracked Hashes!", 'success')
    # Oppertunity for either a stored procedure or for some fancy queries.

    return render_template('jobs_assigned_hashfiles_cracked.html.j2', title='Jobs Assigned Hashfiles Cracked', hashfile=hashfile, job=job, cracked_hashfiles_hashes=cracked_hashfiles_hashes)

@jobs.route("/jobs/<int:job_id>/tasks", methods=['GET'])
@login_required
def jobs_list_tasks(job_id):
    """Function to list tasks for a given job"""
    job = Jobs.query.get(job_id)
    tasks = Tasks.query.order_by(Tasks.name.asc()).all()
    job_tasks = JobTasks.query.filter_by(job_id=job_id)
    task_groups = TaskGroups.query.all()
    wordlists = Wordlists.query.all()
    # Right now we're doing nested loops in the template, this could probably be solved with a left/join select

    # Does this job have per-hash alerts? Drives the conditional "Alert Hashes" wizard step.
    alert_hashes = False
    if job.hashfile_id:
        alert_hashes = db.session.query(HashNotifications).join(HashfileHashes, HashNotifications.hash_id == HashfileHashes.hash_id).filter(HashfileHashes.hashfile_id == job.hashfile_id).first() is not None

    return render_template('jobs_assigned_tasks.html.j2', title='Jobs Assigned Tasks', job=job, tasks=tasks, job_tasks=job_tasks, task_groups=task_groups, wordlists=wordlists, alert_hashes=alert_hashes, website=_job_uses_website_keywords(job_id))

@jobs.route("/jobs/<int:job_id>/assign_task/<int:task_id>", methods=['GET'])
@login_required
def jobs_assign_task(job_id, task_id):
    """Function to assign task to job"""

    # Someone smarter than me can turn this into a single DB Query
    jobtask_exists = JobTasks.query.filter_by(job_id=job_id, task_id=task_id).first()
    wordlist = Wordlists.query.get(Tasks.query.get(task_id).wl_id)
    # hc_attackmode = Tasks.query.get(task_id).hc_attackmode
    
    if jobtask_exists:
        #if hc_attackmode == '0' or hc_attackmode == '1' or hc_attackmode == '6' or hc_attackmode == '7':
        if wordlist:
            if wordlist.type == 'static':
                flash('Task already assigned to the job.', 'warning')
            else:
                job_task = JobTasks(job_id=job_id, task_id=task_id, status='Not Started')
                db.session.add(job_task)
                db.session.commit() 
        else:
            flash('Task already assigned to the job.', 'warning')
    else:
        job_task = JobTasks(job_id=job_id, task_id=task_id, status='Not Started')
        db.session.add(job_task)
        db.session.commit()

    return redirect("/jobs/"+str(job_id)+"/tasks")

@jobs.route("/jobs/<int:job_id>/assign_task_group/<int:task_group_id>", methods=['GET'])
@login_required
def jobs_assign_task_group(job_id, task_group_id):
    """Function to assign task group to job"""

    task_group = TaskGroups.query.get(task_group_id)

    for task_group_entry in json.loads(task_group.tasks):
        # Check if task.hc_attackmode = 0, 1, 6, or 7. If so allow duplicates
        jobtask_exists = JobTasks.query.filter_by(job_id=job_id, task_id=task_group_entry).first()
        wordlist = Wordlists.query.get(Tasks.query.get(task_group_entry).wl_id)

        if jobtask_exists:
            if wordlist:
                if wordlist.type == 'static':
                    continue
                else:
                    job_task = JobTasks(job_id=job_id, task_id=task_group_entry, status='Not Started')
                    db.session.add(job_task)
                    db.session.commit()
            else:
                continue
        else:
            job_task = JobTasks(job_id=job_id, task_id=task_group_entry, status='Not Started')
            db.session.add(job_task)
            db.session.commit()


        # job_task = JobTasks(job_id=job_id, task_id=task_group_entry, status='Not Started')
        # db.session.add(job_task)
        # db.session.commit()

    return redirect("/jobs/" + str(job_id) + "/tasks")

@jobs.route("/jobs/<int:job_id>/assign_task/lucky", methods=['GET'])
@login_required
def jobs_assign_lucky_task_group(job_id):

    job = Jobs.query.get(job_id)
    hashfile = Hashfiles.query.get(job.hashfile_id)
    hashfile_hashes = HashfileHashes.query.filter_by(hashfile_id=hashfile.id).first()
    hash = Hashes.query.get(hashfile_hashes.hash_id)


    # Get top 10 effective tasks
    most_effective_tasks_raw = db.session.query(func.count(Hashes.id).label("row_count"), Hashes.task_id, Tasks.name,).join(Tasks, Hashes.task_id == Tasks.id) \
        .filter(Hashes.cracked == '1') \
        .filter(Hashes.task_id is not None) \
        .filter(Hashes.task_id != '0') \
        .filter(Hashes.hash_type == hash.hash_type) \
        .group_by(Hashes.task_id) \
        .order_by(func.count(Hashes.id).desc()) \
        .limit(10) \
        .all()

    if len(most_effective_tasks_raw) == 0:
        flash('Not enough data to generate top tasks.', 'danger')
    else:
    # for each effective task 
        for entry in most_effective_tasks_raw:
            job_tasks = JobTasks.query.filter_by(job_id=job_id).all()
            if entry.task_id not in {job_task.task_id for job_task in job_tasks}:
                job_task = JobTasks(job_id=job_id, task_id=entry.task_id, status='Not Started')
                db.session.add(job_task)
                db.session.commit()

        flash('Successfully Added Top 10 Tasks', 'success')
    return redirect("/jobs/" + str(job_id) + "/tasks")

@jobs.route("/jobs/<int:job_id>/move_task_up/<int:task_id>", methods=['GET'])
@login_required
def jobs_move_task_up(job_id, task_id):
    """Function to move assigned task up on task list for job"""

    job_tasks = JobTasks.query.filter_by(job_id=job_id).all()

    # We create an array of all related jobtasks, remove existing jobtasks, re-arrange, and create new jobtasks (this way we dont have to worry about non-contigous jobtasks ids)
    temp_jobtasks = []
    new_jobtasks = []

    for entry in job_tasks:
        temp_jobtasks.append(str(entry.task_id))

    if temp_jobtasks[0] == str(task_id):
        flash('Task is already at the top', 'warning')
        return redirect("/jobs/"+str(job_id)+"/tasks")

    element_index = temp_jobtasks.index(str(task_id))
    temp_value = temp_jobtasks[element_index - 1]
    temp_jobtasks[element_index - 1] = str(task_id)
    temp_jobtasks[element_index] = str(temp_value)

    new_jobtasks = temp_jobtasks

    JobTasks.query.filter_by(job_id=job_id).delete()
    db.session.commit()

    for entry in new_jobtasks:
        job_task = JobTasks(job_id=job_id, task_id=entry, status='Not Started')
        db.session.add(job_task)
        db.session.commit()

    return redirect("/jobs/"+str(job_id)+"/tasks")

@jobs.route("/jobs/<int:job_id>/move_task_down/<int:task_id>", methods=['GET'])
@login_required
def jobs_move_task_down(job_id, task_id):
    """Function to move assigned task down on task list for job"""

    job_tasks = JobTasks.query.filter_by(job_id=job_id).all()

    # We create an array of all related jobtasks, remove existing jobtasks, re-arrange, and create new jobtasks (this way we dont have to worry about non-contigous jobtasks ids)
    temp_jobtasks = []
    new_jobtasks = []

    for entry in job_tasks:
        temp_jobtasks.append(str(entry.task_id))

    if temp_jobtasks[-1] == str(task_id):
        flash('Task is already at the bottom', 'warning')
        return redirect("/jobs/"+str(job_id)+"/tasks")

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
        job_task = JobTasks(job_id=job_id, task_id=entry, status='Not Started')
        db.session.add(job_task)
        db.session.commit()

    return redirect("/jobs/"+str(job_id)+"/tasks")

@jobs.route("/jobs/<int:job_id>/remove_task/<int:task_id>", methods=['GET'])
@login_required
def jobs_remove_task(job_id, task_id):
    """Function to remove task from task list on job"""

    job_task = JobTasks.query.filter_by(job_id=job_id, task_id=task_id).first()
    if job_task is None:
        flash('That task is no longer on this job — it may have already been removed.', 'warning')
        return redirect("/jobs/"+str(job_id)+"/tasks")
    db.session.delete(job_task)
    if not try_commit(f'remove task {task_id} from job {job_id}'):
        flash('Could not remove the task — it may have already been removed.', 'danger')

    return redirect("/jobs/"+str(job_id)+"/tasks")

@jobs.route("/jobs/<int:job_id>/remove_all_tasks", methods=['GET'])
@login_required
def jobs_remove_all_tasks(job_id):
    """Function to remove all tasks from job"""

    job_tasks = JobTasks.query.filter_by(job_id=job_id)
    for tasks in job_tasks:
        db.session.delete(tasks)
    db.session.commit()
    return redirect("/jobs/"+str(job_id)+"/tasks")

@jobs.route("/jobs/<int:job_id>/notifications", methods=['GET', 'POST'])
@login_required
def jobs_assign_notifications(job_id):
    """Function to assign notifications for job"""
    form = JobsNotificationsForm()
    job = Jobs.query.get(job_id)

    # Moving task check to /summary. Otherwise this will always skip /notifications now that notifications are before tasks
    # populate the forms dynamically with the choices in the database
    # form.hashes.choices = [(str(c[0].id), str(bytes.fromhex(c[1].username).decode('latin-1')) + ':' + c[0].ciphertext) for c in db.session.query(Hashes, HashfileHashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '0').filter(HashfileHashes.hashfile_id==job.hashfile_id).all()]

    if form.validate_on_submit():
        if form.job_completion_email.data == True:
            # Check if we already have a notification set
            pre_existing_job_notification = JobNotifications.query.filter_by(job_id=job_id, owner_id=current_user.id, method='email').first()
            if pre_existing_job_notification is None:
                job_notification = JobNotifications(
                    owner_id = current_user.id,
                    job_id = job_id,
                    method = 'email'
                )
                db.session.add(job_notification)
                db.session.commit()
        if form.job_completion_pushover.data == True:
            pre_existing_job_notification = JobNotifications.query.filter_by(job_id=job_id, owner_id=current_user.id, method='push').first()
            if pre_existing_job_notification is None:
                job_notification = JobNotifications(
                    owner_id = current_user.id,
                    job_id = job_id,
                    method = 'push'
                )
                db.session.add(job_notification)
                db.session.commit()
        if form.job_completion_slack.data == True:
            pre_existing_job_notification = JobNotifications.query.filter_by(job_id=job_id, owner_id=current_user.id, method='slack').first()
            if pre_existing_job_notification is None:
                job_notification = JobNotifications(
                    owner_id = current_user.id,
                    job_id = job_id,
                    method = 'slack'
                )
                db.session.add(job_notification)
                db.session.commit()
        # Per-hash alerts: carry the chosen channel(s) to the hash-selection step as
        # a comma-joined list (e.g. "email,push,slack"); empty -> skip to tasks.
        hash_methods = []
        if form.hash_completion_email.data:
            hash_methods.append('email')
        if form.hash_completion_pushover.data:
            hash_methods.append('push')
        if form.hash_completion_slack.data:
            hash_methods.append('slack')
        if hash_methods:
            return redirect("/jobs/" + str(job_id) + "/notifications/" + ",".join(hash_methods) + "/hashes")
        return redirect("/jobs/" + str(job_id) + "/tasks")
    else:
        settings = Settings.query.first()
        return render_template('jobs_assigned_notifications.html.j2', title='Jobs Assigned Notifications', job=job, form=form, settings=settings)

@jobs.route("/jobs/<int:job_id>/notifications/<method>/hashes", methods=['GET', 'POST'])
@login_required
def jobs_assign_notification_hashes(job_id, method):
    """Function to assign notification for hashes recovered from job"""

    job = Jobs.query.get(job_id)
    hashes = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '0').filter(HashfileHashes.hashfile_id==job.hashfile_id).with_entities(Hashes.id, HashfileHashes.username, Hashes.ciphertext).all()
    existing_hash_notifications = HashNotifications.query.filter_by(owner_id=current_user.id)
    # `method` is a comma-joined list of channels, e.g. "email,push,slack".
    methods = [m for m in (method or '').split(',') if m in ('email', 'push', 'slack')]
    if request.method == 'POST':
        selected_ids = set(request.form.getlist('selected'))
        for entry in hashes:
            if str(entry[0]) not in selected_ids:
                continue
            for m in methods:
                # one row per (hash, channel); skip if that exact pairing exists
                exists = HashNotifications.query.filter_by(
                    hash_id=entry[0], owner_id=current_user.id, method=m).first()
                if not exists:
                    db.session.add(HashNotifications(
                        owner_id=current_user.id, hash_id=entry[0], method=m))
        db.session.commit()
        return redirect("/jobs/"+str(job_id)+"/tasks")

    return render_template('jobs_assigned_notifications_hashes.html.j2', title='Assigned Hash Notifications', job=job, hashes=hashes, existing_hash_notifications=existing_hash_notifications)

@jobs.route("/jobs/delete/<int:job_id>", methods=['GET', 'POST'])
@login_required
def jobs_delete(job_id):
    """Function to delete job"""

    job = Jobs.query.get(job_id)
    if job is None:
        flash('Job not found — it may have already been deleted.', 'warning')
        return redirect(url_for('jobs.jobs_list'))
    if current_user.admin or job.owner_id == current_user.id:
        job_target = f'job:{job.id} {job.name!r}'   # capture before delete (instance expires post-commit)
        JobTasks.query.filter_by(job_id=job_id).delete()
        JobNotifications.query.filter_by(job_id=job_id).delete()

        db.session.delete(job)
        if not try_commit(f'delete job {job_id}'):
            flash('Job could not be deleted — it may have already been removed.', 'danger')
            return redirect(url_for('jobs.jobs_list'))
        log_event('job.delete', target=job_target)
        flash('Job has been deleted!', 'success')
        return redirect(url_for('jobs.jobs_list'))

    flash('You do not have rights to delete this job!', 'danger')
    return redirect(url_for('jobs.jobs_list'))

@jobs.route("/jobs/<int:job_id>/website", methods=['GET', 'POST'])
@login_required
def jobs_website_keywords(job_id):
    """Conditional wizard step: capture the URL to crawl for the
    (DYNAMIC) Website Keywords wordlist. Skipped (redirect to summary) when the
    job has no task using that wordlist."""
    job = Jobs.query.get(job_id)
    if not _job_uses_website_keywords(job_id):
        return redirect("/jobs/" + str(job_id) + "/summary")

    form = JobWebsiteKeywordsForm()
    if form.validate_on_submit():
        job.crawl_url = form.crawl_url.data
        db.session.commit()
        return redirect("/jobs/" + str(job_id) + "/summary")
    elif request.method == 'GET':
        form.crawl_url.data = job.crawl_url

    return render_template('jobs_website_keywords.html.j2', title='Job Website Keywords',
                           job=job, form=form, alert_hashes=_job_has_alert_hashes(job))

@jobs.route("/jobs/<int:job_id>/summary", methods=['GET', 'POST'])
@login_required
def jobs_summary(job_id):
    """Function to present job summary"""

    # Check if job has any assigned tasks, and if not, send the user back to the task assigned page.
    job_tasks = JobTasks.query.filter_by(job_id=job_id).all()
    if len(job_tasks) == 0:
        flash('You must assign at least one task.', 'warning')
        return redirect("/jobs/"+str(job_id)+"/tasks")

    job = Jobs.query.get(job_id)
    form = JobSummaryForm()

    settings = Settings.query.first()
    tasks = Tasks.query.all()
    hashfile = Hashfiles.query.get(job.hashfile_id)
    customer = Customers.query.get(job.customer_id)
    cracked_cnt = db.session.query(Hashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '1').filter(HashfileHashes.hashfile_id==hashfile.id).count()
    hash_total = db.session.query(Hashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(HashfileHashes.hashfile_id==hashfile.id).count()
    cracked_rate = str(cracked_cnt) + '/' + str(hash_total)
    # Representative hashcat mode for the hashfile -> a concise friendly name
    # (same derivation as the assigned-hashfile view) to show next to the
    # cracked count on the summary.
    hash_mode = db.session.query(func.min(Hashes.hash_type)) \
        .join(HashfileHashes, Hashes.id == HashfileHashes.hash_id) \
        .filter(HashfileHashes.hashfile_id == hashfile.id).scalar()
    hashfile_hash_type = ''
    if hash_mode is not None:
        _names = {}
        _f = JobsNewHashFileForm()
        for _sel in (_f.hash_type, _f.pwdump_hash_type, _f.netntlm_hash_type,
                     _f.kerberos_hash_type, _f.shadow_hash_type):
            for _v, _lab in _sel.choices:
                if _v is not None and str(_v) not in _names:
                    _nm = _lab.split(') ', 1)[1] if ') ' in _lab else _lab
                    _names[str(_v)] = _nm.split(' / ')[0].split(',')[0].strip()
        hashfile_hash_type = _names.get(str(hash_mode), 'mode ' + str(hash_mode))
    hash_notification_cnt = db.session.query(HashNotifications).join(HashfileHashes, HashNotifications.hash_id==HashfileHashes.hash_id).filter(HashfileHashes.hashfile_id == hashfile.id).count()
    hash_notification = db.session.query(HashNotifications).join(HashfileHashes, HashNotifications.hash_id==HashfileHashes.hash_id).filter(HashfileHashes.hashfile_id == hashfile.id).first()
    job_notification = JobNotifications.query.filter_by(job_id = job.id).first()

    job_notification = JobNotifications.query.filter_by(job_id=job_id).first()

    if form.validate_on_submit():
        # "Create & Queue Job": create the job AND queue it in one step. Mirrors
        # jobs_start — set the job and its tasks to Queued, stamp queued_at,
        # propagate the job priority to each task, and pre-build each task's
        # hashcat command so agents can pick up the work immediately.
        job.status = 'Queued'
        job.queued_at = datetime.now()
        job.updated_at = datetime.now()
        for job_task in job_tasks:
            job_task.status = 'Queued'
            job_task.priority = job.priority
            job_task.command = build_hashcat_command(job.id, job_task.task_id)
        db.session.commit()

        flash('Job created and queued', 'success')

        return redirect(url_for('jobs.jobs_list'))

    return render_template('jobs_summary.html.j2', title='Job Summary', job=job, form=form, job_notification=job_notification, cracked_rate=cracked_rate, cracked_cnt=cracked_cnt, hash_total=hash_total, hashfile_hash_type=hashfile_hash_type, job_tasks=job_tasks, hash_notification_cnt=hash_notification_cnt, customer=customer, hashfile=hashfile, tasks=tasks, hash_notification=hash_notification, settings=settings, website=_job_uses_website_keywords(job_id))

@jobs.route("/jobs/start/<int:job_id>", methods=['GET'])
@login_required
def jobs_start(job_id):
    """Function to start job"""

    job = Jobs.query.get(job_id)
    job_tasks = JobTasks.query.filter_by(job_id = job_id).all()

    if job and job_tasks:
        if current_user.admin or job.owner_id == current_user.id:
            job.status = 'Queued'
            job.queued_at = datetime.now()
            for job_task in job_tasks:
                job_task.status = 'Queued'
                job_task.priority = job.priority
                job_task.command = build_hashcat_command(job.id, job_task.task_id)

            db.session.commit()
            flash('Job has been Started!', 'success')
            return redirect(url_for('main.home'))
        else:
            flash('You do not have rights to start this job!', 'danger')
            return redirect(url_for('jobs.jobs_list'))
    else:
        flash('Error in starting job', 'danger')
        return redirect(url_for('jobs.jobs_list'))

@jobs.route("/jobs/stop/<int:job_id>", methods=['GET'])
@login_required
def jobs_stop(job_id):
    """Function to stop a job"""

    job = Jobs.query.get(job_id)
    job_tasks = JobTasks.query.filter_by(job_id = job_id).all()

    if job:
        if current_user.admin or job.owner_id == current_user.id:
            if job.status == 'Running' or job.status == 'Queued':
                job.status = 'Canceled'
                job.ended_at = datetime.now()

                for job_task in job_tasks:
                    job_task.status = 'Canceled'
                    job_task.agent_id = None
                db.session.commit()
                flash('Job has been stopped!', 'success')
            else:
                flash('Job not activly running.', 'danger')
        else:
            flash('You do not have rights to stop this job!', 'danger')
    else:
        flash('Error in stopping job', 'danger')
    return redirect(url_for('jobs.jobs_list'))
