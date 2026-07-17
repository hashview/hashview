from flask import Blueprint, jsonify, redirect, request, send_from_directory, current_app, url_for
from hashview.models import Agents, JobTasks, Tasks, Wordlists, Rules, Jobs, Hashes, Hashfiles, HashfileHashes, Users, HashNotifications, Settings, JobNotifications, Customers
from hashview.utils.utils import get_md5_hash, get_linecount, get_filehash, update_dynamic_wordlist, update_job_task_status, import_hashfilehashes, validate_pwdump_hashfile, validate_netntlm_hashfile, validate_kerberos_hashfile, validate_shadow_hashfile, validate_user_hash_hashfile, validate_hash_only_hashfile, send_email, send_pushover, notify_admins, build_hashcat_command, ntlm_hash_hex
from hashview.models import db
from sqlalchemy.ext.declarative import DeclarativeMeta
from sqlalchemy import func
from packaging import version
from datetime import datetime, timedelta
import hashview
import os
import json
import secrets
import hashlib
import binascii
import gzip
import shutil

api = Blueprint('api', __name__)

#
# Yeah, i know its bad and should be converted to a legit REST API.
# This code should be considered tempoary as we work over the port.
# Ideally this will get replaced (along with the agent code) some time later
#

class AlchemyEncoder(json.JSONEncoder):

    def default(self, obj):
        if isinstance(obj.__class__, DeclarativeMeta):
            # an SQLAlchemy class
            fields = {}
            for field in [x for x in dir(obj) if not x.startswith('_') and x != 'metadata']:
                data = obj.__getattribute__(field)
                try:
                    json.dumps(data) # this will fail on non-encodable values, like other classes
                    fields[field] = data
                except TypeError:
                    fields[field] = None
            # a json-encodable dict
            return fields

        return json.JSONEncoder.default(self, obj)

def is_authorized(user, agent, request):
    isUser = False
    if request.cookies:
        if userAuthorized(request.cookies.get('uuid')):
            return True
        if isUser == False:
            if agentAuthorized(request.cookies.get('uuid')):
                return True
    else:
        return False

def userAuthorized(uuid):
    user = Users.query.filter_by(api_key=uuid).first()
    if user:
        return True
    return False

def agentAuthorized(uuid):
    agent = Agents.query.filter_by(uuid=uuid).first()
    if agent:
        if agent.status == 'Online' or agent.status == 'Working' or agent.status == 'Idle' or agent.status == 'Authorized':
            return True
    return False

def update_heartbeat(uuid):
    agent = Agents.query.filter_by(uuid=uuid).first()
    if agent:
        agent.src_ip = request.remote_addr
        agent.last_checkin = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        db.session.commit()

def versionCheck(agent_version):
    if agent_version:
        if version.parse(agent_version) < version.parse(hashview.__version__):
            return False
        return True
    else:
        return False

@api.route('/v1/not_authorized', methods=['GET', 'POST'])
def v1_api_unauthorized():
    message = {
        'status': 200,
        'type': 'Error',
        'msg': 'Your agent is not authorized to work with this cluster.'
    }
    return jsonify(message)

@api.route('/v1/upgrade_required')
def v1_api_upgrade_required():
    message = {
        'status': 426,
        'type': 'message',
        'msg': 'Version missmatch, update your agent!'
    }
    return jsonify(message)

@api.route('/v1/admin/settings', methods=['GET'])
def v1_api_get_admin_settings():
    if not is_authorized(user=True, agent=True, request=request):
        return redirect("/v1/not_authorized")

    update_heartbeat(request.cookies.get('uuid'))
    settings = Settings.query.all()
    message = {
        'status': 200,
        'settings': json.dumps(settings, cls=AlchemyEncoder)
    }
    return jsonify(message)    

@api.route('/v1/agents/heartbeat', methods=['POST'])
def v1_api_set_agent_heartbeat():
    # Get uuid
    uuid = request.cookies.get('uuid')
    if not versionCheck(request.cookies.get('agent_version')):
        return redirect("/v1/upgrade_required")

    settings = Settings.query.first()

    # Get agent from db
    agent = Agents.query.filter_by(uuid=uuid).first()
    if not agent:
        # no agent found, time to add it to our db
        new_agent = Agents( name = request.cookies.get('name'),
                        src_ip = request.remote_addr,
                        uuid = uuid,
                        status = 'Pending',
                        last_checkin = datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        db.session.add(new_agent)
        db.session.commit()
        message = {
            'status': 200,
            'type': 'message',
            'msg': 'Go Away'
        }
        return jsonify(message)

    else:
        update_heartbeat(uuid)
        if agent.status == 'Pending':
            # Agent exists, but has not ben activated. Update heartbeet and turn agent away
            update_heartbeat(uuid)
            message = {
                'status': 200,
                'type': 'message',
                'msg': 'Go Away'
            }
            return jsonify(message)
        else:
            # check if job_task
            agent_data = request.get_json()

            # Check authorization cookies
            if agent_data['agent_status'] == 'Working':
                agent.status = 'Working'

                # Check if task has exceeded maximum runtime
                job_task = JobTasks.query.filter_by(agent_id = agent.id).first()
                if not job_task or job_task.status == 'Canceled':
                    message = {
                        'status': 200,
                        'type': 'message',
                        'msg': 'Canceled',
                    }
                    return jsonify(message)

                if settings.max_runtime_tasks > 0 and datetime.strptime(str(job_task.started_at), '%Y-%m-%d %H:%M:%S') + timedelta(hours=settings.max_runtime_tasks) < datetime.now():
                    update_job_task_status(job_task.id, 'Canceled')
                    message = {
                        'status': 200,
                        'type': 'message',
                        'msg': 'Canceled',
                    }
                    return jsonify(message)

                # check if job has exceeded maximum runtime
                job = Jobs.query.get(job_task.job_id)
                if settings.max_runtime_jobs > 0 and datetime.strptime(str(job.started_at), '%Y-%m-%d %H:%M:%S') + timedelta(hours=settings.max_runtime_jobs) < datetime.now():
                    job_tasks = JobTasks.query.filter_by(job_id = job.id).all()
                    for job_task in job_tasks:
                        update_job_task_status(job_task.id, 'Canceled')

                    job.status = 'Canceled'
                    job.ended_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    db.session.commit()

                    message = {
                        'status': 200,
                        'type': 'message',
                        'msg': 'Canceled',
                    }
                    return jsonify(message)
                
                if agent_data['hc_status']:
                    agent.hc_status = agent_data['agent_status']
                    hc_status = str(agent_data['hc_status']).replace("\'", "\"")
                    json_response = json.loads(hc_status)
                    agent.benchmark = json_response['Speed #']
                    agent.hc_status = str(agent_data['hc_status']).replace("\'", "\"")

                db.session.commit()

            if agent_data['agent_status'] == 'Idle':
                # Clear hc_status if we're idle
                agent.status = "Idle"
                agent.hc_status = ""
                db.session.commit()
                already_assigned_task = JobTasks.query.filter_by(agent_id = agent.id).first()
                if already_assigned_task != None:
                    message = {
                        'status': 200,
                        'type': 'message',
                        'msg': 'START',
                        'job_task_id': already_assigned_task.id
                    }
                    return jsonify(message)
                else:
                    # Get first unassigned jobtask and 'assign' it to this agent
                    job_task_entry = JobTasks.query.filter_by(status = 'Queued').order_by(JobTasks.priority.desc(), JobTasks.id).first()
                    if job_task_entry:
                        job_task_entry.agent_id = agent.id
                        job_task_entry.status = 'Running'
                        job_task_entry.started_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        db.session.commit()
                        message = {
                            'status': 200,
                            'type': 'message',
                            'msg': 'START',
                            'job_task_id': job_task_entry.id
                        }
                        return jsonify(message)
                update_heartbeat(uuid)
                message = {
                    'status': 200,
                    'type': 'message',
                    'msg': 'OK'
                }
                return jsonify(message)
            else:
                update_heartbeat(uuid)
                message = {
                    'status': 200,
                    'type': 'message',
                    'msg': 'OK'
                }
                return jsonify(message)

@api.route('/v1/customers', methods=['GET'])
def v1_api_get_customers():
    if not is_authorized(user=True, agent=True, request=request):
        return redirect("/v1/not_authorized")

    update_heartbeat(request.cookies.get('uuid'))
    customers = Customers.query.all()
    message = {
        'status': 200,
        'users': json.dumps(customers, cls=AlchemyEncoder)
    }
    return jsonify(message)

@api.route('/v1/customers/add', methods=['POST'])
def v1_api_add_customer():
    # Authorization check
    if not is_authorized(user=True, agent=False, request=request):
        return redirect("/v1/not_authorized")

    # Expect JSON body
    customer_data = request.get_json()
    if not customer_data:
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': 'Missing customer data in request body'
        })

    try:
        # Create DB entry
        customer_entry = Customers(
            name=customer_data.get('name'),
            description=customer_data.get('description')
        )
        db.session.add(customer_entry)
        db.session.commit()

        message = {
            'status': 200,
            'type': 'message',
            'msg': 'Customer added',
            'customer_id': customer_entry.id
        }
        return jsonify(message)
    except Exception as e:
        return jsonify({
            'status': 500,
            'type': 'Error',
            'msg': f'Failed to add customer: {e}'
        })

@api.route('/v1/rules', methods=['GET'])
def v1_api_get_rules():
    if not is_authorized(user=True, agent=True, request=request):
        return redirect("/v1/not_authorized")

    update_heartbeat(request.cookies.get('uuid'))
    rules = Rules.query.all()
    message = {
        'status': 200,
        'rules': json.dumps(rules, cls=AlchemyEncoder)
    }
    return jsonify(message)

# serve a rules file
@api.route('/v1/rules/<int:rules_id>', methods=['GET'])
def v1_api_get_rules_download(rules_id):
    if not is_authorized(user=True, agent=True, request=request):
        return redirect("/v1/not_authorized")

    update_heartbeat(request.cookies.get('uuid'))
    rules = Rules.query.get(rules_id)
    if not rules:
        return jsonify({'status': 404, 'type': 'Rules', 'msg': 'Rules file not found'}), 404
    # rules.path is DB-controlled and must NEVER reach a shell (CWE-78). Resolve
    # to a bare basename, gzip it in-process (no os.system), and stream the gz.
    rules_name = os.path.basename(rules.path or '')
    src_path = os.path.join(current_app.root_path, 'control/rules', rules_name)
    if not rules_name or not os.path.isfile(src_path):
        return jsonify({'status': 404, 'type': 'Rules', 'msg': 'Rules file missing on disk'}), 404
    gz_name = rules_name + '.gz'
    gz_path = os.path.join(current_app.root_path, 'control/tmp', gz_name)
    with open(src_path, 'rb') as f_in, gzip.open(gz_path, 'wb', compresslevel=9) as f_out:
        shutil.copyfileobj(f_in, f_out)
    return send_from_directory('control/tmp', gz_name, mimetype='application/octet-stream')

# Provide wordlist info (really should be plural)
@api.route('/v1/wordlists', methods=['GET'])
def v1_api_get_wordlist():
    if not is_authorized(user=True, agent=True, request=request):
        return redirect("/v1/not_authorized")

    update_heartbeat(request.cookies.get('uuid'))
    wordlists = Wordlists.query.all()
    message = {
        'status': 200,
        'wordlists': json.dumps(wordlists, cls=AlchemyEncoder)
    }
    return jsonify(message)

# serve a wordlist
@api.route('/v1/wordlists/<int:wordlist_id>', methods=['GET'])
def v1_api_get_wordlist_download(wordlist_id):
    if not is_authorized(user=True, agent=True, request=request):
        return redirect("/v1/not_authorized")

    update_heartbeat(request.cookies.get('uuid'))
    wordlist = Wordlists.query.get(wordlist_id)
    if not wordlist:
        return jsonify({'status': 404, 'type': 'Wordlists', 'msg': 'Wordlist not found'}), 404
    # wordlist.path is DB-controlled and must NEVER reach a shell (CWE-78).
    # Resolve to a bare basename, gzip it in-process (no os.system), stream the gz.
    wordlist_name = os.path.basename(wordlist.path or '')
    src_path = os.path.join(current_app.root_path, 'control/wordlists', wordlist_name)
    if not wordlist_name or not os.path.isfile(src_path):
        return jsonify({'status': 404, 'type': 'Wordlists', 'msg': 'Wordlist file missing on disk'}), 404
    random_hex = secrets.token_hex(8)
    gz_name = wordlist_name + "_" + random_hex + ".gz"
    gz_path = os.path.join(current_app.root_path, 'control/tmp', gz_name)
    with open(src_path, 'rb') as f_in, gzip.open(gz_path, 'wb', compresslevel=9) as f_out:
        shutil.copyfileobj(f_in, f_out)
    return send_from_directory('control/tmp', gz_name, mimetype='application/octet-stream')

# Update Dynamic Wordlist
@api.route('/v1/updateWordlist/<int:wordlist_id>', methods=['GET'])
def v1_api_get_update_wordlist(wordlist_id):
    if not is_authorized(user=True, agent=True, request=request):
        return redirect("/v1/not_authorized")

    update_heartbeat(request.cookies.get('uuid'))
    update_dynamic_wordlist(wordlist_id)
    message = {
        'status': 200,
        'type': 'message',
        'msg': 'OK'
    }
    return jsonify(message)

# Create new wordlist
@api.route('/v1/wordlists/add/<wordlist_name>', methods=['POST'])
def v1_api_add_wordlist(wordlist_name):
    # Authorization check
    if not is_authorized(user=True, agent=True, request=request):
        return redirect("/v1/not_authorized")

    # Expect raw plain‑text body (Content‑Type: text/plain)
    raw_content = request.get_data(as_text=True)
    if not raw_content:
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': 'Missing wordlist content in request body'
        })

    # Resolve user from api_key cookie
    user_uuid = request.cookies.get('uuid')
    user = Users.query.filter_by(api_key=user_uuid).first()
    if not user:
        return jsonify({
            'status': 403,
            'type': 'Error',
            'msg': 'User not found'
        })

    # Generate a random filename for storage
    random_name = secrets.token_hex(8) + '.txt'
    file_path = os.path.abspath(os.path.join(current_app.root_path, 'control/wordlists', random_name))

    # Save the raw content to disk
    try:
        with open(file_path, 'w') as f:
            f.write(raw_content)
    except Exception as e:
        return jsonify({
            'status': 500,
            'type': 'Error',
            'msg': f'Failed to write wordlist file: {e}'
        })

    # Create DB entry using the URL parameter as the name
    wordlist_entry = Wordlists(
        name=wordlist_name,
        owner_id=user.id,
        type='static',
        path=file_path,
        checksum=get_filehash(file_path),
        size=get_linecount(file_path)
    )
    db.session.add(wordlist_entry)
    db.session.commit()

    message = {
        'status': 200,
        'type': 'message',
        'msg': 'Wordlist added',
        'wordlist_id': wordlist_entry.id
    }
    return jsonify(message)

# force or restart a queue item
# used when agent goes offline and comes back online
# without a running hashcat cmd while task still assigned to them
@api.route('/v1/jobTasks/<int:job_task_id>', methods=['GET'])
def v1_api_get_queue_assignment(job_task_id):
    if not is_authorized(user=True, agent=True, request=request):
        return redirect("/v1/not_authorized")

    update_heartbeat(request.cookies.get('uuid'))

    # Get agent id from UUID
    agent = Agents.query.filter_by(uuid=request.cookies.get('uuid')).first()
    job_task = JobTasks.query.filter_by(agent_id=agent.id).first()

    message = {
        'status': 200,
        'job_task': json.dumps(job_task, cls=AlchemyEncoder)
    }
    return jsonify(message)

# Provide job info
@api.route('/v1/jobs/<int:job_id>', methods=['GET'])
def v1_api_get_job(job_id):
    if not is_authorized(user=True, agent=True, request=request):
        return redirect("/v1/not_authorized")

    update_heartbeat(request.cookies.get('uuid'))
    job = Jobs.query.get(job_id)

    message = {
        'status': 200,
        'job': json.dumps(job, cls=AlchemyEncoder)
    }
    return jsonify(message)

# Create a new job
@api.route('/v1/jobs/add', methods=['POST'])
def v1_api_post_add_job():
    if not is_authorized(user=True, agent=False, request=request):
        return redirect("/v1/not_authorized")

    uuid = request.cookies.get('uuid')
    user = Users.query.filter_by(api_key=uuid).first()
    if not user:
        return jsonify({
            'status': 403,
            'type': 'Error',
            'msg': 'User not found'
        })
    
    # Expect JSON body
    job_data = request.get_json()
    if not job_data:
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': 'Missing job data in request body'
        })

    try:
        # Create DB entry
        job_entry = Jobs(
            name=job_data.get('name'),
            hashfile_id=job_data.get('hashfile_id'),
            owner_id=user.id,
            customer_id=job_data.get('customer_id'),
            status='Ready',
            limit_recovered=job_data.get('limit_recovered', False)
        )
        db.session.add(job_entry)
        db.session.commit()

        # Create job tasks based on top 10 tasks
        hashfile = Hashfiles.query.get(job_data.get('hashfile_id'))
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
            return jsonify({
                'status': 500,
                'type': 'Error',
                'msg': f'Not enough data to determine effective tasks for this hash type. Please add more cracked hashes of this type before creating a job.'
            })
        else:
        # for each effective task 
            for entry in most_effective_tasks_raw:
                job_tasks = JobTasks.query.filter_by(job_id=job_entry.id).all()
                if entry.task_id not in {job_task.task_id for job_task in job_tasks}:
                    job_task = JobTasks(job_id=job_entry.id, task_id=entry.task_id, status='Not Started')
                    db.session.add(job_task)
                    db.session.commit()      

        # Job notifications: one row per (job, owner, channel), using the same
        # method tokens as the web UI ('email'/'push'/'slack'), de-duped the
        # same way. The old code passed notify_email/notify_pushover kwargs that
        # don't exist on JobNotifications (its columns are owner_id, job_id,
        # method) and omitted the required owner_id, so every jobs/add 500'd
        # here after the job had already been committed. Any notification
        # failure is now rolled back and logged so it can't undo a created job.
        try:
            notify_map = [
                ('email', job_data.get('notify_email', False)),
                ('push', job_data.get('notify_pushover', False)),
                ('slack', job_data.get('notify_slack', False)),
            ]
            for method, requested in notify_map:
                if requested:
                    exists = JobNotifications.query.filter_by(
                        job_id=job_entry.id, owner_id=user.id, method=method).first()
                    if not exists:
                        db.session.add(JobNotifications(
                            owner_id=user.id, job_id=job_entry.id, method=method))
            db.session.commit()
        except Exception:
            db.session.rollback()
            current_app.logger.exception(
                'API /v1/jobs: job %s created but notification setup failed',
                job_entry.id)

        message = {
            'status': 200,
            'type': 'message',
            'msg': 'Job added',
            'job_id': job_entry.id
        }
        return jsonify(message)
    except Exception as e:
        return jsonify({
            'status': 500,
            'type': 'Error',
            'msg': f'Failed to add job: {e}'
        })

# Start a job
@api.route('/v1/jobs/start/<int:job_id>', methods=['POST'])
def v1_api_post_start_job(job_id):
    if not is_authorized(user=True, agent=False, request=request):
        return redirect("/v1/not_authorized")

    job = Jobs.query.get(job_id)
    job_tasks = JobTasks.query.filter_by(job_id = job_id).all()
    uuid = request.cookies.get('uuid')
    current_user = Users.query.filter_by(api_key=uuid).first()

    if job and job_tasks:
        if job.status != 'Queued':
            return jsonify({
                'status': 400,
                'type': 'Error',
                'msg': 'Job is not in a queued state'
            })        
        if current_user.admin or job.owner_id == current_user.id:
            job.status = 'Queued'
            job.queued_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            for job_task in job_tasks:
                job_task.status = 'Queued'
                job_task.priority = job.priority
                job_task.command = build_hashcat_command(job.id, job_task.task_id)

            db.session.commit()
            return jsonify  ({
                'status': 200,
                'type': 'message',
                'msg': 'Job started',
                'job_id': job.id
            })
        else:
            return jsonify({
                'status': 403,
                'type': 'Error',
                'msg': 'User not found'
            })
    else:
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': 'Invalid job ID'
        })

# Provide task info
@api.route('/v1/tasks/<int:task_id>', methods=['GET'])
def v1_api_get_task(task_id):
    if not is_authorized(user=True, agent=True, request=request):
        return redirect("/v1/not_authorized")

    update_heartbeat(request.cookies.get('uuid'))
    task = Tasks.query.get(task_id)
    message = {
        'status': 200,
        'task': json.dumps(task, cls=AlchemyEncoder)
    }
    return jsonify(message)

# Upload a large hashfile
@api.route('/v1/hashfiles/upload/<int:customer_id>/<int:file_format>/<int:hash_type>/<hashfile_name>', methods=['POST'])
def v1_api_post_hashfile_upload(customer_id, file_format, hash_type, hashfile_name):
    if not is_authorized(user=True, agent=False, request=request):
        return redirect("/v1/not_authorized")
    
    customers = Customers.query.get(customer_id)
    if not customers:
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': 'Invalid customer ID'
        })

    # file_format:
    # 0 = pwdump
    # 1 = NetNTLM
    # 2 = kerberos
    # 3 = shadow
    # 4 = user:hash
    # 5 = hash_only

    # Expect raw plain‑text body (Content‑Type: text/plain)
    raw_content = request.get_data(as_text=True)
    if not raw_content:
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': 'Missing hashfile content in request body'
        })

    if file_format not in [0,1,2,3,4,5]:
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': 'Invalid file format. Valid formats are 0=pwdump, 1=NetNTLM, 2=kerberos, 3=shadow, 4=user:hash, 5=hash_only'
        })

    # Resolve user from api_key cookie
    user_uuid = request.cookies.get('uuid')
    user = Users.query.filter_by(api_key=user_uuid).first()
    if not user:
        return jsonify({
            'status': 403,
            'type': 'Error',
            'msg': 'User not found'
        })

    # Generate a random filename for storage
    random_name = secrets.token_hex(8) + '.txt'
    file_path = os.path.abspath(os.path.join(current_app.root_path, 'control/tmp/', random_name))

    # Save the raw content to disk
    try:
        with open(file_path, 'w') as f:
            f.write(raw_content)
        f.close()
    except Exception as e:
        return jsonify({
            'status': 500,
            'type': 'Error',
            'msg': f'Failed to write hashfile: {e}'
        })

    # import contents from file
    try:
        print(f"[DEBUG] Validating hashfile {file_path} of type {file_format} for hashtype {hash_type}")
        if file_format == 0:
            has_problem = validate_pwdump_hashfile(file_path, str(hash_type))
        elif file_format == 1:
            has_problem = validate_netntlm_hashfile(file_path, str(hash_type))
        elif file_format == 2:
            has_problem = validate_kerberos_hashfile(file_path, str(hash_type)) 
        elif file_format == 3:
            has_problem = validate_shadow_hashfile(file_path, str(hash_type))
        elif file_format == 4:
            has_problem = validate_user_hash_hashfile(file_path, str(hash_type))
        elif file_format == 5:
            has_problem = validate_hash_only_hashfile(file_path, str(hash_type)) 
        else:
            has_problem = 'Invalid File Format'

        if has_problem:
            return jsonify({
                'status': 500,
                'type': 'Error',
                'msg': f'Invalid Hash: {has_problem}'
            })            
 
        else:
            hashfile = Hashfiles(name=hashfile_name, customer_id=customer_id, owner_id=user.id)
            db.session.add(hashfile)

            db.session.commit()

            # Parse Hashfile
            if file_format == 0:
                file_format = 'pwdump'
            elif file_format == 1:
                file_format = 'NetNTLM'
            elif file_format == 2:
                file_format = 'kerberos'
            elif file_format == 3:
                file_format = 'shadow'
            elif file_format == 4:
                file_format = 'user_hash'
            elif file_format == 5:
                file_format = 'hash_only'
            if not import_hashfilehashes(   hashfile_id=hashfile.id,
                                            hashfile_path=file_path,
                                            file_type=file_format,
                                            hash_type=hash_type
                                            ):
                return jsonify({
                    'status': 500,
                    'type': 'Error',
                    'msg': f'Something went wrong. Check the filetype / hashtype and try again.'
                })                  

            hashfile_hashes_cnt = db.session.query(HashfileHashes).filter_by(hashfile_id=hashfile.id).count()
            if hashfile_hashes_cnt == 0:
                db.session.delete(hashfile)
                db.session.commit()
                return jsonify({
                    'status': 500,
                    'type': 'Error',
                    'msg': f'No valid hashes found in the hashfile. Hashfile not added.'
                })   

            cracked_hashfiles_hashes_cnt = db.session.query(Hashes).join(HashfileHashes, Hashes.id == HashfileHashes.hash_id).filter(Hashes.cracked == '1').filter(HashfileHashes.hashfile_id==hashfile.id).count()
                
            # Return the insta crack result
            return jsonify({
                'status': 200,
                'type': 'message',
                'msg': 'Hashfile added',
                'hashfile_id': hashfile.id,
                'hash_count': hashfile_hashes_cnt,
                'instacracked': cracked_hashfiles_hashes_cnt
            })

    except Exception as e:
        return jsonify({
            'status': 500,
            'type': 'Error',
            'msg': f'Hash import Failed: {e}'
        })

# generate and serve hashfile
@api.route('/v1/hashfiles/<int:hashfile_id>', methods=['GET'])
def v1_api_get_hashfile(hashfile_id):
    if not is_authorized(user=True, agent=True, request=request):
        return redirect("/v1/not_authorized")

    update_heartbeat(request.cookies.get('uuid'))
    random_hex = secrets.token_hex(8)
    file_object = open('hashview/control/tmp/' + random_hex, 'w')

    # do a left join select to get our ciphertext hashes
    dbresults = db.session.query(Hashes, HashfileHashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '0').filter(HashfileHashes.hashfile_id==hashfile_id).all()
    for result in dbresults:
        file_object.write(result[0].ciphertext + '\n')
    file_object.close()

    return send_from_directory('control/tmp/', random_hex)

# List hashfiles that contain hashes of a given hash_type, with per-file
# total/cracked counts scoped to that type. Lets API clients pick a hashfile
# to build a job against without hardcoding an ID.
@api.route('/v1/hashfiles/hash_type/<int:hash_type>', methods=['GET'])
def v1_api_get_hashfiles_by_hash_type(hash_type):
    if not is_authorized(user=True, agent=False, request=request):
        return redirect("/v1/not_authorized")

    uuid = request.cookies.get('uuid')
    user = Users.query.filter_by(api_key=uuid).first()
    if not user:
        return jsonify({
            'status': 403,
            'type': 'Error',
            'msg': 'User not found'
        })

    # hash_type lives on Hashes (per-hash), not on Hashfiles: a file can hold
    # mixed types, so match via the HashfileHashes junction and scope the
    # counts to THIS hash_type within each file.
    matching_ids = [row[0] for row in
                    db.session.query(HashfileHashes.hashfile_id)
                    .join(Hashes, Hashes.id == HashfileHashes.hash_id)
                    .filter(Hashes.hash_type == hash_type)
                    .distinct().all()]

    results = []
    for hashfile_id in matching_ids:
        hashfile = Hashfiles.query.get(hashfile_id)
        if hashfile is None:
            continue
        base = db.session.query(Hashes.id) \
            .join(HashfileHashes, HashfileHashes.hash_id == Hashes.id) \
            .filter(HashfileHashes.hashfile_id == hashfile_id) \
            .filter(Hashes.hash_type == hash_type)
        total = base.count()
        cracked = base.filter(Hashes.cracked == '1').count()
        results.append({
            'id': hashfile.id,
            'name': hashfile.name,
            'customer_id': hashfile.customer_id,
            'owner_id': hashfile.owner_id,
            'uploaded_at': hashfile.uploaded_at.isoformat() if hashfile.uploaded_at else None,
            'hash_type': hash_type,
            'total_hashes': total,
            'cracked_hashes': cracked,
        })

    # Structured list (not AlchemyEncoder) because the count fields are
    # derived, not model columns. An empty list with status 200 is the valid
    # "no hashfiles of this type" answer.
    message = {
        'status': 200,
        'type': 'message',
        'hashfiles': results
    }
    return jsonify(message)

# Upload Cracked Hashes
# old and probably unused
@api.route('/v1/uploadCrackFile/<int:task_id>/<int:hash_type>', methods=['POST'])
def v1_api_put_jobtask_crackfile_upload(task_id, hash_type):
    if not is_authorized(user=False, agent=True, request=request):
        return redirect("/v1/not_authorized")

    update_heartbeat(request.cookies.get('uuid'))

    # TODO
    # We really should validate if task_id is legit
    
    # save to file
    file_contents = request.get_json()

    #for entry in lines:
    for entry in file_contents['file'].split('\n'):
        if ':' in entry:
            encoded_plaintext = entry.split(':')[-1]
            #plaintext = bytes.fromhex(encoded_plaintext.rstrip())
            plaintext = encoded_plaintext.rstrip().upper()
            elements = entry.split(':')
            # Remove cracked hash
            elements.pop()
            ciphertext = ':'.join(elements)

            #print('Plaintext: ' + str(bytes.fromhex(plaintext).decode('latin-1')))
            #print('Ciphertext: ' + str(ciphertext))

            record = Hashes.query.filter_by(hash_type=hash_type, sub_ciphertext=get_md5_hash(ciphertext), cracked='0').first()
            if record:
                try:
                    #record.plaintext = plaintext.decode('latin-1')
                    record.plaintext = plaintext
                    record.cracked = 1
                    #print('i should be updating the datetime')
                    record.recovered_at = datetime.today()
                    record.task_id = task_id
                    db.session.commit()
                except Exception as error:
                    print('Failed to import following cracked hash: ' + str(encoded_plaintext))
                    print('Reason: ' + str(error))

    # Send Hash Completion Notifications
    hash_notifications = HashNotifications.query.all()
    for hash_notification in hash_notifications:
        user = Users.query.get(hash_notification.owner_id)
        message = "Congratulations, a hash has been recovered!: \n\n"

        # Check if hash is cracked
        hash = Hashes.query.get(hash_notification.hash_id)
        if hash.cracked:

            message += 'You can check the results using the following link: ' + "\n"
            message += url_for('searches.searches_list', hash_id=hash.id, _external=True)
            if hash_notification.method == 'email':
                send_email(user, 'Hashview User Hash Recovered!', message)
            elif hash_notification.method == 'push':
                if user.pushover_user_key and user.pushover_app_id:
                    send_pushover(user, 'Message from Hashview', message)
            else:
                send_email(user, 'Hashview: Missing Pushover Key', 'Hello, you were due to recieve a pushover notification, but because your account was not provisioned with an pushover ID and Key, one could not be set. Please log into hashview and set these options under Manage->Profile.')
            db.session.delete(hash_notification)
            db.session.commit()

    message = {
        'status': 200,
        'type': 'message',
        'msg': 'OK'
    }
    return jsonify(message)

# Upload Cracked Hashes
@api.route('/v1/uploadCrackFile/<int:job_task_id>', methods=['POST'])
def v1_api_post_jobtask_crackfile_upload(job_task_id):
    if not is_authorized(user=False, agent=True, request=request):
        return redirect("/v1/not_authorized")

    update_heartbeat(request.cookies.get('uuid'))

    # TODO 
    # Validate calling agent is actually assigned jobtask

    # For one-and-done jobs
    recovered_at_least_one_hash = False

    # save to file
    file_contents = request.get_json()

    # Get Hashtype from job_task_id
    job_task = JobTasks.query.get(job_task_id)

    # Get Job from job_task
    job = Jobs.query.get(job_task.job_id)

    # Get hashfile from job
    hashfile = Hashfiles.query.get(job.hashfile_id)

    # Get hashfilehashes from hashfile
    hashfilehashes = HashfileHashes.query.filter_by(hashfile_id=hashfile.id).first()

    # Get single hash
    single_hash = Hashes.query.get(hashfilehashes.hash_id)

    hash_type = single_hash.hash_type

    #for entry in lines:
    for entry in file_contents['file'].split('\n'):
        if ':' in entry:
            encoded_plaintext = entry.split(':')[-1]
            plaintext = encoded_plaintext.rstrip().upper()
            elements = entry.split(':')
            # Remove cracked hash
            elements.pop()
            if hash_type == 22000:
                # special case for 22000
                # example <partial ciphertext>:<ssid>:<hex encoded plaintext>
                elements.pop()  # remove the second to last element for 22000
            ciphertext = ':'.join(elements)
            if hash_type == 22000:
                # special case for 22000
                partial_hash = "WPA*02*{}%".format(ciphertext.replace(':', '*'))
                record = Hashes.query.filter_by(hash_type=hash_type, cracked='0').filter(Hashes.ciphertext.like(partial_hash)).first()
                if not record:
                    print(f"[DEBUG] No record found for partial hash {partial_hash}")
            else:
                record = Hashes.query.filter_by(hash_type=hash_type, sub_ciphertext=get_md5_hash(ciphertext), cracked='0').first()
            if record:
                try:
                    #record.plaintext = plaintext.decode('latin-1')
                    record.plaintext = plaintext
                    record.cracked = 1
                    #print('i should be updating the datetime')
                    record.recovered_at = datetime.today()
                    record.task_id = job_task.task_id
                    record.recovered_by = job.owner_id
                    db.session.commit()
                    recovered_at_least_one_hash = True

                except Exception as error:
                    print('Failed to import following cracked hash: ' + str(encoded_plaintext))
                    print('Reason: ' + str(error))

    # Send Hash Completion Notifications
    hash_notifications = HashNotifications.query.all()
    for hash_notification in hash_notifications:
        user = Users.query.get(hash_notification.owner_id)
        message = "Congratulations, a hash has been recovered!: \n\n"

        # Check if hash is cracked
        hash = Hashes.query.get(hash_notification.hash_id)
        if hash:
            if hash.cracked:

                message += 'You can check the results using the following link: ' + "\n"
                message += url_for('searches.searches_list', hash_id=hash.id, _external=True)
                if hash_notification.method == 'email':
                    send_email(user, 'Hashview User Hash Recovered!', message)
                elif hash_notification.method == 'push':
                    if user.pushover_user_key and user.pushover_app_id:
                        send_pushover(user, 'Message from Hashview', message)
                else:
                    send_email(user, 'Hashview: Missing Pushover Key', 'Hello, you were due to recieve a pushover notification, but because your account was not provisioned with an pushover ID and Key, one could not be set. Please log into hashview and set these options under Manage->Profile.')
                db.session.delete(hash_notification)
                db.session.commit()

    # Check if job type is one and done
    if job.limit_recovered and recovered_at_least_one_hash:

        # cancel all running and queued job tasks
        jobtasks = JobTasks.query.filter_by(job_id=job.id)
        for jobtask in jobtasks:
            update_job_task_status( jobtask_id = jobtask.id,
                                    status = 'Canceled')
        #     if jobtask.status == 'Running':
        #         print(f"setting jobtask.id {jobtask.id} from {jobtask.status} to Canceled")
        #         jobtask.status = 'Canceled'
        #     elif jobtask.status == 'Ready':
        #         print(f"setting jobtask.id {jobtask.id} from {jobtask.status} to Canceled")
        #         jobtask.status = 'Canceled'
        # db.session.commit()

        # # set job status to completed
        # job.status = 'Completed'
        # job.ended_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # print(f"setting Job.id {job.id} to Completed")
        # db.session.commit()

    message = {
        'status': 200,
        'type': 'message',
        'msg': 'OK'
    }
    return jsonify(message)

# Get Hashtype
@api.route('/v1/getHashType/<int:hashfile_id>', methods=['GET'])
def v1_api_getHashType(hashfile_id):
    if not is_authorized(user=True, agent=True, request=request):
        return redirect("/v1/not_authorized")
    
    update_heartbeat(request.cookies.get('uuid'))
    hashfile_hash = HashfileHashes.query.filter_by(hashfile_id = hashfile_id).first()
    hash = Hashes.query.get(hashfile_hash.hash_id)

    message = {
        'status': 200,
        'type': 'message',
        'msg': 'OK',
        'hash_type': hash.hash_type
    }
    return jsonify(message)

# Update JobTask status
@api.route('/v1/jobtask/status', methods=['POST'])
def v1_api_set_queue_jobtask_status():
    if not is_authorized(user=False, agent=True, request=request):
        return redirect("/v1/not_authorized")

    update_heartbeat(request.cookies.get('uuid'))

    status_json = request.get_json()

    if (update_job_task_status(jobtask_id = status_json['job_task_id'], status = status_json['task_status'])):
        message = {
            'status': 200,
            'type': 'message',
            'msg': 'OK'
        }
    else:
        message = {
            'status': 500,
            'type': 'message',
            'msg': 'Error setting jobtask status. Detail: job_task_id='+str(status_json['job_task_id'])+' status='+str(status_json['task_status'])
        }
    return jsonify(message)

# Search
@api.route('/v1/search', methods=['POST'])
def v1_api_search():
    if not is_authorized(user=True, agent=False, request=request):
        return redirect("/v1/not_authorized")
    
    search_json = request.get_json()
    if search_json:
        # Right now we're only asking hash, in the future we may get requests to search by user or by plaintext
        if search_json['hash']:
            # we could search by subciphertext instead of ciphertext if things get slow.
            # subcipher text is indexed whereas ciphertext is not
            cracked_hash = Hashes.query.filter_by(cracked=True).filter_by(ciphertext=search_json['hash']).first()
            if cracked_hash:
                msg = {
                    'hash_type': cracked_hash.hash_type,
                    'hash': search_json['hash'],
                    'plaintext': bytes.fromhex(cracked_hash.plaintext).decode('latin-1')
                }
                message = {
                    'status': 200,
                    'type': 'message',
                    'msg': msg
                }            
            else:
                message = {
                    'status': 200,
                    'type': 'message',
                    'msg': 'Search complete. No Results Found.'
                }            
        else:
            message = {
                'status': 500,
                'type': 'message',
                'msg': 'Invalid Search'
            }
    else:
        message = {
            'status': 500,
            'type': 'message',
            'msg': 'Invalid Search'
        }            
    return jsonify(message)

# Error
@api.route('/v1/error', methods=['POST'])
def v1_api_error():
    if not is_authorized(user=False, agent=True, request=request):
        return redirect("/v1/not_authorized")

    uuid = request.cookies.get('uuid')
    agent = Agents.query.filter_by(uuid=uuid).first()
    message_json = request.get_json()

    subject = 'Error on ' + str(agent.name)
    message_body = message_json['error']

    notify_admins(subject, message_body)

    message = {
        'status': 200,
        'type': 'message',
        'msg': 'OK'
        }
    return jsonify(message)

@api.route('/v1/hashes/import/<int:hash_type>', methods=['POST'])
def v1_api_hashes_import(hash_type):
    if not is_authorized(user=True, agent=False, request=request):
        return redirect("/v1/not_authorized")    
    
    # The route converter yields an int; comparing to the string '1000' made
    # this branch unreachable (every request fell through to 'Unsupported
    # Hashtype'), so NTLM import silently did nothing. Compare as int.
    if hash_type == 1000:

        # Expect raw plain‑text body (Content‑Type: text/plain)
        raw_content = request.get_data(as_text=True)
        if not raw_content:
            return jsonify({
                'status': 400,
                'type': 'Error',
                'msg': 'Missing cracked content in request body'
            })
        
        # Resolve user from api_key cookie
        user_uuid = request.cookies.get('uuid')
        user = Users.query.filter_by(api_key=user_uuid).first()
        if not user:
            return jsonify({
                'status': 403,
                'type': 'Error',
                'msg': 'User not found'
            })

        # Generate a random filename for storage
        random_name = secrets.token_hex(8) + '.txt'
        file_path = os.path.abspath(os.path.join(current_app.root_path, 'control/tmp', random_name))

        # Save the raw content to disk
        try:
            with open(file_path, 'w') as f:
                f.write(raw_content)
            f.close()
        except Exception as e:
            return jsonify({
                'status': 500,
                'type': 'Error',
                'msg': f'Failed to write file: {e}'
            })


        # import contents from file
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.rstrip('\r\n')
                    if not line:
                        continue
                    parts = line.split(':')
                    ciphertext = parts[0]
                    # everything after the first ':' is the plaintext (it may
                    # itself contain ':')
                    plaintext = ':'.join(parts[1:])

                    # NTLM = MD4(UTF-16LE(pw)); ntlm_hash_hex falls back to a
                    # pure-Python MD4 where OpenSSL 3.x drops md4 from hashlib.
                    # Compare case-insensitively: hashcat/Hashview store hashes
                    # in lowercase hex while ntlm_hash_hex returns uppercase.
                    if ciphertext.lower() == ntlm_hash_hex(plaintext).lower():
                        # valid hash:plaintext
                        record = Hashes.query.filter_by(hash_type=hash_type, sub_ciphertext=get_md5_hash(ciphertext), cracked='0').first()
                        if record:
                            try:
                                encoded_plaintext = plaintext.encode('latin-1').hex()
                                record.plaintext = encoded_plaintext 
                                record.cracked = 1
                                record.recovered_at = datetime.today()
                                record.recovered_by = user.id
                                db.session.commit()
                            except Exception as error:
                                return jsonify({
                                    'status': 500,
                                    'type': 'Error',
                                    'msg': f'Failed to import following cracked hash {str(encoded_plaintext)}: {str(error)}'
                                })  
                    else:
                        return jsonify({
                            'status': 500,
                            'type': 'Error',
                            'msg': f'Plaintext for hash {ciphertext}, was found to be invalid.'
                        })
        except Exception as e:
            return jsonify({
                'status': 500,
                'type': 'Error',
                'msg': f'Failed to openfile file: {e}'
            })

        # Send Hash Completion Notifications
        hash_notifications = HashNotifications.query.all()
        for hash_notification in hash_notifications:
            user = Users.query.get(hash_notification.owner_id)
            message = "Congratulations, a hash has been recovered!: \n\n"

            # Check if hash is cracked
            hash = Hashes.query.get(hash_notification.hash_id)
            if hash.cracked:

                message += 'You can check the results using the following link: ' + "\n"
                message += url_for('searches.searches_list', hash_id=hash.id, _external=True)
                if hash_notification.method == 'email':
                    send_email(user, 'Hashview User Hash Recovered!', message)
                elif hash_notification.method == 'push':
                    if user.pushover_user_key and user.pushover_app_id:
                        send_pushover(user, 'Message from Hashview', message)
                else:
                    send_email(user, 'Hashview: Missing Pushover Key', 'Hello, you were due to recieve a pushover notification, but because your account was not provisioned with an pushover ID and Key, one could not be set. Please log into hashview and set these options under Manage->Profile.')
                db.session.delete(hash_notification)
                db.session.commit()

        message = {
            'status': 200,
            'type': 'message',
            'msg': 'OK'
        }
        return jsonify(message)

    else:
        message = {
            'status': 403,
            'type': 'message',
            'msg': 'Unsupported Hashtype'
            }
    return jsonify(message)