import json
import os
import secrets
from datetime import datetime, timedelta

from flask import (
    Blueprint,
    current_app,
    jsonify,
    redirect,
    request,
    send_from_directory,
)
from packaging import version
from sqlalchemy import func
from sqlalchemy.ext.declarative import DeclarativeMeta

import hashview
from hashview.models import (
    Agents,
    Customers,
    Hashes,
    HashfileConversions,
    HashfileHashes,
    Hashfiles,
    JobNotifications,
    Jobs,
    JobTasks,
    Rules,
    Settings,
    Tasks,
    Users,
    Wordlists,
    db,
)
from hashview.utils.audit import log_event
from hashview.utils.utils import (
    build_hashcat_command,
    compress_to_gz,
    decompress_gz,
    get_filehash,
    get_linecount,
    get_md5_hash,
    hexplain_to_text,
    import_hashfilehashes,
    ingest_static_wordlist_file,
    is_gzip,
    notify_admins,
    ntlm_hash_hex,
    process_recovered_hash_notifications,
    text_from_field,
    update_dynamic_wordlist,
    update_job_task_status,
    validate_hash_only_hashfile,
    validate_kerberos_hashfile,
    validate_netntlm_hashfile,
    validate_pwdump_hashfile,
    validate_shadow_hashfile,
    validate_user_hash_hashfile,
)

api = Blueprint('api', __name__)

#
# Yeah, i know its bad and should be converted to a legit REST API.
# This code should be considered tempoary as we work over the port.
# Ideally this will get replaced (along with the agent code) some time later
#

# Column names that must NEVER be serialized to an API/agent response,
# regardless of which model is being dumped — secrets + credential material.
# (/v1/admin/settings is reachable by any authorized user OR agent, so a stored
# secret would otherwise leak to every agent.)
_ENCODER_DENYLIST = frozenset({
    'password', 'api_key',
    'azure_client_secret', 'slack_bot_token',
})

class AlchemyEncoder(json.JSONEncoder):

    def default(self, obj):
        if isinstance(obj.__class__, DeclarativeMeta):
            # an SQLAlchemy class
            fields = {}
            for field in [x for x in dir(obj)
                          if not x.startswith('_')
                          and x != 'metadata'
                          and x not in _ENCODER_DENYLIST]:
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
    # Honor the caller's user/agent flags so each route enforces its own
    # privilege boundary: a user-only route (user=True, agent=False) must
    # reject agent credentials, and an agent-only route (user=False,
    # agent=True) must reject user credentials. Previously this ignored both
    # flags and returned True for ANY valid user OR agent, letting agents hit
    # user-only routes and users hit agent-only routes.
    uuid = request.cookies.get('uuid')
    # Reject an absent/empty credential outright. Without this, a request with
    # no 'uuid' cookie passes None to userAuthorized()/agentAuthorized(), which
    # run filter_by(api_key=None)/filter_by(uuid=None) -> "WHERE col IS NULL".
    # api_key is nullable and is NOT set at user creation (only via
    # /profile/generate_api_key), so a NULL match would impersonate any
    # key-less user. (The old `if request.cookies` check was defeated by sending
    # any unrelated cookie with no uuid.)
    if not uuid:
        return False
    if user and userAuthorized(uuid):
        return True
    if agent and agentAuthorized(uuid):
        return True
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
        # Stamp with the DATABASE's clock (func.now()) rather than a Python datetime.
        # The heartbeat writer and the dashboard renderer can run in different process
        # timezones (e.g. UTC vs the host's local time); using the single DB clock for
        # both the write and the online/offline cutoff makes the comparison
        # timezone-independent and stops live agents from being shown as offline.
        agent.last_checkin = func.now()
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
                        last_checkin = func.now())
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

                if settings.max_runtime_tasks > 0 and job_task.started_at is not None and job_task.started_at + timedelta(hours=settings.max_runtime_tasks) < datetime.now():
                    update_job_task_status(job_task.id, 'Canceled')
                    message = {
                        'status': 200,
                        'type': 'message',
                        'msg': 'Canceled',
                    }
                    return jsonify(message)

                # check if job has exceeded maximum runtime
                job = Jobs.query.get(job_task.job_id)
                if settings.max_runtime_jobs > 0 and job.started_at is not None and job.started_at + timedelta(hours=settings.max_runtime_jobs) < datetime.now():
                    job_tasks = JobTasks.query.filter_by(job_id = job.id).all()
                    for job_task in job_tasks:
                        update_job_task_status(job_task.id, 'Canceled')

                    job.status = 'Canceled'
                    job.ended_at = datetime.now()
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
                if already_assigned_task is not None:
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
                        job_task_entry.started_at = datetime.now()
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

    # Expect JSON body (silent=True so an empty/invalid body returns None
    # instead of raising a 400 HTML page that callers can't parse as JSON)
    customer_data = request.get_json(silent=True)
    if not customer_data:
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': 'Missing customer data in request body'
        })

    try:
        # Create DB entry (Customers only has id + name)
        customer_entry = Customers(
            name=customer_data.get('name')
        )
        db.session.add(customer_entry)
        db.session.commit()

        log_event('customer.create', target=f'customer:{customer_entry.id} {customer_entry.name!r}')
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
    if rules is None:
        return jsonify({'status': 404, 'type': 'Error', 'msg': 'Rule not found'}), 404

    # Rules are stored plaintext at rest; compress into control/tmp and serve
    # that. No shell; pure-Python streamed gzip -9 (same pattern as the
    # dynamic-wordlist download above). The random tmp name avoids predictable
    # paths and collisions between concurrent downloads.
    rules_dir = os.path.join(current_app.root_path, 'control/rules')
    tmp_dir = os.path.join(current_app.root_path, 'control/tmp')
    src_path = os.path.join(rules_dir, os.path.basename(rules.path))
    if not os.path.exists(src_path):
        return jsonify({'status': 404, 'type': 'Error', 'msg': 'Rule file missing on disk'}), 404

    tmp_gz = os.path.join(tmp_dir, secrets.token_hex(8) + '.gz')
    compress_to_gz(src_path, tmp_gz, 9)
    return send_from_directory(tmp_dir, os.path.basename(tmp_gz), mimetype='application/octet-stream')

# Create new rule
@api.route('/v1/rules/add/<rule_name>', methods=['POST'])
def v1_api_add_rule(rule_name):
    # User-upload action (resolves the caller to a Users row by api_key), so
    # it's user-only — the agent only GETs rules, it never POSTs here.
    if not is_authorized(user=True, agent=False, request=request):
        return redirect("/v1/not_authorized")

    # Read the body as BYTES (not as_text) so an uploaded gzip rule file isn't
    # corrupted by text decoding. The body may be plain text or a gzip file.
    raw_content = request.get_data()
    if not raw_content:
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': 'Missing rule content in request body'
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

    # Unlike wordlists, rules are stored PLAINTEXT at rest (control/rules/),
    # so a gzip body is decompressed before landing. The <hex>.txt naming
    # matches the web UI's save_file() convention.
    tmp_path = os.path.abspath(os.path.join(current_app.root_path, 'control/tmp', secrets.token_hex(8)))
    final_path = os.path.join(current_app.root_path, 'control/rules', secrets.token_hex(8) + '.txt')
    try:
        with open(tmp_path, 'wb') as f:
            f.write(raw_content)
        if is_gzip(tmp_path):
            # Raises on a malformed gzip stream, which doubles as validation
            decompress_gz(tmp_path, final_path)
        else:
            os.rename(tmp_path, final_path)
    except Exception as e:
        if os.path.exists(final_path):
            os.remove(final_path)
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': f'Failed to process rule (not valid text or gzip?): {e}'
        })
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

    # Same metadata helpers as the web UI upload (rules_add): size/checksum
    # are computed over the plaintext file.
    rule = Rules(
        name=rule_name,
        owner_id=user.id,
        path=final_path,
        size=get_linecount(final_path),
        checksum=get_filehash(final_path)
    )
    db.session.add(rule)
    db.session.commit()

    log_event('rule.create', actor=(user.email_address, user.id),
              target=f'rule:{rule.id} {rule.name!r}')
    message = {
        'status': 200,
        'type': 'message',
        'msg': 'Rule added',
        'rule_id': rule.id
    }
    return jsonify(message)

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
    if wordlist is None:
        return jsonify({'status': 404, 'type': 'Error', 'msg': 'Wordlist not found'}), 404

    wordlists_dir = os.path.join(current_app.root_path, 'control/wordlists')
    tmp_dir = os.path.join(current_app.root_path, 'control/tmp')
    wordlist_name = wordlist.path.split('/')[-1]

    if wordlist.type == 'static':
        # Stored compressed at rest: serve the .gz directly. The stored bytes
        # are stable, so the agent's sha256(.gz) matches the DB checksum.
        return send_from_directory(wordlists_dir, wordlist_name, mimetype='application/octet-stream')

    # Dynamic wordlists stay uncompressed on the server (regenerated from the
    # DB via /v1/updateWordlist). Compress the current .txt into control/tmp
    # and serve that. No shell; pure-Python streamed gzip -9.
    tmp_gz = os.path.join(tmp_dir, secrets.token_hex(8) + '.gz')
    compress_to_gz(wordlist.path, tmp_gz, 9)
    return send_from_directory(tmp_dir, os.path.basename(tmp_gz), mimetype='application/octet-stream')

# Update Dynamic Wordlist
@api.route('/v1/updateWordlist/<int:wordlist_id>', methods=['GET'])
def v1_api_get_update_wordlist(wordlist_id):
    if not is_authorized(user=True, agent=True, request=request):
        return redirect("/v1/not_authorized")

    update_heartbeat(request.cookies.get('uuid'))

    # Resolve the job this agent is currently running so crawl-based dynamic
    # wordlists (Website Keywords) can read the per-job target URL. The
    # heartbeat assigns the dispatched JobTask agent_id + 'Running' before the
    # agent calls this, so the most-recent Running task for the agent is it.
    job_id = None
    agent = Agents.query.filter_by(uuid=request.cookies.get('uuid')).first()
    if agent:
        running = JobTasks.query.filter_by(agent_id=agent.id, status='Running') \
                                .order_by(JobTasks.id.desc()).first()
        if running:
            job_id = running.job_id

    update_dynamic_wordlist(wordlist_id, job_id)
    message = {
        'status': 200,
        'type': 'message',
        'msg': 'OK'
    }
    return jsonify(message)

# Create new wordlist
@api.route('/v1/wordlists/add/<wordlist_name>', methods=['POST'])
def v1_api_add_wordlist(wordlist_name):
    # Authorization check. This is a user-upload action — it resolves the
    # caller to a Users row by api_key — so it's user-only. The agent never
    # POSTs here (it only GETs wordlists / updateWordlist), so requiring a user
    # credential refuses agent uuids cleanly instead of letting them through to
    # a "User not found" 403.
    if not is_authorized(user=True, agent=False, request=request):
        return redirect("/v1/not_authorized")

    # Read the body as BYTES (not as_text) so an uploaded gzip wordlist isn't
    # corrupted by text decoding. The body may be plain text or a gzip file.
    raw_content = request.get_data()
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

    # Write the raw body to a control/tmp temp, then ingest it into
    # compressed-at-rest storage (handles plain text or gzip; validates gzip).
    tmp_path = os.path.abspath(os.path.join(current_app.root_path, 'control/tmp', secrets.token_hex(8)))
    try:
        with open(tmp_path, 'wb') as f:
            f.write(raw_content)
        wordlist_entry = ingest_static_wordlist_file(tmp_path, user.id, wordlist_name)
    except Exception as e:
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': f'Failed to process wordlist (not valid text or gzip?): {e}'
        })
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

    db.session.add(wordlist_entry)
    db.session.commit()

    log_event('wordlist.create', actor=(user.email_address, user.id),
              target=f'wordlist:{wordlist_entry.id} {wordlist_entry.name!r}')
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

# Delete a job
@api.route('/v1/jobs/<int:job_id>', methods=['DELETE'])
def v1_api_delete_job(job_id):
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

    job = Jobs.query.get(job_id)
    if job is None:
        return jsonify({'status': 404, 'type': 'Error', 'msg': 'Job not found'}), 404

    if not (user.admin or job.owner_id == user.id):
        return jsonify({
            'status': 403,
            'type': 'Error',
            'msg': 'You do not have rights to delete this job'
        })

    # Mirror the web UI's jobs_delete cleanup: jobtasks and job notifications
    # go with the job. Like the web UI, this deliberately has no status guard —
    # a Queued/Running job can be deleted too.
    job_target = f'job:{job.id} {job.name!r}'
    try:
        JobTasks.query.filter_by(job_id=job_id).delete()
        JobNotifications.query.filter_by(job_id=job_id).delete()
        db.session.delete(job)
        db.session.commit()
    except Exception as e:
        return jsonify({
            'status': 500,
            'type': 'Error',
            'msg': f'Failed to delete job: {e}'
        })

    log_event('job.delete', actor=(user.email_address, user.id), target=job_target)
    message = {
        'status': 200,
        'type': 'message',
        'msg': 'Job deleted',
        'job_id': job_id
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
                'msg': 'Not enough data to determine effective tasks for this hash type. Please add more cracked hashes of this type before creating a job.'
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
        # same way. (The old code passed notify_email/notify_pushover kwargs
        # that don't exist on JobNotifications and omitted the required
        # owner_id, so every jobs/add 500'd here after committing the job.)
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

        log_event('job.create', actor=(user.email_address, user.id),
                  target=f'job:{job_entry.id} {job_entry.name!r}')
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
            job.queued_at = datetime.now()
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

# Create a new task (Wordlist + optional rule, i.e. hashcat attack mode 0)
@api.route('/v1/tasks/add', methods=['POST'])
def v1_api_add_task():
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

    # Expect JSON body: {"name": ..., "wl_id": ..., "rule_id": <optional>}
    task_data = request.get_json(silent=True)
    if not task_data:
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': 'Missing task data in request body'
        })

    name = str(task_data.get('name') or '').strip()
    if not name:
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': 'Task name is required'
        })
    if Tasks.query.filter_by(name=name).first():
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': 'A task with that name already exists'
        })

    wl_id = task_data.get('wl_id')
    if wl_id is None or not str(wl_id).isdigit():
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': 'wl_id is required and must be a wordlist id'
        })
    if not Wordlists.query.get(int(wl_id)):
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': 'Invalid wl_id'
        })

    # rule_id is optional: absent/'None'/'' means a plain dictionary attack
    # (same as the web UI's 'None' rule choice).
    rule_id = task_data.get('rule_id')
    if rule_id in (None, 'None', ''):
        rule_id = None
    else:
        if not str(rule_id).isdigit():
            return jsonify({
                'status': 400,
                'type': 'Error',
                'msg': 'rule_id must be a rule id'
            })
        rule_id = int(rule_id)
        if not Rules.query.get(rule_id):
            return jsonify({
                'status': 400,
                'type': 'Error',
                'msg': 'Invalid rule_id'
            })

    try:
        task = Tasks(
            name=name,
            owner_id=user.id,
            wl_id=int(wl_id),
            rule_id=rule_id,
            hc_attackmode=0
        )
        db.session.add(task)
        db.session.commit()
    except Exception as e:
        return jsonify({
            'status': 500,
            'type': 'Error',
            'msg': f'Failed to add task: {e}'
        })

    log_event('task.create', actor=(user.email_address, user.id),
              target=f'task:{task.id} {task.name!r}')
    message = {
        'status': 200,
        'type': 'message',
        'msg': 'Task added',
        'task_id': task.id
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
                    'msg': 'Something went wrong. Check the filetype / hashtype and try again.'
                })                  

            hashfile_hashes_cnt = db.session.query(HashfileHashes).filter_by(hashfile_id=hashfile.id).count()
            if hashfile_hashes_cnt == 0:
                db.session.delete(hashfile)
                db.session.commit()
                return jsonify({
                    'status': 500,
                    'type': 'Error',
                    'msg': 'No valid hashes found in the hashfile. Hashfile not added.'
                })   

            cracked_hashfiles_hashes_cnt = db.session.query(Hashes).join(HashfileHashes, Hashes.id == HashfileHashes.hash_id).filter(Hashes.cracked == '1').filter(HashfileHashes.hashfile_id==hashfile.id).count()

            log_event('hashfile.create', actor=(user.email_address, user.id),
                      target=f'hashfile:{hashfile.id} {hashfile.name!r}',
                      detail=f'hashes={hashfile_hashes_cnt} instacracked={cracked_hashfiles_hashes_cnt}')
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

# List hashfiles containing at least one hash of the given hash type.
# No collision with /v1/hashfiles/<int:hashfile_id>: the static 'hash_type/'
# segment wins over the int converter in Flask routing.
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
            elements = entry.split(':')
            # Remove cracked hash
            elements.pop()
            ciphertext = ':'.join(elements)

            #print('Plaintext: ' + str(bytes.fromhex(plaintext).decode('latin-1')))
            #print('Ciphertext: ' + str(ciphertext))

            record = Hashes.query.filter_by(hash_type=hash_type, sub_ciphertext=get_md5_hash(ciphertext), cracked='0').first()
            if record:
                try:
                    record.plaintext = hexplain_to_text(encoded_plaintext)
                    record.cracked = 1
                    #print('i should be updating the datetime')
                    record.recovered_at = datetime.today()
                    record.task_id = task_id
                    db.session.commit()
                except Exception as error:
                    print('Failed to import following cracked hash: ' + str(encoded_plaintext))
                    print('Reason: ' + str(error))

    # Send per-hash "recovered" notifications (email/push/slack) for any now-cracked watched hash.
    process_recovered_hash_notifications()

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
                    record.plaintext = hexplain_to_text(encoded_plaintext)
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

    # Send per-hash "recovered" notifications (email/push/slack) for any now-cracked watched hash.
    process_recovered_hash_notifications()

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
        # job.ended_at = datetime.now()
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
                    'plaintext': cracked_hash.plaintext
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
    if not agent:
        # is_authorized() already confirmed an agent credential; this guards the
        # narrow race where the agent row is removed between the auth check and
        # this lookup, so we never dereference None on agent.name.
        return redirect("/v1/not_authorized")
    message_json = request.get_json(silent=True) or {}

    subject = 'Error on ' + str(agent.name)
    message_body = message_json.get('error')

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
    # Hashtype'). Compare as int so NTLM import actually runs.
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
            with open(file_path, encoding='utf-8', errors='surrogateescape') as f:
                for line in f:
                    line = line.rstrip('\r\n')
                    parts = line.split(':')
                    ciphertext = parts[0]
                    # everything after the first ':' is the plaintext (it may itself contain ':')
                    plaintext = ':'.join(parts[1:])

                    # encipher plaintext and compare cipher text (NTLM = MD4(UTF-16LE(pw)));
                    # ntlm_hash_hex falls back to pure-Python MD4 where OpenSSL 3.x
                    # no longer provides md4.
                    if ciphertext == ntlm_hash_hex(plaintext):
                        # valid hash:plaintext
                        record = Hashes.query.filter_by(hash_type=hash_type, sub_ciphertext=get_md5_hash(ciphertext), cracked='0').first()
                        if record:
                            try:
                                record.plaintext = text_from_field(plaintext)
                                record.cracked = 1
                                record.recovered_at = datetime.today()
                                record.recovered_by = user.id
                                db.session.commit()
                            except Exception as error:
                                return jsonify({
                                    'status': 500,
                                    'type': 'Error',
                                    'msg': f'Failed to import following cracked hash {str(ciphertext)}: {str(error)}'
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

        # Send per-hash "recovered" notifications (email/push/slack) for any now-cracked watched hash.
        process_recovered_hash_notifications()

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

@api.route('/v1/hashfiles/upload/wpa_pcap/<int:customer_id>/<hashfile_name>', methods=['POST'])
def v1_api_post_wpa_pcap_upload(customer_id, hashfile_name):
    if not is_authorized(user=True, agent=False, request=request):
        return redirect("/v1/not_authorized")

    customer = Customers.query.get(customer_id)
    if not customer:
        return jsonify({'status': 400, 'type': 'Error', 'msg': 'Invalid customer ID'})

    user = Users.query.filter_by(api_key=request.cookies.get('uuid')).first()

    raw_content = request.get_data()
    if not raw_content:
        return jsonify({'status': 400, 'type': 'Error', 'msg': 'Missing capture file content in request body'})

    file_path = os.path.abspath(os.path.join(
        current_app.root_path, 'control/tmp', secrets.token_hex(8) + '.pcapng'
    ))
    try:
        with open(file_path, 'wb') as f:
            f.write(raw_content)
    except Exception as e:
        return jsonify({'status': 500, 'type': 'Error', 'msg': f'Failed to save capture file: {e}'})

    hashfile = Hashfiles(name=hashfile_name, customer_id=customer_id, owner_id=user.id)
    db.session.add(hashfile)
    db.session.commit()

    conv = HashfileConversions(
        hashfile_id=hashfile.id,
        source_type='wpa_pcap',
        status='pending',
        source_path=file_path,
    )
    db.session.add(conv)
    db.session.commit()

    log_event('hashfile.create', actor=(user.email_address, user.id),
              target=f'hashfile:{hashfile.id} {hashfile.name!r}',
              detail='source_type=wpa_pcap status=pending')

    return jsonify({
        'status': 200,
        'type': 'message',
        'msg': 'Capture uploaded. Conversion queued.',
        'hashfile_id': hashfile.id,
        'conversion_id': conv.id,
    })

@api.route('/v1/hashfiles/<int:hashfile_id>/conversion', methods=['GET'])
def v1_api_get_conversion_status(hashfile_id):
    if not is_authorized(user=True, agent=False, request=request):
        return redirect("/v1/not_authorized")

    hashfile = Hashfiles.query.get(hashfile_id)
    if not hashfile:
        return jsonify({'status': 404, 'type': 'Error', 'msg': 'Hashfile not found'})

    conv = HashfileConversions.query.filter_by(hashfile_id=hashfile_id).first()
    if not conv:
        return jsonify({'status': 404, 'type': 'Error', 'msg': 'No conversion record for this hashfile'})

    return jsonify({
        'status': 200,
        'type': 'message',
        'hashfile_id': hashfile_id,
        'conversion_id': conv.id,
        'source_type': conv.source_type,
        'conversion_status': conv.status,
        'conversion_error': conv.conversion_error,
    })