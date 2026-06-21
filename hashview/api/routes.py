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
    AgentBenchmarks,
    Agents,
    Customers,
    Hashes,
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
    build_job_task_commands,
    compress_to_gz,
    decompress_gz,
    get_filehash,
    get_linecount,
    get_md5_hash,
    hashtypes_in_use,
    hexplain_to_text,
    import_hashfilehashes,
    ingest_static_wordlist_file,
    is_gzip,
    notify_admins,
    ntlm_hash_hex,
    process_recovered_hash_notifications,
    rechunk_queued_tasks_for_hashtype,
    slowest_benchmark,
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


def _remove_file(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    except OSError as error:
        # Don't fail the request, but surface the problem so an admin can
        # troubleshoot temp files stacking up in control/tmp (see issue #226).
        current_app.logger.warning(
            'Failed to remove temporary file %s: %s', path, error)


def _send_generated_file(directory, filename, **kwargs):
    file_path = os.path.join(directory, filename)
    response = send_from_directory(directory, filename, **kwargs)
    response.call_on_close(lambda: _remove_file(file_path))
    return response


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
        # The version gate applies to KNOWN agents (they're about to sync/work).
        # A brand-new agent is registered as Pending above regardless of version,
        # so a freshly stood-up (or behind) agent always lands in the agents table
        # for an admin to approve instead of being turned away before it's ever
        # recorded (which left it invisible — not even a DB row).
        if not versionCheck(request.cookies.get('agent_version')):
            update_heartbeat(uuid)
            return redirect("/v1/upgrade_required")
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
            # silent=True so an empty/invalid body returns None (-> JSON error) instead
            # of Flask's HTML 400 page, which the agent can't parse (#212).
            agent_data = request.get_json(silent=True)
            if not agent_data:
                return jsonify({
                    'status': 400,
                    'type': 'Error',
                    'msg': 'Missing heartbeat data in request body'
                })
            if 'agent_status' not in agent_data:
                return jsonify({
                    'status': 400,
                    'type': 'Error',
                    'msg': "Missing 'agent_status' in heartbeat data"
                })

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
                    # hc_status is hashcat's status dict as rendered by the agent
                    # (Python repr, single quotes). Parse it DEFENSIVELY: an agent
                    # whose hashcat outlived a restart sends a non-JSON placeholder,
                    # and a partial/mid-reboot status can be malformed. A bad value
                    # must never 500 the heartbeat -- just skip the telemetry update
                    # so the agent keeps its assigned work and retries next beat.
                    raw = str(agent_data['hc_status']).replace("\'", "\"")
                    try:
                        json_response = json.loads(raw)
                        agent.hc_status = raw
                        agent.benchmark = json_response['Speed #']
                        # Persist device telemetry. Unlike hc_status (cleared on idle),
                        # these are RETAINED so the agents page can show a card's
                        # model/count/temps even when the agent isn't currently cracking.
                        if json_response.get('GPU_Count') is not None:
                            agent.gpu_count = json_response['GPU_Count']
                        if json_response.get('GPU_Model'):
                            agent.gpu_model = json_response['GPU_Model']
                        if json_response.get('Temps'):
                            agent.gpu_temps = json_response['Temps']
                    except (ValueError, KeyError, TypeError):
                        current_app.logger.warning(
                            'Heartbeat from agent %s had unparseable hc_status; '
                            'skipping telemetry update.', uuid)

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

                # Benchmark-first: chunk sizing needs a per-hashtype benchmark from
                # every agent. If this agent is missing one for any hash type
                # currently in use, have it benchmark those BEFORE taking crack work
                # (results come back via POST /v1/agents/benchmark). New hash types
                # introduced later are picked up automatically here.
                have = {b.hash_type for b in
                        AgentBenchmarks.query.filter_by(agent_id=agent.id).all()}
                missing = sorted(hashtypes_in_use() - have)
                if missing:
                    update_heartbeat(uuid)
                    message = {
                        'status': 200,
                        'type': 'message',
                        'msg': 'BENCHMARK',
                        'hash_modes': missing,
                    }
                    return jsonify(message)

                # Get the next Queued chunk and 'assign' it to this agent. Order so
                # ALL chunks of a task are exhausted before the next task starts: by
                # priority, then the task's first (lowest) JobTask id — chunk 1 reuses
                # the original row's low id, so min(id) per (job, task) is the job's
                # task order — then chunk number within the task. Ordering by raw id
                # alone interleaves tasks (every task's chunk 1, then the chunk 2s, …)
                # because chunks 2..N are created later and get higher ids.
                task_first = (db.session.query(
                                  JobTasks.job_id.label('job_id'),
                                  JobTasks.task_id.label('task_id'),
                                  func.min(JobTasks.id).label('first_id'))
                              .group_by(JobTasks.job_id, JobTasks.task_id)
                              .subquery())
                job_task_entry = (db.session.query(JobTasks)
                                  .join(task_first,
                                        (JobTasks.job_id == task_first.c.job_id)
                                        & (JobTasks.task_id == task_first.c.task_id))
                                  .filter(JobTasks.status == 'Queued')
                                  .order_by(JobTasks.priority.desc(),
                                            task_first.c.first_id.asc(),
                                            JobTasks.chunk_no.asc(),
                                            JobTasks.id.asc())
                                  .first())
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

@api.route('/v1/agents/benchmark', methods=['POST'])
def v1_api_post_agent_benchmark():
    # Agent reports hashcat benchmark speeds (raw H/s) per hash mode. Upsert one
    # row per (agent, hash_type); re-running a benchmark overwrites the old value.
    if not is_authorized(user=False, agent=True, request=request):
        return redirect("/v1/not_authorized")

    update_heartbeat(request.cookies.get('uuid'))
    agent = Agents.query.filter_by(uuid=request.cookies.get('uuid')).first()

    data = request.get_json(silent=True)
    if not data or 'benchmark_results' not in data:
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': 'Missing benchmark_results in request body'
        })

    results = data['benchmark_results'] or {}
    # Hash types with no usable benchmark BEFORE this report. If this report gives
    # one its first usable speed, queued whole tasks of that type can now be split
    # (jobs queued for a brand-new type while every agent was busy ran un-chunked).
    pending = set()
    for mode in results:
        try:
            m = int(mode)
        except (TypeError, ValueError):
            continue
        if not slowest_benchmark(m):
            pending.add(m)

    for mode, speed in results.items():
        try:
            mode_i = int(mode)
            speed_i = int(float(speed))
        except (TypeError, ValueError):
            continue  # skip an unparseable entry rather than failing the batch
        row = AgentBenchmarks.query.filter_by(agent_id=agent.id, hash_type=mode_i).first()
        if row:
            row.speed = speed_i
            row.updated_at = datetime.now()
        else:
            db.session.add(AgentBenchmarks(
                agent_id=agent.id, hash_type=mode_i, speed=speed_i,
                updated_at=datetime.now()))
    db.session.commit()

    # Now that benchmarks for these types may exist, re-plan any still-queued whole
    # tasks of theirs into chunks (no-op if the type is still unusable / nothing queued).
    for m in pending:
        rechunk_queued_tasks_for_hashtype(m)

    return jsonify({'status': 200, 'type': 'message', 'msg': 'OK'})

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
    except Exception:
        current_app.logger.exception('API /v1/customers: failed to add customer')
        return jsonify({
            'status': 500,
            'type': 'Error',
            'msg': 'Failed to add customer.'
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
    return _send_generated_file(
        tmp_dir, os.path.basename(tmp_gz), mimetype='application/octet-stream')

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
    except Exception:
        current_app.logger.exception('API /v1/rules: failed to process rule')
        if os.path.exists(final_path):
            os.remove(final_path)
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': 'Failed to process rule (not valid text or gzip?).'
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
    return _send_generated_file(
        tmp_dir, os.path.basename(tmp_gz), mimetype='application/octet-stream')

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
    except Exception:
        current_app.logger.exception('API /v1/wordlists: failed to process wordlist')
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': 'Failed to process wordlist (not valid text or gzip?).'
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
    except Exception:
        current_app.logger.exception('API /v1/jobs: failed to delete job')
        return jsonify({
            'status': 500,
            'type': 'Error',
            'msg': 'Failed to delete job.'
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
    
    # Expect JSON body. silent=True so an empty/invalid body returns None (-> the JSON
    # 400 below) instead of Flask's HTML 400 page, which JSON clients can't parse (#212).
    job_data = request.get_json(silent=True)
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
            .filter(Hashes.task_id.isnot(None)) \
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
    except Exception:
        current_app.logger.exception('API /v1/jobs: failed to add job')
        return jsonify({
            'status': 500,
            'type': 'Error',
            'msg': 'Failed to add job.'
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
        if job.status in ('Running', 'Queued'):
            return jsonify({
                'status': 400,
                'type': 'Error',
                'msg': 'Job is already running or queued'
            })        
        if current_user.admin or job.owner_id == current_user.id:
            job.status = 'Queued'
            job.queued_at = datetime.now()
            build_job_task_commands(job)

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
    except Exception:
        current_app.logger.exception('API /v1/tasks: failed to add task')
        return jsonify({
            'status': 500,
            'type': 'Error',
            'msg': 'Failed to add task.'
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
    except Exception:
        current_app.logger.exception('API: failed to write hashfile')
        return jsonify({
            'status': 500,
            'type': 'Error',
            'msg': 'Failed to write hashfile.'
        })

    # import contents from file
    try:
        current_app.logger.debug('API: validating hashfile %s of format %s for hashtype %s',
                                 file_path, file_format, hash_type)
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

    except Exception:
        current_app.logger.exception('API: hash import failed')
        return jsonify({
            'status': 500,
            'type': 'Error',
            'msg': 'Hash import Failed.'
        })

# generate and serve hashfile
@api.route('/v1/hashfiles/<int:hashfile_id>', methods=['GET'])
def v1_api_get_hashfile(hashfile_id):
    if not is_authorized(user=True, agent=True, request=request):
        return redirect("/v1/not_authorized")

    update_heartbeat(request.cookies.get('uuid'))
    random_hex = secrets.token_hex(8)
    # Build the path from current_app.root_path (like the sibling routes) so it does
    # not depend on the current working directory (issue #227).
    tmp_dir = os.path.join(current_app.root_path, 'control/tmp')
    file_path = os.path.join(tmp_dir, random_hex)

    # Left join to get the uncracked ciphertext hashes. Stream rows with yield_per and
    # a context manager so a large hashfile isn't fully materialized in memory.
    dbresults = db.session.query(Hashes, HashfileHashes) \
        .outerjoin(HashfileHashes, Hashes.id == HashfileHashes.hash_id) \
        .filter(Hashes.cracked == '0') \
        .filter(HashfileHashes.hashfile_id == hashfile_id) \
        .yield_per(1000)
    with open(file_path, 'w') as file_object:
        for result in dbresults:
            file_object.write(result[0].ciphertext + '\n')

    return _send_generated_file(tmp_dir, random_hex)

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
    # silent=True so an empty/invalid body returns None (-> JSON error) instead of
    # Flask's HTML 400 page, which the agent can't parse (#212).
    file_contents = request.get_json(silent=True)
    if not file_contents or 'file' not in file_contents:
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': 'Missing file data in request body'
        })

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
                    current_app.logger.debug('API: no record found for partial hash %s', partial_hash)
            else:
                record = Hashes.query.filter_by(hash_type=hash_type, sub_ciphertext=get_md5_hash(ciphertext), cracked='0').first()
            if record:
                try:
                    record.plaintext = hexplain_to_text(encoded_plaintext)
                    record.cracked = 1
                    record.recovered_at = datetime.today()
                    record.task_id = job_task.task_id
                    record.recovered_by = job.owner_id
                    db.session.commit()
                    recovered_at_least_one_hash = True

                except Exception:
                    current_app.logger.exception('API: failed to import a cracked hash during agent heartbeat')

    # Send per-hash "recovered" notifications (email/push/slack) for any now-cracked watched hash.
    process_recovered_hash_notifications()

    # Check if job type is one and done
    if job.limit_recovered and recovered_at_least_one_hash:

        # cancel all running and queued job tasks
        jobtasks = JobTasks.query.filter_by(job_id=job.id)
        for jobtask in jobtasks:
            update_job_task_status( jobtask_id = jobtask.id,
                                    status = 'Canceled')

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

    # silent=True so an empty/invalid body returns None (-> JSON error) instead of
    # Flask's HTML 400 page, which the agent can't parse (#212).
    status_json = request.get_json(silent=True)
    if not status_json or 'job_task_id' not in status_json or 'task_status' not in status_json:
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': 'Missing job task status data in request body'
        })

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
    
    # silent=True: an empty/invalid body returns None (-> JSON "Invalid Search")
    # rather than Flask's HTML 400 page (issue #213).
    search_json = request.get_json(silent=True)
    if not search_json:
        return jsonify({'status': 500, 'type': 'message', 'msg': 'Invalid Search'})

    not_found = {'status': 200, 'type': 'message', 'msg': 'Search complete. No Results Found.'}

    # Provide exactly one of hash / plaintext / username (checked in that order).

    # By exact ciphertext -> the single recovered hash (back-compatible object shape).
    if search_json.get('hash'):
        ciphertext = search_json['hash']
        cracked_hash = Hashes.query.filter_by(cracked=True, ciphertext=ciphertext).first()
        if not cracked_hash:
            return jsonify(not_found)
        return jsonify({'status': 200, 'type': 'message', 'msg': {
            'hash_type': cracked_hash.hash_type,
            'hash': ciphertext,
            'plaintext': cracked_hash.plaintext,
        }})

    # By recovered plaintext -> every cracked hash with that plaintext (a list).
    if search_json.get('plaintext'):
        matches = Hashes.query.filter_by(cracked=True, plaintext=search_json['plaintext']).all()
        if not matches:
            return jsonify(not_found)
        return jsonify({'status': 200, 'type': 'message', 'msg': [
            {'hash_type': h.hash_type, 'hash': h.ciphertext, 'plaintext': h.plaintext}
            for h in matches
        ]})

    # By username -> the associated hash(es), with plaintext when recovered (a list).
    if search_json.get('username'):
        username = search_json['username']
        rows = (db.session.query(Hashes)
                .join(HashfileHashes, Hashes.id == HashfileHashes.hash_id)
                .filter(HashfileHashes.username == username)
                .all())
        seen = set()
        results = []
        for h in rows:
            if h.id in seen:  # a username can map to the same hash across hashfiles
                continue
            seen.add(h.id)
            results.append({
                'username': username,
                'hash_type': h.hash_type,
                'hash': h.ciphertext,
                'plaintext': h.plaintext if h.cracked else None,
            })
        if not results:
            return jsonify(not_found)
        return jsonify({'status': 200, 'type': 'message', 'msg': results})

    return jsonify({'status': 500, 'type': 'message', 'msg': 'Invalid Search'})

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
        except Exception:
            current_app.logger.exception('API: failed to write file')
            return jsonify({
                'status': 500,
                'type': 'Error',
                'msg': 'Failed to write file.'
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
                            except Exception:
                                current_app.logger.exception('API: failed to import cracked hash %s', ciphertext)
                                return jsonify({
                                    'status': 500,
                                    'type': 'Error',
                                    'msg': 'Failed to import cracked hash.'
                                })  
                    else:
                        return jsonify({
                            'status': 500,
                            'type': 'Error',
                            'msg': f'Plaintext for hash {ciphertext}, was found to be invalid.'
                        })
        except Exception:
            current_app.logger.exception('API: failed to open/parse uploaded file')
            return jsonify({
                'status': 500,
                'type': 'Error',
                'msg': 'Failed to open file.'
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
