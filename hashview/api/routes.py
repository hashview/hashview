import json
import os
import secrets
from datetime import datetime, timedelta

from flask import (
    current_app,
    jsonify,
    redirect,
    request,
    send_from_directory,
)
from sqlalchemy import case, exists, func
from sqlalchemy.exc import IntegrityError

# The blueprint and the shared helpers now live in hashview/api/_shared.py
# (issue #441). They are imported INTO this module's namespace rather than used
# through it, so every reference here -- and every test that monkeypatches e.g.
# hashview.api.routes.is_authorized -- keeps resolving exactly as before.
from hashview.api._shared import (  # noqa: F401
    _ENCODER_DENYLIST,
    AlchemyEncoder,
    _error,
    agentAuthorized,
    alchemy_to_native,
    api,
    is_authorized,
    update_heartbeat,
    userAuthorized,
    versionCheck,
)
from hashview.models import (
    AgentBenchmarks,
    Agents,
    Customers,
    Hashes,
    HashfileHashes,
    Hashfiles,
    HashNotifications,
    JobNotifications,
    Jobs,
    JobTasks,
    Rules,
    Settings,
    TaskGroups,
    Tasks,
    Users,
    Wordlists,
    db,
)
from hashview.utils.audit import log_event
from hashview.utils.utils import (
    MAX_TASKS_PER_GROUP,
    _job_hash_type,
    build_job_task_commands,
    compress_to_gz,
    dynamic_wordlist_ids,
    get_cracked_hash_verifier,
    get_md5_hash,
    hashfile_hash_type,
    hashtypes_in_use,
    hexplain_to_text,
    import_hashfilehashes,
    ingest_static_wordlist_file,
    notify_admins,
    process_recovered_hash_notifications,
    rechunk_queued_tasks_for_hashtype,
    remove_file,
    send_generated_file,
    slowest_benchmark,
    task_uses_dynamic_wordlist,
    text_from_field,
    top_effective_task_ids,
    update_dynamic_wordlist,
    update_job_task_status,
    validate_hash_only_hashfile,
    validate_kerberos_hashfile,
    validate_netntlm_hashfile,
    validate_pwdump_hashfile,
    validate_shadow_hashfile,
    validate_user_hash_hashfile,
)


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
        'settings': alchemy_to_native(settings)
    }
    return jsonify(message)

# Active chunk statuses -- work that is in flight or still pending for a task.
_ACTIVE_JOBTASK_STATUSES = ('Running', 'Queued', 'Not Started', 'Importing')


def _parent_task_started_at(job_id, task_id):
    """Earliest started_at across all chunks of a (job, task) group -- i.e. when
    the parent task first began processing. None if nothing has started yet.

    A task can fan out into many chunks that run in parallel on different agents,
    so the per-chunk started_at can't bound the task's total runtime; the group's
    MIN(started_at) is the real start. A whole, un-chunked task is just a group of
    one, so this returns its own started_at."""
    return (db.session.query(func.min(JobTasks.started_at))
            .filter(JobTasks.job_id == job_id,
                    JobTasks.task_id == task_id,
                    JobTasks.started_at.isnot(None))
            .scalar())


def _task_runtime_exceeded(job_id, task_id, max_hours):
    """True if the parent task has been running longer than max_hours (wall-clock
    from the earliest chunk start). 0/None disables the cap."""
    if not max_hours or max_hours <= 0:
        return False
    started = _parent_task_started_at(job_id, task_id)
    return started is not None and started + timedelta(hours=max_hours) < datetime.now()


def _cancel_task_group(job_id, task_id):
    """Cancel every still-active chunk of a (job, task) group (see
    _ACTIVE_JOBTASK_STATUSES), so an over-limit task stops entirely and no
    further chunk of it gets dispatched."""
    current_app.logger.info(
        'Job %s task %s exceeded max_runtime_tasks; cancelling its active chunks.',
        job_id, task_id)
    for jt in JobTasks.query.filter_by(job_id=job_id, task_id=task_id).all():
        if jt.status in _ACTIVE_JOBTASK_STATUSES:
            update_job_task_status(jt.id, 'Canceled')


def _hashfile_has_uncracked(hashfile_id):
    """True if the hashfile still has at least one uncracked hash left to solve."""
    return (db.session.query(HashfileHashes.id)
            .join(Hashes, Hashes.id == HashfileHashes.hash_id)
            .filter(HashfileHashes.hashfile_id == hashfile_id, Hashes.cracked == 0)
            .first() is not None)


def _cancel_job_active_tasks(job_id):
    """Cancel every still-active task/chunk of a job. Used when the whole hashfile
    is recovered (nothing left to crack) or for one-and-done jobs -- running the
    rest would just burn cycles on an already-solved hashfile. Cancelling the last
    active task lets update_job_task_status roll the job up to Completed."""
    for jt in JobTasks.query.filter_by(job_id=job_id).all():
        if jt.status in _ACTIVE_JOBTASK_STATUSES:
            update_job_task_status(jt.id, 'Canceled')


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

                # Enforce max_runtime_tasks on the PARENT task, not each chunk.
                # Chunks run in parallel, so summing their runtimes overcounts;
                # measure from the earliest chunk start of this (job, task) group
                # and, when over the cap, cancel the whole group's still-active
                # chunks. A whole, un-chunked task is a group of one, so it's still
                # capped exactly as before.
                if _task_runtime_exceeded(job_task.job_id, job_task.task_id,
                                          settings.max_runtime_tasks):
                    _cancel_task_group(job_task.job_id, job_task.task_id)
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
                    # hc_status is hashcat's status dict rendered by the agent (Python
                    # repr -> JSON). Only json.loads is in the try: a malformed value
                    # (e.g. a non-JSON placeholder from an agent whose hashcat outlived
                    # a restart) must never 500 the heartbeat -- log and skip telemetry.
                    # Missing keys are tolerated via .get below.
                    raw = str(agent_data['hc_status']).replace("\'", "\"")
                    try:
                        json_response = json.loads(raw)
                    except (ValueError, TypeError):
                        current_app.logger.warning(
                            'Heartbeat from agent %s had unparseable hc_status; '
                            'skipping telemetry update.', uuid)
                    else:
                        agent.hc_status = raw
                        if json_response.get('Speed #') is not None:
                            agent.benchmark = json_response['Speed #']
                        # Device telemetry: RETAINED across idle so the agents page can
                        # show a card's model/count/temps even when not cracking.
                        if json_response.get('GPU_Count') is not None:
                            agent.gpu_count = json_response['GPU_Count']
                        if json_response.get('GPU_Model'):
                            agent.gpu_model = json_response['GPU_Model']
                        if json_response.get('Temps'):
                            agent.gpu_temps = json_response['Temps']

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
                # Don't dispatch this agent a task whose hash type it has already
                # reported unsupported (speed 0) -- it would just re-report 0 and
                # waste the chunk slot. Walk the ordered candidates and skip those.
                unsupported = {b.hash_type for b in
                               AgentBenchmarks.query.filter_by(agent_id=agent.id, speed=0).all()}
                job_task_entry = None
                for candidate in (db.session.query(JobTasks)
                                  .join(task_first,
                                        (JobTasks.job_id == task_first.c.job_id)
                                        & (JobTasks.task_id == task_first.c.task_id))
                                  .filter(JobTasks.status == 'Queued')
                                  .order_by(JobTasks.priority.desc(),
                                            task_first.c.first_id.asc(),
                                            JobTasks.chunk_no.asc(),
                                            JobTasks.id.asc())):
                    cand_job = Jobs.query.get(candidate.job_id)
                    if unsupported and cand_job is not None and _job_hash_type(cand_job) in unsupported:
                        continue
                    job_task_entry = candidate
                    break
                if job_task_entry:
                    # Don't start a fresh chunk of a task that's already over its
                    # runtime cap. This closes the gap where, at the cap moment, no
                    # chunk happened to be running (all just completed, only queued
                    # left), so the Working-heartbeat check couldn't fire. Cancel the
                    # whole group and let the next beat pick a different task.
                    if _task_runtime_exceeded(job_task_entry.job_id,
                                              job_task_entry.task_id,
                                              settings.max_runtime_tasks):
                        _cancel_task_group(job_task_entry.job_id, job_task_entry.task_id)
                        update_heartbeat(uuid)
                        message = {
                            'status': 200,
                            'type': 'message',
                            'msg': 'OK'
                        }
                        return jsonify(message)
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
            s = int(float(results[mode]))
        except (TypeError, ValueError):
            current_app.logger.debug(
                'Agent %s benchmark pre-scan: unparseable entry %r=%r; skipping.',
                agent.id, mode, results[mode])
            continue
        if s > 0 and not slowest_benchmark(m):
            pending.add(m)

    for mode, speed in results.items():
        try:
            mode_i = int(mode)
            speed_i = int(float(speed))
        except (TypeError, ValueError):
            # skip an unparseable entry rather than failing the batch, but leave a
            # trace so a misbehaving agent is diagnosable
            current_app.logger.warning(
                'Agent %s sent an unparseable benchmark entry %r=%r; skipping.',
                agent.id, mode, speed)
            continue
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


@api.route('/v1/agents/benchmark', methods=['GET'])
def v1_api_get_agent_benchmarks():
    # Expose already-stored per-(agent, hash type) benchmarks as rig performance.
    # Aggregated per hash type to the SLOWEST agent's speed, matching how chunk
    # sizing works (slowest_benchmark). Read-only; touches no agent code.
    #
    # Consumers are humans/dashboards, not agents: an agent has no use for the
    # fleet-wide view, so agent keys are rejected and no heartbeat is recorded
    # (a heartbeat would misreport this caller as a live agent).
    if not is_authorized(user=True, agent=False, request=request):
        return redirect("/v1/not_authorized")

    hash_type = request.args.get('hash_type', type=int)
    if hash_type is not None:
        speed = slowest_benchmark(hash_type)
        if speed is None:
            # No agent has benchmarked this type yet — distinguish "unknown"
            # from a real speed instead of returning a null the caller has to
            # special-case.
            return jsonify({'status': 404, 'type': 'Error',
                            'msg': f'No benchmark recorded for hash type {hash_type}'}), 404
        return jsonify({'status': 200, 'hash_type': hash_type, 'speed': speed})

    rows = (db.session.query(AgentBenchmarks.hash_type,
                             db.func.min(AgentBenchmarks.speed))
            .filter(AgentBenchmarks.speed > 0)
            .group_by(AgentBenchmarks.hash_type).all())
    # An empty fleet is not an error: 200 with an empty map, like the other
    # collection endpoints.
    return jsonify({'status': 200,
                    'performance': {str(ht): spd for ht, spd in rows}})

@api.route('/v1/customers', methods=['GET'])
def v1_api_get_customers():
    if not is_authorized(user=True, agent=True, request=request):
        return redirect("/v1/not_authorized")

    update_heartbeat(request.cookies.get('uuid'))
    customers = Customers.query.all()
    message = {
        'status': 200,
        'users': alchemy_to_native(customers)
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





# Provide wordlist info (really should be plural)
@api.route('/v1/wordlists', methods=['GET'])
def v1_api_get_wordlist():
    if not is_authorized(user=True, agent=True, request=request):
        return redirect("/v1/not_authorized")

    update_heartbeat(request.cookies.get('uuid'))
    wordlists = Wordlists.query.all()
    message = {
        'status': 200,
        'wordlists': alchemy_to_native(wordlists)
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

    if wordlist.type == 'static':
        # Static lists are stored compressed at rest: serve the .gz directly. The
        # stored bytes are stable, so the agent's sha256(.gz) matches the DB
        # checksum. Resolve by basename against the wordlists dir rather than
        # trusting a possibly-relative wordlist.path against the CWD (legacy rows
        # can hold a relative path). When the row outlives its file -- e.g. a
        # wordlist stranded by an upgrade -- return a clear JSON 404 instead of
        # send_from_directory's bare HTML page, so the agent logs an actionable
        # body and the operator knows to re-upload. (Mirrors /v1/rules/<id>.)
        wordlist_name = os.path.basename(wordlist.path or '')
        src_path = os.path.join(wordlists_dir, wordlist_name)
        if not wordlist_name or not os.path.exists(src_path):
            return jsonify({'status': 404, 'type': 'Error',
                            'msg': 'Wordlist file missing on disk: ' + (wordlist_name or '(no path)')}), 404
        return send_from_directory(wordlists_dir, wordlist_name, mimetype='application/octet-stream')

    # Dynamic lists are regenerated from the DB on demand and served gzipped.
    # Generate into a per-request unique temp file (never the shared
    # wordlist.path); the DB row metadata is deliberately left untouched
    # (dest_path is set).
    tmp_txt = os.path.join(tmp_dir, secrets.token_hex(8) + '.txt')
    update_dynamic_wordlist(wordlist_id, dest_path=tmp_txt)

    # Compress the plaintext into control/tmp and serve that. No shell; pure-
    # Python streamed gzip -9. Both temp files live under control/tmp and are
    # cleaned up: the .txt now, the .gz after the response is streamed.
    tmp_gz = os.path.join(tmp_dir, secrets.token_hex(8) + '.gz')
    compress_to_gz(tmp_txt, tmp_gz, 9)
    remove_file(tmp_txt)
    return send_generated_file(
        tmp_dir, os.path.basename(tmp_gz), mimetype='application/octet-stream')

# Create new wordlist
@api.route('/v1/wordlists/add/<wordlist_name>', methods=['POST'])
def v1_api_add_wordlist(wordlist_name):
    # Authorization check. This is a user-upload action — it resolves the
    # caller to a Users row by api_key — so it's user-only. The agent never
    # POSTs here (it only GETs wordlists), so requiring a user
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
    if not agent:
        return jsonify({
            'status': 404,
            'type': 'Error',
            'msg': 'Agent not found'
        }), 404
    job_task = JobTasks.query.filter_by(agent_id=agent.id).first()

    message = {
        'status': 200,
        'job_task': alchemy_to_native(job_task)
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
        'job': alchemy_to_native(job)
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

# Job priority is 1 (lowest) .. 5 (highest) -- see Jobs.priority. Nothing in the
# schema bounds it (no CHECK constraint), and the web form's SelectField is the
# only other guard, so the API has to bound it itself.
JOB_PRIORITY_MIN = 1
JOB_PRIORITY_MAX = 5
JOB_PRIORITY_DEFAULT = 3

# How /v1/jobs/add decides which tasks a new job gets. 'lucky' is the default so
# a body that predates this field behaves exactly as it always has.
JOB_TASK_MODES = ('lucky', 'tasks', 'task_group')




def _validate_job_priority(job_data):
    """Resolve the requested job priority. Returns (priority, error_or_None).

    Absent or null yields the model default, so every client written before this
    field existed keeps creating jobs unchanged.
    """
    raw = job_data.get('priority')
    if raw is None:
        return JOB_PRIORITY_DEFAULT, None

    # str(x).isdigit() is this file's idiom for "a non-negative integer, however
    # it was typed" (see wl_id in /v1/tasks/add). It takes the "5" a form-style
    # client sends and rejects 3.5, "high", -1 and True -- the last of which a
    # bare isinstance(x, int) would quietly accept as priority 1.
    if not str(raw).isdigit() or not (JOB_PRIORITY_MIN <= int(raw) <= JOB_PRIORITY_MAX):
        return None, _error(400, f'priority must be an integer from {JOB_PRIORITY_MIN} '
                                 f'(lowest) to {JOB_PRIORITY_MAX} (highest)')

    # The admin switch that hides the priority control in the web UI applies to
    # API callers too -- an api_key IS a user. Refuse rather than silently
    # substituting 3, so a caller is never told nothing while their choice is
    # discarded. Settings can legitimately be absent on a bare install; treat
    # that as disabled, matching the column default.
    settings = Settings.query.first()
    if not (settings and settings.enabled_job_weights):
        return None, _error(400, 'Job priority weighting is disabled by the administrator. '
                                 'Omit "priority", or ask an admin to enable job weights '
                                 'in Settings.')
    return int(raw), None


def _resolve_lucky_task_ids(hashfile_id):
    """Mode 'lucky': the historically most effective tasks for this hashfile."""
    hash_type = hashfile_hash_type(hashfile_id)
    if hash_type is None:
        # Previously an AttributeError on one of three chained lookups, swallowed
        # by the catch-all into "Failed to add job."
        return None, _error(500, 'Could not determine a hash type for that hashfile. '
                                 'Check hashfile_id, and that the hashfile has hashes '
                                 'in it.')
    task_ids = top_effective_task_ids(hash_type)
    if not task_ids:
        # Message prefix is unchanged: clients and tests substring-match it. The
        # pointer to the other modes is appended because this is exactly the dead
        # end a fresh system hits (#351) -- ranking needs cracks that carry a
        # task_id, and /v1/hashes/import does not set one.
        return None, _error(500, 'Not enough data to determine effective tasks for this '
                                 'hash type. Please add more cracked hashes of this type '
                                 'before creating a job, or assign tasks explicitly with '
                                 'mode "tasks" or "task_group".')
    # No dedupe needed: top_effective_task_ids groups by task_id, and the job is
    # brand new so nothing is assigned to it yet.
    return task_ids, None


def _resolve_explicit_task_ids(job_data):
    """Mode 'tasks': exactly the ids the caller named, in the order given.

    Strict on purpose. The caller authored this list, so an unknown id or an
    illegal repeat is a bug in their request -- dropping either one silently
    would build a job that does not match what was asked for.
    """
    task_ids = job_data.get('task_ids')
    if not isinstance(task_ids, list) or not task_ids:
        return None, _error(400, 'task_ids must be a non-empty list of task ids '
                                 'when mode is "tasks"')
    if len(task_ids) > MAX_TASKS_PER_GROUP:
        return None, _error(400, f'A job can hold at most {MAX_TASKS_PER_GROUP} tasks '
                                 f'({len(task_ids)} submitted)')

    dynamic_ids = dynamic_wordlist_ids()
    ordered, seen = [], set()
    for raw_id in task_ids:
        # bool is an int in Python; reject it before int() turns True into 1.
        if isinstance(raw_id, bool) or not str(raw_id).isdigit():
            return None, _error(400, f'Invalid task id: {raw_id!r}')
        tid = int(raw_id)
        task = Tasks.query.get(tid)
        if task is None:
            return None, _error(400, f'Invalid task id: {raw_id!r}')
        if tid in seen and not task_uses_dynamic_wordlist(task, dynamic_ids):
            return None, _error(400, f'Task {tid} appears more than once; only a task '
                                     f'using a dynamic wordlist may be assigned to a job '
                                     f'more than once')
        # A legal repeat is kept, not collapsed: JobTasks has no position column,
        # so this list IS the queue order and a repeated dynamic task means run
        # it again at that point.
        ordered.append(tid)
        seen.add(tid)
    return ordered, None


def _resolve_task_group_task_ids(job_data):
    """Mode 'task_group': the group's members, in stored order.

    Lenient where mode 'tasks' is strict, and for the same reason inverted: the
    caller named a group, not the ids, so stale membership is not theirs to fix.
    Members whose task is gone are skipped and counted, which is what
    jobs_assign_task_group does -- except the count is returned rather than only
    flashed.
    """
    raw_group_id = job_data.get('task_group_id')
    if isinstance(raw_group_id, bool) or not str(raw_group_id).isdigit():
        return None, 0, _error(400, 'task_group_id must be a task group id when mode '
                                    'is "task_group"')
    task_group = TaskGroups.query.get(int(raw_group_id))
    if task_group is None:
        # A body field that fails to resolve, so a body-400 like 'Invalid wl_id'
        # -- the real 404s in this file are all path parameters.
        return None, 0, _error(400, f'Invalid task_group_id: {int(raw_group_id)}')

    try:
        members = json.loads(task_group.tasks)
    except (TypeError, ValueError):
        members = []
    if not isinstance(members, list):
        members = []

    dynamic_ids = dynamic_wordlist_ids()
    ordered, seen, skipped = [], set(), 0
    for raw_id in members:
        try:
            tid = int(raw_id)
        except (TypeError, ValueError):
            skipped += 1
            continue
        task = Tasks.query.get(tid)
        if task is None:
            skipped += 1
            continue
        if tid in seen and not task_uses_dynamic_wordlist(task, dynamic_ids):
            skipped += 1
            continue
        ordered.append(tid)
        seen.add(tid)

    if not ordered:
        # Never create a taskless job: /v1/jobs/start requires `job and job_tasks`,
        # so it could never be started and would just clutter the jobs list.
        return None, skipped, _error(400, f'Task group {task_group.name!r} has no '
                                          f'assignable tasks ({skipped} member(s) no '
                                          f'longer exist)')
    return ordered, skipped, None


def _resolve_job_task_ids(job_data):
    """Pick the assignment mode and resolve it. Returns (ordered, skipped, error).

    Mode defaults to 'lucky' so a body written before this field behaves exactly
    as before. A companion field supplied under the wrong mode is refused rather
    than ignored: silently running the heuristic when the caller thought they had
    chosen their own tasks is the failure shape this endpoint is being fixed for.
    """
    mode = job_data.get('mode', 'lucky')
    if mode not in JOB_TASK_MODES:
        return None, 0, _error(400, 'mode must be one of: ' + ', '.join(JOB_TASK_MODES))

    for field, owner in (('task_ids', 'tasks'), ('task_group_id', 'task_group')):
        if job_data.get(field) is not None and mode != owner:
            return None, 0, _error(400, f'{field} is only valid with mode {owner!r} '
                                        f'(mode is {mode!r})')

    if mode == 'tasks':
        ordered, err = _resolve_explicit_task_ids(job_data)
        return ordered, 0, err
    if mode == 'task_group':
        return _resolve_task_group_task_ids(job_data)
    ordered, err = _resolve_lucky_task_ids(job_data.get('hashfile_id'))
    return ordered, 0, err


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

    # Everything below runs BEFORE the job row is created, and before the
    # catch-all try/except that turns any exception into 'Failed to add job.'.
    # Two payoffs: a refusal reports its real diagnosis rather than a generic
    # 500, and it leaves no orphan job behind -- the job used to be committed
    # first and the task gate evaluated afterwards, so every refused call left a
    # taskless 'Ready' job that no one could start.
    priority, err = _validate_job_priority(job_data)
    if err:
        return jsonify(err)

    task_ids, tasks_skipped, err = _resolve_job_task_ids(job_data)
    if err:
        return jsonify(err)

    try:
        job_entry = Jobs(
            name=job_data.get('name'),
            hashfile_id=job_data.get('hashfile_id'),
            owner_id=user.id,
            customer_id=job_data.get('customer_id'),
            priority=priority,
            status='Ready',
            limit_recovered=job_data.get('limit_recovered', False)
        )
        db.session.add(job_entry)
        # flush, not commit: the id is needed for the child rows below but the
        # whole create stays one transaction, so a later failure rolls all of it
        # back instead of stranding the job.
        db.session.flush()

        # Insert in the resolved order and do not dedupe here: task_ids is
        # already the final ordered list, and a dynamic-wordlist task may
        # legitimately repeat. JobTasks has no position column -- insertion order
        # IS queue order, and dispatch reads min(JobTasks.id) per (job, task).
        for task_id in task_ids:
            db.session.add(JobTasks(job_id=job_entry.id, task_id=task_id, status='Not Started'))

        # Job notifications: one row per (job, owner, channel), using the same
        # method tokens as the web UI ('email'/'push'/'slack'). No existence
        # query -- the job is new, so there is nothing to collide with.
        notify_map = [
            ('email', job_data.get('notify_email', False)),
            ('push', job_data.get('notify_pushover', False)),
            ('slack', job_data.get('notify_slack', False)),
        ]
        for method, requested in notify_map:
            if requested:
                db.session.add(JobNotifications(
                    owner_id=user.id, job_id=job_entry.id, method=method))
        db.session.commit()
    except Exception:
        # Without the rollback a failed commit leaves the session unusable for
        # the rest of the request.
        db.session.rollback()
        current_app.logger.exception('API /v1/jobs: failed to add job')
        return jsonify({
            'status': 500,
            'type': 'Error',
            'msg': 'Failed to add job.'
        })

    log_event('job.create', actor=(user.email_address, user.id),
              target=f'job:{job_entry.id} {job_entry.name!r}')
    return jsonify({
        'status': 200,
        'type': 'message',
        'msg': 'Job added',
        'job_id': job_entry.id,
        'tasks_assigned': len(task_ids),
        'tasks_skipped': tasks_skipped
    })

# Stop a job
@api.route('/v1/jobs/stop/<int:job_id>', methods=['POST'])
def v1_api_post_stop_job(job_id):
    """Cancel a Running or Queued job and every task under it.

    Mirrors the web UI's jobs_stop: owner or admin only, the job must actually be
    active, and each JobTasks row is set to 'Canceled' with its agent cleared so
    the work is not handed back out. Clearing agent_id is the part that matters
    -- a cancelled row that still names an agent looks assigned to the heartbeat.

    Until now /v1 could start a job but never stop one, so an API-driven run had
    to be cancelled from the web UI.
    """
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
            'msg': 'You do not have rights to stop this job'
        })

    if job.status not in ('Running', 'Queued'):
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': f'Job is not actively running (status {job.status!r})'
        })

    try:
        job.status = 'Canceled'
        job.ended_at = datetime.now()
        for job_task in JobTasks.query.filter_by(job_id=job_id).all():
            job_task.status = 'Canceled'
            job_task.agent_id = None
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception('API /v1/jobs: failed to stop job')
        return jsonify({
            'status': 500,
            'type': 'Error',
            'msg': 'Failed to stop job.'
        })

    log_event('job.stop', actor=(user.email_address, user.id),
              target=f'job:{job.id} {job.name!r}')
    return jsonify({
        'status': 200,
        'type': 'message',
        'msg': 'Job stopped',
        'job_id': job.id
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

# List all tasks
@api.route('/v1/tasks', methods=['GET'])
def v1_api_get_tasks():
    if not is_authorized(user=True, agent=True, request=request):
        return redirect("/v1/not_authorized")

    update_heartbeat(request.cookies.get('uuid'))
    tasks = Tasks.query.all()
    message = {
        'status': 200,
        'tasks': alchemy_to_native(tasks)
    }
    return jsonify(message)

# Provide task info
@api.route('/v1/tasks/<int:task_id>', methods=['GET'])
def v1_api_get_task(task_id):
    if not is_authorized(user=True, agent=True, request=request):
        return redirect("/v1/not_authorized")

    update_heartbeat(request.cookies.get('uuid'))
    task = Tasks.query.get(task_id)
    message = {
        'status': 200,
        'task': alchemy_to_native(task)
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

def _validate_ordered_task_ids(task_ids):
    """Validate a list of task ids against the Tasks table, dedupe preserving
    first-occurrence order (mirrors task_groups_add/task_groups_edit in the
    web UI blueprint). Returns (ordered_list, error_msg_or_None) — on the
    first invalid id, ordered_list is None and error_msg is set.

    The submitted list is length-capped at MAX_TASKS_PER_GROUP before anything
    else runs, so an oversized payload is rejected at the door rather than
    after a full Tasks load — and the caller gets the real diagnosis (too many
    tasks) instead of whichever stale id happened to appear first."""
    if len(task_ids) > MAX_TASKS_PER_GROUP:
        return None, (f'A task group can hold at most {MAX_TASKS_PER_GROUP} tasks '
                      f'({len(task_ids)} submitted)')
    valid_ids = {t.id for t in Tasks.query.all()}
    ordered = []
    for raw_id in task_ids:
        try:
            tid = int(raw_id)
        except (TypeError, ValueError):
            return None, f'Invalid task id: {raw_id!r}'
        if tid not in valid_ids:
            return None, f'Invalid task id: {raw_id!r}'
        if tid not in ordered:
            ordered.append(tid)
    return ordered, None

# List all task groups
@api.route('/v1/task_groups', methods=['GET'])
def v1_api_get_task_groups():
    if not is_authorized(user=True, agent=False, request=request):
        return redirect("/v1/not_authorized")

    groups = TaskGroups.query.all()
    native = alchemy_to_native(groups)
    for row in native:
        try:
            row['tasks'] = json.loads(row['tasks']) if row['tasks'] else []
        except (ValueError, TypeError):
            row['tasks'] = []
    message = {
        'status': 200,
        'task_groups': native
    }
    return jsonify(message)

# Create a new task group with an ordered task membership list
@api.route('/v1/task_groups/add', methods=['POST'])
def v1_api_add_task_group():
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

    # Expect JSON body: {"name": ..., "tasks": [id, ...]}
    group_data = request.get_json(silent=True)
    if not group_data:
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': 'Missing task group data in request body'
        })

    name = str(group_data.get('name') or '').strip()
    if not name:
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': 'Task group name is required'
        })
    if TaskGroups.query.filter_by(name=name).first():
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': 'A task group with that name already exists'
        })

    task_ids = group_data.get('tasks', [])
    if not isinstance(task_ids, list):
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': 'tasks must be a list of task ids'
        })
    ordered, err = _validate_ordered_task_ids(task_ids)
    if err:
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': err
        })

    try:
        task_group = TaskGroups(name=name, owner_id=user.id, tasks=json.dumps(ordered))
        db.session.add(task_group)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': 'A task group with that name already exists'
        })
    except Exception:
        db.session.rollback()
        current_app.logger.exception('API /v1/task_groups: failed to add task group')
        return jsonify({
            'status': 500,
            'type': 'Error',
            'msg': 'Failed to add task group.'
        })

    log_event('task_group.create', actor=(user.email_address, user.id),
              target=f'task_group:{task_group.id} {task_group.name!r}')
    message = {
        'status': 200,
        'type': 'message',
        'msg': 'Task group added',
        'task_group_id': task_group.id
    }
    return jsonify(message)

# Set or append a task group's task membership
@api.route('/v1/task_groups/<int:task_group_id>/tasks', methods=['POST'])
def v1_api_set_task_group_tasks(task_group_id):
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

    task_group = TaskGroups.query.get(task_group_id)
    if task_group is None:
        return jsonify({'status': 404, 'type': 'Error', 'msg': 'Task group not found'}), 404

    if not (user.admin or task_group.owner_id == user.id):
        return jsonify({
            'status': 403,
            'type': 'Error',
            'msg': 'You do not have rights to modify this task group'
        })

    body = request.get_json(silent=True)
    if not body:
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': 'Missing task group data in request body'
        })

    task_ids = body.get('tasks')
    if not isinstance(task_ids, list):
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': 'tasks must be a list of task ids'
        })

    mode = body.get('mode', 'replace')
    if mode not in ('replace', 'append'):
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': "mode must be 'replace' or 'append'"
        })

    ordered, err = _validate_ordered_task_ids(task_ids)
    if err:
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': err
        })

    if mode == 'append':
        try:
            existing = json.loads(task_group.tasks) if task_group.tasks else []
        except (ValueError, TypeError):
            existing = []
        new_list = existing + [tid for tid in ordered if tid not in existing]
    else:
        new_list = ordered

    # The cap is on the RESULTING membership, which is the only check that also
    # covers mode='append': `existing` is read straight back out of the column
    # and never revalidated, so repeated small appends would otherwise walk a
    # group past the limit. Counting new_list (not len(existing) + len(ordered))
    # matters — the merge above dedupes, so appending an id the group already
    # holds must not be rejected.
    if len(new_list) > MAX_TASKS_PER_GROUP:
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': f'A task group can hold at most {MAX_TASKS_PER_GROUP} tasks '
                   f'({len(new_list)} after this change)'
        })

    try:
        task_group.tasks = json.dumps(new_list)
        db.session.commit()
    except Exception:
        current_app.logger.exception('API /v1/task_groups: failed to update task group tasks')
        return jsonify({
            'status': 500,
            'type': 'Error',
            'msg': 'Failed to update task group.'
        })

    log_event('task_group.edit', actor=(user.email_address, user.id),
              target=f'task_group:{task_group.id} {task_group.name!r}')
    message = {
        'status': 200,
        'type': 'message',
        'msg': 'Task group updated',
        'task_group_id': task_group.id,
        'tasks': new_list
    }
    return jsonify(message)

# Delete a task group
@api.route('/v1/task_groups/<int:task_group_id>', methods=['DELETE'])
def v1_api_delete_task_group(task_group_id):
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

    task_group = TaskGroups.query.get(task_group_id)
    if task_group is None:
        return jsonify({'status': 404, 'type': 'Error', 'msg': 'Task group not found'}), 404

    if not (user.admin or task_group.owner_id == user.id):
        return jsonify({
            'status': 403,
            'type': 'Error',
            'msg': 'You do not have rights to delete this task group'
        })

    task_group_target = f'task_group:{task_group.id} {task_group.name!r}'
    try:
        db.session.delete(task_group)
        db.session.commit()
    except Exception:
        current_app.logger.exception('API /v1/task_groups: failed to delete task group')
        return jsonify({
            'status': 500,
            'type': 'Error',
            'msg': 'Failed to delete task group.'
        })

    log_event('task_group.delete', actor=(user.email_address, user.id), target=task_group_target)
    message = {
        'status': 200,
        'type': 'message',
        'msg': 'Task group deleted',
        'task_group_id': task_group_id
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

    return send_generated_file(tmp_dir, random_hex)

@api.route('/v1/hashfiles/<int:hashfile_id>', methods=['DELETE'])
def v1_api_delete_hashfile(hashfile_id):
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

    hashfile = Hashfiles.query.get(hashfile_id)
    if hashfile is None:
        return jsonify({'status': 404, 'type': 'Error', 'msg': 'Hashfile not found'}), 404

    if not (user.admin or hashfile.owner_id == user.id):
        return jsonify({
            'status': 403,
            'type': 'Error',
            'msg': 'You do not have rights to delete this hashfile'
        })

    # Refuse while the hashfile is still assigned to a job — the web UI does the
    # same (hashfiles_delete) and does NOT cascade job deletion from a hashfile.
    if Jobs.query.filter_by(hashfile_id=hashfile_id).first():
        return jsonify({
            'status': 409,
            'type': 'Error',
            'msg': 'Hashfile is currently associated with a job'
        }), 409

    # Mirror the web UI's hashfiles_delete cascade, atomically: the hashfile-hash
    # links, the hashfile, then any uncracked hashes / notifications it orphans.
    hashfile_target = f'hashfile:{hashfile.id} {hashfile.name!r}'
    try:
        HashfileHashes.query.filter_by(hashfile_id=hashfile.id).delete(synchronize_session=False)
        db.session.delete(hashfile)
        Hashes.query.filter(Hashes.cracked == 0).filter(
            ~exists().where(HashfileHashes.hash_id == Hashes.id)
        ).delete(synchronize_session=False)
        HashNotifications.query.filter(
            ~exists().where(Hashes.id == HashNotifications.hash_id)
        ).delete(synchronize_session=False)
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception('API /v1/hashfiles: failed to delete hashfile')
        return jsonify({
            'status': 500,
            'type': 'Error',
            'msg': 'Failed to delete hashfile.'
        })

    log_event('hashfile.delete', actor=(user.email_address, user.id), target=hashfile_target)
    return jsonify({
        'status': 200,
        'type': 'message',
        'msg': 'Hashfile deleted',
        'hashfile_id': hashfile_id
    })

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
    #
    # One grouped query, not one per hashfile (issue #228). The previous form
    # took a DISTINCT list of hashfile ids and then, for each, ran an ORM
    # Hashfiles.query.get() plus two separate COUNTs -- three round trips per
    # matching file. Joining from Hashfiles and grouping does the same work in
    # a single statement.
    #
    # Joining FROM Hashfiles also subsumes the old `if hashfile is None:
    # continue` guard: a HashfileHashes row pointing at a deleted hashfile has
    # no row to join to, so it drops out instead of needing a lookup to
    # discover it is an orphan.
    rows = db.session.query(
            Hashfiles.id,
            Hashfiles.name,
            Hashfiles.customer_id,
            Hashfiles.owner_id,
            Hashfiles.uploaded_at,
            func.count(Hashes.id),
            func.coalesce(func.sum(case((Hashes.cracked == True, 1), else_=0)), 0),  # noqa: E712
        ) \
        .join(HashfileHashes, HashfileHashes.hashfile_id == Hashfiles.id) \
        .join(Hashes, Hashes.id == HashfileHashes.hash_id) \
        .filter(Hashes.hash_type == hash_type) \
        .group_by(Hashfiles.id) \
        .order_by(Hashfiles.id) \
        .all()

    results = []
    for (hashfile_id, name, customer_id, owner_id,
         uploaded_at, total, cracked) in rows:
        results.append({
            'id': hashfile_id,
            'name': name,
            'customer_id': customer_id,
            'owner_id': owner_id,
            'uploaded_at': uploaded_at.isoformat() if uploaded_at else None,
            'hash_type': hash_type,
            'total_hashes': int(total or 0),
            'cracked_hashes': int(cracked or 0),
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

# List every hashfile belonging to a customer (issue #346). Nested under the
# customer to mirror the web UI's per-customer view; unlike the by-hash-type
# route above, counts are NOT scoped to a single type -- total/cracked cover all
# hashes in the file and hash_type is the file's representative mode (min type,
# matching hashfiles_list()). An unknown customer is a valid empty result
# (status 200, hashfiles: []), not a 404 -- same contract as the by-hash-type
# route.
@api.route('/v1/customers/<int:customer_id>/hashfiles', methods=['GET'])
def v1_api_get_customer_hashfiles(customer_id):
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

    results = []
    for hashfile in Hashfiles.query.filter_by(customer_id=customer_id).all():
        agg = db.session.query(
            func.count(Hashes.id),
            func.coalesce(func.sum(case((Hashes.cracked == True, 1), else_=0)), 0),
            func.min(Hashes.hash_type),
        ).join(HashfileHashes, Hashes.id == HashfileHashes.hash_id) \
         .filter(HashfileHashes.hashfile_id == hashfile.id).first()
        results.append({
            'id': hashfile.id,
            'name': hashfile.name,
            'customer_id': hashfile.customer_id,
            'owner_id': hashfile.owner_id,
            'uploaded_at': hashfile.uploaded_at.isoformat() if hashfile.uploaded_at else None,
            'hash_type': agg[2],
            'total_hashes': int(agg[0] or 0),
            'cracked_hashes': int(agg[1] or 0),
        })

    return jsonify({
        'status': 200,
        'type': 'message',
        'hashfiles': results
    })

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
    if not job_task:
        return jsonify({
            'status': 404,
            'type': 'Error',
            'msg': 'Job task not found'
        }), 404

    # Get Job from job_task
    job = Jobs.query.get(job_task.job_id)
    if not job:
        return jsonify({
            'status': 404,
            'type': 'Error',
            'msg': 'Job not found'
        }), 404

    # Get hashfile from job
    hashfile = Hashfiles.query.get(job.hashfile_id)
    if not hashfile:
        return jsonify({
            'status': 404,
            'type': 'Error',
            'msg': 'Hashfile not found'
        }), 404

    # Get hashfilehashes from hashfile
    hashfilehashes = HashfileHashes.query.filter_by(hashfile_id=hashfile.id).first()
    if not hashfilehashes:
        return jsonify({
            'status': 404,
            'type': 'Error',
            'msg': 'Hashfile hashes not found'
        }), 404

    # Get single hash
    single_hash = Hashes.query.get(hashfilehashes.hash_id)
    if not single_hash:
        return jsonify({
            'status': 404,
            'type': 'Error',
            'msg': 'Hash not found'
        }), 404

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

    # Stop the job when there's nothing left to crack. One-and-done jobs stop after
    # the first recovery; ANY job stops once its hashfile is fully recovered --
    # continuing to run the remaining chunks/tasks would just burn cycles on a
    # solved hashfile. Cancelling the still-active tasks lets update_job_task_status
    # roll the job up to Completed. Gated on a fresh recovery so the (cheap)
    # "any uncracked left?" check only runs when the recovery state changed.
    if recovered_at_least_one_hash and (
            job.limit_recovered or not _hashfile_has_uncracked(job.hashfile_id)):
        reason = ('one-and-done (limit_recovered)' if job.limit_recovered
                  else 'hashfile fully recovered')
        current_app.logger.info('Job %s: cancelling remaining tasks (%s).', job.id, reason)
        _cancel_job_active_tasks(job.id)

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
    if not hashfile_hash:
        return jsonify({
            'status': 404,
            'type': 'Error',
            'msg': 'Hashfile not found'
        }), 404
    hash = Hashes.query.get(hashfile_hash.hash_id)
    if not hash:
        return jsonify({
            'status': 404,
            'type': 'Error',
            'msg': 'Hash not found'
        }), 404

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

    # Verify-only model: only accept a submitted plaintext for a hash type the
    # server can LOCALLY recompute. get_cracked_hash_verifier returns None for
    # anything unsupported (incl. LM 3000), which we reject up front.
    verifier = get_cracked_hash_verifier(hash_type)
    if verifier is None:
        return jsonify({'status': 403, 'type': 'message', 'msg': 'Unsupported Hashtype'})

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
    except Exception:
        current_app.logger.exception('API: failed to write file')
        return jsonify({
            'status': 500,
            'type': 'Error',
            'msg': 'Failed to write file.'
        })


    # import contents from file. The import is atomic: all verified records are
    # mutated in the session and committed ONCE after the loop completes. Any
    # verification failure rolls back so nothing from this request persists.
    try:
        try:
            with open(file_path, encoding='utf-8', errors='surrogateescape') as f:
                for line in f:
                    line = line.rstrip('\r\n')
                    if not line:
                        continue
                    parts = line.split(':')
                    ciphertext = parts[0]
                    # everything after the first ':' is the plaintext (it may itself contain ':')
                    plaintext = ':'.join(parts[1:])

                    # Recompute the digest from the submitted plaintext (plus any salt
                    # embedded in the ciphertext) and compare case-insensitively.
                    # Never trust unverified plaintext.
                    if verifier(plaintext, ciphertext):
                        # valid hash:plaintext. Hashfile imports store hex hashes
                        # lowercased and key sub_ciphertext off the lowercased value,
                        # so look up on ciphertext.lower() to actually hit the record.
                        record = Hashes.query.filter_by(hash_type=hash_type, sub_ciphertext=get_md5_hash(ciphertext.lower()), cracked='0').first()
                        if record:
                            # Mutate in the session; commit happens once after the loop.
                            record.plaintext = text_from_field(plaintext)
                            record.cracked = 1
                            record.recovered_at = datetime.today()
                            record.recovered_by = user.id
                    else:
                        # A single bad line invalidates the whole request; roll back
                        # any pending changes so nothing persists.
                        db.session.rollback()
                        return jsonify({
                            'status': 500,
                            'type': 'Error',
                            'msg': f'Plaintext for hash {ciphertext}, was found to be invalid.'
                        })

            # All lines verified. Commit the whole batch atomically.
            try:
                db.session.commit()
            except Exception:
                current_app.logger.exception('API: failed to import cracked hashes')
                db.session.rollback()
                return jsonify({
                    'status': 500,
                    'type': 'Error',
                    'msg': 'Failed to import cracked hash.'
                })
        except Exception:
            current_app.logger.exception('API: failed to open/parse uploaded file')
            db.session.rollback()
            return jsonify({
                'status': 500,
                'type': 'Error',
                'msg': 'Failed to open file.'
            })
    finally:
        remove_file(file_path)

    # Send per-hash "recovered" notifications (email/push/slack) for any now-cracked watched hash.
    process_recovered_hash_notifications()

    message = {
        'status': 200,
        'type': 'message',
        'msg': 'OK'
    }
    return jsonify(message)


# ---------------------------------------------------------------------------
# Resource modules (issue #441).
#
# Imported for their side effects: each one registers its handlers on the
# shared `api` blueprint from hashview/api/_shared.py. create_app() still does
# `from hashview.api.routes import api`, so importing this module has to pull
# them all in or their routes simply would not exist -- which
# test_openapi_spec.py's route/method parity check catches immediately.
#
# At the bottom of the file so the imports above are already bound, and noqa'd
# because that placement is exactly what E402 flags.
# ---------------------------------------------------------------------------
from hashview.api import rules  # noqa: E402,F401

