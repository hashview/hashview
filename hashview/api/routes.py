import json
from datetime import datetime, timedelta

from flask import (
    current_app,
    jsonify,
    redirect,
    request,
)
from sqlalchemy import func

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
    Hashes,
    HashfileHashes,
    Hashfiles,
    Jobs,
    JobTasks,
    Settings,
    db,
)
from hashview.utils.utils import (
    _job_hash_type,
    get_md5_hash,
    hashtypes_in_use,
    hexplain_to_text,
    notify_admins,
    process_recovered_hash_notifications,
    rechunk_queued_tasks_for_hashtype,
    slowest_benchmark,
    update_job_task_status,
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
# Dotted form on purpose: `from hashview.api import customers` would bind the
# name `customers` at module level, which collides with a local of the same name
# in v1_api_post_hashfile_upload (ruff F811). This binds only `hashview`.
import hashview.api.customers  # noqa: E402,F401
import hashview.api.hashes  # noqa: E402,F401
import hashview.api.hashfiles  # noqa: E402,F401
import hashview.api.jobs  # noqa: E402,F401
import hashview.api.rules  # noqa: E402,F401
import hashview.api.task_groups  # noqa: E402,F401
import hashview.api.tasks  # noqa: E402,F401
import hashview.api.wordlists  # noqa: E402,F401

