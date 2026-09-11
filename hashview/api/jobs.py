"""/v1 job routes: detail, create, start, stop, delete.

Also owns the job-creation input rules -- the priority bounds and the three
task-assignment modes (#351).

Carved out of routes.py per issue #441; pure code motion.
"""
import json
from datetime import datetime

from flask import (
    current_app,
    jsonify,
    redirect,
    request,
)

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
    JobNotifications,
    Jobs,
    JobTasks,
    Settings,
    TaskGroups,
    Tasks,
    Users,
    db,
)
from hashview.utils.audit import log_event
from hashview.utils.utils import (
    MAX_TASKS_PER_GROUP,
    build_job_task_commands,
    dynamic_wordlist_ids,
    hashfile_hash_type,
    task_uses_dynamic_wordlist,
    top_effective_task_ids,
)


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
