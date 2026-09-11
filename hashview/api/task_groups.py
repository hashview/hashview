"""/v1 task-group routes: list, create, set membership, delete.

Carved out of routes.py per issue #441; pure code motion.
"""
import json

from flask import (
    current_app,
    jsonify,
    redirect,
    request,
)
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
    TaskGroups,
    Tasks,
    Users,
    db,
)
from hashview.utils.audit import log_event
from hashview.utils.utils import (
    MAX_TASKS_PER_GROUP,
)


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
