"""/v1 task routes: list, detail, create.

Carved out of routes.py per issue #441; pure code motion.
"""

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
    Rules,
    Tasks,
    Users,
    Wordlists,
    db,
)
from hashview.utils.audit import log_event
from hashview.utils.utils import rule_file_missing, wordlist_file_missing


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
    wordlist = Wordlists.query.get(int(wl_id))
    if not wordlist:
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': 'Invalid wl_id'
        })
    # The row existing is not enough: a wordlist whose file is gone can never be
    # downloaded by an agent, so a task built on it can never run (issue #383).
    # This is the API's only warning -- there is no picker to grey out here.
    if wordlist_file_missing(wordlist):
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': 'Wordlist file is missing on disk and cannot be used in a task'
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
        rule = Rules.query.get(rule_id)
        if not rule:
            return jsonify({
                'status': 400,
                'type': 'Error',
                'msg': 'Invalid rule_id'
            })
        if rule_file_missing(rule):
            return jsonify({
                'status': 400,
                'type': 'Error',
                'msg': 'Rule file is missing on disk and cannot be used in a task'
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
