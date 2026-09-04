"""Flask routes to handle Task Groups"""
import json

from flask import Blueprint, abort, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required

from hashview.models import Hashes, TaskGroups, Tasks, Users, db
from hashview.task_groups.forms import TaskGroupsForm
from hashview.utils.audit import log_event
from hashview.utils.utils import MAX_TASKS_PER_GROUP, try_commit

task_groups = Blueprint('task_groups', __name__)

# Flask's session is a signed *cookie*, so anything round-tripped through
# session['task_groups_form_err'] has to stay well inside the ~4 KB browser
# cookie limit. A cap-sized selection is ~60 KB of CSV, and a browser silently
# drops an over-sized cookie — which would take the login with it. Selections
# past this budget are dropped from the round-trip instead; the error still
# renders, the modal just reopens with an empty list.
_MAX_ROUNDTRIP_TASK_IDS = 2000


def _session_safe_task_ids(raw):
    """The submitted task_ids CSV, or '' when it is too big to carry in the session."""
    return raw if len(raw) <= _MAX_ROUNDTRIP_TASK_IDS else ''

@task_groups.route("/task_groups", methods=['GET', 'POST'])
@login_required
def task_groups_list():
    """Function to list task groups"""
    task_groups = TaskGroups.query.all()
    tasks = Tasks.query.all()
    users = Users.query.all()

    tasks_by_id = {t.id: t for t in tasks}
    user_names = {u.id: (((u.first_name or '') + ' ' + (u.last_name or '')).strip() or '—')
                  for u in users}

    # Historical hits (recovered passwords) per task, summed across each group's tasks.
    recovered_by_task = {
        row.task_id: row.recovered_count
        for row in Hashes.query.with_entities(
            Hashes.task_id, db.func.count(Hashes.id).label('recovered_count')
        ).filter(Hashes.cracked == '1').group_by(Hashes.task_id).all()
    }

    group_tasks = {}   # group.id -> ordered list of Task objects
    group_hits = {}    # group.id -> summed historical hits
    group_owner = {}   # group.id -> owner display name
    for group in task_groups:
        try:
            ids = json.loads(group.tasks) if group.tasks else []
        except (ValueError, TypeError):
            ids = []
        ordered = [tasks_by_id[i] for i in ids if i in tasks_by_id]
        group_tasks[group.id] = ordered
        group_hits[group.id] = sum(recovered_by_task.get(t.id, 0) for t in ordered)
        group_owner[group.id] = user_names.get(group.owner_id, '—')

    return render_template('task_groups.html.j2', title='Task Groups', task_groups=task_groups,
                           users=users, tasks=tasks, group_tasks=group_tasks,
                           group_hits=group_hits, group_owner=group_owner,
                           task_group_form=TaskGroupsForm(),
                           max_tasks_per_group=MAX_TASKS_PER_GROUP,
                           form_err=session.pop('task_groups_form_err', None))

@task_groups.route("/task_groups/add", methods=['GET', 'POST'])
@login_required
def task_groups_add():
    """Add a task group. Reached two ways: the New-group modal on the listing
    (posts from_modal=1) and the legacy standalone /task_groups/add page."""

    task_group_form = TaskGroupsForm()
    tasks = Tasks.query
    if task_group_form.validate_on_submit():
        # The "New group" modal posts an ordered, comma-separated list of task ids in
        # `task_ids`; the legacy standalone page does not send that field.
        if 'task_ids' in request.form:
            valid_ids = {t.id for t in Tasks.query.all()}
            ordered = []
            for piece in request.form.get('task_ids', '').split(','):
                piece = piece.strip()
                if piece.isdigit():
                    tid = int(piece)
                    if tid in valid_ids and tid not in ordered:
                        ordered.append(tid)
            # Cap the membership that would actually be stored — unknown and
            # duplicate ids are silently dropped above, so `ordered` (not the
            # raw submitted count) is what has to fit MAX_TASKS_PER_GROUP.
            if len(ordered) > MAX_TASKS_PER_GROUP:
                session['task_groups_form_err'] = {
                    'modal': 'new-group-modal',
                    'values': {
                        'name': task_group_form.name.data or '',
                        'task_ids': _session_safe_task_ids(request.form.get('task_ids', '')),
                    },
                    'errors': [f'A task group can hold at most {MAX_TASKS_PER_GROUP:,} tasks '
                               f'({len(ordered):,} selected).'],
                }
                return redirect(url_for('task_groups.task_groups_list'))
            task_group = TaskGroups(name=task_group_form.name.data, owner_id=current_user.id, tasks=json.dumps(ordered))
            db.session.add(task_group)
            db.session.commit()
            log_event('task_group.create', target=f'task_group:{task_group.id} {task_group.name!r}')
            flash(f'Task group {task_group_form.name.data} created!', 'success')
            return redirect(url_for('task_groups.task_groups_list'))
        # Legacy flow: create an empty group then go to the assign-tasks page.
        task_group = TaskGroups(name=task_group_form.name.data, owner_id=current_user.id, tasks=json.dumps([]))
        db.session.add(task_group)
        db.session.commit()
        log_event('task_group.create', target=f'task_group:{task_group.id} {task_group.name!r}')
        flash(f'Task {task_group_form.name.data} created!', 'success')
        return redirect("assigned_tasks/"+str(task_group.id))
    # Validation failed. From the modal → reopen it on the listing with the error
    # inside and the typed name preserved; from the legacy standalone page →
    # re-render that page.
    if request.form.get('from_modal'):
        session['task_groups_form_err'] = {
            'modal': 'new-group-modal',
            'values': {
                'name': task_group_form.name.data or '',
                'task_ids': _session_safe_task_ids(request.form.get('task_ids', '')),
            },
            'errors': [e for errs in task_group_form.errors.values() for e in errs],
        }
        return redirect(url_for('task_groups.task_groups_list'))
    return render_template('task_groups_add.html.j2', title='Tasks Add', tasks=tasks, task_group_form=task_group_form)

@task_groups.route("/task_groups/edit", methods=['POST'])
@login_required
def task_groups_edit():
    """Update a task group's name and ordered task list (from the edit modal)."""
    task_group = TaskGroups.query.get(request.form.get('group_id', type=int))
    if task_group is None:
        flash('Task Group not found — it may have already been deleted.', 'warning')
        return redirect(url_for('task_groups.task_groups_list'))
    if not (current_user.admin or task_group.owner_id == current_user.id):
        abort(403)
    task_group_form = TaskGroupsForm()
    # Keeping this group's own name must not trip the uniqueness validator.
    task_group_form._editing_id = task_group.id
    if task_group_form.validate_on_submit():
        valid_ids = {t.id for t in Tasks.query.all()}
        ordered = []
        for piece in request.form.get('task_ids', '').split(','):
            piece = piece.strip()
            if piece.isdigit():
                tid = int(piece)
                if tid in valid_ids and tid not in ordered:
                    ordered.append(tid)
        # Checked before either attribute is assigned, so a rejected edit
        # leaves no dirty state on the identity-mapped row.
        if len(ordered) > MAX_TASKS_PER_GROUP:
            session['task_groups_form_err'] = {
                'modal': 'edit-group-modal',
                'values': {
                    'name': task_group_form.name.data or '',
                    'group_id': task_group.id,
                    'task_ids': _session_safe_task_ids(request.form.get('task_ids', '')),
                },
                'errors': [f'A task group can hold at most {MAX_TASKS_PER_GROUP:,} tasks '
                           f'({len(ordered):,} selected).'],
            }
            return redirect(url_for('task_groups.task_groups_list'))
        task_group.name = task_group_form.name.data
        task_group.tasks = json.dumps(ordered)
        db.session.commit()
        log_event('task_group.edit', target=f'task_group:{task_group.id} {task_group.name!r}')
        flash(f'Task group {task_group_form.name.data} updated!', 'success')
        return redirect(url_for('task_groups.task_groups_list'))
    # Validation failed — reopen the Edit-group modal for this group with the
    # specific error inside it (was: a generic flash over the listing).
    session['task_groups_form_err'] = {
        'modal': 'edit-group-modal',
        'values': {
            'name': task_group_form.name.data or '',
            'group_id': task_group.id,
            'task_ids': _session_safe_task_ids(request.form.get('task_ids', '')),
        },
        'errors': [e for errs in task_group_form.errors.values() for e in errs] or ['Could not update task group.'],
    }
    return redirect(url_for('task_groups.task_groups_list'))

@task_groups.route("/task_groups/assigned_tasks/<int:task_group_id>", methods=['GET', 'POST'])
@login_required
def task_groups_assigned_tasks(task_group_id):
    """Function to list assigned tasks for task group"""

    task_group = TaskGroups.query.get(task_group_id)
    tasks = Tasks.query
    task_group_tasks = json.loads(task_group.tasks)
    return render_template('task_groups_assigntask.html.j2', title='Task Group: Assign Tasks', task_group=task_group, tasks=tasks, task_group_tasks=task_group_tasks,
                           max_tasks_per_group=MAX_TASKS_PER_GROUP)

@task_groups.route("/task_groups/assigned_tasks/<int:task_group_id>/add_task/<int:task_id>", methods=['GET'])
@login_required
def task_groups_assigned_tasks_add_task(task_group_id, task_id):
    """Function to assign task to task group"""

    task_group = TaskGroups.query.get(task_group_id)
    task_group_tasks = json.loads(task_group.tasks)
    # >= on the pre-append length: appending would make it len + 1, so a group
    # sitting at the cap can take no more. This route is the only incremental
    # growth path, and it neither dedupes nor validates the id it appends.
    if len(task_group_tasks) >= MAX_TASKS_PER_GROUP:
        flash(f'This task group already holds the maximum of {MAX_TASKS_PER_GROUP:,} tasks.',
              'warning')
        return redirect("/task_groups/assigned_tasks/"+str(task_group.id))
    task_group_tasks.append(task_id)
    task_group.tasks = json.dumps(task_group_tasks)
    db.session.commit()
    return redirect("/task_groups/assigned_tasks/"+str(task_group.id))

@task_groups.route("/task_groups/assigned_tasks/<int:task_group_id>/remove_task/<int:task_id>", methods=['GET'])
@login_required
def task_groups_assigned_tasks_remove_task(task_group_id, task_id):
    """Function to remove task to task group"""

    task_group = TaskGroups.query.get(task_group_id)
    if task_group is None:
        flash('Task Group not found — it may have already been deleted.', 'warning')
        return redirect(url_for('task_groups.task_groups_list'))
    task_group_tasks = json.loads(task_group.tasks)
    if task_id not in task_group_tasks:
        flash('That task is no longer in this group — it may have already been removed.', 'warning')
        return redirect("/task_groups/assigned_tasks/"+str(task_group.id))
    task_group_tasks.remove(task_id)
    task_group.tasks = json.dumps(task_group_tasks)
    if not try_commit(f'remove task {task_id} from task_group {task_group_id}'):
        flash('Could not remove the task — please try again.', 'danger')
    return redirect("/task_groups/assigned_tasks/"+str(task_group.id))

@task_groups.route("/task_groups/assigned_tasks/<int:task_group_id>/promote_task/<int:task_id>", methods=['GET'])
@login_required
def task_groups_assigned_tasks_promote_task(task_group_id, task_id):
    """Function to move assigned task up higher in queue on task group"""

    task_group = TaskGroups.query.get(task_group_id)
    task_group_tasks = json.loads(task_group.tasks)
    if task_group_tasks[0] == task_id:
        # Cant promote further
        return redirect("/task_groups/assigned_tasks/"+str(task_group.id))
    else:
        new_task_group_tasks = []
        # Creating manual index since for loop doesnt allow you to modify the itterator value
        index = 0
        while index < len(task_group_tasks):
            if index+1 < len(task_group_tasks):
                if task_group_tasks[index+1] == task_id:
                    new_task_group_tasks.append(task_id)
                    new_task_group_tasks.append(task_group_tasks[index])
                    index = index + 1
                else:
                    new_task_group_tasks.append(task_group_tasks[index])
            else:
                new_task_group_tasks.append(task_group_tasks[index])
            index+=1
    task_group.tasks = json.dumps(new_task_group_tasks)
    db.session.commit()
    return redirect("/task_groups/assigned_tasks/"+str(task_group.id))

@task_groups.route("/task_groups/assigned_tasks/<int:task_group_id>/demote_task/<int:task_id>", methods=['GET'])
@login_required
def task_groups_assigned_tasks_demote_task(task_group_id, task_id):
    """Function to move assigned task up lower in queue on task group"""

    task_group = TaskGroups.query.get(task_group_id)
    task_group_tasks = json.loads(task_group.tasks)
    if task_group_tasks[-1] == task_id:
        # Cant demote further
        return redirect("/task_groups/assigned_tasks/"+str(task_group.id))
    else:
        new_task_group_tasks = []
        # Creating manual index since for loop doesnt allow you to modify the itterator value
        index = 0
        while index < len(task_group_tasks):
            if index+1 < len(task_group_tasks):
                if task_group_tasks[index] == task_id:
                    new_task_group_tasks.append(task_group_tasks[index+1])
                    new_task_group_tasks.append(task_id)
                    index = index + 1
                else:
                    new_task_group_tasks.append(task_group_tasks[index])
            else:
                new_task_group_tasks.append(task_group_tasks[index])
            index+=1
    task_group.tasks = json.dumps(new_task_group_tasks)
    db.session.commit()
    return redirect("/task_groups/assigned_tasks/"+str(task_group.id))

@task_groups.route("/task_groups/delete/<int:task_group_id>", methods=['POST'])
@login_required
def task_groups_delete(task_group_id):
    """Function to delete task group"""

    task_group = TaskGroups.query.get(task_group_id)
    if task_group is None:
        flash('Task Group not found — it may have already been deleted.', 'warning')
        return redirect(url_for('task_groups.task_groups_list'))
    if current_user.admin or task_group.owner_id == current_user.id:
        task_group_target = f'task_group:{task_group.id} {task_group.name!r}'
        db.session.delete(task_group)
        if not try_commit(f'delete task_group {task_group_id}'):
            flash('Task Group could not be deleted — it may have already been removed.', 'danger')
            return redirect(url_for('task_groups.task_groups_list'))
        log_event('task_group.delete', target=task_group_target)
        flash('Task Group has been deleted!', 'success')
        return redirect(url_for('task_groups.task_groups_list'))

    abort(403)
