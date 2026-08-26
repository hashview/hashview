"""Flask routes to handle Tasks"""
import json
import os

from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required

from hashview.models import (
    Hashes,
    Jobs,
    JobTasks,
    Rules,
    TaskGroups,
    Tasks,
    Users,
    Wordlists,
    db,
)
from hashview.tasks.forms import TasksForm
from hashview.utils.audit import log_event
from hashview.utils.utils import apply_name_filter, try_commit

tasks = Blueprint('tasks', __name__)


def _human_size(num):
    """Human-readable byte size (e.g. 133 MB) for the task info modal."""
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if num < 1024 or unit == 'TB':
            if unit == 'B':
                return '%d B' % num
            return (f'{num:.1f} {unit}').replace('.0 ', ' ')
        num /= 1024.0

@tasks.route("/tasks", methods=['GET', 'POST'])
@login_required
def tasks_list():
    """Function to list tasks"""
    
    # Add pagination to reduce load time when many tasks exist
    page = request.args.get('page', 1, type=int)
    per_page = 20  # Adjust as needed

    # Get sorting parameters
    sort_by = request.args.get('sort_by', 'name', type=str)
    sort_order = request.args.get('sort_order', 'asc', type=str)

    # Name filter. Applied server-side, before pagination, so it searches every
    # task rather than only the ones rendered on the current page.
    name_filter = request.args.get('q', '', type=str).strip()

    # Build the query with sorting
    if sort_by == 'recovered':
        # Special case: sort by recovered password count (requires subquery)
        subquery = db.session.query(
            Hashes.task_id,
            db.func.count(Hashes.id).label('recovered_count')
        ).filter(Hashes.cracked == '1').group_by(Hashes.task_id).subquery()

        query = Tasks.query.outerjoin(subquery, Tasks.id == subquery.c.task_id)
        if sort_order == 'desc':
            query = query.order_by(db.func.coalesce(subquery.c.recovered_count, 0).desc())
        else:
            query = query.order_by(db.func.coalesce(subquery.c.recovered_count, 0).asc())
    elif sort_by == 'owner':
        # Sort by owner's first name
        query = Tasks.query.join(Users, Tasks.owner_id == Users.id)
        if sort_order == 'desc':
            query = query.order_by(Users.first_name.desc())
        else:
            query = query.order_by(Users.first_name.asc())
    elif sort_by == 'type':
        # Sort by attack mode
        if sort_order == 'desc':
            query = Tasks.query.order_by(Tasks.hc_attackmode.desc())
        else:
            query = Tasks.query.order_by(Tasks.hc_attackmode.asc())
    else:
        # Default: sort by task name
        if sort_order == 'desc':
            query = Tasks.query.order_by(Tasks.name.desc())
        else:
            query = Tasks.query.order_by(Tasks.name.asc())

    query = apply_name_filter(query, Tasks.name, name_filter)

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    tasks = pagination.items

    users = Users.query.all()
    jobs = Jobs.query.all()
    job_tasks = JobTasks.query.all()
    wordlists = Wordlists.query.all()
    task_groups = TaskGroups.query.all()

    task_recovery_performance = Hashes.query.with_entities(
        Hashes.task_id,
        db.func.count(Hashes.id).label('recovered_count')
    ).filter(Hashes.cracked == '1').group_by(Hashes.task_id).all()

    # Best-effort on-disk byte size for wordlists referenced by the tasks on this page
    # (the info modal shows "<size> · <N> words"). Missing files just omit the byte size.
    wl_by_id = {w.id: w for w in wordlists}
    referenced_wl = set()
    for t in tasks:
        if t.wl_id:
            referenced_wl.add(t.wl_id)
        if t.wl_id_2:
            referenced_wl.add(t.wl_id_2)
    wl_filesize = {}
    for wid in referenced_wl:
        w = wl_by_id.get(wid)
        if w and w.path:
            try:
                wl_filesize[wid] = _human_size(os.path.getsize(w.path))
            except OSError:
                pass

    # Tasks assigned to one or more jobs cannot be edited (the edit route enforces this
    # too); the list view uses this to disable the edit button for those tasks.
    tasks_in_jobs = {jt.task_id for jt in job_tasks}

    # Tasks that belong to a task group can't be bulk-deleted (the delete routes skip
    # them); the list view padlocks these so the checkbox isn't offered.
    tasks_in_task_groups = _task_group_task_ids(task_groups)

    # DISTINCT jobs each task is used in, for the info modal's "Used in N jobs"
    # panel. Collapse chunk rows so a job the task was split across is listed once
    # (not once per chunk); a task used more than once in the same job also lists
    # that job once.
    jobs_by_id = {j.id: j for j in jobs}
    jobs_by_task = {}
    _seen_job_for_task = {}
    for jt in job_tasks:
        job = jobs_by_id.get(jt.job_id)
        if job is None:
            continue
        seen = _seen_job_for_task.setdefault(jt.task_id, set())
        if job.id in seen:
            continue
        seen.add(job.id)
        jobs_by_task.setdefault(jt.task_id, []).append(job)

    return render_template('tasks.html.j2', title='tasks', tasks=tasks, users=users, jobs=jobs, job_tasks=job_tasks, jobs_by_task=jobs_by_task, wordlists=wordlists, task_groups=task_groups, task_recovery_performance=task_recovery_performance, pagination=pagination, sort_by=sort_by, sort_order=sort_order, name_filter=name_filter, rules=Rules.query.all(), wl_filesize=wl_filesize, tasks_in_jobs=tasks_in_jobs, tasks_in_task_groups=tasks_in_task_groups, tasksForm=TasksForm(), form_err=session.pop('tasks_form_err', None))

@tasks.route("/tasks/add", methods=['GET', 'POST'])
@login_required
def tasks_add():
    """Add a new task. Reached two ways: the Add-task modal on the listing
    (posts from_modal=1) and the legacy standalone /tasks/add page."""

    tasksForm = TasksForm()

    # clear select field for wordlists and rules
    tasksForm.rule_id.choices = []
    tasksForm.wl_id.choices = []
    tasksForm.wl_id_2.choices = []

    wordlists = Wordlists.query.all()
    rules = Rules.query.all()

    for wordlist in wordlists:
        tasksForm.wl_id.choices += [(wordlist.id, wordlist.name)]
        tasksForm.wl_id_2.choices += [(wordlist.id, wordlist.name)]

    tasksForm.rule_id.choices = [('None', 'None')]
    for rule in rules:
        tasksForm.rule_id.choices += [(rule.id, rule.name)]

    if tasksForm.validate_on_submit():

        if tasksForm.rule_id.data == 'None':
            rule_id = None
        else:
            rule_id = tasksForm.rule_id.data

        if tasksForm.wl_id_2.data is None:
            wl_id_2 = None
        else:
            wl_id_2 = tasksForm.wl_id_2.data

        if tasksForm.j_rule.data is None:
            j_rule = None
        else:
            j_rule = tasksForm.j_rule.data

        if tasksForm.k_rule.data is None:
            k_rule = None
        else:
            k_rule = tasksForm.k_rule.data
        

        # What attack mode are we dealing with
        # (set below by whichever attack-mode branch runs; stays None for the
        #  unsupported-mode else branch so we only audit an actual create)
        task = None
        # Straight Dictionary with optional rules
        if tasksForm.hc_attackmode.data == 0:
            task = Tasks(   name=tasksForm.name.data,
                            owner_id=current_user.id,
                            wl_id=tasksForm.wl_id.data,
                            rule_id=rule_id,
                            hc_attackmode=tasksForm.hc_attackmode.data,
                            loopback=tasksForm.loopback.data
            )
            db.session.add(task)
            db.session.commit()
            flash(f'Task {tasksForm.name.data} created!', 'success')
        # Combinator
        elif tasksForm.hc_attackmode.data == 1:
            task = Tasks(   name=tasksForm.name.data,
                            owner_id=current_user.id,
                            wl_id=tasksForm.wl_id.data,
                            wl_id_2=wl_id_2,
                            rule_id=None,
                            j_rule=j_rule,
                            k_rule=k_rule,
                            hc_attackmode=tasksForm.hc_attackmode.data
            )
            db.session.add(task)
            db.session.commit()
            flash(f'Task {tasksForm.name.data} created!', 'success')
        # Bruteforce Mask mode
        elif tasksForm.hc_attackmode.data == 3:
            task = Tasks(   name=tasksForm.name.data,
                            owner_id=current_user.id,
                            wl_id=None,
                            rule_id=None,
                            hc_attackmode=tasksForm.hc_attackmode.data,
                            hc_mask=tasksForm.mask.data
            )
            db.session.add(task)
            db.session.commit()
            flash(f'Task {tasksForm.name.data} created!', 'success')
        # Hybrid Wordlist + Mask or Hybrid Mask + Wordlist
        elif tasksForm.hc_attackmode.data == 6 or tasksForm.hc_attackmode.data == 7:
            task = Tasks(   name=tasksForm.name.data,
                            owner_id=current_user.id,
                            wl_id=tasksForm.wl_id.data,
                            rule_id=None,
                            hc_attackmode=tasksForm.hc_attackmode.data,
                            hc_mask=tasksForm.mask.data,
            )
            db.session.add(task)
            db.session.commit()
            flash(f'Task {tasksForm.name.data} created!', 'success')
        else:
            flash('Attack Mode not supported... yet...', 'danger')
        if task is not None:
            log_event('task.create', target=f'task:{task.id} {task.name!r}')
        return redirect(url_for('tasks.tasks_list'))
    # Validation failed. From the modal → reopen it on the listing with the error
    # shown inside and the typed name preserved; from the legacy standalone page →
    # re-render that page (WTForms preserves values + shows field errors inline).
    if request.form.get('from_modal'):
        session['tasks_form_err'] = {
            'modal': 'add-task-modal',
            'values': {'name': tasksForm.name.data or ''},
            'errors': [e for errs in tasksForm.errors.values() for e in errs],
        }
        return redirect(url_for('tasks.tasks_list'))
    return render_template('tasks_add.html.j2', title='Tasks Add', tasksForm=tasksForm)

@tasks.route("/tasks/edit/<int:task_id>", methods=['GET', 'POST'])
@login_required
def task_edit(task_id):
    """Function to edit task"""

    task = Tasks.query.get(task_id)
    if task is None:
        flash('Task not found — it may have already been deleted.', 'warning')
        return redirect(url_for('tasks.tasks_list'))

    # Check if task is currently assigned to a job.
    # We probably dont care if its assigned to a task group though
    affected_jobs = JobTasks.query.filter_by(task_id=task_id).all()
    if affected_jobs:
        flash('Can not edit this task. It is currently associated to one or more jobs.', 'danger')
        return redirect(url_for('tasks.tasks_list'))

    if current_user.admin or task.owner_id == current_user.id:
        tasksForm = TasksForm()

        # clear select field for wordlists and rules
        tasksForm.rule_id.choices = []
        tasksForm.wl_id.choices = []
        tasksForm.wl_id_2.choices = []

        wordlists = Wordlists.query.all()
        # Add the current value for wordlist.
        if task.hc_attackmode == 0:
            edit_task_wl = Wordlists.query.get(task.wl_id)
            if edit_task_wl:
                tasksForm.wl_id.choices.append((edit_task_wl.id, edit_task_wl.name))
        rules = Rules.query.all()
        # Check if the current value for rule is an integer.
        if isinstance(task.rule_id, int):
            edit_task_rl = Rules.query.get(task.rule_id)
            if edit_task_rl:
                tasksForm.rule_id.choices.append((edit_task_rl.id, edit_task_rl.name))
                tasksForm.rule_id.choices.append(('None', 'None'))
        else:
            # If it's not an integer, set rule_id and rule_name to 'None'.
            tasksForm.rule_id.choices.append(('None', 'None'))

        # Populate the choices for wordlists excluding the current value.
        for wordlist in wordlists:
            tasksForm.wl_id.choices += [(wordlist.id, wordlist.name)]
            tasksForm.wl_id_2.choices += [(wordlist.id, wordlist.name)]

        for rule in rules:
            tasksForm.rule_id.choices += [(rule.id, rule.name)]
        
        tasksForm.submit.label.text = 'Update'
        # Keeping this task's own name must not trip the uniqueness validator.
        tasksForm._editing_id = task.id

        if tasksForm.validate_on_submit():

            if tasksForm.hc_attackmode.data == 0:
                task.name = tasksForm.name.data
                task.wl_id = tasksForm.wl_id.data
                # Normalize the 'None' sentinel to NULL (matches tasks_add); storing the
                # literal string 'None' into the integer rule_id column raises MySQL 1366.
                task.rule_id = None if tasksForm.rule_id.data == 'None' else tasksForm.rule_id.data
                task.hc_attackmode = tasksForm.hc_attackmode.data
                task.hc_mask = None
                task.loopback = tasksForm.loopback.data

                db.session.add(task)
                db.session.commit()
                flash(f'Task {tasksForm.name.data} updated!', 'success')
            # Combinator
            elif tasksForm.hc_attackmode.data == 1:
                task.name = tasksForm.name.data
                task.wl_id = tasksForm.wl_id.data
                task.wl_id_2 = tasksForm.wl_id_2.data
                task.j_rule = tasksForm.j_rule.data
                task.k_rule = tasksForm.k_rule.data
                task.hc_attackmode = tasksForm.hc_attackmode.data
                task.loopback = False

                db.session.add(task)
                db.session.commit()
                flash(f'Task {tasksForm.name.data} updated!', 'success')
            # Mask mode
            elif tasksForm.hc_attackmode.data == 3:
                task.name = tasksForm.name.data
                task.wl_id = None
                task.rule_id = None
                task.hc_attackmode = tasksForm.hc_attackmode.data
                task.hc_mask = tasksForm.mask.data
                task.loopback = False

                db.session.add(task)
                db.session.commit()
                flash(f'Task {tasksForm.name.data} updated!', 'success')
            # Hybrid Wordlist + Mask or Hybrid Mask + Wordlist
            elif tasksForm.hc_attackmode.data == 6 or tasksForm.hc_attackmode.data == 7:
                task.name = tasksForm.name.data
                task.wl_id = tasksForm.wl_id.data
                task.rule_id = None
                task.hc_attackmode = tasksForm.hc_attackmode.data
                task.hc_mask = tasksForm.mask.data
                task.loopback = False

                db.session.add(task)
                db.session.commit()
                flash(f'Task {tasksForm.name.data} updated!', 'success')
            else:
                flash('Attack Mode not supported... yet...', 'danger')
            if tasksForm.hc_attackmode.data in (0, 1, 3, 6, 7):
                log_event('task.edit', target=f'task:{task.id} {task.name!r}')
            return redirect(url_for('tasks.tasks_list'))
        else:
            tasksForm.name.data = task.name
            tasksForm.hc_attackmode.data = task.hc_attackmode
            tasksForm.wl_id.data = task.wl_id
            tasksForm.wl_id_2.data = task.wl_id_2
            tasksForm.rule_id.data = task.rule_id
            tasksForm.j_rule.data = task.j_rule
            tasksForm.k_rule.data = task.k_rule
            tasksForm.mask.data = task.hc_mask
            tasksForm.loopback.data = task.loopback

        return render_template('tasks_edit.html.j2', title='Tasks Edit', tasksForm=tasksForm, task=task, wordlists=wordlists, rules=rules)

    flash('You are unauthorized to edit this task.', 'danger')
    return redirect(url_for('tasks.tasks_list'))

def _task_group_task_ids(task_groups):
    """Set of task ids that belong to any task group. `TaskGroups.tasks` holds a
    JSON list of ints (see task_groups routes); parse it exactly rather than a
    substring match so task 1 isn't reported as a member because some group
    contains task 10. Shared by the list view (to show a padlock) and both delete
    paths (to skip in-group tasks) so the UI and backend agree."""
    ids = set()
    for tg in task_groups:
        try:
            parsed = json.loads(tg.tasks) if tg.tasks else []
        except (ValueError, TypeError):
            continue
        for tid in parsed:
            try:
                ids.add(int(tid))
            except (TypeError, ValueError):
                continue
    return ids


def _delete_task(task):
    """Delete one task row. Returns try_commit()'s result. Shared by the single
    (tasks_delete) and bulk (tasks_bulk_delete) delete paths."""
    db.session.delete(task)
    return try_commit(f'delete task {task.id}')


@tasks.route("/tasks/delete/<int:task_id>", methods=['POST'])
@login_required
def tasks_delete(task_id):
    """Function to delete task"""

    task = Tasks.query.get(task_id)
    if task is None:
        flash('Task not found — it may have already been deleted.', 'warning')
        return redirect(url_for('tasks.tasks_list'))
    task_groups = TaskGroups.query.all()
    if current_user.admin or task.owner_id == current_user.id:

        # Check if associated with JobTask (which implies its associated with a job)
        jobtasks = JobTasks.query.all()
        for jobtask in jobtasks:
            if jobtask.task_id == task_id:
                flash('Can not delete. Task is associated to one or more jobs.', 'danger')
                return redirect(url_for('tasks.tasks_list'))

        if task_id in _task_group_task_ids(task_groups):
            flash('Can not delete. The Task is associated to one or more Task Groups.', 'danger')
            return redirect(url_for('tasks.tasks_list'))

        task_target = f'task:{task.id} {task.name!r}'
        if not _delete_task(task):
            flash('Task could not be deleted — it may have already been removed.', 'danger')
            return redirect(url_for('tasks.tasks_list'))
        log_event('task.delete', target=task_target)
        flash('Task has been deleted!', 'success')
        return redirect(url_for('tasks.tasks_list'))
    else:
        flash('You are unauthorized to delete this task.', 'danger')
        return redirect(url_for('tasks.tasks_list'))


@tasks.route("/tasks/bulk_delete", methods=['POST'])
@login_required
def tasks_bulk_delete():
    """Delete several tasks at once (from the tasks list's bulk-select bar).

    Mirrors the UI selectability rule and the single-delete guards: a task is
    deletable only by its owner or an admin, and only when it isn't assigned to a
    job (nor to a task group). Each id is guarded independently -- one skip never
    aborts the batch -- and a per-outcome summary is flashed."""
    deleted = skipped_job = skipped_group = skipped_rights = skipped_missing = failed = 0
    job_task_ids = {jt.task_id for jt in JobTasks.query.all()}
    group_task_ids = _task_group_task_ids(TaskGroups.query.all())
    seen = set()
    for raw in request.form.getlist('task_ids'):
        try:
            task_id = int(raw)
        except (TypeError, ValueError):
            continue
        if task_id in seen:
            continue
        seen.add(task_id)

        task = Tasks.query.get(task_id)
        if task is None:
            skipped_missing += 1
            continue
        if not (current_user.admin or task.owner_id == current_user.id):
            skipped_rights += 1
            continue
        if task_id in job_task_ids:
            skipped_job += 1
            continue
        if task_id in group_task_ids:
            skipped_group += 1
            continue

        task_target = f'task:{task.id} {task.name!r}'
        if _delete_task(task):
            log_event('task.delete', target=task_target)
            deleted += 1
        else:
            failed += 1

    parts = []
    if deleted:
        parts.append(f'{deleted} deleted')
    if skipped_job:
        parts.append(f'{skipped_job} skipped — assigned to a job')
    if skipped_group:
        parts.append(f'{skipped_group} skipped — in a task group')
    if skipped_rights:
        parts.append(f'{skipped_rights} skipped — insufficient rights')
    if skipped_missing:
        parts.append(f'{skipped_missing} skipped — not found')
    if failed:
        parts.append(f'{failed} failed')

    if not parts:
        flash('No tasks selected for deletion.', 'warning')
    elif deleted and not (skipped_job or skipped_group or skipped_rights or skipped_missing or failed):
        flash(', '.join(parts) + '.', 'success')
    elif deleted:
        flash(', '.join(parts) + '.', 'warning')
    else:
        flash(', '.join(parts) + '.', 'danger')
    return redirect(url_for('tasks.tasks_list'))
