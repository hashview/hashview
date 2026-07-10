import os

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename

from hashview.models import Hashes, Jobs, JobTasks, Rules, Tasks, Users, Wordlists, db
from hashview.rules.forms import RulesForm
from hashview.utils.audit import log_event
from hashview.utils.utils import get_filehash, get_linecount, save_file, try_commit

rules = Blueprint('rules', __name__)


def _rule_ttype(task):
    """Friendly attack-type label for a task (matches the Tasks/Wordlists views)."""
    if task.hc_attackmode == 0 and task.rule_id:
        return 'DICT + RULE'
    if task.hc_attackmode == 0:
        return 'DICTIONARY'
    if task.hc_attackmode == 1:
        return 'COMBINATOR'
    if task.hc_attackmode == 3:
        return 'MASK'
    if task.hc_attackmode in (6, 7):
        return 'HYBRID'
    return '?'

#############################################
# Rules
#############################################

@rules.route("/rules", methods=['GET'])
@login_required
def rules_list():
    rules = Rules.query.all()
    tasks = Tasks.query.all()
    jobs = Jobs.query.all()
    jobtasks = JobTasks.query.all()
    users = Users.query.all()

    # --- per-rule info-modal data ---
    wl_names = {w.id: w.name for w in Wordlists.query.all()}
    user_names = {u.id: (((u.first_name or '') + ' ' + (u.last_name or '')).strip() or '—')
                  for u in users}
    recovered_by_task = {
        row.task_id: row.recovered_count
        for row in Hashes.query.with_entities(
            Hashes.task_id, db.func.count(Hashes.id).label('recovered_count')
        ).filter(Hashes.cracked == '1').group_by(Hashes.task_id).all()
    }
    jobs_by_task = {}
    for jt in jobtasks:
        jobs_by_task.setdefault(jt.task_id, set()).add(jt.job_id)

    rule_used_tasks = {}   # rule.id -> [{name, wordlist, type, hits}]
    rule_hits = {}         # rule.id -> summed historical hits
    rule_task_count = {}   # rule.id -> number of tasks using it
    rule_job_count = {}    # rule.id -> number of distinct jobs using those tasks
    rule_owner = {}        # rule.id -> owner display name
    for rule in rules:
        used = [t for t in tasks if t.rule_id == rule.id]
        rows, job_ids, total = [], set(), 0
        for t in used:
            hits = recovered_by_task.get(t.id, 0)
            total += hits
            job_ids |= jobs_by_task.get(t.id, set())
            rows.append({
                'name': t.name,
                'wordlist': wl_names.get(t.wl_id),
                'type': _rule_ttype(t),
                'hits': hits,
            })
        rule_used_tasks[rule.id] = rows
        rule_hits[rule.id] = total
        rule_task_count[rule.id] = len(used)
        rule_job_count[rule.id] = len(job_ids)
        rule_owner[rule.id] = user_names.get(rule.owner_id, '—')

    return render_template('rules.html.j2', title='Rules', rules=rules, tasks=tasks, jobs=jobs,
                           jobtasks=jobtasks, users=users, rule_used_tasks=rule_used_tasks,
                           rule_hits=rule_hits, rule_task_count=rule_task_count,
                           rule_job_count=rule_job_count, rule_owner=rule_owner, rulesForm=RulesForm(),
                           form_err=session.pop('rules_form_err', None))

@rules.route("/rules/add", methods=['GET', 'POST'])
@login_required
def rules_add():
    """Add a rule. Reached two ways: the Upload-rule modal on the listing (posts
    from_modal=1) and the legacy standalone /rules/add page."""
    form = RulesForm()
    if form.validate_on_submit() and form.rules.data:
        rules_path = os.path.join(current_app.root_path, save_file('control/rules', form.rules.data))

        rule = Rules(   name=form.name.data,
                        owner_id=current_user.id,
                        path=rules_path,
                        size=get_linecount(rules_path),
                        checksum=get_filehash(rules_path))
        db.session.add(rule)
        db.session.commit()
        log_event('rule.create', target=f'rule:{rule.id} {rule.name!r}')
        flash('Rules File created!', 'success')
        return redirect(url_for('rules.rules_list'))
    # Validation failed (or no file chosen). From the modal → reopen it on the
    # listing with the error inside (the file input can't be re-populated, so the
    # user re-picks it); from the legacy standalone page → re-render that page.
    if request.form.get('from_modal'):
        errors = [e for errs in form.errors.values() for e in errs]
        if not form.rules.data:
            errors.append('Please choose a .rule file to upload.')
        session['rules_form_err'] = {
            'modal': 'upload-rule-modal',
            'values': {},
            'errors': errors,
        }
        return redirect(url_for('rules.rules_list'))
    return render_template('rules_add.html.j2', title='Rules Add', form=form)

@rules.route("/rules/edit/<int:rule_id>", methods=['GET', 'POST'])
@login_required
def rules_view(rule_id):
    rule = Rules.query.get(rule_id)
    if rule is None:
        flash('Rule not found — it may have already been deleted.', 'warning')
        return redirect(url_for('rules.rules_list'))
    # Read file content
    try:
        with open(rule.path) as f:
            content = f.read()
    except Exception as e:
        flash(f'Error reading file: {e}', 'danger')
        return redirect(url_for('rules.rules_list'))

    can_edit = current_user.admin or rule.owner_id == current_user.id

    if request.method == 'POST':
        if not can_edit:
            flash('Unauthorized action!', 'danger')
            return redirect(url_for('rules.rules_view', rule_id=rule.id))
        new_content = request.form.get('content')
        try:
            with open(rule.path, 'w') as f:
                f.write(new_content)
            # Update metadata
            rule.size = get_linecount(rule.path)
            rule.checksum = get_filehash(rule.path)
            db.session.commit()
            log_event('rule.edit', target=f'rule:{rule.id} {rule.name!r}')
            flash('Rule file updated.', 'success')
        except Exception as e:
            flash(f'Error saving file: {e}', 'danger')
        return redirect(url_for('rules.rules_view', rule_id=rule.id))

    return render_template('rules_edit.html.j2', rule=rule, content=content, can_edit=can_edit)
 

@rules.route("/rules/download/<int:rule_id>", methods=['GET'])
@login_required
def rules_download(rule_id):
    """Deliver a rule file's contents."""
    rule = Rules.query.get_or_404(rule_id)
    if not rule.path or not os.path.exists(rule.path):
        flash('Rule file not found on disk.', 'danger')
        return redirect(url_for('rules.rules_list'))

    directory = os.path.dirname(os.path.abspath(rule.path))
    filename = os.path.basename(rule.path)
    download_name = secure_filename(rule.name) or 'rules'
    if not download_name.endswith('.rule'):
        download_name += '.rule'
    return send_from_directory(directory, filename, as_attachment=True,
                               download_name=download_name)


@rules.route("/rules/delete/<int:rule_id>", methods=['GET', 'POST'])
@login_required
def rules_delete(rule_id):
    rule = Rules.query.get(rule_id)
    if rule is None:
        flash('Rule not found — it may have already been deleted.', 'warning')
        return redirect(url_for('rules.rules_list'))
    if current_user.admin or rule.owner_id == current_user.id:
        # Check if part of a task
        tasks = Tasks.query.filter_by(rule_id=rule.id).first()
        if tasks:
            flash('Rule is currently used in a task and can not be deleted.', 'danger')
            return redirect(url_for('rules.rules_list'))
        rule_target = f'rule:{rule.id} {rule.name!r}'
        db.session.delete(rule)
        if not try_commit(f'delete rule {rule_id}'):
            flash('Rule could not be deleted — it may have already been removed.', 'danger')
            return redirect(url_for('rules.rules_list'))
        log_event('rule.delete', target=rule_target)
        flash('Rule file has been deleted!', 'success')
    else:
        flash('Unauthorized action!', 'danger')
    return redirect(url_for('rules.rules_list'))
