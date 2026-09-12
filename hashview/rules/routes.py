import os
import secrets
from datetime import datetime

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
from hashview.rules.forms import RuleContentForm, RuleRestoreForm, RulesForm
from hashview.utils.audit import log_event
from hashview.utils.utils import (
    apply_name_filter,
    get_filehash,
    get_linecount,
    missing_rule_ids,
    remove_rule_file,
    resolve_control_file,
    rule_file_missing,
    save_file,
    try_commit,
)

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
    # Pagination, sorting, and filtering mirror /tasks. The filter is applied
    # to the query before .paginate() so it searches every rule rather than
    # only the ones this page happens to render.
    page = request.args.get('page', 1, type=int) or 1
    per_page = 20

    sort_by = request.args.get('sort_by', 'name', type=str)
    sort_order = request.args.get('sort_order', 'asc', type=str)
    descending = sort_order == 'desc'
    name_filter = request.args.get('q', '', type=str).strip()

    if sort_by == 'size':
        query = Rules.query.order_by(
            Rules.size.desc() if descending else Rules.size.asc())
    elif sort_by == 'owner':
        query = Rules.query.join(Users, Rules.owner_id == Users.id).order_by(
            Users.first_name.desc() if descending else Users.first_name.asc())
    elif sort_by == 'last_updated':
        query = Rules.query.order_by(
            Rules.last_updated.desc() if descending else Rules.last_updated.asc())
    else:
        # Default (and any unrecognised sort_by): by rule name.
        sort_by = 'name'
        query = Rules.query.order_by(
            Rules.name.desc() if descending else Rules.name.asc())

    query = apply_name_filter(query, Rules.name, name_filter)
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    rules = pagination.items

    users = Users.query.all()

    # --- per-rule info-modal data, for the rules on this page only ---
    # Scoped to pagination.items so the cost is bounded by page size rather
    # than by the size of the rules table.
    # Catalog health (#383). The missing set is global -- unfiltered and
    # unpaginated -- so the page header can report the whole table, not just
    # this page; it is a handful of stats either way. rule_bytes stays scoped
    # to the rendered rows, since it is only read by their info modals.
    missing_rules = missing_rule_ids()
    rule_bytes = {}
    for r in rules:
        src_path = resolve_control_file(r.path, 'rules')
        if src_path:
            try:
                rule_bytes[r.id] = os.path.getsize(src_path)
            except OSError:
                pass

    rule_ids = [r.id for r in rules]
    tasks = (Tasks.query.filter(Tasks.rule_id.in_(rule_ids)).all()
             if rule_ids else [])
    tasks_by_rule = {}
    for t in tasks:
        tasks_by_rule.setdefault(t.rule_id, []).append(t)

    task_ids = [t.id for t in tasks]
    wl_names = {w.id: w.name for w in Wordlists.query.all()}
    user_names = {u.id: (((u.first_name or '') + ' ' + (u.last_name or '')).strip() or '—')
                  for u in users}
    recovered_by_task = {
        row.task_id: row.recovered_count
        for row in Hashes.query.with_entities(
            Hashes.task_id, db.func.count(Hashes.id).label('recovered_count')
        ).filter(Hashes.cracked == '1',
                 Hashes.task_id.in_(task_ids)).group_by(Hashes.task_id).all()
    } if task_ids else {}
    jobs_by_task = {}
    if task_ids:
        for jt in JobTasks.query.filter(JobTasks.task_id.in_(task_ids)).all():
            jobs_by_task.setdefault(jt.task_id, set()).add(jt.job_id)

    # Jobs referenced by those tasks, for the delete dialog's blocker list: an
    # operator needs the job to unpick before the task can be edited or deleted.
    job_ids = {jid for ids in jobs_by_task.values() for jid in ids}
    jobs_by_id = {j.id: j for j in Jobs.query.filter(Jobs.id.in_(job_ids)).all()} if job_ids else {}

    rule_used_tasks = {}   # rule.id -> [{id, name, wordlist, type, hits, jobs}]
    rule_hits = {}         # rule.id -> summed historical hits
    rule_task_count = {}   # rule.id -> number of tasks using it
    rule_job_count = {}    # rule.id -> number of distinct jobs using those tasks
    rule_owner = {}        # rule.id -> owner display name
    for rule in rules:
        used = tasks_by_rule.get(rule.id, [])
        rows, job_ids, total = [], set(), 0
        for t in used:
            hits = recovered_by_task.get(t.id, 0)
            total += hits
            job_ids |= jobs_by_task.get(t.id, set())
            rows.append({
                'id': t.id,
                'name': t.name,
                'wordlist': wl_names.get(t.wl_id),
                'type': _rule_ttype(t),
                'hits': hits,
                'jobs': [{'id': j.id, 'name': j.name, 'status': j.status}
                         for j in (jobs_by_id.get(jid) for jid in sorted(jobs_by_task.get(t.id, set())))
                         if j is not None],
            })
        rule_used_tasks[rule.id] = rows
        rule_hits[rule.id] = total
        rule_task_count[rule.id] = len(used)
        rule_job_count[rule.id] = len(job_ids)
        rule_owner[rule.id] = user_names.get(rule.owner_id, '—')

    return render_template('rules.html.j2', title='Rules', rules=rules,
                           users=users, rule_used_tasks=rule_used_tasks,
                           rule_hits=rule_hits, rule_task_count=rule_task_count,
                           rule_job_count=rule_job_count, rule_owner=rule_owner, rulesForm=RulesForm(),
                           pagination=pagination, sort_by=sort_by, sort_order=sort_order,
                           name_filter=name_filter,
                           missing_rule_ids=missing_rules, rule_bytes=rule_bytes,
                           ruleRestoreForm=RuleRestoreForm(),
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
    # Read file content. A file that is GONE yields an empty editor rather than
    # bailing out: that turns this route into the in-place restore for a
    # stranded row (issue #383), and it is what makes the startup backfill's
    # own advice -- "re-upload the wordlist to restore it" -- actually possible
    # for rules without minting a new row and orphaning every task reference.
    # A file that is present but unreadable still bails; that is a real error.
    src_path = resolve_control_file(rule.path, 'rules')
    file_missing = src_path is None
    content = ''
    if not file_missing:
        try:
            with open(src_path) as f:
                content = f.read()
        except Exception as e:
            flash(f'Error reading file: {e}', 'danger')
            return redirect(url_for('rules.rules_list'))

    can_edit = current_user.admin or rule.owner_id == current_user.id
    contentForm = RuleContentForm()

    if request.method == 'POST':
        if not can_edit:
            flash('Unauthorized action!', 'danger')
            return redirect(url_for('rules.rules_view', rule_id=rule.id))
        # Gate on the form, not request.form: this route WRITES (and, since the
        # #383 work, creates) a file under control/rules, and there is no global
        # CSRFProtect -- so reading the textarea directly left it drivable from
        # any page an owner or admin happened to visit.
        if not contentForm.validate_on_submit():
            flash('Could not save the rule file — the form was invalid or expired. '
                  'Please try again.', 'danger')
            return redirect(url_for('rules.rules_view', rule_id=rule.id))
        new_content = contentForm.content.data or ''
        # This route can now CREATE a file, so normalize the write target into
        # control/rules the way remove_rule_file does. That keeps a crafted or
        # legacy path from writing outside the rules directory, and self-heals a
        # row whose stored path was relative.
        dest_path = os.path.join(current_app.root_path, 'control/rules',
                                 os.path.basename(rule.path or ''))
        try:
            with open(dest_path, 'w') as f:
                f.write(new_content)
            # Update metadata
            rule.path = dest_path
            rule.size = get_linecount(dest_path)
            rule.checksum = get_filehash(dest_path)
            db.session.commit()
            if file_missing:
                log_event('rule.restore', target=f'rule:{rule.id} {rule.name!r}',
                          detail=f'path={dest_path}')
                flash('Rule file restored. Every task that uses it works again.', 'success')
            else:
                log_event('rule.edit', target=f'rule:{rule.id} {rule.name!r}')
                flash('Rule file updated.', 'success')
        except Exception as e:
            flash(f'Error saving file: {e}', 'danger')
        return redirect(url_for('rules.rules_view', rule_id=rule.id))

    return render_template('rules_edit.html.j2', rule=rule, content=content,
                           can_edit=can_edit, file_missing=file_missing,
                           form=contentForm)
 

@rules.route("/rules/<int:rule_id>/restore", methods=['POST'])
@login_required
def rules_restore(rule_id):
    """Replace a rule's file IN PLACE, keeping the row's id and path (#383).

    The remedy for a row that outlived its file while tasks still reference it.
    Re-uploading through rules_add cannot fix that case -- it always mints a new
    row and a new path, so the stale Tasks.rule_id is orphaned further.

    Owner-or-admin, deliberately not admin-only: restoring a file is strictly
    less destructive than the delete the owner can already do, and admin-gating
    it would funnel every routine re-upload through an admin.
    """
    rule = Rules.query.get(rule_id)
    if rule is None:
        flash('Rule not found — it may have already been deleted.', 'warning')
        return redirect(url_for('rules.rules_list'))
    if not (current_user.admin or rule.owner_id == current_user.id):
        flash('Unauthorized action!', 'danger')
        return redirect(url_for('rules.rules_list'))

    form = RuleRestoreForm()
    if not form.validate_on_submit() or not form.rules.data:
        flash('Please choose a .rule file to restore from.', 'danger')
        return redirect(url_for('rules.rules_list'))

    # Stage under control/tmp and os.replace() onto the stored path, so a failed
    # upload can never destroy a file that is still good. The basename is
    # preserved, which is what keeps build_hashcat_command emitting the same
    # agent-side path -- and therefore what keeps materialized JobTasks.command
    # strings valid across the restore.
    tmp_path = os.path.join(current_app.root_path, 'control/tmp', secrets.token_hex(8))
    dest_path = os.path.join(current_app.root_path, 'control/rules',
                             os.path.basename(rule.path or ''))
    if not os.path.basename(dest_path):
        dest_path = os.path.join(current_app.root_path, 'control/rules',
                                 secrets.token_hex(8) + '.txt')
    try:
        form.rules.data.save(tmp_path)
        os.replace(tmp_path, dest_path)
    except Exception:
        current_app.logger.exception('Failed to restore rule file for rule %s', rule_id)
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        flash('Rule file could not be restored.', 'danger')
        return redirect(url_for('rules.rules_list'))

    rule.path = dest_path
    rule.size = get_linecount(dest_path)
    rule.checksum = get_filehash(dest_path)
    rule.last_updated = datetime.today()
    if not try_commit(f'restore rule {rule_id}'):
        flash('Rule file could not be restored.', 'danger')
        return redirect(url_for('rules.rules_list'))
    log_event('rule.restore', target=f'rule:{rule.id} {rule.name!r}',
              detail=f'path={dest_path}')
    flash('Rule file restored. Every task that uses it works again.', 'success')
    return redirect(url_for('rules.rules_list'))


@rules.route("/rules/download/<int:rule_id>", methods=['GET'])
@login_required
def rules_download(rule_id):
    """Deliver a rule file's contents."""
    rule = Rules.query.get_or_404(rule_id)
    # Resolve through the shared helper rather than stat'ing rule.path directly:
    # the stored path can be relative (seeded rows) and only control/rules is
    # ever served from, so this agrees with GET /v1/rules/<id> and the missing
    # badge on the listing (issue #383).
    src_path = resolve_control_file(rule.path, 'rules')
    if src_path is None:
        flash('Rule file not found on disk.', 'danger')
        return redirect(url_for('rules.rules_list'))

    directory = os.path.dirname(src_path)
    filename = os.path.basename(src_path)
    download_name = secure_filename(rule.name) or 'rules'
    if not download_name.endswith('.rule'):
        download_name += '.rule'
    return send_from_directory(directory, filename, as_attachment=True,
                               download_name=download_name)


# POST only. This used to accept GET as well, which -- with no global
# CSRFProtect -- made a single <img src="/rules/delete/1"> on any page a
# cross-site delete. Every caller already POSTs, so dropping GET is a no-op for
# legitimate use.
@rules.route("/rules/delete/<int:rule_id>", methods=['POST'])
@login_required
def rules_delete(rule_id):
    rule = Rules.query.get(rule_id)
    if rule is None:
        flash('Rule not found — it may have already been deleted.', 'warning')
        return redirect(url_for('rules.rules_list'))
    if current_user.admin or rule.owner_id == current_user.id:
        # Check if part of a task
        task_count = Tasks.query.filter_by(rule_id=rule.id).count()
        if task_count:
            # Name the count: "can not be deleted" on its own is a dead end, and
            # the delete dialog now lists which tasks (and their jobs) block it.
            flash(f'Rule is used by {task_count} task'
                  f'{"" if task_count == 1 else "s"} and can not be deleted.', 'danger')
            return redirect(url_for('rules.rules_list'))
        # Capture the path before the row goes: the row is removed first so a
        # failed unlink only orphans a file, rather than leaving a row that
        # points at nothing (same order as wordlists_delete).
        rule_path = rule.path
        rule_target = f'rule:{rule.id} {rule.name!r}'
        file_was_missing = rule_file_missing(rule)
        db.session.delete(rule)
        if not try_commit(f'delete rule {rule_id}'):
            flash('Rule could not be deleted — it may have already been removed.', 'danger')
            return redirect(url_for('rules.rules_list'))
        log_event('rule.delete', target=rule_target)
        remove_rule_file(rule_path)
        if file_was_missing:
            flash('Rule deleted (its file was already gone from disk).', 'success')
        else:
            flash('Rule file has been deleted!', 'success')
    else:
        flash('Unauthorized action!', 'danger')
    return redirect(url_for('rules.rules_list'))
