"""Flask routes to handle Wordlists"""
import os
import secrets
import threading

from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename

from hashview.models import Hashes, JobTasks, Rules, Tasks, Users, Wordlists, db
from hashview.utils.audit import log_event
from hashview.utils.utils import (
    ingest_static_wordlist_file,
    send_generated_file,
    try_commit,
    update_dynamic_wordlist,
)
from hashview.utils.wordlist_import import list_importable, run_import_async
from hashview.wordlists.forms import WordlistsForm

wordlists = Blueprint('wordlists', __name__)


def _wl_ttype(task):
    """Friendly attack-type label for a task (matches the Tasks/Task-Groups views)."""
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


@wordlists.route("/wordlists", methods=['GET'])
@login_required
def wordlists_list():
    """Function to present list of wordlists"""

    static_wordlists = Wordlists.query.filter_by(type='static').all()
    dynamic_wordlists = Wordlists.query.filter_by(type='dynamic').all()
    wordlists = Wordlists.query.all()
    tasks = Tasks.query.all()
    users = Users.query.all()

    # --- per-wordlist info-modal data ---
    rule_names = {r.id: r.name for r in Rules.query.all()}
    user_names = {u.id: (((u.first_name or '') + ' ' + (u.last_name or '')).strip() or '—')
                  for u in users}
    recovered_by_task = {
        row.task_id: row.recovered_count
        for row in Hashes.query.with_entities(
            Hashes.task_id, db.func.count(Hashes.id).label('recovered_count')
        ).filter(Hashes.cracked == '1').group_by(Hashes.task_id).all()
    }
    jobs_by_task = {}
    for jt in JobTasks.query.all():
        jobs_by_task.setdefault(jt.task_id, set()).add(jt.job_id)

    wl_used_tasks = {}   # wordlist.id -> [{name, rule, type, hits}]
    wl_hits = {}         # wordlist.id -> summed historical hits
    wl_task_count = {}   # wordlist.id -> number of tasks using it
    wl_job_count = {}    # wordlist.id -> number of distinct jobs using those tasks
    wl_owner = {}        # wordlist.id -> owner display name
    for wl in wordlists:
        used = [t for t in tasks if t.wl_id == wl.id or t.wl_id_2 == wl.id]
        rows, job_ids, total = [], set(), 0
        for t in used:
            hits = recovered_by_task.get(t.id, 0)
            total += hits
            job_ids |= jobs_by_task.get(t.id, set())
            rows.append({
                'name': t.name,
                'rule': rule_names.get(t.rule_id) if t.rule_id else None,
                'type': _wl_ttype(t),
                'hits': hits,
            })
        wl_used_tasks[wl.id] = rows
        wl_hits[wl.id] = total
        wl_task_count[wl.id] = len(used)
        wl_job_count[wl.id] = len(job_ids)
        wl_owner[wl.id] = user_names.get(wl.owner_id, '—')

    return render_template('wordlists.html.j2', title='Wordlists',
                           static_wordlists=static_wordlists, dynamic_wordlists=dynamic_wordlists,
                           wordlists=wordlists, tasks=tasks, users=users,
                           wl_used_tasks=wl_used_tasks, wl_hits=wl_hits,
                           wl_task_count=wl_task_count, wl_job_count=wl_job_count,
                           wl_owner=wl_owner, wordlistsForm=WordlistsForm(),
                           import_files=list_importable(current_app))


@wordlists.route("/wordlists/import", methods=['POST'])
@login_required
def wordlists_import():
    """Import selected wordlists that were scp'd into control/wordlists_import/.

    Runs in a background thread (the ingest of a multi-GB file is minutes of
    decompress/recompress and must not block the request). The imported
    wordlist is owned by the user who triggered the import."""
    # Only offer files that are present, pending, and quiescent (a file still
    # uploading is excluded both here and re-checked inside run_import).
    available = {f['name'] for f in list_importable(current_app)
                 if f['status'] == 'pending' and not f['uploading']}
    if request.form.get('all'):
        selected = available
    else:
        selected = {os.path.basename(s) for s in request.form.getlist('files')}
    to_import = sorted(available & selected)

    if not to_import:
        flash('Nothing to import — selected files are missing or still uploading.', 'warning')
        return redirect(url_for('wordlists.wordlists_list'))

    app = current_app._get_current_object()
    owner_id = current_user.id
    threading.Thread(target=run_import_async, args=(app, to_import, owner_id), daemon=True).start()
    flash(f'Import started for {len(to_import)} file(s) — they will appear in the list once '
          'processing finishes.', 'success')
    return redirect(url_for('wordlists.wordlists_list'))

@wordlists.route("/wordlists/add", methods=['GET', 'POST'])
@login_required
def wordlists_add():
    """Function to add new wordlist"""

    form = WordlistsForm()
    # The upload modal posts via XHR (so it can show live upload/compress
    # status) and sets this header; for those requests we answer with JSON
    # instead of a redirect. A plain (no-JS) form post still gets the
    # flash + redirect behaviour.
    is_ajax = request.headers.get('X-Requested-With') == 'fetch'

    if form.validate_on_submit():
        if form.wordlist.data:
            # Save the upload to control/tmp first, then ingest it into
            # compressed-at-rest storage. The ingest accepts plain text OR a
            # gzip file (validated); on an invalid gzip it raises and we reject.
            tmp_path = os.path.join(current_app.root_path, 'control/tmp', secrets.token_hex(8))
            form.wordlist.data.save(tmp_path)
            try:
                wordlist = ingest_static_wordlist_file(tmp_path, current_user.id, form.name.data)
            except Exception:
                if is_ajax:
                    return jsonify({'status': 'error',
                                    'msg': 'File is not a valid text or gzip wordlist.'}), 400
                flash('Upload failed: file is not a valid text or gzip wordlist.', 'danger')
                return redirect(url_for('wordlists.wordlists_list'))
            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            db.session.add(wordlist)
            db.session.commit()
            log_event('wordlist.create', target=f'wordlist:{wordlist.id} {wordlist.name!r}')
            flash('Wordlist created!', 'success')
            if is_ajax:
                # Flash above is shown after the modal reloads the page.
                return jsonify({'status': 'ok', 'msg': 'Done — wordlist created.',
                                'redirect': url_for('wordlists.wordlists_list')})
            return redirect(url_for('wordlists.wordlists_list'))
        elif is_ajax:
            return jsonify({'status': 'error', 'msg': 'No file was selected.'}), 400

    if is_ajax:
        # validation failed (missing name, bad/expired CSRF token, …)
        msg = '; '.join(m for errs in form.errors.values() for m in errs) or 'Invalid upload request.'
        return jsonify({'status': 'error', 'msg': msg}), 400
    return render_template('wordlists_add.html.j2', title='Wordlist Add', form=form)

@wordlists.route("/wordlists/delete/<int:wordlist_id>", methods=['POST'])
@login_required
def wordlists_delete(wordlist_id):
    """Function to delete wordlist"""

    wordlist = Wordlists.query.get(wordlist_id)
    if wordlist is None:
        flash('Wordlist not found — it may have already been deleted.', 'warning')
        return redirect(url_for('wordlists.wordlists_list'))
    if current_user.admin or wordlist.owner_id == current_user.id:

        # prevent deletion of dynamic list (must return — otherwise the row,
        # and now the file on disk, would be removed below)
        if wordlist.type == 'dynamic':
            flash('Dynamic Wordlists can not be deleted.', 'danger')
            return redirect(url_for('wordlists.wordlists_list'))

        # Check if associated with a Task
        tasks = Tasks.query.all()
        for task in tasks:
            if task.wl_id == wordlist_id:
                flash('Failed. Wordlist is associated to one or more tasks', 'danger')
                return redirect(url_for('wordlists.wordlists_list'))

        # Capture the on-disk path before the row is gone, remove the DB row,
        # then delete the stored (compressed) file from disk. Order is
        # DB-first so a failed unlink only orphans a file rather than leaving
        # a row that points at a missing file; the unlink is best-effort.
        wordlist_path = wordlist.path
        wordlist_target = f'wordlist:{wordlist.id} {wordlist.name!r}'
        db.session.delete(wordlist)
        if not try_commit(f'delete wordlist {wordlist_id}'):
            flash('Wordlist could not be deleted — it may have already been removed.', 'danger')
            return redirect(url_for('wordlists.wordlists_list'))
        log_event('wordlist.delete', target=wordlist_target)

        if wordlist_path and os.path.exists(wordlist_path):
            try:
                os.remove(wordlist_path)
            except OSError:
                current_app.logger.exception('Failed to remove wordlist file from disk: %s', wordlist_path)

        flash('Wordlist has been deleted!', 'success')
    else:
        flash('Unauthorized Action!', 'danger')
    return redirect(url_for('wordlists.wordlists_list'))


@wordlists.route("/wordlists/download/<int:wordlist_id>", methods=['GET'])
@login_required
def wordlists_download(wordlist_id):
    """Deliver a wordlist's contents. Static wordlists are stored compressed and
    served as-is (.gz); dynamic wordlists are regenerated from the database on
    demand and served uncompressed (.txt)."""
    wordlist = Wordlists.query.get_or_404(wordlist_id)

    if wordlist.type == 'dynamic':
        # Nothing keeps the canonical file at wordlist.path current -- only the
        # manual refresh button writes it, so on a fresh install it is still the
        # zero-byte seed placeholder. Regenerate instead, into a per-request
        # unique temp file rather than the shared path, so concurrent downloads
        # can't truncate the file out from under each other. The DB row's
        # size/checksum metadata is deliberately left alone; this mirrors
        # GET /v1/wordlists/<id>.
        tmp_dir = os.path.join(current_app.root_path, 'control/tmp')
        tmp_txt = os.path.join(tmp_dir, secrets.token_hex(8) + '.txt')
        update_dynamic_wordlist(wordlist_id, dest_path=tmp_txt)
        download_name = (secure_filename(wordlist.name) or 'wordlist') + '.txt'
        return send_generated_file(tmp_dir, os.path.basename(tmp_txt),
                                   as_attachment=True, download_name=download_name)

    if not wordlist.path or not os.path.exists(wordlist.path):
        flash('Wordlist file not found on disk.', 'danger')
        return redirect(url_for('wordlists.wordlists_list'))

    directory = os.path.dirname(os.path.abspath(wordlist.path))
    filename = os.path.basename(wordlist.path)
    ext = '.gz' if wordlist.path.endswith('.gz') else '.txt'
    download_name = (secure_filename(wordlist.name) or 'wordlist') + ext
    return send_from_directory(directory, filename, as_attachment=True,
                               download_name=download_name)


@wordlists.route("/wordlists/update/<int:wordlist_id>", methods=['GET'])
@login_required
def dynamicwordlist_update(wordlist_id):
    """Function to update dynamic wordlist"""

    wordlist = Wordlists.query.get(wordlist_id)
    if wordlist.type == 'dynamic':
        update_dynamic_wordlist(wordlist_id)
        flash('Updated Dynamic Wordlist', 'success')
    else:
        flash('Invalid wordlist', 'danger')
    return redirect(url_for('wordlists.wordlists_list'))
