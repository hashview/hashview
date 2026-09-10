"""Flask routes to handle Settings"""
import os
import re
from datetime import datetime

from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    stream_with_context,
    url_for,
)
from flask_login import current_user, login_required
from sqlalchemy import func

import hashview
from hashview.models import Hashes, Settings, db
from hashview.settings.forms import DatabaseBackupForm, HashviewSettingsForm
from hashview.utils.audit import clear_logs_on_disk, log_event, logs_dir
from hashview.utils.backup import (
    BackupError,
    create_encrypted_db_backup,
    purge_stale_backups,
)
from hashview.utils.hashcat_modes import hash_type_names
from hashview.utils.utils import send_slack_channel

# control/tmp filename of a generated backup, e.g. '1a2b3c4d5e6f7a8b.sql.gz.enc'
_BACKUP_TOKEN_RE = re.compile(r'^[0-9a-f]{16}\.sql\.gz\.enc$')

# A hashcat mode as it may arrive in a query string. ASCII digits only, and short
# enough that the value stays inside MySQL's signed INT range -- see the comment in
# settings_hashes_download for why neither half of that is optional.
_MODE_RE = re.compile(r'^[0-9]{1,7}$')


settings = Blueprint('settings', __name__)


def _human_size(num):
    """Human-readable byte size (e.g. 12.1 KB, 4.8 MB, 1.3 GB)."""
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if num < 1024 or unit == 'TB':
            if unit == 'B':
                return '%d B' % num
            return (f'{num:.1f} {unit}').replace('.0 ', ' ')
        num /= 1024.0


# Export flavours for the Data-management hashes table. Each maps to one column
# of that table, so the link under a figure downloads exactly the rows it counts.
_HASH_EXPORT_TYPES = ('all', 'found', 'left')

# Exports are paged on the primary key rather than fetched in one go: this table
# covers the whole corpus (869k rows on this instance) and the mysqlconnector
# dialect reports supports_server_side_cursors = False, so yield_per() cannot
# stop the driver from buffering the entire result set client-side -- measured at
# a 114 MB peak for the largest export. Keyset paging keeps that flat at ~4 MB
# for ~28% more wall-clock, and works the same on SQLite. 5,000 was measured
# against 20,000, which cost 3x the memory for no time saved.
_HASH_EXPORT_BATCH = 5000


def _hashes_rollup():
    """Per-hash_type totals straight from the ``hashes`` table.

    No join to hashfile_hashes: `hashes` already holds one row per unique
    (sub_ciphertext, hash_type), so a hash shared by several hashfiles is counted
    once. That makes these figures deliberately different from the per-customer
    numbers on /analytics, which count accounts.

    Two grouped queries rather than one COUNT + SUM(CASE WHEN cracked). Measured
    on a 869k-row table, the single-query form takes ~2.8s: it scans
    ix_hashes_hash_type but has to fetch `cracked` from the clustered row for
    every one of those rows. Splitting it lets each half stay index-only -- the
    totals are covered by ix_hashes_hash_type, and the cracked counts range-scan
    ix_hashes_cracked_recovered_at over the (much smaller) cracked partition.
    Same numbers, ~400ms. Neither index is new; nothing on the insert path pays
    for this page.

    Returns ``(rows, total, cracked)`` with rows ordered by size, each a dict of
    mode / name / total / cracked / uncracked.
    """
    names = hash_type_names(short=False)
    totals = db.session.query(
        Hashes.hash_type, func.count(Hashes.id),
    ).group_by(Hashes.hash_type).all()
    cracked_counts = dict(db.session.query(
        Hashes.hash_type, func.count(Hashes.id),
    ).filter(Hashes.cracked == 1).group_by(Hashes.hash_type).all())

    rows = []
    for hash_type, total in totals:
        total = int(total or 0)
        cracked = int(cracked_counts.get(hash_type) or 0)
        mode = '' if hash_type is None else str(hash_type)
        rows.append({
            'mode': mode,
            # LM (3000) is deliberately absent from the mode tables, and a row
            # could carry any mode at all via the API, so fall back to the number.
            'name': names.get(mode, 'mode ' + mode if mode else 'unknown'),
            'total': total,
            'cracked': cracked,
            'uncracked': total - cracked,
        })
    rows.sort(key=lambda row: (-row['total'], row['mode']))
    return rows, sum(r['total'] for r in rows), sum(r['cracked'] for r in rows)


#############################################
# Settings
#############################################

@settings.route("/settings", methods=['GET', 'POST'])
@login_required
def settings_list():
    """Function to return list of Settings"""

    if current_user.admin:
        hashview_form = HashviewSettingsForm()
        settings = Settings.query.first()

        tmp_folder_size = 0
        for file in os.scandir('hashview/control/tmp/'):
            tmp_folder_size += os.stat(file).st_size
        tmp_folder_size = _human_size(tmp_folder_size)

        audit_logs_size = 0
        _logs_dir = logs_dir(current_app)
        if os.path.isdir(_logs_dir):
            for file in os.scandir(_logs_dir):
                audit_logs_size += os.stat(file).st_size
        audit_logs_size = _human_size(audit_logs_size)

        if hashview_form.validate_on_submit():
            settings.retention_period = hashview_form.retention_period.data
            settings.max_runtime_jobs = hashview_form.max_runtime_jobs.data
            settings.max_runtime_tasks = hashview_form.max_runtime_tasks.data
            settings.agent_timeout_minutes = hashview_form.agent_timeout_minutes.data
            settings.enabled_job_weights = hashview_form.enabled_job_weights.data
            settings.enabled_chunking = hashview_form.enabled_chunking.data
            settings.chunk_target_duration = hashview_form.chunk_target_duration.data
            settings.email_enabled = hashview_form.email_enabled.data
            settings.pushover_enabled = hashview_form.pushover_enabled.data
            settings.slack_enabled = hashview_form.slack_enabled.data
            settings.slack_bot_token = hashview_form.slack_bot_token.data
            settings.slack_admin_channel = hashview_form.slack_admin_channel.data or None
            # --- Authentication (local / Azure Entra ID SSO) ---
            # Only assign when the POST carried a valid choice; otherwise keep
            # the stored value (a partial save must not silently flip modes).
            if hashview_form.auth_method.data in ('local', 'azure'):
                settings.auth_method = hashview_form.auth_method.data
            settings.azure_tenant_id = hashview_form.azure_tenant_id.data or None
            settings.azure_client_id = hashview_form.azure_client_id.data or None
            settings.azure_redirect_uri = hashview_form.azure_redirect_uri.data or None
            settings.azure_allowed_groups = hashview_form.azure_allowed_groups.data or None
            # Write-only secret: only overwrite when a new value was actually typed,
            # so re-saving the page doesn't blank the stored secret.
            if hashview_form.azure_client_secret.data:
                settings.azure_client_secret = hashview_form.azure_client_secret.data
            # Never lock everyone out: if azure is selected but the config is
            # incomplete, keep auth local and warn (the id=1 break-glass + the
            # local form stay available).
            if settings.auth_method == 'azure' and not (
                    settings.azure_tenant_id and settings.azure_client_id and settings.azure_client_secret):
                settings.auth_method = 'local'
                flash('Azure mode needs a tenant ID, client ID, and client secret. '
                      'Other settings saved; authentication stays Local until the Azure config is complete.', 'warning')
            else:
                flash('Updated Hashview settings!', 'success')
            db.session.commit()
            return redirect(url_for('settings.settings_list'))
        elif request.method == 'GET':
            hashview_form.retention_period.data = settings.retention_period
            hashview_form.max_runtime_jobs.data = settings.max_runtime_jobs
            hashview_form.max_runtime_tasks.data = settings.max_runtime_tasks
            hashview_form.agent_timeout_minutes.data = settings.agent_timeout_minutes
            hashview_form.enabled_job_weights.data = settings.enabled_job_weights
            hashview_form.enabled_chunking.data = settings.enabled_chunking
            hashview_form.chunk_target_duration.data = settings.chunk_target_duration
            hashview_form.email_enabled.data = settings.email_enabled
            hashview_form.pushover_enabled.data = settings.pushover_enabled
            hashview_form.slack_enabled.data = settings.slack_enabled
            hashview_form.slack_bot_token.data = settings.slack_bot_token
            hashview_form.slack_admin_channel.data = settings.slack_admin_channel
            hashview_form.auth_method.data = settings.auth_method
            hashview_form.azure_tenant_id.data = settings.azure_tenant_id
            hashview_form.azure_client_id.data = settings.azure_client_id
            hashview_form.azure_redirect_uri.data = settings.azure_redirect_uri
            hashview_form.azure_allowed_groups.data = settings.azure_allowed_groups
            # azure_client_secret is write-only — never echo it back to the page.

        # Only on the render path -- a successful POST redirects, and this is the
        # one part of the page that costs a couple of grouped queries.
        hashes_rows, hashes_total, hashes_cracked = _hashes_rollup()

        try:
            database_version = db.session.execute('SELECT version_num FROM alembic_version LIMIT 1;').scalar()
        except Exception:
            database_version = 'error'

        # The exact HTTPS callback to register in the Azure App Registration.
        default_azure_redirect = url_for('auth.azure_callback', _external=True, _scheme='https')

        return render_template(
            'settings.html.j2',
            title               = 'settings',
            settings            = settings,
            HashviewForm        = hashview_form,
            backupForm          = DatabaseBackupForm(),
            tmp_folder_size     = tmp_folder_size,
            audit_logs_size     = audit_logs_size,
            hashes_rows         = hashes_rows,
            hashes_total        = hashes_total,
            hashes_cracked      = hashes_cracked,
            application_version = hashview.__version__,
            database_version    = database_version,
            default_azure_redirect = default_azure_redirect,
            azure_secret_set    = bool(settings.azure_client_secret),
        )

    abort(403)


@settings.route("/settings/send_test_admin_slack", methods=['GET'])
@login_required
def send_test_admin_slack():
    """Send a test administrative notification to the configured Slack room."""
    if not current_user.admin:
        abort(403)
    settings_row = Settings.query.first()
    if not settings_row or not settings_row.slack_admin_channel:
        flash('Set a Slack administrative room first.', 'danger')
        return redirect(url_for('settings.settings_list'))
    send_slack_channel(settings_row.slack_admin_channel,
                        'Test Administrative Message From Hashview',
                        'This is a test administrative Slack message from Hashview.')
    flash('Test administrative Slack message sent.', 'success')
    return redirect(url_for('settings.settings_list'))


@settings.route("/settings/backup", methods=['POST'])
@login_required
def settings_backup():
    """Generate an encrypted, gzip-compressed mysqldump of the whole database.

    Returns JSON with the one-time decryption password, a one-time download
    URL, the ciphertext sha256, and decrypt instructions. The password is only
    ever placed in this response body — never logged.
    """
    if not current_user.admin:
        abort(403)
    form = DatabaseBackupForm()
    if not form.validate_on_submit():
        return jsonify({'status': 'error', 'msg': 'Invalid or expired session token. Reload the page and try again.'}), 400

    tmp_dir = os.path.join(current_app.root_path, 'control/tmp')
    purge_stale_backups(tmp_dir)        # reap any previous undownloaded backups
    try:
        enc_path, password, sha256 = create_encrypted_db_backup(
            current_app.config['SQLALCHEMY_DATABASE_URI'], tmp_dir)
    except BackupError as exc:
        return jsonify({'status': 'error', 'msg': str(exc)}), 500
    except Exception:
        current_app.logger.exception('Database backup failed.')   # never logs the password
        return jsonify({'status': 'error', 'msg': 'Backup failed — check the server logs.'}), 500

    token = os.path.basename(enc_path)
    download_name = 'hashview-backup-' + datetime.utcnow().strftime('%Y%m%d-%H%M%S') + '.sql.gz.enc'
    instructions = [
        "Decrypt (you'll be prompted for the one-time password above):",
        "    openssl enc -d -aes-256-cbc -pbkdf2 -in " + download_name + " -out backup.sql.gz",
        "Decompress:",
        "    gunzip backup.sql.gz",
        "Restore (optional):",
        "    mysql -u <user> -p hashview < backup.sql",
        "Requires OpenSSL 1.1.1+ (the -pbkdf2 flag is mandatory on decrypt).",
    ]
    return jsonify({
        'status': 'ok',
        'password': password,
        'download_url': url_for('settings.settings_backup_download', token=token),
        'download_name': download_name,
        'sha256': sha256,
        'instructions': instructions,
    })


@settings.route("/settings/backup/download/<token>", methods=['GET'])
@login_required
def settings_backup_download(token):
    """Stream a previously generated encrypted backup as an attachment."""
    if not current_user.admin:
        abort(403)
    if not _BACKUP_TOKEN_RE.match(token):
        abort(404)
    tmp_dir = os.path.join(current_app.root_path, 'control/tmp')
    if not os.path.exists(os.path.join(tmp_dir, token)):
        abort(404)
    # Friendly, dated name derived from the file's own mtime (the token is opaque).
    try:
        stamp = datetime.utcfromtimestamp(os.path.getmtime(os.path.join(tmp_dir, token)))
        download_name = 'hashview-backup-' + stamp.strftime('%Y%m%d-%H%M%S') + '.sql.gz.enc'
    except OSError:
        download_name = 'hashview-backup.sql.gz.enc'
    return send_from_directory(tmp_dir, token, as_attachment=True,
                               download_name=download_name, mimetype='application/octet-stream')

@settings.route('/settings/clear_temp')
@login_required
def clear_temp_folder():
    """Function to clear temp folder"""
    if current_user.admin:
        for file in os.scandir('hashview/control/tmp/'):
            os.remove(file.path)
        flash('Temp folder cleared.', 'success')
        return redirect(url_for('settings.settings_list'))

    abort(403)


@settings.route('/settings/purge_cracked', methods=['POST'])
@login_required
def purge_cracked():
    """Permanently wipe all recovered plaintext: reset every cracked hash back to
    its uncracked state (clears plaintext + recovery metadata, keeps the hashes)."""
    if not current_user.admin:
        abort(403)
    count = Hashes.query.filter(Hashes.cracked == 1).update(
        {
            Hashes.plaintext: None,
            Hashes.cracked: 0,
            Hashes.recovered_at: None,
            Hashes.task_id: None,
            Hashes.recovered_by: None,
        },
        synchronize_session=False,
    )
    db.session.commit()
    flash(f'Purged {count:,} recovered password(s) — those hashes are now uncracked.', 'success')
    return redirect(url_for('settings.settings_list'))


@settings.route('/settings/clear_logs', methods=['POST'])
@login_required
def clear_logs():
    """Clear the on-disk audit + error logs (admin only).

    POST + CSRF (unlike clear_temp's GET) because wiping the audit trail is a
    sensitive action. The live audit.log/error.log are truncated in place
    rather than unlinked — the RotatingFileHandler holds an open fd, and
    deleting the path would leave it writing to an unlinked inode. Rotated
    *.log.N backups are removed outright. The clear is itself audited.
    """
    if not current_user.admin:
        abort(403)
    removed_backups = clear_logs_on_disk(current_app)
    # Audited after the clear, so this is the first line in the freshly-emptied log.
    log_event('logs.clear', detail=f'removed_backups={removed_backups}')
    flash('Audit and error logs cleared.', 'success')
    return redirect(url_for('settings.settings_list'))


@settings.route('/settings/hashes/download', methods=['GET'])
@login_required
def settings_hashes_download():
    """Stream the hashes behind one figure of the Data-management hashes table.

    ``type`` picks the column -- ``all`` every hash, ``found`` the recovered ones
    as ``ciphertext:plaintext``, ``left`` the ones still uncracked. ``mode``
    narrows to a single hash_type; omitted, it exports every mode (the table's
    summary tiles).

    Straight off ``hashes`` with no hashfile join, so the file holds exactly as
    many lines as the figure that linked to it: one per unique
    (sub_ciphertext, hash_type). Usernames live on hashfile_hashes and are
    therefore not in scope here -- /analytics is where per-customer,
    username-bearing exports come from.
    """
    if not current_user.admin:
        abort(403)

    export_type = request.args.get('type', 'all')
    if export_type not in _HASH_EXPORT_TYPES:
        abort(400)

    # Digits only, and converted to an int *here* rather than inside the generator.
    # Everything below runs while the response body is being iterated, after the 200
    # and the Content-Disposition header are already committed -- an exception there
    # cannot become the abort(400) this guard intends. It degrades to a bare 500, or
    # for a non-latin-1 filename it dies inside werkzeug's send_header and hangs the
    # request. So the whole class is settled before the Response is constructed.
    #
    # str.isdigit() on its own is not that check. It is also true for superscript
    # digits (U+00B2 SUPERSCRIPT TWO, which int() rejects outright) and for non-ASCII
    # decimal digits (U+0662 ARABIC-INDIC TWO, which int() reads as 2 while the raw
    # character stays in the filename). The 7-digit bound then keeps the value under
    # MySQL's signed INT ceiling, past which the driver raises DataError; hashcat's
    # highest real mode is five digits.
    mode = request.args.get('mode', '')
    if mode and not _MODE_RE.match(mode):
        abort(400)
    mode_int = int(mode) if mode else None

    def page(after_id):
        """One batch of rows with an id above ``after_id``, in id order.

        Ordering on the PK makes this a plain index range scan: MySQL appends the
        PK to every secondary index, so ix_hashes_hash_type already behaves as
        (hash_type, id) for the per-mode exports.
        """
        query = db.session.query(Hashes.id, Hashes.ciphertext, Hashes.plaintext) \
            .filter(Hashes.id > after_id)
        if mode_int is not None:
            query = query.filter(Hashes.hash_type == mode_int)
        if export_type == 'found':
            query = query.filter(Hashes.cracked == 1)
        elif export_type == 'left':
            query = query.filter(Hashes.cracked == 0)
        return query.order_by(Hashes.id).limit(_HASH_EXPORT_BATCH).all()

    log_event('hashes.export', detail=f'type={export_type} mode={mode or "all"}')

    def generate():
        after_id = 0
        while True:
            rows = page(after_id)
            if not rows:
                return
            for row_id, ciphertext, plaintext in rows:
                after_id = row_id
                if ciphertext is None:
                    continue
                if export_type == 'found':
                    # Cracked rows always carry a plaintext; an empty password is
                    # a legitimate value, so only a genuine NULL is skipped.
                    if plaintext is None:
                        continue
                    yield f'{ciphertext}:{plaintext}\n'
                else:
                    yield f'{ciphertext}\n'
            if len(rows) < _HASH_EXPORT_BATCH:
                return

    filename = f'hashes_{mode or "all"}_{export_type}.txt'
    return Response(
        stream_with_context(generate()),
        mimetype='text/plain',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'},
    )
