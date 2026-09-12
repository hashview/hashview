"""Flask routes for the admin Logs viewer.

Renders the on-disk audit/error JSON-lines (written by hashview.utils.audit)
as Phosphor-styled tables. Read-only viewer + raw-file export; clearing the
logs lives in Settings -> Data management (settings.clear_logs).
"""
import json
import os
import re
from datetime import datetime

from flask import (
    Blueprint,
    abort,
    current_app,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)
from flask_login import current_user, login_required

from hashview.utils.audit import AUDIT_FILE, ERROR_FILE, logs_dir, read_log_entries

logs = Blueprint('logs', __name__)

# Audit action verb -> (badge label, phosphor badge color class)
_ACTION_BADGE = {
    'create': ('CREATE', 'green'),
    'edit': ('UPDATE', 'amber'),
    'delete': ('DELETE', 'red'),
    'login': ('LOGIN', 'cyan'),
    'login_failed': ('FAILED', 'red'),
    'password_reset': ('RESET', 'amber'),
    'password_reset_request': ('RESET', 'amber'),
    'admin_reset': ('RESET', 'amber'),
    'clear': ('CLEAR', 'dim'),
    # System-generated health events (scheduler). offline/recovered have been
    # emitted since agent_health_check landed but were never mapped, so they
    # rendered grey via the fallback.
    'offline': ('OFFLINE', 'red'),
    'recovered': ('RECOVERED', 'green'),
    'file_missing': ('MISSING', 'red'),
    'file_restored': ('RESTORED', 'green'),
    'restore': ('RESTORE', 'amber'),
}

# Entity (event noun) -> sidebar icon name (icons.html.j2)
_ENTITY_ICON = {
    'job': 'jobs', 'hashfile': 'file', 'wordlist': 'book', 'rule': 'rule',
    'customer': 'briefcase', 'user': 'users', 'task': 'task',
    'task_group': 'group', 'settings': 'settings', 'logs': 'list',
}


def _humanize(ts):
    """('HH:MM:SS', 'Ns ago') from an ISO-8601 ts; ('ts', '') on parse error."""
    try:
        dt = datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return (ts or '', '')
    local = dt.astimezone()
    now = datetime.now(dt.tzinfo) if dt.tzinfo else datetime.now()
    secs = max(0, int((now - dt).total_seconds()))
    if secs < 60:
        rel = f'{secs}s ago'
    elif secs < 3600:
        rel = f'{secs // 60}m ago'
    elif secs < 86400:
        rel = f'{secs // 3600}h ago'
    else:
        rel = f'{secs // 86400}d ago'
    return (local.strftime('%H:%M:%S'), rel)


def _parse_target(target):
    """'job:17 \\'Q2 audit\\'' -> ('job', '17', 'Q2 audit'); 'user:3 a@b.com' -> ('user','3','a@b.com')."""
    if not target:
        return ('', '', '')
    etype, _, rest = target.partition(':')
    rest = rest.strip()
    # rest is "<id> <name>": leading token is the id, the remainder is the name
    eid, _, name = rest.partition(' ')
    name = name.strip()
    if len(name) >= 2 and name[0] == name[-1] and name[0] in ("'", '"'):
        name = name[1:-1]
    return (etype.strip(), eid.strip(), name)


def _traceback_location(traceback):
    """Best-effort 'file:line' of the last frame in a Python traceback string."""
    if not traceback:
        return ''
    matches = re.findall(r'File "([^"]+)", line (\d+)', traceback)
    if not matches:
        return ''
    path, line = matches[-1]
    # Trim to the package-relative path when possible (e.g. hashview/jobs/routes.py).
    idx = path.rfind('hashview/')
    if idx != -1:
        path = path[idx:]
    return f'{path}:{line}'


def _decorate_audit(entry):
    """Shape a raw audit JSON record into display fields for the table."""
    event = entry.get('event') or ''
    verb = event.split('.', 1)[1] if '.' in event else event
    label, color = _ACTION_BADGE.get(verb, (verb.upper() or 'EVENT', 'dim'))
    etype, eid, ename = _parse_target(entry.get('target'))
    if not etype:
        etype = event.split('.', 1)[0]   # e.g. 'user' for user.login (no target)
    if not ename:
        ename = entry.get('detail') or '—'
    t, rel = _humanize(entry.get('ts'))
    actor = entry.get('actor') or 'system'
    search = ' '.join(str(x) for x in (
        t, label, etype, ename, actor, entry.get('ip'), event)).lower()
    return {
        'time': t, 'rel': rel, 'action': label, 'action_class': color,
        'entity_type': etype, 'entity_id': eid, 'entity_name': ename,
        'icon': _ENTITY_ICON.get(etype, 'list'),
        'actor': actor, 'actor_id': entry.get('actor_id'),
        'ip': entry.get('ip') or '—',
        'ts': entry.get('ts') or '',
        'outcome': entry.get('outcome') or '',
        'target': entry.get('target') or '', 'detail': entry.get('detail') or '',
        'action_key': verb, 'search': search,
        'raw_json': json.dumps(entry, indent=2, ensure_ascii=False),
    }


def _decorate_error(entry):
    """Shape a raw server.error JSON record into display fields."""
    target = entry.get('target') or ''
    method, _, path = target.partition(' ')
    detail = entry.get('detail') or ''
    # detail is repr(exception): "ZeroDivisionError('division by zero')"
    exc_class, _, rest = detail.partition('(')
    exc_class = exc_class.strip() or 'Error'
    exc_msg = rest.rstrip(')').strip().strip("'\"")
    t, rel = _humanize(entry.get('ts'))
    actor = entry.get('actor') or 'system'
    traceback = entry.get('traceback') or ''
    search = ' '.join(str(x) for x in (
        t, method, path, exc_class, exc_msg, actor)).lower()
    return {
        'time': t, 'rel': rel, 'method': method or 'GET', 'path': path or target,
        'exc_class': exc_class, 'exc_msg': exc_msg, 'actor': actor,
        'ip': entry.get('ip') or '—', 'ts': entry.get('ts') or '',
        'location': _traceback_location(traceback),
        'traceback': traceback, 'search': search,
        'raw_json': json.dumps(entry, indent=2, ensure_ascii=False),
    }


@logs.route('/logs', methods=['GET'])
@login_required
def logs_view():
    """Admin-only viewer for the on-disk audit + error logs."""
    if not current_user.admin:
        abort(403)
    view = 'error' if request.args.get('view') == 'error' else 'audit'
    audit_rows = [_decorate_audit(e) for e in read_log_entries(current_app, 'audit')]
    error_rows = [_decorate_error(e) for e in read_log_entries(current_app, 'error')]
    # Distinct action labels present, for the "All actions" dropdown.
    actions = sorted({r['action'] for r in audit_rows})
    return render_template(
        'logs.html.j2',
        title='Logs',
        view=view,
        audit_rows=audit_rows,
        error_rows=error_rows,
        audit_count=len(audit_rows),
        error_count=len(error_rows),
        actions=actions,
    )


@logs.route('/logs/download/<which>', methods=['GET'])
@login_required
def logs_download(which):
    """Download the raw audit.log or error.log as an attachment (admin only)."""
    if not current_user.admin:
        abort(403)
    if which not in ('audit', 'error'):
        abort(404)
    filename = ERROR_FILE if which == 'error' else AUDIT_FILE
    directory = logs_dir(current_app)
    if not os.path.exists(os.path.join(directory, filename)):
        # Nothing logged yet — bounce back rather than 404 the admin.
        return redirect(url_for('logs.logs_view', view=which))
    return send_from_directory(directory, filename, as_attachment=True,
                               download_name=filename, mimetype='application/json')
