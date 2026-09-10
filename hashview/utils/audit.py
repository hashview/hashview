"""On-disk audit / event logging.

Major events (authentication, CRUD on jobs/wordlists/rules/customers/hashfiles/
tasks/task groups, and unhandled server errors) are written as JSON-lines to
two size-rotated files under ``<package>/control/logs/``:

    audit.log  - auth + CRUD events (one JSON object per line)
    error.log  - unhandled exceptions that would yield an HTTP 500, with traceback

Each audit line carries a timestamp and the initiating user (resolved from the
Flask-Login session for web routes, or the ``uuid`` API-key cookie for the
``/v1`` API). Logging is best-effort: ``log_event`` never raises, so a logging
failure can never break a request.

The files are cleared by an admin from Settings -> Data management
(``settings.clear_logs``).
"""
import json
import logging
import os
from logging.handlers import RotatingFileHandler

from flask import got_request_exception, has_request_context, request

AUDIT_LOGGER = 'hashview.audit'
ERROR_LOGGER = 'hashview.error'
AUDIT_FILE = 'audit.log'
ERROR_FILE = 'error.log'

_MAX_BYTES = 5 * 1024 * 1024   # 5 MB per file before rotation
_BACKUPS = 5


def logs_dir(app):
    """Directory holding the audit/error logs for ``app``.

    Honors the ``HASHVIEW_LOGS_DIR`` config override (used by tests to point at
    a temp dir, and available to operators who want logs elsewhere); otherwise
    defaults to ``<package>/control/logs``.
    """
    override = app.config.get('HASHVIEW_LOGS_DIR')
    if override:
        return override
    return os.path.join(app.root_path, 'control', 'logs')


def read_log_entries(app, which='audit', limit=500):
    """Return parsed JSON-lines from the audit or error log, newest first.

    `which` is 'audit' or 'error'. Reads the live file only (current rotation),
    parses each non-blank line as JSON (silently skipping malformed lines), and
    returns at most `limit` entries, most-recent first. Returns [] if the file
    doesn't exist yet. Used by the admin Logs viewer.
    """
    filename = ERROR_FILE if which == 'error' else AUDIT_FILE
    path = os.path.join(logs_dir(app), filename)
    if not os.path.exists(path):
        return []
    entries = []
    with open(path, encoding='utf-8') as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except (ValueError, TypeError):
                continue   # skip a torn/partial line rather than failing the view
    entries.reverse()      # newest first
    return entries[:limit]


class _JsonFormatter(logging.Formatter):
    """Render one JSON object per log record.

    The event payload is passed through ``record.audit`` (wrapped in a single
    key so it can't collide with reserved ``LogRecord`` attributes). The
    timestamp reuses the app-wide ISO8601-with-tz ``formatTime`` monkeypatch
    installed in ``create_app`` so it matches the rest of Hashview's logs.
    """

    def format(self, record):
        payload = getattr(record, 'audit', None)
        if payload is None:
            payload = {'event': 'log', 'detail': record.getMessage()}
        payload = {'ts': self.formatTime(record), **payload}
        if record.exc_info:
            payload['traceback'] = self.formatException(record.exc_info)
        # default=str is a last-resort guard: a stray non-serializable value
        # must never raise inside the formatter and lose the line.
        return json.dumps(payload, ensure_ascii=False, default=str)


def _safe_remote_addr():
    return request.remote_addr if has_request_context() else None


def resolve_actor():
    """Return ``(email_or_None, id_or_None)`` for the acting user.

    Order: authenticated web session (Flask-Login) -> ``uuid`` API-key cookie
    -> anonymous. Safe to call outside a request context (scheduler/CLI), where
    it returns ``(None, None)``.
    """
    if not has_request_context():
        return (None, None)
    # 1) web session
    try:
        from flask_login import current_user
        if getattr(current_user, 'is_authenticated', False):
            return (getattr(current_user, 'email_address', None),
                    getattr(current_user, 'id', None))
    except Exception:  # nosec B110 - actor lookup is best-effort; fall through to api_key/anonymous
        pass
    # 2) api_key cookie
    try:
        uuid = request.cookies.get('uuid')
        if uuid:
            from hashview.models import Users
            user = Users.query.filter_by(api_key=uuid).first()
            if user:
                return (user.email_address, user.id)
    except Exception:  # nosec B110 - actor lookup is best-effort; fall through to anonymous
        pass
    # 3) anonymous / unauthenticated
    return (None, None)


def log_event(event, target=None, outcome='success', detail=None, actor=None):
    """Append one audit record to audit.log. Never raises.

    event   - dotted event name, e.g. 'job.create', 'user.login_failed'
    target  - the affected resource, e.g. "job:17 'Q2 audit'"
    outcome - 'success' | 'failure'
    detail  - free-form extra context (e.g. an attempted email on a failed login)
    actor   - explicit (email, id) tuple; auto-resolved from the request when None
    """
    try:
        if actor is None:
            actor_email, actor_id = resolve_actor()
        elif isinstance(actor, tuple):
            actor_email, actor_id = actor
        else:
            actor_email, actor_id = (actor, None)
        payload = {
            'event': event,
            'actor': actor_email,
            'actor_id': actor_id,
            'ip': _safe_remote_addr(),
            'target': target,
            'outcome': outcome,
            'detail': detail,
        }
        logging.getLogger(AUDIT_LOGGER).info(event, extra={'audit': payload})
    except Exception:  # nosec B110 - audit logging must never break a request
        # Logging must never break a request.
        pass


def pool_snapshot():
    """Current SQLAlchemy connection-pool counters, or ``None`` if unavailable.

    Pure introspection -- it reads the pool's own accounting and never opens a
    connection, which is what makes it safe to call from the handler for a
    *pool exhaustion* error. ``checkedout`` is the number in use and
    ``overflow`` how far past ``pool_size`` the pool has had to stretch
    (negative until it starts using the overflow), so together they say whether
    an exhaustion was real contention or simply an undersized pool.

    Returns whatever the pool implementation exposes: SQLite's
    SingletonThreadPool (the unit tests) has none of the QueuePool counters, so
    the dict is filtered down to the callables that actually exist.
    """
    try:
        from hashview.models import db
        pool = db.engine.pool
        snapshot = {'impl': type(pool).__name__}
        for name in ('size', 'checkedin', 'checkedout', 'overflow', 'timeout'):
            probe = getattr(pool, name, None)
            if callable(probe):
                snapshot[name] = probe()
        return snapshot
    except Exception:   # nosec B110 - diagnostics must never break error logging
        return None


def _is_connection_error(exception):
    """True for the SQLAlchemy errors whose diagnosis needs the pool counters.

    TimeoutError is the pool refusing to hand out a connection within
    pool_timeout; OperationalError covers the server-side equivalents ("too
    many connections", "server has gone away"). Imported lazily so this module
    stays importable without SQLAlchemy.
    """
    try:
        from sqlalchemy.exc import OperationalError
        from sqlalchemy.exc import TimeoutError as SATimeoutError
    except Exception:   # pragma: no cover - SQLAlchemy is a hard dependency
        return False
    return isinstance(exception, SATimeoutError | OperationalError)


def _on_request_exception(sender, exception, **extra):
    """got_request_exception receiver: record every unhandled exception (the
    ones that yield an HTTP 500) to error.log with a traceback.

    Defined at module scope on purpose: blinker holds receivers weakly, so a
    closure would be garbage-collected and silently stop firing.
    """
    try:
        actor_email, actor_id = resolve_actor()
        method = request.method if has_request_context() else None
        path = request.path if has_request_context() else None
        entry = {
            'event': 'server.error',
            'actor': actor_email,
            'actor_id': actor_id,
            'ip': _safe_remote_addr(),
            'target': f'{method} {path}',
            'outcome': 'failure',
            'detail': repr(exception),
        }
        # A pool-exhaustion traceback says the pool was full but not why, and by
        # the time anyone reads the log the pool is idle again. Recording the
        # counters alongside the error is the difference between "connections
        # were all checked out, something was holding them" and "the pool is
        # simply too small for this load".
        if _is_connection_error(exception):
            snapshot = pool_snapshot()
            if snapshot:
                entry['pool'] = snapshot
        logging.getLogger(ERROR_LOGGER).error(
            'server.error',
            exc_info=exception,
            extra={'audit': entry},
        )
    except Exception:  # nosec B110 - the error-logger must not itself raise during exception handling
        pass


def register_error_signal(app):
    """Wire the 500-capture signal for this app instance."""
    got_request_exception.connect(_on_request_exception, app)


def clear_logs_on_disk(app):
    """Empty the audit + error logs; return the number of rotated backups removed.

    The live audit.log/error.log are emptied by CLOSING their handlers (which
    releases the open fd and sets stream=None) and then truncating the files to
    zero — the next log_event reopens the handler in append mode onto the now
    empty file. Truncating without closing first would leave the handler writing
    at its old offset (a sparse, corrupt file). Rotated ``*.log.N`` backups are
    deleted outright.
    """
    directory = logs_dir(app)
    live = {AUDIT_FILE, ERROR_FILE}
    for logger_name in (AUDIT_LOGGER, ERROR_LOGGER):
        for handler in logging.getLogger(logger_name).handlers:
            if getattr(handler, '_hashview_audit', False):
                handler.close()   # next emit reopens via FileHandler._open()
    removed_backups = 0
    if os.path.isdir(directory):
        for entry in os.scandir(directory):
            if entry.name in live:
                open(entry.path, 'w').close()   # truncate to 0 bytes
            else:
                os.remove(entry.path)
                removed_backups += 1
    return removed_backups


def configure_audit_logging(app):
    """Create control/logs and (re)attach the JSON file handlers + 500 hook.

    Idempotent per-app: handlers we previously installed (marked
    ``_hashview_audit``) are removed and closed before re-adding, so calling
    this once per ``create_app`` (as every unit test does) never stacks
    handlers or leaks file descriptors.
    """
    directory = logs_dir(app)
    os.makedirs(directory, exist_ok=True)

    formatter = _JsonFormatter()
    targets = {AUDIT_LOGGER: AUDIT_FILE, ERROR_LOGGER: ERROR_FILE}
    for logger_name, filename in targets.items():
        logger = logging.getLogger(logger_name)
        logger.setLevel(logging.INFO)
        logger.propagate = False
        # create_app runs loggingDictConfig() (default disable_existing_loggers
        # = True) just before this, which disables already-created loggers. A
        # second create_app (e.g. every unit test after the first) would
        # therefore leave these loggers disabled and silently drop events.
        # Re-enable explicitly.
        logger.disabled = False
        for handler in list(logger.handlers):
            if getattr(handler, '_hashview_audit', False):
                logger.removeHandler(handler)
                handler.close()
        handler = RotatingFileHandler(
            os.path.join(directory, filename),
            maxBytes=_MAX_BYTES, backupCount=_BACKUPS, encoding='utf-8')
        handler.setFormatter(formatter)
        handler._hashview_audit = True
        logger.addHandler(handler)

    register_error_signal(app)
