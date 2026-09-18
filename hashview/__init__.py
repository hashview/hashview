import datetime
import logging
from logging.config import dictConfig as loggingDictConfig

from flask import Flask, flash, jsonify, redirect, request, url_for
from jinja2 import select_autoescape

__version__ = '0.8.3'


def get_application_version() -> str:
    """ jinja2 function to get the application version from within a template """
    return __version__


def do_gui_setup_if_needed():
    from flask import current_app
    logger = current_app.logger

    from urllib.parse import urlparse
    static_path = url_for('static', filename='')
    parsed_url  = urlparse(request.url)

    if parsed_url.path.startswith(static_path):
        # allow static files through
        return

    from hashview.models import db
    from hashview.setup import admin_pass_needs_changed
    from hashview.users.routes import bcrypt
    if admin_pass_needs_changed(db, bcrypt):
        logger.info('Admin password needs changed.')
        if url_for('setup.admin_pass_get') != parsed_url.path:
            return redirect(url_for('setup.admin_pass_get'))
        return None

    from hashview.setup import settings_needs_added
    if settings_needs_added(db):
        logger.info('Settings needs created.')
        if url_for('setup.settings_get') != parsed_url.path:
            return redirect(url_for('setup.settings_get'))
        return None


def setup_defaults_if_needed():
    from flask import current_app
    logger = current_app.logger
    logger.info('Setting up defaults on before first request.')

    from hashview.models import db

    try:
        logger.info('Upgrading Database if needed Progressing.')
        import alembic.command
        migrate_ext = current_app.extensions['migrate']
        config = migrate_ext.migrate.get_config(migrate_ext.directory)
        # set configure_logger so that migrations/env.py doesn't override the logging setup
        config.attributes['configure_logger'] = False
        alembic.command.upgrade(config, 'head')
        logger.info('Upgrading Database if needed is Complete.')
    except Exception:
        logger.exception('Upgrading Database failed.')

    # The uniqueness constraint on hashes(sub_ciphertext, hash_type) cannot be
    # created while duplicate rows exist, and the migration that creates it is
    # recorded as applied the moment it skips over them -- so no later
    # `db upgrade` ever reattempts, and an operator who merges their duplicates
    # afterwards is stranded with no constraint and no way to ask for one.
    # Retrying here is what makes "restart Hashview" advice that can actually be
    # followed. Gated on the cheap inspector check first, so the GROUP BY only
    # runs while the constraint is genuinely missing, and never again once it
    # exists.
    try:
        from hashview.utils.dedupe import (
            UNIQUE_CONSTRAINT,
            constraint_present,
            create_unique_constraint,
            duplicate_summary,
        )
        with db.engine.connect() as conn:
            if not constraint_present(conn):
                duplicate_groups = duplicate_summary(conn)[0]
                if duplicate_groups:
                    logger.warning(
                        '%s is missing: %s duplicate (sub_ciphertext, hash_type) '
                        'pair(s) block it, so hash imports can still race. Merge '
                        'them under Settings -> Data management, or with '
                        'scripts/repair_duplicate_hashes.py --apply.',
                        UNIQUE_CONSTRAINT, duplicate_groups)
                elif create_unique_constraint(conn):
                    logger.info('Created %s.', UNIQUE_CONSTRAINT)
    except Exception:
        logger.exception('Could not create the hashes uniqueness constraint.')

    try:
        from hashview.scheduler import register_default_jobs
        logger.info('Adding Default Scheduled Jobs Progressing.')
        # Bind the REAL app object, not the current_app proxy: flask-apscheduler
        # runs jobs in a background thread with no application context, so a
        # LocalProxy would raise "Working outside of application context" when the
        # job does `with app.app_context()` — the job would silently never run.
        register_default_jobs(current_app._get_current_object())
        logger.info('Adding Default Scheduled Jobs is Complete.')
    except Exception:
        logger.exception('Adding Default Scheduled Jobs failed.')

    try:
        from hashview.setup import add_admin_user, admin_user_needs_added
        from hashview.users.routes import bcrypt
        if admin_user_needs_added(db):
            logger.info('Adding Admin User.')
            add_admin_user(db, bcrypt)
    except Exception:
        logger.exception('Adding Admin User failed.')

    try:
        from hashview.setup import (
            add_default_dynamic_wordlists,
            default_dynamic_wordlists_need_added,
        )
        if default_dynamic_wordlists_need_added(db):
            logger.info('Adding Default Dynamic Wordlist.')
            add_default_dynamic_wordlists(db)
    except Exception:
        logger.exception('Adding Default Dynamic Wordlists failed.')

    try:
        from hashview.setup import (
            add_default_static_wordlist,
            default_static_wordlist_need_added,
        )
        if default_static_wordlist_need_added(db):
            logger.info('Adding Default Static Wordlist.')
            add_default_static_wordlist(db)
    except Exception:
        logger.exception('Adding Default Static Wordlist failed.')

    try:
        # Compress any pre-existing uncompressed static wordlists (including the
        # default Rockyou.txt seeded just above) and backfill byte_size. Runs
        # after defaults exist; idempotent and per-row resilient.
        from hashview.setup import compress_existing_wordlists_if_needed
        logger.info('Compressing existing wordlists if needed.')
        compress_existing_wordlists_if_needed(db)
        logger.info('Compressing existing wordlists is complete.')
    except Exception:
        logger.exception('Compressing existing wordlists failed.')

    try:
        # One-time: convert legacy hex-encoded usernames/plaintext to UTF-8 text.
        from hashview.setup import decode_legacy_hex_if_needed
        decode_legacy_hex_if_needed(db)
    except Exception:
        logger.exception('Decoding legacy hex usernames/plaintext failed.')

    try:
        from hashview.setup import add_default_rules, default_rules_need_added
        if default_rules_need_added(db):
            logger.info('Adding Default Rules.')
            add_default_rules(db)
    except Exception:
        logger.exception('Adding Default Rules failed.')

    try:
        from hashview.setup import add_default_tasks, default_tasks_need_added
        if default_tasks_need_added(db):
            logger.info('Adding Default Tasks.')
            add_default_tasks(db)
    except Exception:
        logger.exception('Adding Default Tasks failed.')


def jinja_hex_decode(text):
    """jinja2 filter for displaying usernames/plaintext.

    These are now stored as plain UTF-8 text (no more latin-1 hex), so this is a
    passthrough — kept (with its historical name) so existing
    ``{{ value | jinja_hex_decode }}`` templates keep working without edits.
    Non-UTF-8 binary values are stored as hashcat-style ``$HEX[...]`` and shown
    as-is."""
    return text


def jinja_human_count(value):
    """jinja2 filter: render a large quantity compactly -- 1234567890 -> '1.2B'.

    For keyspaces, which routinely run to 10+ digits: a mask attack's candidate
    count is not something anyone reads digit by digit, and the exact figure
    belongs in the progress columns (use `commafy` there). Values under 1000 and
    anything non-numeric pass through untouched.
    """
    if value is None or isinstance(value, bool):
        return value
    try:
        number = int(value)
    except (TypeError, ValueError):
        return value
    for limit, suffix in ((10 ** 18, 'E'), (10 ** 15, 'P'), (10 ** 12, 'T'),
                          (10 ** 9, 'B'), (10 ** 6, 'M'), (10 ** 3, 'K')):
        if number >= limit:
            return f"{number / limit:.1f}".rstrip('0').rstrip('.') + suffix
    return str(number)


def jinja_commafy(value):
    """jinja2 filter: render a quantity with thousands separators.

    1000 -> '1,000', 1000000 -> '1,000,000'; values below 1000 are unchanged.
    Ints and integer-valued strings format without a fractional part; real
    floats keep theirs ('1,234.5'). Anything non-numeric (None, bools, or a
    composite string like '5/10 (50%)') passes through untouched, so the filter
    is safe to pipe onto any expression that *might* be a count.

    Use for counts/totals throughout the UI. Do NOT use on a raw recovered
    password — those can be all digits but are not quantities.
    """
    if value is None or isinstance(value, bool):
        return value
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        pass
    try:
        return f"{float(value):,}"
    except (TypeError, ValueError):
        return value


def create_app(testing=False, config_overrides=None):
    app = Flask(__name__)
    if testing:
        app.config["TESTING"] = True
    # Templates use the .html.j2 extension, which Flask's default
    # select_autoescape() does not cover. Without this, every {{ var }}
    # in every template renders raw - stored XSS via any user-supplied
    # field (job name, customer name, agent name, etc.).
    app.jinja_env.autoescape = select_autoescape(
        enabled_extensions=("html", "htm", "xml", "xhtml", "j2"),
        default_for_string=True,
    )

    # https://flask.palletsprojects.com/en/2.2.x/logging/
    # When you want to configure logging for your project, you should do it as
    # soon as possible when the program starts.
    loggingDictConfig({
        'version': 1,
        # Don't disable loggers configured elsewhere (e.g. the hashview.audit /
        # hashview.error loggers set up by configure_audit_logging). The default
        # (True) would silently disable them whenever create_app runs again.
        'disable_existing_loggers': False,
        'formatters': {
            'default': {
                'format': ('%(asctime)s [%(levelname)-8s] for %(name)s: '
                           '%(message)s in (%(module)s:%(lineno)d)'),
            }
        },
        'handlers': {
            'wsgi': {
                'class': 'logging.StreamHandler',
                'stream': 'ext://flask.logging.wsgi_errors_stream',
                'formatter': 'default'
            }
        },
        'root': {
            'level': 'DEBUG' if app.debug else 'INFO',
            'handlers': ['wsgi']
        }
    })
    logging.Formatter.formatTime = (
        lambda self, record, datefmt=None: \
            datetime.datetime
                .fromtimestamp(record.created, datetime.UTC)
                .astimezone()
                .isoformat(sep="T", timespec="milliseconds")
    )

    # Audit/event logging to disk (control/logs/audit.log + error.log). Done
    # here, after app=Flask(__name__), so it can use app.root_path to create
    # the dir and attach file handlers (the dictConfig above runs too early /
    # console-only). Also wires the got_request_exception 500 hook.
    from hashview.utils.audit import configure_audit_logging
    configure_audit_logging(app)

    # Drop folder for importing large wordlists copied onto the server (scp); the
    # Wordlists page lists + imports its contents. Created here so it exists for
    # users to scp into before first use.
    import os as _os
    _os.makedirs(_os.path.join(app.root_path, 'control', 'wordlists_import'), exist_ok=True)

    if not testing:
        from hashview.config import Config
        app.config.from_object(Config)
    if config_overrides:
        app.config.update(config_overrides)

    from hashview.models import db
    db.init_app(app)

    from flask_migrate import Migrate
    migrate = Migrate()
    migrate.init_app(app, db)

    from hashview.scheduler import scheduler
    scheduler.init_app(app)
    if not (testing or app.config.get("HASHVIEW_DISABLE_SCHEDULER")):
        scheduler.start()

    from hashview.users.routes import bcrypt
    bcrypt.init_app(app)

    from hashview.users.routes import login_manager
    login_manager.init_app(app)

    # TimeoutMail, not flask_mail.Mail: the stock one builds its SMTP socket
    # with no timeout, so an unresponsive relay blocks the sending thread
    # forever -- and sends happen inside request handlers. See utils/mail.py.
    from hashview.utils.mail import TimeoutMail
    mail = TimeoutMail()
    mail.init_app(app)

    from hashview.agents.routes import agents
    from hashview.analytics.routes import analytics
    from hashview.api.routes import api
    from hashview.api_docs.routes import api_docs
    from hashview.auth.routes import auth as auth_blueprint
    from hashview.customers.routes import customers
    from hashview.hashfiles.routes import hashfiles
    from hashview.jobs.routes import jobs
    from hashview.logs.routes import logs
    from hashview.main.routes import main
    from hashview.notifications.routes import notifications
    from hashview.rules.routes import rules
    from hashview.searches.routes import searches
    from hashview.settings.routes import settings
    from hashview.setup.routes import blueprint as setup_blueprint
    from hashview.task_groups.routes import task_groups
    from hashview.tasks.routes import tasks
    from hashview.users.routes import users
    from hashview.wordlists.routes import wordlists
    from hashview.wrapped.routes import wrapped

    app.register_blueprint(agents)
    app.register_blueprint(api)
    app.register_blueprint(api_docs)
    app.register_blueprint(auth_blueprint)
    app.register_blueprint(customers)
    app.register_blueprint(hashfiles)
    app.register_blueprint(jobs)
    app.register_blueprint(logs)
    app.register_blueprint(main)
    app.register_blueprint(rules)
    app.register_blueprint(settings)
    app.register_blueprint(tasks)
    app.register_blueprint(task_groups)
    app.register_blueprint(users)
    app.register_blueprint(wordlists)
    app.register_blueprint(analytics)
    app.register_blueprint(notifications)
    app.register_blueprint(searches)
    app.register_blueprint(wrapped)
    app.register_blueprint(setup_blueprint)

    app.add_template_filter(jinja_hex_decode)
    app.add_template_filter(jinja_commafy, 'commafy')
    app.add_template_filter(jinja_human_count, 'human_count')
    app.add_template_global(get_application_version, get_application_version.__name__)
    # Expose a csrf_token() template global (no global CSRFProtect is installed) so the
    # account-settings modal in the layout can post to the CSRF-protected profile route.
    from flask_wtf.csrf import generate_csrf
    app.jinja_env.globals['csrf_token'] = generate_csrf

    # db_maxlength('Customers', 'name') -> 40. The modals hand-write their
    # <input> elements rather than rendering WTForms fields (which emit
    # maxlength from their Length validator automatically), so this is how a
    # hand-written input stays pinned to the column it is stored in.
    from hashview.utils.form_limits import template_maxlength
    app.jinja_env.globals['db_maxlength'] = template_maxlength

    # Version-tagged static URLs: asset('css/x.css') -> /static/css/x.css?v=<ver>.
    # The version query lets the browser far-future-cache the file yet re-fetch it
    # after an upgrade (the URL changes when __version__ changes).
    app.jinja_env.globals['asset'] = lambda filename: url_for('static', filename=filename, v=__version__)

    _static_prefix = (app.static_url_path or '/static') + '/'

    @app.after_request
    def _static_cache_headers(response):
        # Long-cache ONLY explicitly versioned static assets (URLs carrying ?v=).
        # Un-versioned /static URLs keep Flask's default revalidate behavior, so
        # partial adoption of asset() can never serve a stale file after an upgrade.
        if request.path.startswith(_static_prefix) and request.args.get('v'):
            response.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
        return response

    @app.context_processor
    def inject_nav_counts():
        """Sidebar nav badge counts + agent fleet summary. Only queried for
        authenticated requests (so login/setup pages do no work), and guarded so a
        pre-migration database can never break page rendering."""
        from flask_login import current_user
        if not getattr(current_user, "is_authenticated", False):
            return {}
        try:
            from datetime import datetime, timedelta

            from sqlalchemy import text

            from hashview.models import (
                Agents,
                Customers,
                Hashfiles,
                Jobs,
                Rules,
                TaskGroups,
                Tasks,
                Users,
                Wordlists,
                db,
            )

            # _hps/_fmt: the single source in utils (function-local import dodges a
            # load-time circular import on the package root).
            from hashview.utils.utils import fmt_hps as _fmt
            from hashview.utils.utils import parse_hps as _hps

            agents = Agents.query.all()
            # last_checkin is stamped with the database clock (api.update_heartbeat uses
            # func.now()); derive the cutoff from that SAME clock so the comparison is
            # independent of whatever timezone this web process runs in. Falls back to the
            # process clock only if the DB time can't be read.
            try:
                db_now = db.session.execute(text("SELECT NOW()")).scalar()
                if isinstance(db_now, str):
                    db_now = datetime.strptime(db_now[:19], '%Y-%m-%d %H:%M:%S')
            except Exception:
                db_now = None
            # Configurable per Settings.agent_timeout_minutes (default 60 = the old
            # hardcoded 1-hour cutoff). function-local import dodges a load-time
            # circular import on the package root (same as fmt_hps/parse_hps above).
            from hashview.utils.utils import get_agent_timeout_minutes
            cutoff = (db_now or datetime.utcnow()) - timedelta(minutes=get_agent_timeout_minutes())

            # An agent is "up" when it's connected (recent check-in) and in a
            # running or idle/ready state; the speed total only counts agents actively
            # cracking ("Working"). Everything else (pending, stale, never checked in,
            # disconnected) counts as down/offline.
            up_states = {'working', 'syncing', 'idle', 'authorized', 'online'}
            running_states = {'working'}

            def _connected(a):
                return a.last_checkin is not None and a.last_checkin >= cutoff

            def _state(a):
                return (a.status or '').strip().lower()

            # Single source of truth for "is this agent up" (sidebar, agents page, AND
            # the dashboard all read from this, so they can never disagree).
            up_ids = {a.id for a in agents if _connected(a) and _state(a) in up_states}
            up = len(up_ids)
            total_hps = sum(_hps(a.benchmark) for a in agents
                            if _connected(a) and _state(a) in running_states)

            return {
                "nav_counts": {
                    "jobs": Jobs.query.count(),
                    "agents": len(agents),
                    "tasks": Tasks.query.count(),
                    "task_groups": TaskGroups.query.count(),
                    "hashfiles": Hashfiles.query.count(),
                    "wordlists": Wordlists.query.count(),
                    "rules": Rules.query.count(),
                    "users": Users.query.count(),
                    "customers": Customers.query.count(),
                },
                "agent_stats": {
                    "up": up,
                    "down": len(agents) - up,
                    "total": len(agents),
                    "speed": _fmt(total_hps),
                    "online_ids": up_ids,
                    "gpus": sum((a.gpu_count or 0) for a in agents),
                },
                "job_queue": {
                    "running": Jobs.query.filter_by(status='Running').count(),
                    "queued": Jobs.query.filter_by(status='Queued').count(),
                },
            }
        except Exception:  # pragma: no cover - defensive: never break rendering
            return {}

    @app.context_processor
    def inject_notify_channels():
        """Per-channel master switches (Settings -> Notifications), available to
        every template (job wizard, account-settings modal, notifications page) so
        disabled channels can be hidden. Defaults to email+pushover on / slack off
        when Settings is missing or unreadable (e.g. a pre-migration database)."""
        defaults = {'email': True, 'pushover': True, 'slack': False}
        try:
            from hashview.models import Settings
            s = Settings.current()
            if not s:
                return {'notify_channels': defaults}
            return {'notify_channels': {
                'email': bool(s.email_enabled),
                'pushover': bool(s.pushover_enabled),
                'slack': bool(s.slack_enabled),
            }}
        except Exception:  # pragma: no cover - pre-migration / no DB
            return {'notify_channels': defaults}

    @app.errorhandler(413)
    def _form_too_large(e):
        """#314: Werkzeug enforces MAX_FORM_MEMORY_SIZE (a byte cap on
        non-file form fields, e.g. a pasted-hashes textarea) while parsing the
        request body, before any view function runs -- so this is the only
        place that can intercept it. File uploads are parsed separately and
        are not subject to this cap, hence the workaround suggested below.

        Matches the AJAX/normal-submit contract used elsewhere for form
        errors (see hashview/jobs/routes.py:270,454-455): XHR requests get a
        JSON error body, normal submits get a flash + redirect back to
        wherever the request came from.
        """
        msg = ('Your submission exceeded the maximum allowed size for pasted '
               'form data. Try uploading the hashes as a file instead -- file '
               'uploads are not subject to this limit.')
        is_ajax = request.headers.get('X-Requested-With') == 'fetch'
        if is_ajax:
            return jsonify({'status': 'error', 'msg': msg}), 413
        flash(msg, 'danger')
        return redirect(request.referrer or url_for('main.home'))

    if not (testing or app.config.get("HASHVIEW_SKIP_SETUP")):
        with app.app_context():
            setup_defaults_if_needed()

    if not app.config.get("HASHVIEW_SKIP_GUI_SETUP"):
        app.before_request(do_gui_setup_if_needed)

    return app
