import logging
import datetime

from flask import Flask
from flask import request
from flask import url_for
from flask import redirect
from pathlib import Path
from functools import partial
from logging.config import dictConfig as loggingDictConfig


__version__ = '0.8.1'


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
    if not admin_pass_needs_changed(db, bcrypt):
        logger.info('Admin password does not need changed.')

    else:
        logger.info('Admin password needs changed.')
        if (url_for('setup.admin_pass_get') != parsed_url.path):
            return redirect(url_for('setup.admin_pass_get'))
        else:
            return

    from hashview.setup import settings_needs_added
    if not settings_needs_added(db):
        logger.info('Settings does not need created.')

    else:
        logger.info('Settings needs created.')
        if (url_for('setup.settings_get') != parsed_url.path):
            return redirect(url_for('setup.settings_get'))
        else:
            return


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
    except:
        logger.exception('Upgrading Database failed.')

    try:
        from hashview.scheduler import scheduler
        from hashview.scheduler import data_retention_cleanup
        logger.info('Clearing Scheduled Jobs.')
        scheduler.remove_all_jobs()
        logger.info('Adding Default Scheduled Jobs Progressing.')
        scheduler.add_job(id='DATA_RETENTION', func=partial(data_retention_cleanup, current_app), trigger='cron', hour='*')
        logger.info('Adding Default Scheduled Jobs is Complete.')
    except:
        logger.exception('Adding Default Scheduled Jobs failed.')

    try:
        from hashview.users.routes import bcrypt
        from hashview.setup import add_admin_user
        from hashview.setup import admin_user_needs_added
        if admin_user_needs_added(db):
            logger.info('Adding Admin User.')
            add_admin_user(db, bcrypt)
    except:
        logger.exception('Adding Admin User failed.')

    try:
        from hashview.setup import add_default_dynamic_wordlist
        from hashview.setup import default_dynamic_wordlist_need_added
        if default_dynamic_wordlist_need_added(db):
            logger.info('Adding Default Dynamic Wordlist.')
            add_default_dynamic_wordlist(db)
    except:
        logger.exception('Adding Default Dynamic Wordlist failed.')

    try:
        from hashview.setup import add_default_static_wordlist
        from hashview.setup import default_static_wordlist_need_added
        if default_static_wordlist_need_added(db):
            logger.info('Adding Default Static Wordlist.')
            add_default_static_wordlist(db)
    except:
        logger.exception('Adding Default Static Wordlist failed.')

    try:
        from hashview.setup import add_default_rules
        from hashview.setup import default_rules_need_added
        if default_rules_need_added(db):
            logger.info('Adding Default Rules.')
            add_default_rules(db)
    except:
        logger.exception('Adding Default Rules failed.')

    try:
        from hashview.setup import add_default_tasks
        from hashview.setup import default_tasks_need_added
        if default_tasks_need_added(db):
            logger.info('Adding Default Tasks.')
            add_default_tasks(db)
    except:
        logger.exception('Adding Default Tasks failed.')


def jinja_hex_decode(text):
    """ jinja2 filter to convert hex to bytes """
    if not text:
        return text #if all hashes in a file are already cracked
    else:
        return bytes.fromhex(text).decode('latin-1')


def create_app():
    app = Flask(__name__)

    # https://flask.palletsprojects.com/en/2.2.x/logging/
    # When you want to configure logging for your project, you should do it as
    # soon as possible when the program starts.
    loggingDictConfig({
        'version': 1,
        'formatters': {
            'default': {
                'format': '%(asctime)s [%(levelname)-8s] for %(name)s: %(message)s in (%(module)s:%(lineno)d)',
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
                .fromtimestamp(record.created, datetime.timezone.utc)
                .astimezone()
                .isoformat(sep="T", timespec="milliseconds")
    )

    from hashview.config import Config
    app.config.from_object(Config)

    from hashview.models import db
    db.init_app(app)

    from flask_migrate import Migrate
    migrate = Migrate()
    migrate.init_app(app, db)

    from hashview.scheduler import scheduler
    scheduler.init_app(app)
    scheduler.start()

    from hashview.users.routes import bcrypt
    bcrypt.init_app(app)

    from hashview.users.routes import login_manager
    login_manager.init_app(app)

    from flask_mail import Mail
    mail = Mail()
    mail.init_app(app)

    from hashview.agents.routes import agents
    from hashview.api.routes import api
    from hashview.customers.routes import customers
    from hashview.hashfiles.routes import hashfiles
    from hashview.jobs.routes import jobs
    from hashview.main.routes import main
    from hashview.rules.routes import rules
    from hashview.settings.routes import settings
    from hashview.tasks.routes import tasks
    from hashview.task_groups.routes import task_groups
    from hashview.users.routes import users
    from hashview.wordlists.routes import wordlists
    from hashview.analytics.routes import analytics
    from hashview.notifications.routes import notifications
    from hashview.searches.routes import searches
    from hashview.setup.routes import blueprint as setup_blueprint

    app.register_blueprint(agents)
    app.register_blueprint(api)
    app.register_blueprint(customers)
    app.register_blueprint(hashfiles)
    app.register_blueprint(jobs)
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
    app.register_blueprint(setup_blueprint)

    app.add_template_filter(jinja_hex_decode)
    app.add_template_global(get_application_version, get_application_version.__name__)

    with app.app_context():
        setup_defaults_if_needed()

    app.before_request(do_gui_setup_if_needed)

    return app
