from flask import Flask

__version__ = '0.8.0'

# Jinja2 Filter
def jinja_hex_decode(text):
    if not text:
        return text #if all hashes in a file are already cracked
    else:
        return bytes.fromhex(text).decode('latin-1')


def create_app():
    app = Flask(__name__)

    from hashview.config import Config
    app.config.from_object(Config)

    from hashview.models import db
    db.init_app(app)

    from hashview.users.routes import bcrypt
    bcrypt.init_app(app)

    from hashview.users.routes import login_manager
    login_manager.init_app(app)

    from flask_mail import Mail
    mail = Mail()
    mail.init_app(app)

    from flask_migrate import Migrate
    migrate = Migrate()
    migrate.init_app(app, db)

    from flask_apscheduler import APScheduler
    scheduler = APScheduler()
    scheduler.init_app(app)
    scheduler.start()

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

    # Add custom Jinja2 Filters
    app.add_template_filter(jinja_hex_decode)
    return app
