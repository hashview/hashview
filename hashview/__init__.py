
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from hashview.config import Config
from flask_mail import Mail
from flask_migrate import Migrate

db = SQLAlchemy()
#db.create_all() # Forces schema updates (does not work)
bcrypt = Bcrypt()
login_manager = LoginManager()
login_manager.login_view = 'users.login'
login_manager.login_message_category = 'info'

mail = Mail()

migrate = Migrate()

def create_app(config_class=Config):

    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    migrate.init_app(app, db)

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

    return app