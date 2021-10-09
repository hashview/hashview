
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from hashview.config import Config
from flask_mail import Mail
from flask_migrate import Migrate
from flask_apscheduler import APScheduler
#import hashview.scheduled_tasks.scheduled_tasks as s
#import hashview.utils.foo as s

db = SQLAlchemy()
#s.db = SQLAlchemy()


bcrypt = Bcrypt()
login_manager = LoginManager()
login_manager.login_view = 'users.login'
login_manager.login_message_category = 'info'
mail = Mail()
migrate = Migrate()
scheduler = APScheduler()

#import hashview.models as HM
#s.settings = HM.Settings

def create_app(config_class=Config):

    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    migrate.init_app(app, db)
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

    #from hashview.utils.utils import data_retention_cleanup
    #from hashview.scheduled_tasks.scheduled_tasks import data_retention_cleanup
    #scheduler.add_job(id='DATA_RETENTION', func=data_retention_cleanup, trigger='cron', minute='*')

    return app