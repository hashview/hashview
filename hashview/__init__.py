
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import secrets
from flask_bcrypt import Bcrypt
from flask_login import LoginManager

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:JY+tjL8k!ICq@localhost/hashview_dev'
db = SQLAlchemy(app)
#db = SQLAlchemy
#db.init_app(app)
#db.create_all() # Forces schema updates (does not work)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'users.login'
login_manager.login_message_category = 'info'

from hashview.agents.routes import agents
from hashview.api.routes import api
from hashview.customers.routes import customers
from hashview.hashfiles.routes import hashfiles
from hashview.jobs.routes import jobs
from hashview.main.routes import main
from hashview.rules.routes import rules
from hashview.settings.routes import settings
from hashview.tasks.routes import tasks
from hashview.taskgroups.routes import taskgroups
from hashview.users.routes import users
from hashview.wordlists.routes import wordlists

app.register_blueprint(agents)
app.register_blueprint(api)
app.register_blueprint(customers)
app.register_blueprint(hashfiles)
app.register_blueprint(jobs)
app.register_blueprint(main)
app.register_blueprint(rules)
app.register_blueprint(settings)
app.register_blueprint(tasks)
app.register_blueprint(taskgroups)
app.register_blueprint(users)
app.register_blueprint(wordlists)