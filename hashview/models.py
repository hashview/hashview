from datetime import datetime
from hashview import db, login_manager
from flask_login import UserMixin
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from hashview.config import Config


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(20), nullable=False)
    last_name = db.Column(db.String(20), nullable=False)
    email_address = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)
    pushover_id = db.Column(db.String(50), nullable=True)
    pushover_key = db.Column(db.String(50), nullable=True)
    wordlists = db.relationship('Wordlists', backref='tbd', lazy=True)
    rules = db.relationship('Rules', backref='owner', lazy=True)
    jobs = db.relationship('Jobs', backref='owner', lazy=True)
    tasks = db.relationship('Tasks', backref='owner', lazy=True)
    taskgroups = db.relationship('TaskGroups', backref='owner', lazy=True)

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(Config.SECRET_KEY, expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(Config.SECRET_KEY)
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None     
        return Users.query.get(user_id)

class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    retention_period = db.Column(db.Integer)
    hashcat_path = db.Column(db.String(255))
    db_version = db.Column(db.String(5), nullable=False)

class Jobs(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    status = db.Column(db.String(20), nullable=False)               # Running, Paused, Completed, Queued, Canceled, Ready, Incomplete
    started_at = db.Column(db.DateTime, nullable=True)    # These defaults should be changed
    ended_at = db.Column(db.DateTime, nullable=True)      # These defaults should be changed
    #hashfile_id = db.Column(db.Integer, db.ForeignKey('hashfiles.id'), nullable=False) # has to not be a foreign key since during job creation, hashfile_id doesnt exist, unless we want to create a dummy one?
    hashfile_id = db.Column(db.Integer, nullable=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    #notify_completed = db.Column(db.Boolean, nullable=False, default=False)
    jobtasks = db.relationship('JobTasks', backref='tbd', lazy=True)

class JobTasks(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey('jobs.id'), nullable=False)
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id'), nullable=False)
    command = db.Column(db.String(1024))                  
    status = db.Column(db.String(50), nullable=False)       # Running, Paused, Not Started, Completed, Queued, Canceled, Importing
    agent_id = db.Column(db.Integer, db.ForeignKey('agents.id'))
    # run_time = db.Column(db.Integer, nullable=False, Default=0)   # This should probably be removed and instead update hashfiles runtime
    # keyspace_pos = db.Column(db.BigInteger, nullable=False)
    # keyspace = db.Column(db.BigInteger, nullable=False)

class Customers(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(40), nullable=False)
    #wl_id = db.Column(db.Integer, db.ForeignKey('wordlists.id'), nullable=False) # for dynamic wordlist. Keep?

class Hashfiles(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256), nullable=False)        # can probably be reduced
    uploaded_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    #wl_id = db.Column(db.Integer, db.ForeignKey('wordlists.id'), nullable=False) # for dynamic wordlist. Keep?
    runtime = db.Column(db.Integer, default=0)
    customer_id = db.Column(db.Integer, nullable=False)
    owner_id = db.Column(db.Integer, nullable=False)

class HashfileHashes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hash_id = db.Column(db.Integer, nullable=False)
    username = db.Column(db.String(256), nullable=True, default=None)
    hashfile_id = db.Column(db.Integer, nullable=False)

class Agents(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)         # can probably be reduced
    src_ip = db.Column(db.String(15), nullable=False)
    uuid = db.Column(db.String(60), nullable=False)          # can probably be reduced
    status = db.Column(db.String(20), nullable=False)        # Pending, Syncing, Working, 
    hc_status = db.Column(db.String(6000))
    last_checkin = db.Column(db.DateTime)
    benchmark = db.Column(db.String(20))
    cpu_count = db.Column(db.Integer)
    gpu_count = db.Column(db.Integer)

class Rules(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    last_updated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    path = db.Column(db.String(256), nullable=False)
    size = db.Column(db.Integer, nullable=False, default=0)
    checksum = db.Column(db.String(64), nullable=False)

class Wordlists(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256), nullable=False)
    last_updated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    type = db.Column(db.String(7))                          # Dynamic or Static
    #scope = db.Column(db.String(10), nullable=False)
    path = db.Column(db.String(245), nullable=False)
    size = db.Column(db.Integer, nullable=False)
    checksum = db.Column(db.String(64), nullable=False)

class Tasks(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    hc_attackmode = db.Column(db.String(25), nullable=False) # dictionary, mask, bruteforce, combinator
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    wl_id = db.Column(db.Integer)
    rule_id = db.Column(db.Integer)
    hc_mask = db.Column(db.String(50))
    keyspace = db.Column(db.BigInteger, nullable=False)

class TaskGroups(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    tasks = db.Column(db.String(256), nullable=False)

# I dont think we use this table
class TaskQueues(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jobtask_id = db.Column(db.Integer, db.ForeignKey('jobtasks.id'), nullable=False)
    job_id = db.Column(db.Integer, db.ForeignKey('jobs.id'), nullable=False)
    agent_id = db.Column(db.Integer, db.ForeignKey('agents.id'))
    last_updated = db.Column(db.DateTime, nullable=False)
    # queued_at # is this neccessary?
    status = db.Column(db.String(20), nullable=False)   # Running, Completed, Queued, Canceled, Paused
    command = db.Column(db.String(256), nullable=False) # is command necessary?

class Hashes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sub_ciphertext = db.Column(db.String(32), nullable=False, index=True)
    ciphertext = db.Column(db.String(4096), nullable=False)
    hash_type = db.Column(db.Integer, nullable=False)
    cracked = db.Column(db.Boolean, nullable=False)
    plaintext = db.Column(db.String(256))

class JobNotifications(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, nullable=False)
    job_id = db.Column(db.Integer, nullable=False)
    method = db.Column(db.String(6), nullable=False)    # email, push

class HashNotifications(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, nullable=False)
    hash_id = db.Column(db.Integer, nullable=False)
    method = db.Column(db.String(6), nullable=False)    # email, push