import json
import time

from hashlib import sha512
from datetime import datetime

import sqlalchemy
from flask import current_app
from authlib import jose
from hashview import db, login_manager
from flask_login import UserMixin


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
    pushover_app_id = db.Column(db.String(50), nullable=True)
    pushover_user_key = db.Column(db.String(50), nullable=True)
    last_login_utc = db.Column(db.DateTime, nullable=True, default=datetime.utcnow)
    wordlists = db.relationship('Wordlists', backref='tbd', lazy=True)
    rules = db.relationship('Rules', backref='owner', lazy=True)
    jobs = db.relationship('Jobs', backref='owner', lazy=True)
    tasks = db.relationship('Tasks', backref='owner', lazy=True)
    taskgroups = db.relationship('TaskGroups', backref='owner', lazy=True)

    def _get_reset_token_salt(self) -> str:
        """
        Create salt data for password reset token signing. The return value will be hashed
        together with the signing key. This ensures that changes to any of the fields included
        in the salt invalidates any tokens produced with the old values.
        """
        return json.dumps([
            self.first_name,
            self.last_name,
            self.password if (self.password is not None) else '',
            self.last_login_utc.isoformat() if self.last_login_utc else None
        ])

    def _get_reset_token_key(self) -> bytes:
        key_salt = self._get_reset_token_salt()
        app_secret_key = current_app.config.get('SECRET_KEY')
        key_base_string = f'{key_salt}-signer-{app_secret_key}'
        key_base_bytes  = key_base_string.encode()
        key_bytes = sha512(key_base_bytes).digest()
        return key_bytes

    def get_reset_token(self, expires_sec:int=1800):
        header = dict(alg='HS512')

        issued_at = int(time.time())
        expiration_time = (issued_at + expires_sec)
        payload = dict(
            user_id = self.id,
            iat     = issued_at,
            exp     = expiration_time,
        )

        key_bytes = self._get_reset_token_key()

        token_bytes  = jose.jwt.encode(header, payload, key_bytes)
        token_string = token_bytes.decode('utf-8')
        return token_string

    def verify_reset_token(self, token_string :str) -> 'Users':
        if (not token_string):
            return False

        try:
            payload = jose.jwt.decode(token_string, self._get_reset_token_key())
            payload.validate()

        except (
            jose.errors.DecodeError,
            jose.errors.ExpiredTokenError,
            jose.errors.BadSignatureError,
        ):
            return False

        # authlib treats iat/exp claims as optional
        # ensure they are in the payload, and fail if not
        if 2 != len({'iat', 'exp'} & set(payload.keys())):
            return False

        # in the unlikely event that the salt matches,
        # but the user_id does not, fail
        if self.user_id != payload.get('user_id'):
            return False

        else:
            return True

class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    retention_period = db.Column(db.Integer)
    version = db.Column(db.String(10))

class Jobs(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    status = db.Column(db.String(20), nullable=False)           # Running, Paused, Completed, Queued, Canceled, Ready, Incomplete
    started_at = db.Column(db.DateTime, nullable=True)          # These defaults should be changed
    ended_at = db.Column(db.DateTime, nullable=True)            # These defaults should be changed
    hashfile_id = db.Column(db.Integer, nullable=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

class JobTasks(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, nullable=False)
    task_id = db.Column(db.Integer, nullable=False)
    command = db.Column(db.String(1024))
    status = db.Column(db.String(50), nullable=False)       # Running, Paused, Not Started, Completed, Queued, Canceled, Importing
    agent_id = db.Column(db.Integer, db.ForeignKey('agents.id'))

class Customers(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(40), nullable=False)

class Hashfiles(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256), nullable=False)        # can probably be reduced
    uploaded_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    runtime = db.Column(db.Integer, default=0)
    customer_id = db.Column(db.Integer, nullable=False)
    owner_id = db.Column(db.Integer, nullable=False)

class HashfileHashes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hash_id = db.Column(db.Integer, nullable=False, index=True)
    username = db.Column(db.String(256), nullable=True, default=None, index=True)
    hashfile_id = db.Column(db.Integer, nullable=False)

class Agents(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)         # can probably be reduced
    src_ip = db.Column(db.String(15), nullable=False)
    uuid = db.Column(db.String(60), nullable=False)          # can probably be reduced
    status = db.Column(db.String(20), nullable=False)        # Pending, Syncing, Working, Idle
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
    path = db.Column(db.String(245), nullable=False)
    size = db.Column(db.BigInteger, nullable=False)
    checksum = db.Column(db.String(64), nullable=False)

class Tasks(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    hc_attackmode = db.Column(db.String(25), nullable=False) # dictionary, mask, bruteforce, combinator
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    wl_id = db.Column(db.Integer)
    rule_id = db.Column(db.Integer)
    hc_mask = db.Column(db.String(50))

class TaskGroups(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    tasks = db.Column(db.String(256), nullable=False)

class Hashes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sub_ciphertext = db.Column(db.String(32), nullable=False, index=True)
    ciphertext = db.Column(db.String(16383), nullable=False) # Setting this to max value for now. If we run into this being a limitation in the future we can revisit changing thist to TEXT or BLOB. https://sheeri.org/max-varchar-size/
    hash_type = db.Column(db.Integer, nullable=False, index=True)
    cracked = db.Column(db.Boolean, nullable=False)
    plaintext = db.Column(db.String(256), index=True)

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