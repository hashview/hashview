"""Class file to manage loading of database"""
import json
from datetime import datetime
from hashlib import sha512

from authlib import jose
from flask import current_app
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Users(db.Model, UserMixin):
    """Class object to represent Users"""

    id                = db.Column(db.Integer,    nullable=False, primary_key=True)
    # Widened (20->64 / 50->255) so JIT-provisioned Entra identities (display
    # names, UPN-style emails) fit. See add_azure_sso migration.
    first_name        = db.Column(db.String(64), nullable=False)
    last_name         = db.Column(db.String(64), nullable=False)
    email_address     = db.Column(db.String(255), nullable=False, unique=True)
    password          = db.Column(db.String(60), nullable=False)
    admin             = db.Column(db.Boolean,    nullable=False, default=False)
    pushover_app_id   = db.Column(db.String(50), nullable=True)
    pushover_user_key = db.Column(db.String(50), nullable=True)
    slack_id          = db.Column(db.String(50), nullable=True)   # per-user Slack Member ID (U…)
    # Administrative notifications (agent errors): admins receive them by default
    # (email + pushover, matching the pre-existing notify_admins behavior), and can
    # tune the channels in their profile. Slack admin alerts go to the shared
    # Settings.slack_admin_channel room, not a per-admin DM. See notify_admins.
    admin_notifications_enabled = db.Column(db.Boolean, nullable=False, default=True)
    admin_notify_email          = db.Column(db.Boolean, nullable=False, default=True)
    admin_notify_pushover       = db.Column(db.Boolean, nullable=False, default=True)
    admin_notify_slack          = db.Column(db.Boolean, nullable=False, default=True)
    last_login_utc    = db.Column(db.DateTime,   nullable=True,  default=datetime.utcnow)
    api_key           = db.Column(db.String(60), nullable=True)
    # Auth provenance: 'local' (password) or 'azure' (Entra ID SSO). The setup
    # admin (id=1) is always 'local'. azure_oid is the stable Entra object id,
    # backfilled on first SSO login (matching falls back to email_address).
    auth_source       = db.Column(db.String(10), nullable=False, default='local')
    azure_oid         = db.Column(db.String(64), nullable=True)
    theme             = db.Column(db.String(16), nullable=False, default='auto')
    wordlists         = db.relationship('Wordlists',  backref='tbd',   lazy=True)
    rules             = db.relationship('Rules',      backref='owner', lazy=True)
    jobs              = db.relationship('Jobs',       backref='owner', lazy=True)
    tasks             = db.relationship('Tasks',      backref='owner', lazy=True)
    taskgroups        = db.relationship('TaskGroups', backref='owner', lazy=True)

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
        """Class function to get reset token"""

        header = dict(alg='HS512')

        issued_at = int(datetime.today().timestamp())
        expiration_time = issued_at + expires_sec
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
        """Class function to verify reset token"""

        if not token_string:
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
        if self.id != payload.get('user_id'):
            return False

        return True

class Settings(db.Model):
    """Class object to represent Settings"""

    id = db.Column(db.Integer, primary_key=True)
    retention_period = db.Column(db.Integer)
    max_runtime_jobs = db.Column(db.Integer)                    # Time will be measured in hours
    max_runtime_tasks = db.Column(db.Integer)                   # Time will be measured in hours
    # Minutes Hashview waits for an agent check-in before considering it offline
    # (sidebar/agents page/dashboard + the agent-health scheduler). Default 60 keeps
    # the previously-hardcoded 1-hour cutoff.
    agent_timeout_minutes = db.Column(db.Integer, nullable=False, default=60)
    enabled_job_weights = db.Column(db.Boolean, nullable=False, default=False)
    # Task chunking (Settings -> Jobs). When enabled, eligible tasks (everything
    # except those using a dynamic wordlist) are split into smaller per-agent
    # chunks sized from per-hashtype agent benchmarks. Default OFF so behaviour is
    # unchanged until an admin opts in. chunk_target_duration is the rough
    # wall-clock (seconds) one chunk should take on the SLOWEST benchmarked agent.
    enabled_chunking = db.Column(db.Boolean, nullable=False, default=False)
    chunk_target_duration = db.Column(db.Integer, nullable=False, default=3600)
    # Notification channel master switches (admin-controlled, Settings -> Notifications).
    # email/pushover default True to preserve existing behaviour on upgrade; slack is
    # opt-in. A disabled channel is hidden in the job wizard + user profile and never
    # sends. Slack also needs a bot token; users hold their own Slack Member ID.
    email_enabled = db.Column(db.Boolean, nullable=False, default=True)
    pushover_enabled = db.Column(db.Boolean, nullable=False, default=True)
    slack_enabled = db.Column(db.Boolean, nullable=False, default=False)
    slack_bot_token = db.Column(db.String(255), nullable=True)
    # Slack room (channel id, e.g. C0123ABC) that administrative notifications
    # (agent errors) are posted to; the bot must be in it (or have chat:write.public).
    slack_admin_channel = db.Column(db.String(255), nullable=True)
    # One-time flag for the hex->UTF-8 backfill of legacy usernames/plaintext.
    # Model default True so FRESH installs (new Settings row) skip the backfill;
    # the migration adds it with server_default 0 so EXISTING rows get flagged
    # for the one-time decode on next launch (see decode_legacy_hex_if_needed).
    passwords_decoded = db.Column(db.Boolean, nullable=False, default=True)
    # Authentication method (Settings -> Authentication). 'local' (username +
    # password, the default / pre-existing behaviour) or 'azure' (Microsoft
    # Entra ID OIDC SSO). In azure mode the local password form is a break-glass
    # for the setup admin (id=1) only; everyone else signs in via Microsoft.
    # The azure_* fields hold the App Registration config; azure_client_secret
    # is write-only in the UI and is excluded from API serialization.
    auth_method = db.Column(db.String(10), nullable=False, default='local')
    azure_tenant_id = db.Column(db.String(64), nullable=True)
    azure_client_id = db.Column(db.String(64), nullable=True)
    azure_client_secret = db.Column(db.String(512), nullable=True)
    azure_redirect_uri = db.Column(db.String(512), nullable=True)
    azure_allowed_groups = db.Column(db.String(1024), nullable=True)  # comma-separated group Object IDs

class Jobs(db.Model):
    """Class object to represent Jobs"""

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    # priority: 5 = highest, 1 = lowest
    priority = db.Column(db.Integer, nullable=False, default=3)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    queued_at = db.Column(db.DateTime, nullable=True)
    # status: Running/Paused/Completed/Queued/Canceled/Ready/Incomplete
    status = db.Column(db.String(20), nullable=False)
    started_at = db.Column(db.DateTime, nullable=True)
    ended_at = db.Column(db.DateTime, nullable=True)
    hashfile_id = db.Column(db.Integer, nullable=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    # limit_recovered: one-and-done crack
    limit_recovered = db.Column(db.Boolean, nullable=False, default=False)

class JobTasks(db.Model):
    """Class object to represent JobTasks"""

    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, nullable=False, index=True)
    task_id = db.Column(db.Integer, nullable=False, index=True)
    priority = db.Column(db.Integer, nullable=False, default=3)
    command = db.Column(db.String(1024))
    # status: Running/Paused/Not Started/Completed/Queued/Canceled/Importing
    status = db.Column(db.String(50), nullable=False)
    started_at = db.Column(db.DateTime, nullable=True)      # These defaults should be changed
    agent_id = db.Column(db.Integer, db.ForeignKey('agents.id'))
    # Chunking: when a task is split, each chunk is its own JobTasks row. chunk_no
    # is 1-based within the (job, task); chunk_total is the chunk count. Both NULL
    # for a whole, un-chunked task.
    chunk_no = db.Column(db.Integer, nullable=True)
    chunk_total = db.Column(db.Integer, nullable=True)
    # The chunk's slice, stored so the command is re-derivable on re-queue without
    # re-planning: wordlist base-loop modes set chunk_skip/chunk_limit (word
    # offsets); mask base-loop modes set chunk_mask (the sub-mask). All NULL for a
    # whole, un-chunked task.
    chunk_skip = db.Column(db.BigInteger, nullable=True)
    chunk_limit = db.Column(db.BigInteger, nullable=True)
    chunk_mask = db.Column(db.String(64), nullable=True)

class Customers(db.Model):
    """Class object to represent Customers"""

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(40), nullable=False)

class Hashfiles(db.Model):
    """Class object to represent Hashfiles"""

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256), nullable=False)        # can probably be reduced
    uploaded_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    runtime = db.Column(db.Integer, default=0)
    customer_id = db.Column(db.Integer, nullable=False)
    owner_id = db.Column(db.Integer, nullable=False)
    # The supplied hashes' salts are hex-encoded -> hashcat needs --hex-salt; only
    # meaningful for the colon-delimited hash_only / user_hash formats (see
    # build_hashcat_command + validate_hex_salt).
    hex_salt = db.Column(db.Boolean, nullable=False, default=False)

class HashfileHashes(db.Model):
    """Class object to represent HashfileHashes"""

    id = db.Column(db.Integer, primary_key=True)
    hash_id = db.Column(db.Integer, nullable=False, index=True)
    username = db.Column(db.String(256), nullable=True, default=None, index=True)
    hashfile_id = db.Column(db.Integer, nullable=False, index=True)

class Agents(db.Model):
    """Class object to represent Agents"""

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)         # can probably be reduced
    src_ip = db.Column(db.String(15), nullable=False)
    uuid = db.Column(db.String(60), nullable=False)          # can probably be reduced
    status = db.Column(db.String(20), nullable=False)        # Pending, Syncing, Working, Idle
    hc_status = db.Column(db.String(6000))
    last_checkin = db.Column(db.DateTime)
    # True once an "agent offline" admin alert has been sent; reset when the agent
    # checks back in (so we notify once per offline episode + on recovery). See
    # scheduler.agent_health_check.
    offline_notified = db.Column(db.Boolean, nullable=False, default=False)
    benchmark = db.Column(db.String(20))
    cpu_count = db.Column(db.Integer)
    gpu_count = db.Column(db.Integer)
    # Device telemetry parsed from the agent's hashcat --status-json on each
    # working check-in and RETAINED across idle (so the agents page can show a
    # card's model/temp even when it's not currently cracking). gpu_model is a
    # short label (e.g. 'RTX 4090'); gpu_temps is a comma-separated list of the
    # per-card temperatures in °C (e.g. '71,70,72').
    gpu_model = db.Column(db.String(128))
    gpu_temps = db.Column(db.String(128))

class AgentBenchmarks(db.Model):
    """Per-(agent, hash_type) hashcat benchmark used to size task chunks.

    `speed` is raw hashes/sec summed across the agent's devices, parsed from the
    per-device `Speed.#N..........: <n> H/s` lines of `hashcat -b -m <mode>`. The
    chunk planner sizes chunks from the SLOWEST agent's speed for the job's
    hash_type. One row per (agent, hash_type); re-running a benchmark upserts the row.
    """

    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('agents.id'), nullable=False, index=True)
    hash_type = db.Column(db.Integer, nullable=False, index=True)
    speed = db.Column(db.BigInteger, nullable=False)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    __table_args__ = (
        db.UniqueConstraint('agent_id', 'hash_type', name='uix_agent_hashtype'),
    )

class Rules(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    last_updated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    path = db.Column(db.String(256), nullable=False)
    size = db.Column(db.Integer, nullable=False, default=0)
    checksum = db.Column(db.String(64), nullable=False)

class Wordlists(db.Model):
    """Class object to represent Wordlists"""

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256), nullable=False)
    last_updated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    type = db.Column(db.String(7))                          # Dynamic or Static
    path = db.Column(db.String(245), nullable=False)
    size = db.Column(db.BigInteger, nullable=False)         # line count
    byte_size = db.Column(db.BigInteger, nullable=True)     # on-disk bytes of the file at `path` (compressed for static)
    checksum = db.Column(db.String(64), nullable=False)

class Tasks(db.Model):
    """Class object to represent Tasks"""

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    hc_attackmode = db.Column(db.Integer, nullable=False) # 0, 1, 3, 6, 7
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    wl_id = db.Column(db.Integer)
    wl_id_2 = db.Column(db.Integer)
    j_rule = db.Column(db.String(25))
    k_rule = db.Column(db.String(25))
    rule_id = db.Column(db.Integer)
    hc_mask = db.Column(db.String(50))
    # Opt-in to hashcat's --loopback (straight mode + rules only); see build_hashcat_command
    loopback = db.Column(db.Boolean, nullable=False, default=False)

class TaskGroups(db.Model):
    """Class object to represent TaskGroups"""

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    # Ordered JSON list of task ids. TEXT (65,535 bytes) rather than VARCHAR so
    # a large membership can't silently overflow. The number of entries is
    # capped by utils.MAX_TASKS_PER_GROUP — that cap bounds entries, not bytes,
    # so see the constant's comment for where the column is still the tighter
    # limit.
    tasks = db.Column(db.Text, nullable=False)
    # Named (not bare unique=True) so a model-built schema and the
    # b5c8d9e1f2a4 migration agree on the constraint name — see that
    # migration and the uix_agent_hashtype precedent above.
    __table_args__ = (
        db.UniqueConstraint('name', name='uq_task_groups_name'),
    )

class Hashes(db.Model):
    """Class object to represent Hashes"""

    id = db.Column(db.Integer, primary_key=True)
    sub_ciphertext = db.Column(db.String(32), nullable=False, index=True)
    # TEXT (not VARCHAR): hashes get long (NetNTLMv2, Kerberos) and the column
    # holds some non-ASCII bytes, so a utf8mb4 VARCHAR large enough would exceed
    # MySQL's 65,535-byte row limit. TEXT is stored off-page and holds ~64 KB.
    ciphertext = db.Column(db.Text, nullable=False)
    hash_type = db.Column(db.Integer, nullable=False, index=True)
    cracked = db.Column(db.Boolean, nullable=False)
    recovered_at = db.Column(db.DateTime, nullable=True)
    task_id = db.Column(db.Integer, nullable=True, index=True)
    recovered_by = db.Column(db.Integer, nullable=True)
    plaintext = db.Column(db.String(256), index=True)

    # Composite indexes leading with the equality column (cracked) so the hot
    # dashboard/tasks aggregates over this multi-million-row table are index-driven
    # instead of full scans + filesorts:
    #   (cracked, recovered_at) -> recovery feed ORDER BY recovered_at, chart ranges
    #   (cracked, task_id)      -> per-task recovered counts (GROUP BY task_id)
    __table_args__ = (
        db.Index('ix_hashes_cracked_recovered_at', 'cracked', 'recovered_at'),
        db.Index('ix_hashes_cracked_task_id', 'cracked', 'task_id'),
    )

class JobNotifications(db.Model):
    """Class object to represent JobNotifications"""

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, nullable=False)
    job_id = db.Column(db.Integer, nullable=False)
    method = db.Column(db.String(6), nullable=False)    # email, push

class HashNotifications(db.Model):
    """Class object to represent HashNotification"""

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, nullable=False)
    # Indexed: joined to hashfile_hashes.hash_id on the hot /jobs alert-hash check.
    hash_id = db.Column(db.Integer, nullable=False, index=True)
    method = db.Column(db.String(6), nullable=False)    # email, push
