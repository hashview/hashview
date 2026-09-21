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

    @classmethod
    def current(cls):
        """The instance's settings row, chosen DETERMINISTICALLY.

        Settings is a singleton in intent but not in schema -- nothing stops a
        second row, and this instance has 98 of them (id 1 real, the rest all
        zeros). Every reader used a bare .first(), which in SQL has no defined
        order: MySQL happens to return primary-key order for a plain scan of a
        small table, so id 1 wins today, but that is a property of the chosen
        plan and not a guarantee. If a zero row ever won, the instance would
        silently switch to chunking disabled, no runtime caps, and a retention
        period of 0 -- with nothing in any log to say why.

        Lowest id wins, which is the row the setup wizard wrote first.
        """
        return cls.query.order_by(cls.id.asc()).first()

class Jobs(db.Model):
    """Class object to represent Jobs"""

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    # priority: 5 = highest, 1 = lowest
    priority = db.Column(db.Integer, nullable=False, default=3)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    queued_at = db.Column(db.DateTime, nullable=True)
    # status: Running/Paused/Completed/Queued/Canceled/Ready/Expired/Incomplete
    #   Expired    -- exceeded Settings.max_runtime_jobs
    #   Canceled   -- stopped by a person
    #   Incomplete -- created but never queued; NOT a roll-up outcome
    #                 (see utils._job_completion_outcome)
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
    # status: Running/Paused/Not Started/Completed/Queued/Canceled/Expired/Importing
    #   Expired -- the (job, task) group exceeded Settings.max_runtime_tasks,
    #              or its job exceeded Settings.max_runtime_jobs
    status = db.Column(db.String(50), nullable=False)
    started_at = db.Column(db.DateTime, nullable=True)      # These defaults should be changed
    agent_id = db.Column(db.Integer, db.ForeignKey('agents.id'))
    # Chunking: each dispatched slice is its own JobTasks row. chunk_no is a
    # 1-based issue counter within the attack.
    #
    # chunk_total is NOT a plan size any more: slices are sized for the agent that
    # asks for one, so the count is unknown until the attack finishes. Rows this
    # server stamps carry CHUNK_TOTAL_WHOLE (-1); a value >= 1 is a pre-0.8.4 row
    # still carrying the old chunk count. Both are truthy on purpose -- that is
    # what an un-upgraded agent tests to decide it should key its temp files on
    # the JobTask id. Read utils.is_chunk_row(), never this column, to ask whether
    # a row is a slice.
    chunk_no = db.Column(db.Integer, nullable=True)
    chunk_total = db.Column(db.Integer, nullable=True)
    # The chunk's slice, stored so the command is re-derivable on re-queue without
    # re-planning: wordlist base-loop modes set chunk_skip/chunk_limit (word
    # offsets); mask base-loop modes set chunk_mask (the sub-mask). All NULL for a
    # whole, un-chunked task.
    chunk_skip = db.Column(db.BigInteger, nullable=True)
    chunk_limit = db.Column(db.BigInteger, nullable=True)
    # 255, matching Tasks.hc_mask: a sub-mask is never longer than the task
    # mask it came from (_expand_mask swaps a '?x' position for a 1-2 char
    # literal).
    chunk_mask = db.Column(db.String(255), nullable=True)
    # The attack (JobTaskLedger) this row is a dispatch receipt for. NULL for a
    # row queued by a pre-ledger server; those keep dispatching the old way.
    ledger_id = db.Column(db.Integer, nullable=True, index=True)
    # Base-loop units this row covers, so progress can be summed without
    # re-deriving it from chunk_skip/chunk_limit (a whole row has neither).
    chunk_keyspace = db.Column(db.BigInteger, nullable=True)

class Customers(db.Model):
    """Class object to represent Customers"""

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)

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
    status = db.Column(db.String(20), nullable=False)        # Pending, Authorized, Working, Idle
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
    # Which hashcat this agent runs. hashcat 7 redefines both --keyspace and
    # --skip/--limit to whole-run units -- self-consistent within a version,
    # silently mis-covering across one -- so a measured keyspace is only usable by
    # an agent on the same MAJOR as the one that measured it. hc_version is the
    # raw string for diagnostics; hc_major is what is actually compared, because
    # 6.2.6 and 6.2.7 are identical here and comparing full strings would stall a
    # fleet over a patch bump. NULL until the agent reports it.
    hc_version = db.Column(db.String(32), nullable=True)
    hc_major = db.Column(db.SmallInteger, nullable=True)
    gpu_temps = db.Column(db.String(128))

class AgentBenchmarks(db.Model):
    """Per-(agent, hash_type) hashcat benchmark used to size task chunks.

    `speed` is raw hashes/sec summed across the agent's devices, parsed from the
    per-device `Speed.#N..........: <n> H/s` lines of `hashcat -b -m <mode>`. The
    Each chunk is sized from the speed of the agent that ASKS for it, so a faster
    rig takes a proportionally larger slice of the keyspace. One row per
    (agent, hash_type); re-running a benchmark upserts the row.
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
    # True once a "file missing on disk" admin alert has been sent for this row;
    # cleared when the file reappears (so we notify once per episode + on
    # recovery). Written ONLY by scheduler.catalog_health_check -- it records
    # whether we have TOLD the admins, not whether the file is currently there
    # (that is computed; see utils.rule_file_missing / wordlist_file_missing).
    file_missing_notified = db.Column(db.Boolean, nullable=False, default=False)

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
    # True once a "file missing on disk" admin alert has been sent for this row;
    # cleared when the file reappears (so we notify once per episode + on
    # recovery). Written ONLY by scheduler.catalog_health_check -- it records
    # whether we have TOLD the admins, not whether the file is currently there
    # (that is computed; see utils.rule_file_missing / wordlist_file_missing).
    file_missing_notified = db.Column(db.Boolean, nullable=False, default=False)

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
    # 255, matching JobTasks.chunk_mask (see chunk_mask's comment): a mask is a
    # sequence of '?x' placeholders (2 chars each) plus optional literals, and
    # modes 27000/27100 (NetNTLMv1/v2 (NT), which crack the NT hash itself)
    # force a full 32-position mask -- 64 characters -- which the old
    # VARCHAR(50) rejected outright before it ever reached hashcat.
    hc_mask = db.Column(db.String(255))
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
    # No standalone index: uq_hashes_sub_ciphertext_hash_type leads with this
    # column, so it is a leftmost-prefix superset of the index this replaces.
    # See migration f3b8c1a7d942.
    sub_ciphertext = db.Column(db.String(32), nullable=False)
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
    #
    # The unique constraint is what the import's dedup already assumed: it looks
    # a hash up by (hash_type, sub_ciphertext) and inserts when absent, so
    # without it two concurrent imports of the same hash can both miss and both
    # insert -- and a duplicate splits crack state, because both cracked-hash
    # ingest paths take .first() with cracked='0', so one copy gets the
    # plaintext while a hashfile pointing at the other still reads uncracked.
    # sub_ciphertext leads so the constraint also serves every read of that
    # column on its own, which is why it no longer carries a separate index.
    __table_args__ = (
        db.Index('ix_hashes_cracked_recovered_at', 'cracked', 'recovered_at'),
        db.Index('ix_hashes_cracked_task_id', 'cracked', 'task_id'),
        # Covers SELECT DISTINCT plaintext WHERE cracked -- the dynamic
        # recovered-password wordlists. Without it that DISTINCT builds an
        # on-disk temporary table over the whole corpus before sending a single
        # row. See migration e9f4c2a70b18.
        db.Index('ix_hashes_cracked_plaintext', 'cracked', 'plaintext'),
        db.UniqueConstraint('sub_ciphertext', 'hash_type',
                            name='uq_hashes_sub_ciphertext_hash_type'),
    )

class JobTaskLedger(db.Model):
    """The durable record of one ATTACK on a job, and where its keyspace stands.

    One row per assignment -- not per (job_id, task_id). A task using a dynamic
    wordlist may legitimately be assigned to the same job more than once
    (jobs_assign_task), so (job_id, task_id) is not unique over attacks;
    (job_id, position) is.

    Why a ledger exists at all: JobTasks rows are dispatch RECEIPTS, and once
    chunks are issued on demand the set of them for a task changes over the life
    of a run -- so every question answered by counting or scanning those rows
    ("how many attacks does this job have", "what order are they in", "how far
    along is it", "is the job finished") needs somewhere stable to live.

    keyspace/keyspace_pos are in hashcat BASE-LOOP units, which is exactly what
    --skip/--limit consume. That unit is NOT the candidate count: for
    `-a 3 -m 0 ?d?d?d?d?d` hashcat reports a keyspace of 10,000 against 100,000
    candidates. The ratio is `amp`, and it is always an exact integer -- which is
    also the integrity check on a reported keyspace (total % keyspace == 0).

    For wordlist base-loop modes (0 straight, 1 combinator, 6 hybrid) the keyspace
    IS the left wordlist's line count, so the server knows it exactly. For mask
    base-loop modes (3, 7) it depends on the hash mode and on -S as well as the
    mask, so it cannot be computed here and must be measured by an agent; until
    then the attack runs whole, which needs no --skip/--limit and is therefore
    correct under any unit.
    """

    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, nullable=False, index=True)
    task_id = db.Column(db.Integer, nullable=False, index=True)
    # Dispatch order within the job. Seeded from the ascending JobTasks.id order
    # the job was built in, so it reproduces the previous min(JobTasks.id)
    # ordering exactly -- which stops being usable once rows are minted lazily,
    # because a task whose first row appears an hour in gets a HIGHER min id.
    position = db.Column(db.Integer, nullable=False, default=0)
    # Pending (a mask attack awaiting an agent's --keyspace measurement)
    # | Measuring (an agent holds the measuring lease until measure_expires)
    # | Ready (mintable while keyspace_pos < keyspace)
    # | Closed (no more slices will be issued; see closed_reason)
    # | Unmeasurable (runs whole -- unsplittable, or no usable measurement)
    state = db.Column(db.String(16), nullable=False, default='Pending')
    keyspace = db.Column(db.BigInteger, nullable=True)
    # 'exact' (server-computed, wordlist modes) | 'measured' (agent-reported)
    keyspace_source = db.Column(db.String(10), nullable=True)
    # The cursor. Units in [0, keyspace_pos) have been issued at least once.
    keyspace_pos = db.Column(db.BigInteger, nullable=False, default=0)
    # total_candidates // keyspace. Stored rather than total_candidates because a
    # ten-position ?a mask is 95**10 ~ 6e19, which overflows a signed BIGINT;
    # amp never does.
    amp = db.Column(db.BigInteger, nullable=False, default=1)
    # Smallest slice we will issue, = ceil(keyspace / DEFAULT_MAX_CHUNKS), so the
    # chunk-count cap keeps bounding rows per attack once sizing is per-agent.
    min_slice = db.Column(db.BigInteger, nullable=False, default=1)
    issued_count = db.Column(db.Integer, nullable=False, default=0)
    # False for an attack that can never be split (dynamic wordlist, unparseable
    # mask, no benchmark): it runs whole, and whole is always correct.
    chunkable = db.Column(db.Boolean, nullable=False, default=False)
    # hashcat MAJOR version of the agent that measured the keyspace. hashcat 7
    # redefines both --keyspace and --skip/--limit to whole-run units, which is
    # self-consistent within a version and silently mis-covering across one.
    hc_major = db.Column(db.SmallInteger, nullable=True)
    measured_by = db.Column(db.Integer, nullable=True)
    measure_expires = db.Column(db.DateTime, nullable=True)
    # Digest of the inputs the keyspace depends on. A wordlist re-uploaded under
    # the same id changes Wordlists.size, which silently invalidates every stored
    # offset; this detects that instead of cracking the wrong ranges.
    fingerprint = db.Column(db.String(64), nullable=True)
    closed_reason = db.Column(db.String(32), nullable=True)
    # Bumped by every conditional UPDATE. Load-bearing: PyMySQL does not set
    # CLIENT_FOUND_ROWS, so MySQL rowcount counts CHANGED rows, not matched ones
    # -- a compare-and-swap that could write identical values would report 0 and
    # be misread as "lost the race".
    rev = db.Column(db.Integer, nullable=False, default=0)
    # datetime.now(), not utcnow: every writer of this column uses naive LOCAL
    # time, and mixing the two in one column is what produced the cross-process
    # skew that made agents look offline (the last_checkin bug).
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.now)

    __table_args__ = (
        db.UniqueConstraint('job_id', 'position', name='uix_ledger_job_position'),
    )


class JobNotifications(db.Model):
    """Class object to represent JobNotifications"""

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, nullable=False)
    job_id = db.Column(db.Integer, nullable=False)
    method = db.Column(db.String(6), nullable=False)    # email, push
    # When this notification was last delivered. The row used to be DELETED on
    # delivery, which made a job's notification setup a one-shot: a premature or
    # mistaken completion destroyed it permanently, and a re-run of the job
    # notified nobody. NULL means "not yet sent for the current run"; queueing a
    # job clears it back to NULL. Delivery is gated on a conditional UPDATE of
    # this column, so concurrent completions cannot double-send.
    sent_at = db.Column(db.DateTime, nullable=True)

class HashNotifications(db.Model):
    """Class object to represent HashNotification"""

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, nullable=False)
    # Indexed: joined to hashfile_hashes.hash_id on the hot /jobs alert-hash check.
    hash_id = db.Column(db.Integer, nullable=False, index=True)
    method = db.Column(db.String(6), nullable=False)    # email, push
