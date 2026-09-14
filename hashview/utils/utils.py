"""Flask routes to handle utils"""
import _md5
import binascii
import gzip
import hashlib
import json
import os
import re
import secrets
import struct

import requests
from flask import after_this_request, current_app, send_from_directory, url_for
from flask_mail import Message
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.sql import exists
from sqlalchemy.sql import true as sa_true

from hashview.models import (
    AgentBenchmarks,
    Agents,
    Customers,
    Hashes,
    HashfileHashes,
    Hashfiles,
    HashNotifications,
    JobNotifications,
    Jobs,
    JobTaskLedger,
    JobTasks,
    Rules,
    Settings,
    Tasks,
    Users,
    Wordlists,
    db,
)
from hashview.utils.chunking import (
    DEFAULT_MAX_CHUNKS,
    MASK_MODES,
    WORDLIST_MODES,
    is_chunkable,
    mask_keyspace,
    wordlist_amplifier,
)
from hashview.utils.clock import utcnow
from hashview.utils.hashcat_modes import HASH_CASE_RULES, HASH_ONLY_AUTO_RULES

# Hard cap on how many task assignments one task group may hold (one assignment
# = one id in the ordered JSON list stored in task_groups.tasks). This is the
# PRODUCT limit, sized for the regime deployments actually run in: most never
# pass four-digit task ids, and 10,000 four-digit ids serialize to 60,000 bytes
# — inside the TEXT column's 65,535.
#
# It is deliberately NOT a byte guarantee. json.dumps separates items with
# ', ', so each id costs its digit count + 2: 10,000 five-digit ids are 70,000
# bytes, and past an average of ~4.55 digits the column is the tighter limit
# (5-digit ids: 9,362 entries; 6-digit: 8,191). MySQL runs with
# STRICT_TRANS_TABLES, so exceeding it is an errno-1406 error, not a
# truncation. Widening the column to MEDIUMTEXT would leave this cap as the
# only limit at any id width.
MAX_TASKS_PER_GROUP = 10000


def remove_file(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    except OSError as error:
        # Don't fail the request, but surface the problem so an admin can
        # troubleshoot temp files stacking up in control/tmp (see issue #226).
        current_app.logger.warning(
            'Failed to remove temporary file %s: %s', path, error)


def send_generated_file(directory, filename, **kwargs):
    """Serve a control/tmp scratch file and delete it once served.

    Unlinked via after_this_request rather than response.call_on_close():
    send_from_directory() sets direct_passthrough, and werkzeug's
    get_app_iter() returns the raw file wrapper for that case instead of
    wrapping it in a ClosingIterator, so Response.close() -- and with it every
    call_on_close callback -- never runs. The unlink therefore happens while
    the file is still open for streaming, which is fine on POSIX: the fd stays
    valid and the body is sent in full, only the directory entry goes away.
    """
    file_path = os.path.join(directory, filename)
    response = send_from_directory(directory, filename, **kwargs)

    @after_this_request
    def _cleanup(resp):        # pylint: disable=unused-variable
        remove_file(file_path)
        return resp

    return response


def try_commit(context=''):
    """Commit the current session; on any DB error roll back + log and return False.

    Lets delete routes turn a concurrent double-submit (e.g. two quick clicks on
    a delete button — the second commit raises StaleDataError because the row is
    already gone) into a flash message instead of a 500.
    """
    try:
        db.session.commit()
        return True
    except SQLAlchemyError:
        db.session.rollback()
        current_app.logger.exception('DB commit failed: %s', context)
        return False


def purge_orphaned_hashes():
    """Delete uncracked hashes no hashfile links to any more, and notifications
    whose hash is gone. Two set-based statements; does NOT commit, so the
    caller owns the transaction.

    Shared by every cascade-delete path (hashfile, bulk hashfile, customer) so
    they cannot drift apart. Deliberately expressed as "nothing references this
    any more" rather than as a per-hash reference count: a NOT EXISTS states the
    invariant directly and cannot orphan a link belonging to someone else,
    whereas a count has to be read together with whatever else the surrounding
    loop has already deleted in the same transaction.

    Cracked hashes are kept on purpose — recovered plaintext outlives the
    hashfile it arrived in.
    """
    Hashes.query.filter(Hashes.cracked == 0).filter(
        ~exists().where(HashfileHashes.hash_id == Hashes.id)
    ).delete(synchronize_session=False)
    HashNotifications.query.filter(
        ~exists().where(Hashes.id == HashNotifications.hash_id)
    ).delete(synchronize_session=False)


def save_file(path, form_file):
    """Save an uploaded file under a randomized, non-attacker-controlled name.

    The uploaded filename comes straight from the multipart Content-Disposition
    header and is fully attacker-controlled, so it is NOT used to build the
    on-disk name: the file is stored as ``<random_hex>.txt`` inside ``path``.
    Reusing any part of ``form_file.filename`` here previously let path
    separators and shell metacharacters reach the on-disk name (CWE-22/CWE-78);
    the random ``.txt`` name closes that off with no change for normal uploads
    (they already resolved to ``<hex>.txt``). Display names are stored
    separately from this path by the callers.
    """
    random_hex = secrets.token_hex(8)
    file_name = random_hex + '.txt'
    file_path = os.path.join(current_app.root_path, path, file_name)
    form_file.save(file_path)
    return file_path

def _count_generator(reader):
    b = reader(1024 * 1024)
    while b:
        yield b
        b = reader(1024 * 1024)

def get_linecount(filepath):
    """Function to return line count of file.

    Counts '\\n' bytes and adds one only when the file is non-empty AND its
    final byte is not '\\n' (an unterminated last line still counts as a
    line). A file that ends with '\\n' has no such dangling line, so no +1.
    An empty file has zero lines. The last byte is tracked across the
    streamed 1 MiB chunks, not read separately, so multi-GB files still
    never load fully into memory.
    """

    with open(filepath, 'rb') as fp:
        c_generator = _count_generator(fp.raw.read)
        count = 0
        last_byte = b''
        for buffer in c_generator:
            count += buffer.count(b'\n')
            last_byte = buffer[-1:]
        if last_byte and last_byte != b'\n':
            count += 1
        return count

def get_filehash(filepath):
    """Function to sha256 hash of file"""

    sha256_hash = hashlib.sha256()
    with open(filepath,"rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096),b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# ----------------------------------------------------------------------------
# Wordlist gzip storage helpers
#
# Wordlists are stored compressed (gzip -9) at rest. These helpers centralise
# the compression / validation / line-counting so the UI upload, the API
# upload, the download endpoint, and the launch-time migration all behave
# identically. Everything streams in 1 MB chunks so multi-GB wordlists never
# load fully into memory.
# ----------------------------------------------------------------------------

_GZIP_MAGIC = b'\x1f\x8b'
_CHUNK = 1024 * 1024


def is_gzip(filepath):
    """Return True if the file begins with the gzip magic bytes."""
    with open(filepath, 'rb') as f:
        return f.read(2) == _GZIP_MAGIC


def get_filesize(filepath):
    """Return the on-disk size of a file in bytes."""
    return os.path.getsize(filepath)


def ensure_gz(basename):
    """Return basename with a trailing '.gz' (idempotent).

    Shared filename rule between the server (build_hashcat_command) and the
    agent so the compressed-at-rest file is referenced by the same name on
    both sides. Static paths become '<hex>.gz'; dynamic paths (stored as
    '<hex>.txt' on the server) become '<hex>.txt.gz' for the agent.
    """
    return basename if basename.endswith('.gz') else basename + '.gz'


def compress_to_gz(src_path, dst_path, level=9):
    """Stream-compress src_path into a gzip file at dst_path (no shell)."""
    with open(src_path, 'rb') as src, gzip.open(dst_path, 'wb', compresslevel=level) as dst:
        for chunk in iter(lambda: src.read(_CHUNK), b''):
            dst.write(chunk)


def decompress_gz(src_path, dst_path):
    """Stream-decompress a gzip file at src_path into dst_path.

    Raises (gzip.BadGzipFile / OSError) on a malformed gzip stream, which
    doubles as validation for uploaded .gz files.
    """
    with gzip.open(src_path, 'rb') as src, open(dst_path, 'wb') as dst:
        for chunk in iter(lambda: src.read(_CHUNK), b''):
            dst.write(chunk)


def gz_linecount(filepath):
    """Return the line count of a gzipped text file.

    Streams the decompressed content (the "zcat | wc -l" equivalent) and uses
    the SAME semantics as get_linecount (count of '\\n', +1 only when the
    decompressed content is non-empty and its final byte is not '\\n') so a
    wordlist's reported line count is identical whether it arrived as plain
    text or gzip. Raises on a malformed gzip stream (validation).
    """
    count = 0
    last_byte = b''
    with gzip.open(filepath, 'rb') as f:
        for buffer in iter(lambda: f.read(_CHUNK), b''):
            count += buffer.count(b'\n')
            last_byte = buffer[-1:]
    if last_byte and last_byte != b'\n':
        count += 1
    return count


def _compress_wordlist_to(src_path, dest_gz):
    """Compress an uploaded wordlist (plain text OR gzip) to ``dest_gz`` at -9.

    Shared core of ingest_static_wordlist_file (new row) and
    restore_static_wordlist_file (existing row). For an already-gzipped upload
    we decompress it first -- which validates the gzip -- count lines from the
    plaintext, then RE-compress at -9, since the user may have uploaded a
    weakly-compressed .gz.

    Returns the line count. Raises on an invalid gzip; always cleans up its own
    temp file.
    """
    tmp_dir = os.path.join(current_app.root_path, 'control/tmp')
    if is_gzip(src_path):
        tmp_plain = os.path.join(tmp_dir, secrets.token_hex(8))
        try:
            decompress_gz(src_path, tmp_plain)      # raises on bad gzip
            size = get_linecount(tmp_plain)
            compress_to_gz(tmp_plain, dest_gz, 9)
        finally:
            if os.path.exists(tmp_plain):
                os.remove(tmp_plain)
    else:
        size = get_linecount(src_path)
        compress_to_gz(src_path, dest_gz, 9)
    return size

def restore_static_wordlist_file(src_path, wordlist):
    """Replace a static wordlist's file IN PLACE, keeping its row and path.

    The point of the exercise (issue #383): a stranded row is repaired without
    minting a new id or a new filename, so every Tasks.wl_id / wl_id_2, every
    already-materialized JobTasks.command, and every Hashes.task_id attribution
    stays valid. Re-uploading through wordlists_add cannot do this -- it always
    mints a fresh path -- which is why a re-upload orphans the reference
    further instead of fixing it.

    Deliberately a sibling of ingest_static_wordlist_file rather than a mode
    flag on it: that function's contract is "returns an unsaved Wordlists row"
    and it has three callers who would all have to read a branch they don't use.

    Compresses into control/tmp first and os.replace()s onto the stored path, so
    a rejected upload can never destroy a file that is still good. The basename
    is preserved, which is what keeps build_hashcat_command emitting the
    identical agent-side path. Mutates size/checksum/byte_size/last_updated on
    the row; the CALLER commits.
    """
    wordlists_dir = os.path.join(current_app.root_path, 'control/wordlists')
    tmp_dir = os.path.join(current_app.root_path, 'control/tmp')
    # Normalize into control/wordlists: the row's stored path may be relative,
    # and only this directory is ever served from.
    dest_gz = os.path.join(wordlists_dir, os.path.basename(wordlist.path or ''))
    if not os.path.basename(dest_gz):
        dest_gz = os.path.join(wordlists_dir, secrets.token_hex(8) + '.gz')

    staged = os.path.join(tmp_dir, secrets.token_hex(8) + '.gz')
    try:
        size = _compress_wordlist_to(src_path, staged)   # raises on bad gzip
        os.replace(staged, dest_gz)
    finally:
        if os.path.exists(staged):
            os.remove(staged)

    wordlist.path = dest_gz
    wordlist.size = size
    wordlist.checksum = get_filehash(dest_gz)     # checksum of the COMPRESSED file
    wordlist.byte_size = get_filesize(dest_gz)
    wordlist.last_updated = utcnow()
    return wordlist

def ingest_static_wordlist_file(src_path, owner_id, name):
    """Ingest an uploaded wordlist (plain text OR gzip) into compressed storage.

    Produces a compressed-at-rest static wordlist:
      - line count (`size`) computed with get_linecount semantics,
      - `checksum` = sha256 of the COMPRESSED .gz that gets stored,
      - the stored file is gzip -9 at control/wordlists/<hex>.gz,
      - `byte_size` = on-disk bytes of that .gz.

    For an already-gzipped upload we decompress it (validating the gzip),
    count lines from the plaintext, then RE-compress with -9 to guarantee
    maximum compression (the user may have uploaded a weakly-compressed .gz).

    Returns an unsaved Wordlists row (caller does db.session.add/commit).
    Raises on an invalid gzip upload; always cleans up its own temp files.
    """
    wordlists_dir = os.path.join(current_app.root_path, 'control/wordlists')
    final_gz = os.path.join(wordlists_dir, secrets.token_hex(8) + '.gz')
    size = _compress_wordlist_to(src_path, final_gz)

    return Wordlists(
        name=name,
        owner_id=owner_id,
        type='static',
        path=final_gz,
        checksum=get_filehash(final_gz),     # checksum of the COMPRESSED file
        size=size,
        byte_size=get_filesize(final_gz),
    )

def get_agent_timeout_minutes():
    """Minutes Hashview waits for an agent check-in before considering it offline.
    Single source for the UI cutoff (inject_nav_counts) and the agent-health
    scheduler. Defaults to 60 on a missing Settings row / pre-migration DB."""
    try:
        settings = Settings.current()
        if settings and settings.agent_timeout_minutes:
            return settings.agent_timeout_minutes
    except Exception:  # pragma: no cover - pre-migration / no DB
        return 60
    return 60

def notify_owner_of_cancellation(job, canceled_by, task=None, when=None):
    """Tell a job's owner that somebody ELSE stopped their work.

    Only fires when the canceller is not the owner. Every stop route authorises
    "admin OR owner", so a non-owner canceller is necessarily an administrator --
    and that is precisely the case the owner cannot otherwise see: their job or
    task simply turns up Canceled with nothing to say who did it or when.

    ``task`` scopes the message to one attack; omit it for a whole-job stop.
    ``when`` is the cancellation time, passed in rather than read from the clock
    here so the email and the audit entry cannot disagree.

    Best-effort in every direction: a stop must never fail, or be undone,
    because mail is unreachable. Respects the instance-wide email switch, the
    same as notify_admins.
    """
    try:
        if job is None or canceled_by is None:
            return False
        if job.owner_id is None or job.owner_id == canceled_by.id:
            return False        # you do not need telling that you did it
        settings = Settings.current()
        if settings is not None and not settings.email_enabled:
            return False
        owner = Users.query.get(job.owner_id)
        if owner is None or not owner.email_address:
            return False

        when = when or utcnow()
        actor = f'{canceled_by.first_name} {canceled_by.last_name}'.strip() \
            or canceled_by.email_address
        what = f'Task "{task.name}" on job "{job.name}"' if task is not None \
            else f'Job "{job.name}"'
        subject = (f'Hashview: your task on job "{job.name}" was canceled'
                   if task is not None else
                   f'Hashview: your job "{job.name}" was canceled')
        body = (
            f'{what} was canceled by another user.\n'
            f'\n'
            f'  What:      {what}\n'
            # An inbox cannot run hvLocalizeTimes, so this one stays absolute
            # and names its zone rather than rendering bare digits the reader
            # would reasonably assume were local.
            f'  Canceled:  {when.strftime("%Y-%m-%d %H:%M:%S")} UTC\n'
            f'  By:        {actor} <{canceled_by.email_address}>\n'
            f'\n'
            'You are receiving this because you own the job.\n'
        )
        return send_email(owner, subject, body)
    except Exception:   # nosec B110 - notifying the owner must never block a stop
        current_app.logger.exception('Could not notify the job owner of a cancellation.')
        return False


def notify_admins(subject, message):
    """Deliver an administrative notification (e.g. an agent error) to the admins
    who opted in, over each channel they selected and that is instance-enabled.

    Email/Pushover are delivered per-admin. Slack is different: admin alerts post
    to the single shared room (Settings.slack_admin_channel), so we post there ONCE
    when any opted-in admin selected Slack — never once per admin. Respects the
    instance-wide master switches (a disabled channel never sends)."""
    settings = Settings.current()
    email_on = bool(settings.email_enabled) if settings else True
    push_on = bool(settings.pushover_enabled) if settings else True
    slack_on = bool(settings.slack_enabled) if settings else False
    room = settings.slack_admin_channel if settings else None

    admins = Users.query.filter_by(admin=True, admin_notifications_enabled=True).all()

    slack_wanted = False
    for user in admins:
        if email_on and user.admin_notify_email:
            send_email(user, subject, message)
        if push_on and user.admin_notify_pushover and user.pushover_app_id and user.pushover_user_key:
            send_pushover(user, subject, message)
        if slack_on and user.admin_notify_slack and room:
            slack_wanted = True

    if slack_wanted:
        send_slack_channel(room, subject, message)

def send_email(user, subject, message):
    """Function to send email"""

    msg = Message(subject, recipients=[user.email_address])
    msg.body = message
    try:
        current_app.extensions['mail'].send(msg)
        return True
    except Exception:
        return False

def send_html_email(user, subject, message):
    """Function to send html based email"""

    msg = Message(subject, recipients=[user.email_address])
    msg.html = message
    current_app.extensions['mail'].send(msg)

def send_pushover(user, subject, message):
    """Function to send pushover notification"""

    if not user.pushover_user_key:
        current_app.logger.info('SendPushover is Complete with Failure(User Key not Configured).')
        return

    if not user.pushover_app_id:
        current_app.logger.info('SendPushover is Complete with Failure(App Id not Configured).')
        return

    # https://pushover.net/api
    payload = dict(
        token   = user.pushover_app_id,
        user    = user.pushover_user_key,
        message = message,
        title   = subject,
    )
    response = requests.post('https://api.pushover.net/1/messages.json', params=payload, timeout=30)
    response_json = response.json()
    if 400 <= response.status_code < 500:
        current_app.logger.info('SendPushover is Complete with Failure(%s).', response_json.get('errors'))
        send_email(user, 'Error Sending Push Notification', f'Check your Pushover API keys in  your profile. Original Message: {message}')
        return

    current_app.logger.info('SendPushover is Complete with Success(%s).', response_json)
    return

def _post_slack(channel, subject, message):
    """Post a message to a Slack conversation (a user's Member ID -> DM, or a
    channel id -> that room) via the global bot. Logs the outcome and never
    raises. No-ops (with a log line) when Slack is disabled/unconfigured globally
    or no target channel is given."""

    settings = Settings.current()
    if not settings or not settings.slack_enabled or not settings.slack_bot_token:
        current_app.logger.info('SendSlack is Complete with Failure(Slack not enabled/configured).')
        return

    if not channel:
        current_app.logger.info('SendSlack is Complete with Failure(No Slack target configured).')
        return

    # https://api.slack.com/methods/chat.postMessage - a user's member ID DMs them;
    # a channel id posts to that room (bot needs chat:write, and to be in the
    # channel or hold chat:write.public for public rooms).
    headers = {'Authorization': 'Bearer ' + settings.slack_bot_token}
    payload = {'channel': channel, 'text': '*' + subject + '*\n' + message}
    response = requests.post('https://slack.com/api/chat.postMessage', json=payload, headers=headers, timeout=30)
    response_json = response.json()
    if not response_json.get('ok'):
        current_app.logger.info('SendSlack is Complete with Failure(%s).', response_json.get('error'))
        return

    current_app.logger.info('SendSlack is Complete with Success.')
    return

def send_slack(user, subject, message):
    """Send a Slack DM to a user via the global bot, addressed by their Slack
    Member ID (user.slack_id). No-ops when the user has no Slack Member ID."""
    if not user.slack_id:
        current_app.logger.info('SendSlack is Complete with Failure(User Slack ID not configured).')
        return
    _post_slack(user.slack_id, subject, message)

def send_slack_channel(channel, subject, message):
    """Post to a Slack channel/room (e.g. the administrative-notifications room
    Settings.slack_admin_channel) via the global bot."""
    _post_slack(channel, subject, message)

def deliver_user_notification(user, method, subject, message, html_message=None):
    """Dispatch one notification to `user` over a single `method`
    ('email' | 'push' | 'slack'), centralising the channel branching + the
    missing-config email fallbacks. For 'email', html_message (when given) is
    sent as HTML; otherwise the plaintext message. Unknown methods are a no-op.

    A channel disabled instance-wide (Settings -> Notifications) is skipped
    silently — so a previously-configured notification never fires through a
    channel an admin has since turned off. Missing-config fallbacks only email
    the user when the Email channel is itself enabled."""

    settings = Settings.current()
    # No Settings row (fresh DB): match the UI defaults — email/pushover on, slack off.
    enabled = {
        'email': bool(settings.email_enabled) if settings else True,
        'push': bool(settings.pushover_enabled) if settings else True,
        'slack': bool(settings.slack_enabled) if settings else False,
    }
    if not enabled.get(method):
        current_app.logger.info('Notification skipped: channel "%s" is disabled.', method)
        return

    if method == 'email':
        if html_message is not None:
            send_html_email(user, subject, html_message)
        else:
            send_email(user, subject, message)
    elif method == 'push':
        if user.pushover_user_key and user.pushover_app_id:
            send_pushover(user, subject, message)
        elif enabled['email']:
            send_email(user, 'Hashview: Missing Pushover Key', 'Hello, you were due to recieve a pushover notification, but because your account was not provisioned with an pushover ID and Key, one could not be set. Please log into hashview and set these options under Manage->Profile.')
    elif method == 'slack':
        if settings and settings.slack_bot_token and user.slack_id:
            send_slack(user, subject, message)
        elif enabled['email']:
            send_email(user, 'Hashview: Missing Slack configuration', 'Hello, you were due to receive a Slack notification, but your Slack Member ID is not set. Please set it under your account settings.')

def process_recovered_hash_notifications():
    """Send + clear the per-hash "recovered" notifications for every watched hash
    that is now cracked. Called after an agent/manual upload marks hashes cracked.
    (Previously three identical inline copies in api/routes.py.)"""

    for hash_notification in HashNotifications.query.all():
        hash = Hashes.query.get(hash_notification.hash_id)
        if not hash or not hash.cracked:
            continue
        user = Users.query.get(hash_notification.owner_id)
        message = (
            "Congratulations, a hash has been recovered!: \n\n"
            "You can check the results using the following link: \n"
            + url_for('searches.searches_list', hash_id=hash.id, _external=True)
        )
        deliver_user_notification(user, hash_notification.method, 'Hashview User Hash Recovered!', message)
        db.session.delete(hash_notification)
        db.session.commit()

def get_md5_hash(string):
    """Function to get md5 hash of string"""

    m = _md5.md5(string.encode('utf-8'))
    return m.hexdigest()

def _md4_pure(data):
    """Pure-Python MD4 (RFC 1320). Returns the 16-byte digest.

    Fallback for systems whose OpenSSL 3.x build ships MD4 only in the
    (disabled-by-default) legacy provider, where hashlib.new('md4') raises
    ValueError. Used to verify NTLM plaintexts one line at a time — not a
    hot path, so pure Python is fine.
    """
    def lrot(x, n):
        x &= 0xFFFFFFFF
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    msg = bytearray(data)
    bit_len = (8 * len(msg)) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack('<Q', bit_len)

    A, B, C, D = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    for off in range(0, len(msg), 64):
        X = struct.unpack('<16I', msg[off:off + 64])
        a, b, c, d = A, B, C, D
        # Round 1: F = (b & c) | (~b & d)
        for i in (0, 4, 8, 12):
            a = lrot(a + ((b & c) | (~b & d)) + X[i], 3)
            d = lrot(d + ((a & b) | (~a & c)) + X[i + 1], 7)
            c = lrot(c + ((d & a) | (~d & b)) + X[i + 2], 11)
            b = lrot(b + ((c & d) | (~c & a)) + X[i + 3], 19)
        # Round 2: G = majority(b, c, d), constant 0x5A827999
        for i in (0, 1, 2, 3):
            a = lrot(a + ((b & c) | (b & d) | (c & d)) + X[i] + 0x5A827999, 3)
            d = lrot(d + ((a & b) | (a & c) | (b & c)) + X[i + 4] + 0x5A827999, 5)
            c = lrot(c + ((d & a) | (d & b) | (a & b)) + X[i + 8] + 0x5A827999, 9)
            b = lrot(b + ((c & d) | (c & a) | (d & a)) + X[i + 12] + 0x5A827999, 13)
        # Round 3: H = b ^ c ^ d, constant 0x6ED9EBA1
        for i in (0, 2, 1, 3):
            a = lrot(a + (b ^ c ^ d) + X[i] + 0x6ED9EBA1, 3)
            d = lrot(d + (a ^ b ^ c) + X[i + 8] + 0x6ED9EBA1, 9)
            c = lrot(c + (d ^ a ^ b) + X[i + 4] + 0x6ED9EBA1, 11)
            b = lrot(b + (c ^ d ^ a) + X[i + 12] + 0x6ED9EBA1, 15)
        A = (A + a) & 0xFFFFFFFF
        B = (B + b) & 0xFFFFFFFF
        C = (C + c) & 0xFFFFFFFF
        D = (D + d) & 0xFFFFFFFF

    return struct.pack('<4I', A, B, C, D)

def ntlm_hash_hex(plaintext):
    """Uppercase hex NTLM hash (MD4 over UTF-16LE) of a plaintext string.

    Tries hashlib first (fast, available when OpenSSL still provides md4);
    falls back to the pure-Python MD4 above. Decodes hashcat's ``$HEX[...]``
    wrapper when present so recovered passwords with whitespace or binary bytes
    verify; surrogatepass otherwise mirrors the surrogateescape file read in
    the import endpoint so undecodable bytes round-trip.
    """
    pw_bytes = _utf16le_candidate_bytes(plaintext)
    try:
        # MD4 here IS the NTLM algorithm being verified, not a security control.
        digest = hashlib.new('md4', pw_bytes).digest()  # nosec B324
    except ValueError:
        digest = _md4_pure(pw_bytes)
    return binascii.hexlify(digest).decode('ascii').upper()

def _u8(plaintext):
    """Encode plaintext to bytes for the raw-byte hash families (MD5/SHA1/SHA2/
    MD4-of-UTF8/MySQL). Uses UTF-8 + surrogateescape so undecodable bytes read
    from the import file (opened with errors='surrogateescape') round-trip
    losslessly. NTLM/MSSQL use UTF-16LE instead (see their helpers)."""
    return plaintext.encode('utf-8', 'surrogateescape')

def _hashcat_hex_bytes(plaintext):
    """If ``plaintext`` is hashcat's ``$HEX[<hex>]`` wrapper, return the raw
    candidate bytes it encodes; otherwise return None.

    hashcat emits $HEX[...] whenever a recovered password contains bytes that
    would be ambiguous in the plain outfile (leading/trailing whitespace, the
    ':' delimiter, or non-UTF-8 bytes). The crack-import verifiers must
    recompute the digest over those exact bytes, not over the literal string
    "$HEX[..]". A malformed wrapper returns None so the value is hashed
    literally rather than dropped.
    """
    if plaintext and plaintext.startswith('$HEX[') and plaintext.endswith(']'):
        try:
            return bytes.fromhex(plaintext[5:-1])
        except ValueError:
            return None
    return None

def _raw_candidate_bytes(plaintext):
    """Bytes fed to the raw-byte hash families (MD5/SHA*/MD4-900/MySQL): the
    decoded $HEX bytes when present, else the UTF-8 (surrogateescape) encoding
    of the plaintext string."""
    raw = _hashcat_hex_bytes(plaintext)
    return raw if raw is not None else _u8(plaintext)

def _utf16le_candidate_bytes(plaintext):
    """Bytes fed to the UTF-16LE families (NTLM/MSSQL2012). hashcat builds the
    candidate by zero-extending each raw byte, which equals
    ``latin-1(bytes).encode('utf-16le')``; a plaintext without the $HEX wrapper
    keeps the prior surrogatepass UTF-16LE encoding."""
    raw = _hashcat_hex_bytes(plaintext)
    if raw is not None:
        return raw.decode('latin-1').encode('utf-16le')
    return plaintext.encode('utf-16le', 'surrogatepass')

def md4_hex(plaintext):
    """Lowercase hex MD4 over the UTF-8 bytes of a plaintext string (hashcat mode
    900 -- raw MD4, NOT the UTF-16LE NTLM variant). Mirrors ntlm_hash_hex's
    hashlib-then-pure-Python fallback, since OpenSSL 3.x may drop md4. Decodes
    hashcat's ``$HEX[...]`` wrapper when present."""
    pw_bytes = _raw_candidate_bytes(plaintext)
    try:
        # MD4 here IS the algorithm being verified, not a security control.
        digest = hashlib.new('md4', pw_bytes).digest()  # nosec B324
    except ValueError:
        digest = _md4_pure(pw_bytes)
    return binascii.hexlify(digest).decode('ascii').lower()

def mssql2012_hash_hex(plaintext, salt_bytes):
    """Lowercase hex SHA-512 of UTF-16LE(plaintext) + salt (hashcat mode 1731,
    MSSQL 2012/2014). Decodes hashcat's ``$HEX[...]`` wrapper when present and
    otherwise mirrors ntlm_hash_hex's surrogatepass so undecodable bytes
    round-trip; salt_bytes is the raw 4-byte salt extracted from the ciphertext."""
    return hashlib.sha512(_utf16le_candidate_bytes(plaintext) + salt_bytes).hexdigest()

def _verify_ntlm(pt, ct):
    """Case-insensitive verify of a plaintext against an NTLM (mode 1000) hash."""
    return ntlm_hash_hex(pt).lower() == ct.lower()

def _verify_md4(pt, ct):
    """Case-insensitive verify of a plaintext against a raw MD4 (mode 900) hash."""
    return md4_hex(pt) == ct.lower()

def _verify_md5(pt, ct):
    """Case-insensitive verify of a plaintext against an MD5 (mode 0) hash. md5
    here is the algorithm being verified, not a security control."""
    return hashlib.md5(_raw_candidate_bytes(pt)).hexdigest() == ct.lower()  # nosec B324

def _verify_sha1(pt, ct):
    """Case-insensitive verify of a plaintext against a SHA1 (mode 100) hash. sha1
    here is the algorithm being verified, not a security control."""
    return hashlib.sha1(_raw_candidate_bytes(pt)).hexdigest() == ct.lower()  # nosec B324

def _verify_sha256(pt, ct):
    """Case-insensitive verify of a plaintext against a SHA2-256 (mode 1400) hash."""
    return hashlib.sha256(_raw_candidate_bytes(pt)).hexdigest() == ct.lower()

def _verify_mysql41(pt, ct):
    """Case-insensitive verify against a MySQL4.1/5 (mode 300) hash:
    SHA1(SHA1(pw)). sha1 here is the algorithm being verified, not a control."""
    return hashlib.sha1(hashlib.sha1(_raw_candidate_bytes(pt)).digest()).hexdigest() == ct.lower()  # nosec B324

def _verify_mssql2012(pt, ct):
    """Case-insensitive verify against an MSSQL 2012/2014 (mode 1731) hash. The
    ciphertext is ``0x0200`` + 4-byte salt (8 hex) + SHA-512 digest (128 hex);
    the salt is embedded in the ciphertext and fed back into the recompute.
    Returns False (never raises) on any malformed ciphertext."""
    c = ct.lower()
    if not c.startswith('0x0200') or len(c) != 6 + 8 + 128:
        return False
    try:
        salt = bytes.fromhex(c[6:14])
    except ValueError:
        return False
    return mssql2012_hash_hex(pt, salt) == c[14:]

# Maps hashcat mode -> verifier(plaintext, ciphertext)->bool for the hash types
# the server can LOCALLY recompute. LM (3000) is intentionally excluded.
CRACKED_HASH_VERIFIERS = {
    0: _verify_md5, 100: _verify_sha1, 300: _verify_mysql41,
    900: _verify_md4, 1000: _verify_ntlm, 1400: _verify_sha256,
    1731: _verify_mssql2012,
}

def get_cracked_hash_verifier(hash_type):
    """Return verifier fn (plaintext, ciphertext)->bool for a hashcat mode, or
    None if the server cannot locally recompute it (=> reject the import)."""
    return CRACKED_HASH_VERIFIERS.get(int(hash_type))

def bytes_to_text(raw):
    """Decode recovered bytes for storage/display: UTF-8 when valid, else the
    lossless hashcat-style ``$HEX[<hex>]`` marker. Usernames + plaintext are
    stored as the returned text (no more latin-1 hex), so all Unicode (emojis,
    foreign scripts, combining marks) round-trips and arbitrary binary bytes are
    still preserved exactly."""
    if raw is None:
        return None
    try:
        return raw.decode('utf-8')
    except UnicodeDecodeError:
        return '$HEX[' + raw.hex() + ']'

def decode_hex_plain(plaintext):
    """Inverse of the ``$HEX[<hex>]`` marker produced by bytes_to_text: return the
    human plaintext so length/character-class analysis reflects the real password
    rather than the wrapper (``$HEX[4142]`` is 8 chars on the wire but the password
    is just "AB"). A latin-1 fallback keeps arbitrary binary passwords measurable
    and displayable. Non-marker text (and None) passes straight through as ''-safe
    text, so callers can use the result directly."""
    if plaintext and plaintext.startswith('$HEX[') and plaintext.endswith(']'):
        try:
            raw = bytes.fromhex(plaintext[5:-1])
        except ValueError:
            return plaintext
        try:
            return raw.decode('utf-8')
        except UnicodeDecodeError:
            return raw.decode('latin-1')
    return plaintext or ''

def text_from_field(value):
    """Normalise a str field read from a hashfile (opened with
    ``errors='surrogateescape'``) into storage text: valid UTF-8 stays text;
    bytes that aren't valid UTF-8 become ``$HEX[...]``. A no-op for plain text."""
    if value is None:
        return None
    return bytes_to_text(value.encode('utf-8', 'surrogateescape'))

def hexplain_to_text(hexplain):
    """Decode hashcat's hex_plain field (``--outfile-format`` code 3) to storage
    text. The agent always sends hex of the raw recovered bytes; fall back to
    treating the value as already-text if it somehow isn't valid hex."""
    s = (hexplain or '').strip()
    try:
        return bytes_to_text(bytes.fromhex(s))
    except ValueError:
        return s

# secretsdump.py -history's first (most recent) history row duplicates the
# account's own current-password hash, so it is only worth dropping when the
# account's current-password row is also present in the same file; older
# history rows ('_history1', '_history2', ...) are real, distinct passwords
# and are always kept. Some dumpers omit the index for this first row, hence
# the optional '0'. Case-insensitive so an uppercased dump is still recognised.
_HISTORY_ZERO_RE = re.compile(r'_history0?$', re.IGNORECASE)

# Modes where machine-account semantics apply: 1000 NTLM, 3000 LM. Only
# consulted for the generic 'user:hash' format, where a trailing-'$' username
# in a non-AD dump (an MD5 web-app export, say) is a real account. 2100 (DCC2)
# is deliberately excluded: domain cached credentials cache interactive
# logons for user accounts, not computer accounts, so a trailing '$' there is
# never a machine account. NetNTLM modes are absent on purpose: their
# ciphertexts are colon-delimited, so they arrive as file_type 'NetNTLM',
# which filters unconditionally.
_NTLM_FAMILY_HASH_TYPES = {'1000', '3000'}

# Modes where a '_history0' row is a secretsdump.py artifact worth checking
# for duplication: the NTLM family plus DCC2. A generic 'user:hash' dump (an
# MD5 web-app export, say) gets no history-zero check, since '_history0'
# there is just an unrelated real username.
_AD_HISTORY_HASH_TYPES = _NTLM_FAMILY_HASH_TYPES | {'2100'}


def is_machine_account(username):
    """True for usernames ending in '$': AD machine accounts, whose 120-char
    random password will never crack. Applied to every AD-fed format (pwdump,
    user_hash NTLM family, DCC2, NetNTLM) since it inflates the account count
    and depresses the reported crack rate, and nothing filters at report time --
    import is the only place to drop it."""
    name = (username or '').strip()
    return name.endswith('$')


def history_zero_base_name(username):
    """If username is a '_history0' (or bare '_history') row, return its base
    account name with the suffix stripped; otherwise None. Used to detect a
    history row that duplicates its account's current-password row, which is
    only droppable when that current-password row is also in the file."""
    name = (username or '').strip()
    match = _HISTORY_ZERO_RE.search(name)
    if not match:
        return None
    return name[:match.start()]


def _raw_username_for_history_check(line, file_type, hash_type):
    """Best-effort raw username extraction used only to build the set of
    usernames present in a hashfile, so a '_history0' row can be checked
    against its base account (issue #412). Malformed lines yield None rather
    than raising, since the main import loop is what surfaces those errors."""
    try:
        if file_type == 'hash_only' and str(hash_type) == '2100':
            fields = line.lower().rstrip().split('#')
            return fields[1] if len(fields) > 1 else None
        if file_type in ('user_hash', 'pwdump', 'NetNTLM') and ':' in line:
            return line.split(':')[0]
    except IndexError:
        return None
    return None


# $krb5tgs$17/$18 only: impacket and Rubeus put the service principal name in a
# star-wrapped field between the realm and the checksum. hashcat parses it,
# ignores it for the salt, and echoes the hash back WITHOUT it. Recovered hashes
# are matched by an exact md5 of the stored ciphertext (import_hash_only above,
# and the agent-upload lookup in hashview/api/routes.py), so storing the SPN
# would leave every crack for that hash unmatchable and silently discarded --
# strictly worse than the rejection this replaced. Store what hashcat hands
# back. 13100 keeps its star-wrapped triple: that one does round-trip verbatim.
_KRB_TGS_AES_SPN_RE = re.compile(
    r'^(\$krb5tgs\$1[78]\$[^$]+\$[^$]+\$)\*[^*]*\*\$([0-9a-fA-F]{24}\$[0-9a-fA-F]+)$')


# Kerberos modes whose long-term key is salted with REALM + principal, i.e. the
# AES etypes (17/18). Measured on hashcat 6.2.6 by upper-casing the principal in
# each mode's own example hash: 19600/19700/19800/19900/28800/28900 stop cracking
# (0/1 recovered), while the RC4 etypes 7500/13100/18200 still crack because
# their key is MD4(password) with no salt at all. So the principal's case is
# load-bearing for exactly these six, and folding it silently destroys the hash.
_KRB_PRINCIPAL_SALTED = frozenset({'19600', '19700', '19800', '19900', '28800', '28900'})


def normalize_kerberos_hash(line, hash_type):
    """Return a Kerberos hash in the exact form hashcat echoes back on a crack.

    A recovered hash is matched to its row by an exact md5 of the stored
    ciphertext, so the stored form has to be a fixed point of what hashcat
    prints. Measured against hashcat 6.2.6, that means:

    * drop impacket's star-wrapped SPN field ($krb5tgs$17/$18 only) -- hashcat
      parses it, ignores it for the salt, and omits it from its outfile;
    * lower-case the hex fields, which hashcat normalises;
    * leave the principal and realm exactly as supplied, which hashcat does.

    For the principal-salted AES etypes that last point is not cosmetic: the
    principal is part of the Kerberos salt, so lower-casing a service account
    like ``SQLSvc`` yields a hash that is accepted, queued, and can never crack.
    The unsalted RC4 etypes keep the historical all-lower-case form, which is
    equally a fixed point for them and preserves existing de-duplication.
    """
    line = _KRB_TGS_AES_SPN_RE.sub(r'\1\2', line)
    if str(hash_type) not in _KRB_PRINCIPAL_SALTED:
        return line.lower()
    # ['', tag, etype, principal, realm, <hex fields...>]
    parts = line.split('$')
    if len(parts) < 6:
        return line.lower()
    return '$'.join(parts[:5] + [field.lower() for field in parts[5:]])


# A hex span can be case-folded without changing the hash it denotes, which is
# what makes HASH_CASE_RULES safe to apply. Anything that is not pure hex is left
# alone even when a rule names it -- see normalize_hash_case.
_PURE_HEX_RE = re.compile(r'^[0-9a-fA-F]+$')

# One hex field of a multi-field hash, for the 'fields' span. The lookarounds
# keep the match off a fragment of a base64 blob that merely starts with hex
# characters, and the 8-character floor keeps it off a short numeric field that
# has no case to fold anyway.
_HEX_FIELD_RE = re.compile(r'(?<![A-Za-z0-9+/=])[0-9a-fA-F]{8,}(?![A-Za-z0-9+/=])')


def normalize_hash_case(ciphertext, hash_type):
    """Return a hash in the case hashcat will echo it back in.

    hashcat parses every hex field case-insensitively -- there is one hex parser,
    ``hex_convert()`` in its src/convert.c, and ``(c & 15) + (c >> 6) * 9`` folds
    'A' and 'a' to the same nibble -- and then re-emits it through
    ``u8_to_hex``/``u32_to_hex``/``u64_to_hex``, whose table is the literal
    ``'0'..'9','a'..'f'``. So a hash pasted in upper case is accepted, cracked,
    and reported back in LOWER case.

    That is fatal here rather than cosmetic. A recovered hash is matched to its
    row by an exact md5 of the stored ciphertext (the lookup in
    hashview/api/routes.py that ingests an agent's upload), so a ciphertext
    stored in a case hashcat will not reproduce can never be matched: the hash is
    cracked, the upload finds nothing, and the row stays cracked=0 for ever. This
    is #444 reached by a different route -- there it was an int/str comparison
    skipping the fold, here it is the fold only ever having covered four modes.

    Not a blanket ``.lower()``, for three reasons, each of which would corrupt
    hashes that are correct today:

    * nine modes emit UPPER case (``snprintf("%08X")`` or an explicit
      ``uppercase()``): 3100, 7401, 7700/7701, 7800/7801, 8500, 12300, 15500;
    * fourteen modes carry ``OPTS_TYPE_HASH_COPY`` and echo the line you gave
      them byte for byte, so any fold is wrong: 501, 7100, 10600, 10700, 10900,
      11300, 11400, 11900, 12000, 12001, 12100, 12700, 15200, 16400;
    * a salt hashcat stores as text is echoed verbatim, so folding it changes the
      hash -- the same trap ``normalize_kerberos_hash`` exists to avoid for the
      principal-salted etypes.

    So this is table-driven, and the table only contains modes whose rule was
    verified as a fixed point of hashcat's own encoder. A mode that is not in it
    is returned unchanged, exactly as before.
    """
    rule = HASH_CASE_RULES.get(str(hash_type))
    if rule is None:
        return ciphertext
    span, case = rule
    fold = str.lower if case == 'lower' else str.upper

    if span == 'line':
        return fold(ciphertext)
    if span == 'fields':
        # Formats carrying several hex fields, all of which hashcat folds. Only
        # granted to modes where every other field is a literal hashcat itself
        # chose ('sha1', 'aes', 'cbc-essiv:sha256') rather than free text, so
        # there is nothing here that could hold a hex-looking value hashcat would
        # hand back verbatim -- a Kerberos principal, say, which is why those
        # modes are absent from the table.
        return _HEX_FIELD_RE.sub(lambda m: fold(m.group(0)), ciphertext)

    # Spans are delimited, never fixed-length: several of these modes carry a
    # variable-length blob (a Kerberos edata2, an office/PDF payload), and a rule
    # pinned to the length of hashcat's published example would fold only the
    # last N characters of a longer one and leave the front of it alone -- a hash
    # half-folded is worse than one left alone, because it is a fixed point of
    # nothing.
    if span == 'all':
        start, end = 0, len(ciphertext)
    elif span[0] == 'after':                  # fixed marker, e.g. MSSQL's '0x'
        # Matched, not assumed: an MSSQL hash pasted without its '0x' is all hex
        # from the first character, and folding from offset 2 regardless would
        # leave the first two digits behind -- half a hash, a fixed point of
        # nothing. A line without the marker is not the shape this rule is for.
        if not ciphertext.startswith(span[1]):
            return ciphertext
        start, end = len(span[1]), len(ciphertext)
    elif span[0] == 'head':                   # up to the first separator
        end = ciphertext.find(span[1])
        start = 0
    else:                                     # ('tail', sep): after the last one
        start = ciphertext.rfind(span[1]) + 1
        end = len(ciphertext)

    # A line that does not have the shape the rule was derived for -- a truncated
    # hash, a missing separator, a mode picked by hand for a file of something
    # else -- comes through untouched rather than folded on a guess. So does one
    # whose span is not hex after all: folding that could change the value.
    if start < 0 or end < 0 or start >= end or end > len(ciphertext):
        return ciphertext
    piece = ciphertext[start:end]
    if not _PURE_HEX_RE.match(piece):
        return ciphertext
    return ciphertext[:start] + fold(piece) + ciphertext[end:]


# Hashfile import is batched. It used to run one SELECT + INSERT + commit per
# new hash inside import_hash_only, plus another INSERT + commit for every
# hashfile_hashes row -- roughly 2N commits for N hashes, each forcing an InnoDB
# redo-log fsync, which is what made a large hashfile take minutes (#363). Now a
# chunk of parsed lines is resolved with one SELECT per hash_type, the genuinely
# new rows go in with one statement, and the chunk is committed once.
#
# 5,000 amortises the round trips while keeping both the IN list and the
# executemany payload well inside max_allowed_packet; tests/seed_perf_db.py
# settled on the same chunk size against this schema.
_IMPORT_CHUNK_SIZE = 5000
# The dedup SELECT is sub-batched so the IN list stays a sane size.
_IMPORT_LOOKUP_BATCH = 1000

# Sentinels from _classify_hashfile_line: this line contributes no row, or the
# file is malformed and the whole import should be abandoned.
_LINE_SKIP = object()
_LINE_ABORT = object()


def _classify_hashfile_line(line, file_type, hash_type, present_usernames):
    """Parse one hashfile line into ``(ciphertext, hash_type, username)``.

    Returns ``_LINE_SKIP`` for a line that is deliberately dropped (an AD
    machine account, or a ``_history0`` row whose base account is also present
    in the file) and ``_LINE_ABORT`` for a malformed file.

    Deliberately pure -- it touches no database. Separating the parsing from the
    writing is what lets the caller batch, and it collects the per-format quirks
    in one reviewable place. Note that several branches reassign ``line`` and
    then derive the username from the *reassigned* value; that ordering is
    load-bearing and is preserved exactly as it was when each branch called
    import_hash_only inline. The pwdump branch likewise still overrides
    hash_type to '1000' for the row it emits, whatever was selected.

    ``hash_type`` is normalised to str on the way in, and every comparison below
    relies on that. The web upload passes a form field (str) while the API route
    is declared ``<int:hash_type>`` and passes an int, so the branches that
    compare against '1000'/'2100'/'300'/'1731'/'18200' silently did nothing on
    the API path (#444). The headline casualty was the lowercasing: hashcat
    reports hex hashes lowercased, so an NTLM ciphertext stored verbatim in
    uppercase could never match the md5(ciphertext) lookup that ingests crack
    results -- the hash was cracked and stayed cracked=0 forever.

    Normalised to str rather than int on purpose: the sets and literals this
    module already compares against (_KRB_PRINCIPAL_SALTED,
    _NTLM_FAMILY_HASH_TYPES, _AD_HISTORY_HASH_TYPES, the pwdump branch's '1000')
    are strings, as are the validate_* functions. Going the other way would mean
    rewriting all of them. The Hashes.hash_type column is an Integer and accepts
    either, which is exactly why this stayed invisible for so long.
    """
    hash_type = str(hash_type)
    username = None
    if file_type == 'hash_only':
        # DCC2 is the one hash_only mode whose ciphertext carries a
        # username, so it is the one that can carry a '_history0' row
        # duplicating its account's current-password row (#412).
        if hash_type == '2100':
            dcc2_fields = line.lower().rstrip().split('#')
            if len(dcc2_fields) > 1:
                base = history_zero_base_name(dcc2_fields[1])
                if base is not None and base.strip().lower() in present_usernames:
                    return _LINE_SKIP
        # Store the hash in the case hashcat will echo back, or the crack can
        # never be matched to it. DCC2 stays spelled out here rather than going
        # through normalize_hash_case: hashcat lower-cases the iteration count,
        # username and digest but re-emits the '$DCC2$' tag upper-cased, which is
        # not one of the table's spans.
        if hash_type == '2100':
            line = line.lower().rstrip()
            line = line.replace('$dcc2$', '$DCC2$')
            return line, hash_type, line.split('#')[1]
        return normalize_hash_case(line.rstrip(), hash_type), hash_type, None
    elif file_type == 'user_hash':
        if ':' in line:
            # NTDS dumps are routinely cut down to 'user:nthash', so AD
            # machine accounts and duplicate '_history0' rows (#412)
            # reach this format too. Filter before the row is buffered, or
            # the ciphertext orphans in `hashes` and still gets cracked.
            # hash_type arrives as an int on the API path (routes.py takes
            # <int:hash_type>).
            candidate_username = line.split(':')[0]
            if (hash_type in _NTLM_FAMILY_HASH_TYPES
                    and is_machine_account(candidate_username)):
                return _LINE_SKIP
            base = history_zero_base_name(candidate_username)
            if (hash_type in _AD_HISTORY_HASH_TYPES
                    and base is not None and base.strip().lower() in present_usernames):
                return _LINE_SKIP
            if hash_type == '2100':
                # As in the hash_only branch: the '$DCC2$' tag comes back
                # upper-cased, so this one is not table-driven. `username` is
                # read off the rebound `line` and so ends up being the whole
                # ciphertext -- wrong, pre-existing on this path and on the UI
                # path both, and deliberately left as it was here (#444's
                # test pins it); it is a username bug, not a casing one.
                line = line.split(':', 1)[1].rstrip()
                line = line.lower()
                line = line.replace('$dcc2$', '$DCC2$')
                return line, hash_type, line.split(':')[0]
            # Only the hash field is stored, and in the case hashcat will echo
            # back. 300/1731 used to take a branch that lower-cased the whole
            # line and stored THAT as the ciphertext, username included, so a
            # MySQL or MSSQL hash imported as 'user:hash' was stored as
            # 'user:hash' and could never match a crack (#445).
            hash_value = line.split(':', 1)[1].rstrip()
            return (normalize_hash_case(hash_value, hash_type), hash_type,
                    candidate_username)
        return _LINE_ABORT
    elif file_type == 'shadow':
        return line.split(':')[1], hash_type, line.split(':')[0]
    elif file_type == 'pwdump':
        # do we let user select LM so that we crack those instead of NTLM?
        candidate_username = line.split(':')[0]
        base = history_zero_base_name(candidate_username)
        if is_machine_account(candidate_username) or (
                base is not None and base.strip().lower() in present_usernames):
            return _LINE_SKIP
        return line.split(':')[3].lower(), '1000', candidate_username
    elif file_type == 'kerberos':
        # Normalized so the stored ciphertext equals what hashcat will echo
        # back on a crack -- a recovered hash is matched by an exact md5 of
        # the stored ciphertext, so a plain .lower() (which folds a
        # principal-salted AES etype's case-sensitive principal) makes the
        # hash uncrackable. See normalize_kerberos_hash. `line` is left alone
        # for the username split below, which reads the principal at index 3.
        ciphertext = normalize_kerberos_hash(line.rstrip(), hash_type)
        if hash_type in ('18200', '35400'):
            # $krb5asrep$23$user@REALM:<ck>$<edata>, or the same without
            # the etype field (Rubeus/John) -- which shifts every field
            # one left, so index 3 would be the edata blob. Take the
            # field carrying the ':' either way.
            principal = next(
                (field for field in line.split('$') if ':' in field), '')
            username = principal.split(':')[0]
        else:
            # 13100/35300 wrap the principal in a star-delimited triple
            # (*user$realm$spn*), so index 3 arrives as '*user'.
            username = line.split('$')[3].lstrip('*')
        return ciphertext, hash_type, username
    elif file_type == 'NetNTLM':
        # 5600, domain is case sensitve. Hashcat returns username in
        # upper case.
        candidate_username = line.split(':')[0]
        base = history_zero_base_name(candidate_username)
        if is_machine_account(candidate_username) or (
                base is not None and base.strip().lower() in present_usernames):
            return _LINE_SKIP
        # uppercase uesrname in line
        line_list = line.split(':')
        # uppercase the username in line
        line_list[0] = line_list[0].upper()
        # lowercase the rest (except domain name) 3,4,5
        line_list[3] = line_list[3].lower()
        line_list[4] = line_list[4].lower()
        line_list[5] = line_list[5].lower()
        line = ':'.join(line_list)
        return line.rstrip(), hash_type, line.split(':', maxsplit=1)[0]
    return _LINE_ABORT


def _resolve_hash_ids(wanted):
    """Map ``(hash_type_key, sub_ciphertext) -> hashes.id`` for rows that exist.

    ``wanted`` maps that key to ``(hash_type, ciphertext)``. One SELECT per
    hash_type per _IMPORT_LOOKUP_BATCH sub_ciphertexts, rather than one per
    hash. The hash_type value is passed through as supplied rather than coerced,
    because the column is an Integer and callers hand it in as either a str or
    an int -- the backend's numeric coercion is what makes both work, and
    tests/unit/test_issue_xfail_import_hash_type_int.py pins that.
    """
    by_type = {}
    for (type_key, sub), (row_type, _ciphertext) in wanted.items():
        by_type.setdefault(type_key, (row_type, []))[1].append(sub)

    found = {}
    for type_key, (row_type, subs) in by_type.items():
        for offset in range(0, len(subs), _IMPORT_LOOKUP_BATCH):
            batch = subs[offset:offset + _IMPORT_LOOKUP_BATCH]
            rows = db.session.query(Hashes.id, Hashes.sub_ciphertext).filter(
                Hashes.hash_type == row_type,
                Hashes.sub_ciphertext.in_(batch),
            ).all()
            for hash_id, sub in rows:
                found[(type_key, sub)] = hash_id
    return found


def _import_chunk(hashfile_id, rows, _retrying=False):
    """Resolve, insert and link one chunk of parsed rows, then commit once.

    ``rows`` is a list of ``(ciphertext, hash_type, username)``.

    Retries once on an integrity error. uq_hashes_sub_ciphertext_hash_type makes
    the lookup-then-insert a *checked* race rather than a silent one: if a
    concurrent import inserts one of these hashes between our SELECT and our
    INSERT, the insert now fails instead of quietly creating a second row for
    the same hash. The retry's lookup finds the other importer's row and
    inserts only what is still missing.
    """
    try:
        return _import_chunk_once(hashfile_id, rows)
    except IntegrityError:
        db.session.rollback()
        if _retrying:
            raise
        return _import_chunk(hashfile_id, rows, _retrying=True)


def _import_chunk_once(hashfile_id, rows):
    """One attempt at resolving, inserting and linking a chunk."""
    # Key every row once. The md5 is computed a single time per row here; the
    # old path computed it twice for every new hash.
    keyed = [(str(row_type), get_md5_hash(ciphertext), ciphertext, row_type, username)
             for ciphertext, row_type, username in rows]

    # Collapse duplicates *within* the chunk before inserting. The old code
    # relied on read-your-writes from a per-row commit to notice a repeat later
    # in the same file; keying on (hash_type, sub_ciphertext) does that without
    # a round trip, and a duplicate spanning two chunks is still caught by the
    # lookup below, because earlier chunks are already committed.
    wanted = {}
    for type_key, sub, ciphertext, row_type, _username in keyed:
        wanted.setdefault((type_key, sub), (row_type, ciphertext))

    found = _resolve_hash_ids(wanted)

    missing = [key for key in wanted if key not in found]
    if missing:
        db.session.bulk_insert_mappings(Hashes, [
            {
                'hash_type': wanted[key][0],
                'sub_ciphertext': key[1],
                'ciphertext': wanted[key][1],
                'cracked': 0,
            }
            for key in missing
        ])
        db.session.flush()
        # bulk_insert_mappings does not populate primary keys, so read them
        # back -- still one SELECT per batch rather than one per row.
        found.update(_resolve_hash_ids({key: wanted[key] for key in missing}))

    db.session.bulk_insert_mappings(HashfileHashes, [
        {
            'hash_id': found[(type_key, sub)],
            'hashfile_id': hashfile_id,
            'username': None if username is None else text_from_field(username),
        }
        for type_key, sub, _ciphertext, _row_type, username in keyed
        if (type_key, sub) in found
    ])
    db.session.commit()


def _present_usernames(hashfile_path, file_type, hash_type):
    """Usernames present in the file as their own row (not stripped of any
    suffix), so a '_history0' row can be recognised as a duplicate of its
    account's current-password row and dropped only then (issue #412)."""
    with open(hashfile_path, encoding='utf-8', errors='surrogateescape') as file:
        return {
            raw.strip().lower()
            for raw in (
                _raw_username_for_history_check(line, file_type, hash_type)
                for line in file
            )
            if raw
        }


def import_hashfilehashes(hashfile_id, hashfile_path, file_type, hash_type):
    """Import a hashfile's lines as Hashes + HashfileHashes rows.

    ``hash_type`` may arrive as a str (web upload form field) or an int (the API
    route is declared ``<int:hash_type>``). Neither helper below cares: each
    normalises for itself, which is the property that matters, because both are
    callable without going through here. Normalising a second time in this
    function would be untestable -- remove it and every test still passes, which
    is how a guard rots. Any future helper added to this path must do the same;
    see _classify_hashfile_line for what went wrong when one did not (#444).
    """

    # The file is read twice and streamed both times -- once to collect the
    # usernames the history filter needs, once to import. It used to be pulled
    # into memory whole with readlines().
    #
    # errors='surrogateescape' so a non-UTF-8 hashfile never crashes on read;
    # each stored field is normalised to text via text_from_field().
    present_usernames = _present_usernames(hashfile_path, file_type, hash_type)

    pending = []
    with open(hashfile_path, encoding='utf-8', errors='surrogateescape') as file:
        for line in file:
            # Skip blank and whitespace-only lines, matching the rule
            # _validate_hashfile already applies -- so a file that PASSED
            # validation cannot then blow up in here.
            #
            # This guard used to read `if len(line) == 0`, which is never true:
            # iterating a file yields the newline with the line, so a blank line
            # arrives as '\n' and only a zero-length string would match. It has
            # been dead since it was written (it was `len(line) > 0` around a
            # readlines() loop before #363 batched this, equally dead), and a
            # trailing newline at the end of a hashfile is the overwhelmingly
            # common case -- most editors add one.
            #
            # Downstream every format indexes fixed fields: pwdump, shadow,
            # NetNTLM and kerberos all raise IndexError on '\n' (a 500 on the
            # upload), user_hash aborts the whole file, and hash_only is worse
            # than either -- it imports a row whose ciphertext is the empty
            # string, silently, which then joins dedup and analytics forever.
            if not line.strip():
                continue
            row = _classify_hashfile_line(line, file_type, hash_type, present_usernames)
            if row is _LINE_ABORT:
                # Drop the partial chunk. Chunks already committed stay, which
                # is what the per-row-commit version did as well.
                db.session.rollback()
                return False
            if row is _LINE_SKIP:
                continue
            pending.append(row)
            if len(pending) >= _IMPORT_CHUNK_SIZE:
                _import_chunk(hashfile_id, pending)
                pending = []

    if pending:
        _import_chunk(hashfile_id, pending)

    return True


# Fixed set of length buckets for recovered-password dynamic wordlists.
# Tokens: 'a-b' -> a <= len <= b (combined low bucket); 'N+' -> len >= N
# (catch-all high bucket); 'N' -> len == N (exact). See dynamic_password_
# length_wordlists() for the seeded names and update_dynamic_wordlist() for
# how the token is parsed back out of the wordlist name.
_PASSWORD_LENGTH_BUCKETS = ('0-5', '6', '7', '8', '9+')


def dynamic_password_length_wordlists():
    """(name, path) pairs for each fixed length bucket, used for seeding.

    Kept next to the dispatcher so the seeded names always carry a
    '(length ...)' token the dispatcher knows how to parse.
    """
    out = []
    for token in _PASSWORD_LENGTH_BUCKETS:
        slug = token.replace('+', 'plus')
        out.append((
            f'(DYNAMIC) Recovered Passwords (length {token})',
            f'hashview/control/wordlists/dynamic-len-{slug}.txt',
        ))
    return out


def _decode_plaintext_bytes(plaintext):
    """Return the plaintext as raw bytes, unwrapping hashcat ``$HEX[...]``.

    Non-hex or malformed wrappers fall back to the UTF-8 encoding of the
    stored text, so a value is never dropped.
    """
    if plaintext.startswith('$HEX[') and plaintext.endswith(']'):
        try:
            return bytes.fromhex(plaintext[5:-1])
        except ValueError:
            pass
    return plaintext.encode('utf-8')


def _length_bucket_bounds(name):
    """Parse a '(length ...)' token from ``name`` into (min_length, max_length).

    ``max_length`` is None for an unbounded upper end. Returns None when the
    name carries no token (i.e. the unbucketed "All Recovered Passwords" list,
    which must not be length-filtered). Token forms:
        'a-b' -> (a, b)      inclusive range (combined low bucket)
        'N+'  -> (N, None)   catch-all high bucket
        'N'   -> (N, N)      exact length
    """
    match = re.search(r'\(length\s+(\d+)(?:(-)(\d+)|(\+))?\)', name)
    if not match:
        return None
    low = int(match.group(1))
    if match.group(2):          # 'a-b' range
        return (low, int(match.group(3)))
    if match.group(4):          # 'N+' catch-all
        return (low, None)
    return (low, low)           # 'N' exact


# Sentinel for "no lower bound yet", so the first batch is never confused with a
# batch that legitimately ended on a NULL. Using None for both made the loop
# re-issue the unbounded query forever when the NULL filter was absent -- an
# infinite loop that grows the wordlist file until the disk fills, which a
# mutation test caught as a hang rather than a failure.
_NO_KEYSET_BOUND = object()

# Rows per round trip when walking the recovered corpus. The whole point is
# that this number, not the size of the corpus, bounds what the server sends in
# one go and what the app holds at once.
PLAINTEXT_BATCH_SIZE = 50_000


def iter_distinct_recovered_plaintexts(batch_size=PLAINTEXT_BATCH_SIZE):
    """Yield every distinct recovered plaintext, one bounded batch at a time.

    This used to be a single ``SELECT DISTINCT plaintext FROM hashes WHERE
    cracked = true``, and on a large corpus that is two separate problems.

    Server side: DISTINCT over millions of rows builds an on-disk temporary
    table (tmp_table_size defaults to 16 MB) before it can send anything, then
    has to push every row across. An installation with ~5.9M distinct
    plaintexts spent ~50s in that state and was cut off by net_write_timeout
    (default 60s) mid-fetch -- surfacing as "2013 Lost connection to MySQL
    server during query", which reads like a dead server when the server is
    fine.

    Client side: mysql-connector buffers the entire result set before the
    caller's loop body runs even once (SQLAlchemy's stream_results is a no-op
    here -- this dialect reports supports_server_side_cursors = False), so the
    app also held every plaintext in memory simultaneously.

    Keyset pagination fixes both: each batch is an index range scan that starts
    returning at once, and memory is bounded by batch_size. Ordering by
    plaintext is what makes the keyset sound -- each batch resumes strictly
    after the last value seen, so no value is skipped or repeated, and DISTINCT
    within a batch plus the strict ``>`` across batches give the same set the
    single query did.

    Pairs with the (cracked, plaintext) index from e9f4c2a70b18. WITHOUT that
    index each batch re-derives the whole temporary table and paginating is far
    slower than the single query it replaces (measured on a 2M-row copy: 10.8s
    per batch versus 10.7s for the whole thing). With it, a 50,000-row batch is
    about 0.05s.
    """
    last = _NO_KEYSET_BOUND
    while True:
        # `== true()`, NOT `.is_(True)`. MySQL's IS TRUE is a boolean test
        # operator, not an equality comparison, so it cannot drive index range
        # access: `cracked IS true` abandons ix_hashes_cracked_plaintext and
        # falls back to scanning ix_hashes_plaintext with a row lookup per
        # entry to test cracked -- work proportional to EVERY plaintext in the
        # table rather than the cracked ones. Measured on 4M rows / 25%
        # cracked: 1.8s with `= true`, 129.7s with `IS true`.
        conditions = [Hashes.cracked == sa_true(), Hashes.plaintext.isnot(None)]
        if last is not _NO_KEYSET_BOUND:
            conditions.append(Hashes.plaintext > last)
        rows = (
            Hashes.query
            .filter(*conditions)
            .with_entities(Hashes.plaintext)
            .distinct()
            .order_by(Hashes.plaintext)
            .limit(batch_size)
            .all()
        )
        if not rows:
            return
        for (plaintext,) in rows:
            yield plaintext
        # Resume strictly after the largest value in this batch. Under a
        # case-insensitive collation (MySQL's default) the comparison and
        # DISTINCT agree on what counts as equal, so the variants the single
        # query collapsed are the ones this skips.
        previous, last = last, rows[-1][0]
        if len(rows) < batch_size:
            return
        if previous is not _NO_KEYSET_BOUND and last == previous:
            # The loop can only wedge by re-fetching the same batch forever,
            # which would grow the wordlist file until the disk filled. Detect
            # that by EQUALITY, never by ordering: the database orders by its
            # own collation (MySQL's default is accent- and case-insensitive,
            # so 'ünïcödé' sorts near 'u'), while Python compares codepoints
            # and puts it after 'z'. An ordering check here fires spuriously on
            # any corpus containing non-ASCII passwords -- which, for a
            # password cracker, is all of them.
            raise RuntimeError(
                'recovered-plaintext pagination stopped advancing at '
                f'{last!r}; refusing to loop')


def generate_recovered_password_wordlist(path, min_length=0, max_length=None):
    """Write distinct recovered plaintexts to ``path``, filtered by length.

    This is the single source of dynamic recovered-password wordlist
    generation: callers pass the length window they want and this writes one
    candidate per line. ``min_length``/``max_length`` bound the length
    (inclusive); ``max_length=None`` means no upper bound, and the default
    (0, None) writes every recovered plaintext.

    ``$HEX[...]`` plaintexts are decoded ONLY to measure their true byte
    length for bucketing; the value is stored in the wordlist in its original
    ``$HEX[...]`` form. Stored plaintext is always valid UTF-8 (real text, or
    the ASCII ``$HEX[...]`` wrapper), so the file is written as UTF-8 text.
    """
    with open(path, 'w', encoding='utf-8') as fh:
        for plaintext in iter_distinct_recovered_plaintexts():
            length = len(_decode_plaintext_bytes(plaintext))
            if length < min_length or (max_length is not None and length > max_length):
                continue
            fh.write(plaintext + '\n')


def update_dynamic_wordlist(wordlist_id, dest_path=None):
    """Function to update dynamic wordlist.

    ``dest_path`` selects where the generated content is written. When ``None``
    (the UI "refresh" path) the content goes to the shared, canonical
    ``wordlist.path`` and the row's ``size``/``checksum``/``byte_size`` metadata
    is refreshed. When set (the on-demand agent download) the content goes to
    that caller-supplied path — a per-request unique temp file — and the row's
    metadata is left untouched, so the download is side-effect-free on the DB.
    Returns the path that was written.
    """

    wordlist = Wordlists.query.get(wordlist_id)
    target_path = dest_path or wordlist.path

    if 'Passwords' in wordlist.name:
        # Recovered passwords. A "(length ...)" token in the name selects the
        # length window (see _length_bucket_bounds); without one, the whole
        # recovered corpus is written. All generation is delegated to the
        # single generate_recovered_password_wordlist() function.
        bounds = _length_bucket_bounds(wordlist.name)
        min_length, max_length = bounds if bounds is not None else (0, None)
        generate_recovered_password_wordlist(
            target_path, min_length=min_length, max_length=max_length
        )
    else:
        # Text-derived dynamic wordlists (usernames, customers, NTLM
        # ciphertexts): all stored as text, written directly as UTF-8.
        file = open(target_path, 'w', encoding='utf-8')
        if 'Usernames' in wordlist.name:
            # One column, and no SQL DISTINCT. Both halves are deliberate.
            #
            # This was `HashfileHashes.query.distinct('username')`. The argument
            # is DISTINCT ON, which only PostgreSQL implements: everywhere else
            # SQLAlchemy drops it and warns it will raise in a future release
            # (#373). Dropping it alone would change nothing at all -- an entity
            # query selects the primary key too, so the surviving DISTINCT could
            # never collapse a row. What it did do was materialise every
            # hashfile_hashes row as a full ORM object, on the agent's download
            # path, inside a request handler. Measured on 300k rows: 9.5s and
            # 476MB peak as entities against 2.6s and 71MB as one column, for
            # byte-identical output. The corpus walk one branch up
            # (iter_distinct_recovered_plaintexts) exists because the same shape
            # took a production server out with "2013 Lost connection".
            #
            # And no `.distinct()` on the column either, tempting as it is:
            # hashfile_hashes.username is utf8mb4 with no explicit COLLATE, so
            # on MySQL 8 it inherits utf8mb4_0900_ai_ci -- case- AND
            # accent-insensitive. A SQL-side DISTINCT would fold 'Admin' and
            # 'admin' into one candidate; the Python set below keeps both, which
            # is the behaviour a wordlist wants.
            usernames = HashfileHashes.query.with_entities(HashfileHashes.username)
            username_set = set()
            for entry in usernames:
                if entry.username:
                    username_string = entry.username
                    if '\\' in username_string:
                        username_set.add(username_string.split('\\')[0])
                        username_set.add(username_string.split('\\')[1])
                        username_set.add(username_string)
                    else:
                        username_set.add(username_string)
            for entry in username_set:
                file.write(entry + '\n')
        elif 'Customers' in wordlist.name:
            # Same #373 fix, same reasoning as above, though the stakes here are
            # only tidiness: the customers table is small, and the consumer
            # lowercases, so a collation-folded DISTINCT would have been
            # harmless. The set below is what dedupes.
            customers = Customers.query.with_entities(Customers.name)
            customer_set = set()
            for entry in customers:
                customer_set.add(entry.name.lower())
            for entry in customer_set:
                file.write(entry + '\n')
        elif 'NTLM' in wordlist.name:
            hashes = Hashes.query.filter_by(hash_type='1000').with_entities(Hashes.ciphertext)
            for entry in hashes:
                file.write(str(entry.ciphertext) + '\n')

        file.close()

    # Only the canonical-path (UI refresh) generation owns the row's metadata.
    # An on-demand download generates into a per-request temp file, so it must
    # not touch these columns (they don't describe that transient file, and
    # concurrent jobs would race on the row).
    if dest_path is None:
        # update line count
        wordlist.size = get_linecount(wordlist.path)
        # update file hash (dynamic wordlists stay UNCOMPRESSED on the server, so
        # the checksum remains the sha256 of the plaintext .txt; the agent skips
        # verification for dynamic wordlists since it can't recompute this from
        # the .gz it receives)
        wordlist.checksum = get_filehash(wordlist.path)
        # update on-disk size (bytes of the uncompressed .txt)
        wordlist.byte_size = get_filesize(wordlist.path)
        # update last update
        wordlist.last_updated = utcnow()
        db.session.commit()

    return target_path

def resolve_control_file(stored_path, subdir):
    """Absolute path to a catalog row's file under ``control/<subdir>``, or None.

    ``subdir`` is 'rules' or 'wordlists'. The stored path is reduced to its
    BASENAME and joined to ``<app.root_path>/control/<subdir>`` -- the one
    directory the download routes serve from and the upload routes write to.

    Single candidate, deliberately: no fallback to the raw stored path. That is
    what remove_rule_file, GET /v1/rules/<id> and GET /v1/wordlists/<id> already
    do, so detection, serving and deletion can never disagree about which file a
    row owns. It also resolves the seeded rows -- 'Best64 Rule' and the original
    Rockyou.txt carry a path relative to the package -- correctly no matter what
    the process CWD is, which a raw os.path.exists(row.path) does not, and it
    keeps a crafted or legacy path from reaching outside the control directory.

    hashview/setup/__init__.py has a sibling _resolve() that DOES fall back to
    the stored path; that one's job is relocation (finding a stray file so it can
    be normalized into the canonical dir), not detection. Leave it be.

    Returns None for an empty/NULL path or when the file is absent.
    """
    if not stored_path:
        return None
    target = os.path.join(current_app.root_path, 'control', subdir,
                          os.path.basename(stored_path))
    # isfile, not exists: os.path.basename('/x/..') is '..' and basename('a/b/')
    # is '', so a path of that shape resolves to control/<subdir>/.. or to the
    # directory itself -- both of which exist. The row would read as healthy and
    # then fail later in getsize() or os.replace(). Traversal is already
    # neutralised by the basename call above ('../../etc/passwd' -> 'passwd').
    return target if os.path.isfile(target) else None

def rule_file_missing(rule):
    """True when this rule's row has outlived its file on disk (issue #383)."""
    return resolve_control_file(getattr(rule, 'path', None), 'rules') is None

def wordlist_file_missing(wordlist):
    """True when this wordlist's row has outlived its file on disk (issue #383).

    A DYNAMIC wordlist is never missing. Its file is a regenerable cache, not
    the source of truth: every download goes through
    update_dynamic_wordlist(id, dest_path=<tmp>), which rebuilds the content
    from the database into a per-request temp file and never reads
    wordlist.path. The canonical file is a zero-byte placeholder written once at
    seed time and only ever refreshed by the manual Update button -- so both its
    absence AND its zero length are the expected state, and reporting either
    would be a permanent false alarm on every install.
    """
    if (getattr(wordlist, 'type', None) or '').lower() == 'dynamic':
        return False
    return resolve_control_file(getattr(wordlist, 'path', None), 'wordlists') is None

def missing_rule_ids(rules=None):
    """Ids of Rules rows whose file is gone. Pass already-loaded rows to reuse them.

    One os.path.exists per row rather than a cached listdir of the directory:
    these tables hold single-digit-to-tens of rows while control/rules and
    control/wordlists accumulate orphaned files from deleted rows and test runs,
    so a directory set costs far more allocations than the handful of stats it
    would save. If either table ever reaches ~1,000 rows, swap the probe in these
    bulk helpers (only) for a memoized os.scandir set.
    """
    if rules is None:
        rules = db.session.query(Rules.id, Rules.path).all()
    return {r.id for r in rules if resolve_control_file(r.path, 'rules') is None}

def missing_wordlist_ids(wordlists=None):
    """Ids of static Wordlists rows whose file is gone. Dynamic rows never qualify.

    See missing_rule_ids for why this stats per row, and wordlist_file_missing
    for why dynamic lists are excluded.
    """
    if wordlists is None:
        wordlists = db.session.query(
            Wordlists.id, Wordlists.path, Wordlists.type).all()
    return {w.id for w in wordlists if wordlist_file_missing(w)}

def catalog_task_references(rule_ids=None, wordlist_ids=None):
    """(rule_id -> {task ids}, wordlist_id -> {task ids}) in at most two queries.

    Which tasks reference a catalog row is what separates housekeeping from an
    incident: an unreferenced stale row can simply be removed, while one behind a
    queued job needs an operator to choose between restore and delete. wl_id_2
    counts -- a combinator task's second wordlist is a real reference (see
    build_hashcat_command), and forgetting it is exactly the bug the wordlist
    delete guard had to be fixed for.

    Single implementation for the scheduler's prune, the /v1 listings and the
    UI, so none of them can disagree about what is safe to remove.
    """
    from sqlalchemy import or_

    by_rule, by_wordlist = {}, {}
    if rule_ids:
        for task_id, rule_id in db.session.query(Tasks.id, Tasks.rule_id).filter(
                Tasks.rule_id.in_(rule_ids)).all():
            by_rule.setdefault(rule_id, set()).add(task_id)
    if wordlist_ids:
        for task_id, wl_id, wl_id_2 in db.session.query(
                Tasks.id, Tasks.wl_id, Tasks.wl_id_2).filter(
                    or_(Tasks.wl_id.in_(wordlist_ids),
                        Tasks.wl_id_2.in_(wordlist_ids))).all():
            for candidate in (wl_id, wl_id_2):
                if candidate in wordlist_ids:
                    by_wordlist.setdefault(candidate, set()).add(task_id)
    return by_rule, by_wordlist

def orphaned_rule_ids(rules=None):
    """Ids of Rules rows whose file is gone AND which no task references (#494).

    The debris set: nothing can use these, nothing points at them, and the
    scheduled sweep deletes them once the admins have been told. Computed, never
    stored -- like `missing`, of which it is a strict subset.

    Short-circuits on a healthy catalog so the listings, which call this on every
    GET, pay nothing for the task scan when there is nothing to scan for.
    """
    missing = missing_rule_ids(rules)
    if not missing:
        return set()
    by_rule, _ = catalog_task_references(rule_ids=missing)
    return {rule_id for rule_id in missing if not by_rule.get(rule_id)}

def orphaned_wordlist_ids(wordlists=None):
    """Ids of Wordlists rows whose file is gone AND which no task references.

    See orphaned_rule_ids. Dynamic rows can never appear here, because
    wordlist_file_missing never reports them missing in the first place.
    """
    missing = missing_wordlist_ids(wordlists)
    if not missing:
        return set()
    _, by_wordlist = catalog_task_references(wordlist_ids=missing)
    return {wl_id for wl_id in missing if not by_wordlist.get(wl_id)}

def remove_rule_file(stored_path):
    """Best-effort removal of a rule's file from ``control/rules``.

    Call this AFTER the row has been committed away. The order is deliberate and
    matches wordlists_delete: a failed unlink then merely orphans a file, where
    the reverse would leave a row pointing at a file that is gone.

    The stored path is resolved to ``control/rules/<basename>`` -- the same
    normalization the rule download routes already apply. That is what makes
    this correct for the seeded 'Best64 Rule', whose row carries a path relative
    to the package (see hashview/setup/__init__.py), and what keeps a crafted or
    legacy path from reaching outside the rules directory.

    The unlink is skipped when another rule row still points at the same file:
    POST /v1/rules/add does not dedupe names, so two rows can legitimately exist,
    and on a hand-built row they could share one file. Deleting one must not
    break the other.

    Returns True when the file is absent afterwards, False when it survived --
    either because another row needs it or because the unlink failed.
    """
    if not stored_path:
        return True

    rules_dir = os.path.join(current_app.root_path, 'control/rules')
    target = os.path.join(rules_dir, os.path.basename(stored_path))
    if not os.path.exists(target):
        return True

    basename = os.path.basename(stored_path)
    for other in db.session.query(Rules.path).all():
        if other[0] and os.path.basename(other[0]) == basename:
            current_app.logger.info(
                'Keeping rule file %s: still referenced by another rule row.', target)
            return False

    try:
        os.remove(target)
    except OSError:
        current_app.logger.exception('Failed to remove rule file from disk: %s', target)
        return False
    return True
def top_effective_task_ids(hash_type, limit=10):
    """Task ids that have recovered the most hashes of ``hash_type``, best first.

    Feeds the "assign the top N tasks" action in the web UI (jobs_assign_lucky_
    task_group) and in the API (/v1/jobs/add with a lucky task group). Returns
    ids only -- both callers use nothing else -- so the result can be fed
    straight into JobTasks.

    **The join to `tasks` is load-bearing, not decoration.** `hashes.task_id`
    has no foreign key, and a task can be deleted while its recoveries stay
    behind: tasks_delete refuses only while the task is still referenced by a
    job or a task group, never for the hashes it cracked. So this column
    routinely points at tasks that no longer exist (one such id on the reference
    instance, carrying 224 cracked rows), and the INNER JOIN is the single thing
    stopping a deleted task from being assigned to a new job.

    Do NOT relax it to an outer join to surface deleted names here. The listing
    and Wrapped pages deliberately label a deleted task as deleted, because they
    only display it; this result is assigned. Preserving that distinction is what
    tests/unit/test_lucky_task_assignment.py exists to enforce.
    """
    rows = (db.session.query(Hashes.task_id)
            .join(Tasks, Tasks.id == Hashes.task_id)
            # isnot(None) is redundant against the join -- a NULL task_id cannot
            # match tasks.id -- but it stays deliberately: issue #219 was this
            # filter written as `Hashes.task_id is not None`, a Python identity
            # test on the column object that is always True and filters nothing.
            # test_api_issues_xfail.py::test_219_jobs_add_uses_proper_null_filter
            # inspects this source to stop that form coming back, so the correct
            # spelling has to be present to pin it.
            #
            # `!= 0` earns its place on behaviour: 0 is the historical
            # "not attributed" sentinel and, unlike NULL, would survive the join
            # if a tasks row with id 0 ever existed.
            .filter(Hashes.cracked == '1',
                    Hashes.task_id.isnot(None),
                    Hashes.task_id != 0,
                    Hashes.hash_type == hash_type)
            .group_by(Hashes.task_id)
            .order_by(db.func.count(Hashes.id).desc())
            .limit(limit)
            .all())
    return [row[0] for row in rows]


def hashtypes_in_use():
    """Set of distinct hash_type values currently present in the hashes table.

    This is the canonical "what do we actually need benchmarks for" set used by
    the heartbeat (benchmark-first) and the chunk planner — far smaller than the
    ~485 modes hashcat supports.
    """
    rows = db.session.query(Hashes.hash_type).distinct().all()
    return {row[0] for row in rows if row[0] is not None}


def task_uses_dynamic_wordlist(task, dynamic_ids=None):
    """True when ``task`` may be assigned to the same job more than once.

    The rule in one place: a task is repeatable iff its wordlist is dynamic,
    because a dynamic list's contents change between runs so repeating it is
    meaningful. Everything that assigns tasks to a job has to agree on this, and
    it already had three spellings in the jobs blueprint alone -- a fourth in the
    API is how they drift.

    Asked as "is this wordlist dynamic", never as "is it not static": a task with
    no wordlist (wl_id NULL -- mask/brute-force attacks), a task whose wordlist
    row has been deleted, and an odd ``type`` casing must all answer False. That
    positive, case-sensitive form is deliberate -- see the comment at
    jobs_assign_task.

    ``wl_id_2`` is deliberately NOT consulted: the second wordlist of a
    combination attack has never made a task repeatable, and widening it here
    would quietly change which tasks can be double-assigned.

    Pass ``dynamic_ids`` (a pre-computed dynamic_wordlist_ids() set) when testing
    many tasks, so the wordlists table is read once rather than once per task.
    """
    if task is None or task.wl_id is None:
        # Wordlists.query.get(None) emits "fully NULL primary key identity cannot
        # load any object", which SQLAlchemy warns may become an error.
        return False
    if dynamic_ids is not None:
        return task.wl_id in dynamic_ids
    wordlist = Wordlists.query.get(task.wl_id)
    return wordlist is not None and wordlist.type == 'dynamic'


def dynamic_wordlist_ids():
    """Set of Wordlists.id whose type is 'dynamic' (stored lower-case)."""
    rows = db.session.query(Wordlists.id).filter(Wordlists.type == 'dynamic').all()
    return {row[0] for row in rows}


def slowest_benchmark(hash_type):
    """Smallest agent benchmark (hashes/sec) for ``hash_type``, or None.

    Chunk sizes are computed from the SLOWEST agent so the weakest hardware still
    finishes a chunk in roughly the target duration. Returns None when no agent
    has benchmarked this hash type yet, or when every agent that tried reported
    it unsupported (speed 0) -- caller then runs the task whole.
    """
    return db.session.query(db.func.min(AgentBenchmarks.speed)) \
        .filter(AgentBenchmarks.hash_type == hash_type, AgentBenchmarks.speed > 0) \
        .scalar()


_SPEED_UNIT_MULT = {'': 1, 'K': 1e3, 'M': 1e6, 'G': 1e9, 'T': 1e12, 'P': 1e15, 'E': 1e18}


def parse_hps(s):
    """Parse a speed string to raw hashes/sec, tolerantly.

    Accepts '284.6 GH/s', lowercase 'gh/s', thousands separators ('1,024 MH/s'),
    trailing text ('284.6 GH/s (12ms)'), units k/M/G/T/P/E, a bare number (assumed
    H/s), or an int/float. Returns 0.0 when no number is present. Single source for
    the dashboard task-rate sum, the sidebar aggregate, and agent utilization.
    """
    if s is None:
        return 0.0
    if isinstance(s, int | float):
        return float(s)
    s = str(s)
    m = re.search(r'([0-9][0-9,]*(?:\.[0-9]+)?)\s*([kmgtpe]?)\s*h/s', s, re.IGNORECASE)
    if m:
        return float(m.group(1).replace(',', '')) * _SPEED_UNIT_MULT[m.group(2).upper()]
    m = re.search(r'[0-9][0-9,]*(?:\.[0-9]+)?', s)   # bare number -> assume H/s
    return float(m.group(0).replace(',', '')) if m else 0.0


def fmt_hps(h, places=1):
    """Format raw H/s as a human string (e.g. 2.8e11 -> '284.6 GH/s').

    ``places`` is the decimal precision of the scaled value (default 1; the
    agent-benchmark modal passes 2).
    """
    for unit, div in (('PH/s', 1e15), ('TH/s', 1e12), ('GH/s', 1e9),
                      ('MH/s', 1e6), ('kH/s', 1e3)):
        if h >= div:
            return f'{h / div:.{places}f} {unit}'
    return ('%d H/s' % int(h)) if h else '0 H/s'


def _gpu_label(agent):
    """'8× RTX 4090' from an agent's gpu_count + gpu_model (or '' if unknown)."""
    count = agent.gpu_count or 0
    model = (agent.gpu_model or '').strip()
    if count and model:
        return '%d× %s' % (count, model)
    if count:
        return '%d×' % count
    return ''


def _max_temp(agent):
    """Hottest card temperature (int °C) from the agent's gpu_temps CSV, or None."""
    if not agent.gpu_temps:
        return None
    temps = []
    for part in str(agent.gpu_temps).split(','):
        try:
            temps.append(int(float(part.strip())))
        except (TypeError, ValueError):
            continue
    return max(temps) if temps else None


def agent_telemetry(agents):
    """Per-agent live telemetry for the agents page + fleet modal.

    Returns {agent_id: {gpu, temp, util, hashrate, task}}:
      gpu      -> 'N× MODEL' label (str; '' if unknown)
      temp     -> hottest card °C (int) or None
      util     -> current hashrate as a percent of THIS agent's benchmark for the
                  hash type it is cracking (int), or None when idle / unbenchmarked
      hashrate -> current speed display string, or None
      task     -> the parent task name the agent is cracking, or None
    """
    out = {a.id: {'gpu': _gpu_label(a), 'temp': _max_temp(a), 'util': None,
                  'hashrate': None, 'task': None} for a in agents}
    ids = [a.id for a in agents]
    if not ids:
        return out

    running = {jt.agent_id: jt for jt
               in JobTasks.query.filter(JobTasks.agent_id.in_(ids),
                                        JobTasks.status == 'Running').all()}
    bench = {(b.agent_id, b.hash_type): b.speed for b
             in AgentBenchmarks.query.filter(AgentBenchmarks.agent_id.in_(ids)).all()}
    task_names = {t.id: t.name for t in Tasks.query.all()}
    job_ht = {}

    for a in agents:
        jt = running.get(a.id)
        if not jt:
            continue
        out[a.id]['task'] = task_names.get(jt.task_id)
        out[a.id]['hashrate'] = a.benchmark or None
        if jt.job_id not in job_ht:
            job = Jobs.query.get(jt.job_id)
            job_ht[jt.job_id] = _job_hash_type(job) if job else None
        ht = job_ht[jt.job_id]
        bspeed = bench.get((a.id, ht)) if ht is not None else None
        cur = parse_hps(a.benchmark)
        if bspeed and cur:
            out[a.id]['util'] = int(round(cur / bspeed * 100))
    return out


# A hashcat OPTION at the very start of the mask field, as opposed to a mask that
# merely begins with '-'. A mask can only ever be '-' followed by a mask
# character; hashcat has no option named '-' + punctuation, '-?' or '-0'/'-5'..
# '-9'. The residue ('-<letter>', '-1'..'-4') stays classified as an option,
# which is the status quo.
_LEADING_OPTION = re.compile(r'^(?:--[A-Za-z][A-Za-z0-9-]*|-[A-Za-z1-4])')


def split_mask_field(field, first_token_is_mask=False):
    """Split the free-form Hashcat-mask field and say WHERE the mask ended up.

    Returns ``(parts, mask_index)``:

      parts       the argv elements for this field, in field order -- exactly
                  what mask_argv() returns.
      mask_index  index into ``parts`` of the positional MASK element, or -1 when
                  the field opens with a hashcat option and the mask cannot be
                  located.

    The index is what lets build_hashcat_command hoist the option elements ahead
    of an end-of-options '--' while leaving the mask as a positional behind it
    (issue: a chunk sub-mask such as '-?a?a?a' is read as an option otherwise).

    mask_index is -1 for the options-first form (``-1 ?u?l?d ?1?1?1``): with the
    charset value and the mask both bare tokens there is no way to tell which is
    which, so no sentinel is emitted and the behaviour is exactly as before.

    ``first_token_is_mask=True`` is passed for a CHUNK sub-mask. The chunker
    builds those as <expanded literal prefix> + <suffix of the task mask>, so the
    first token is mask text by construction and the index-0 option heuristic
    must be skipped -- a chunk of '?aabc' is '-abc', which the heuristic would
    otherwise read as an option.
    """
    if not field:
        return [field], -1

    tokens = [(m.start(), m.group()) for m in re.finditer(r'\S+', field)]
    if not tokens:
        return [field], -1

    # The field opens with a real hashcat option -> we cannot tell which of the
    # remaining bare tokens is the mask. Same list as before, no mask index.
    if (not first_token_is_mask
            and tokens[0][1].startswith('-')
            and _LEADING_OPTION.match(tokens[0][1])):
        return [tok for _, tok in tokens], -1

    # Scan from index 1: token 0 is mask text (the mask always comes first in the
    # field), so a '-' there is part of the mask, not an option boundary.
    for index in range(1, len(tokens)):
        start, token = tokens[index]
        if token.startswith('-'):
            # Slice the head out of the ORIGINAL string by offset rather than
            # ' '.join(tokens): a mask may legitimately begin with a space (the
            # ?s/?a expansion emits one), and joining would silently eat it.
            # Strip the whole separator RUN, not a single space. The run is
            # delimiter, not mask: ' '.join(field.split()) used to normalise it
            # away, and leaving it turns a double-space typo into a mask whose
            # every candidate ends in a space. A LEADING space is still
            # preserved, which is why this slices by offset at all.
            head = re.sub(r'[ \t]+$', '', field[:start])
            return [head] + [tok for _, tok in tokens[index:]], 0

    return [field], 0


def mask_argv(mask):
    """Split a stored mask field into argv elements, at option boundaries only.

    The Hashcat-mask field is free-form and unvalidated, and the UI offers no
    home for a custom charset, so operators put the whole thing in it:

        ?1?1?1?1?1 -1 ?u?l?d

    Passed as a single argv element that reaches hashcat as one giant mask and
    dies with "Custom-charset 1 is undefined." (verified against 6.2.6). The
    tokens have to be separate arguments.

    Splitting on every space would be wrong, though: a literal space is a valid
    mask character, and `hashcat -a 3 --stdout '?d ?d'` really does emit "1 0",
    "0 0" and so on -- which works today precisely because the field arrives as
    one element. Cracking a passphrase like "Word 1234" depends on it.

    So the split happens only from the first token that looks like a hashcat
    option (starts with '-'). Everything before that is the mask and keeps its
    spaces; the option and everything after it become their own elements. Both
    argument orders work, because hashcat's getopt permutes options past
    positionals -- checked for modes 3, 6 and 7, including mode 7 where the
    option lands between the mask and the wordlist.

    The one case this cannot resolve is a mask whose own text starts a
    space-separated token with '-' (say "?u?l -?d"): that is read as an option.
    It is ambiguous by construction, and the real fix is to stop overloading
    this field -- give custom charsets their own inputs.

    An empty or None mask is returned unchanged rather than dropped, so this is
    purely a split and nothing else about the command moves.

    Thin wrapper over split_mask_field(), which additionally reports which
    element is the mask; callers that need to hoist options ahead of a '--'
    sentinel use that directly.
    """
    return split_mask_field(mask)[0]


def mask_attack_argv(attackmode, target_file, wordlist_path, mask, *, from_chunk=False):
    """The ``-a <mode> ... <positionals>`` tail of a mask attack (modes 3/6/7).

    Split out of build_hashcat_command so the live hashcat-matrix test can build
    the real token order instead of re-implementing (and drifting from) it. Pure:
    no DB, no Flask.

    Emits hashcat's ``--`` end-of-options sentinel ONLY when the mask would
    otherwise be read as an option -- i.e. it is the positional mask and it
    starts with '-'. Two reasons it is conditional rather than always-on:

      * every command that does not need it keeps a byte-identical argv, so an
        agent that has not been upgraded behaves exactly as it does today; and
      * everything after '--' is a positional, and the agent APPENDS
        ``--status-json`` to the command it receives. After a sentinel that token
        shifts the positionals: mode 6 then opens the mask as a wordlist
        ("No such file or directory") and mode 7 opens --status-json as one.
        Unconditional emission would break every mode 6/7 command in existence on
        any un-upgraded agent.

    ``--status-json`` is therefore emitted here, paired with the sentinel, so a
    mode-3 chunk still reports status on an old agent (whose trailing duplicate
    lands after '--' as an ignored positional). Newer agents insert their own
    copy ahead of the sentinel and skip it when already present.

    Every option must precede '--', including a hoisted custom charset: leaving
    ``-1 ?u?l?d`` after the sentinel yields "Custom-charset 1 is undefined."
    """
    parts, mask_index = split_mask_field(mask, first_token_is_mask=from_chunk)
    if mask_index == 0 and parts[0].startswith('-'):
        mask_opts, sentinel, mask_pos = parts[1:], ['--status-json', '--'], [parts[0]]
    else:
        # Byte-identical to the pre-sentinel behaviour.
        mask_opts, sentinel, mask_pos = [], [], parts

    if attackmode == 3:
        return ['-a', '3'] + mask_opts + sentinel + [target_file] + mask_pos
    if attackmode == 6:
        return ['-a', '6'] + mask_opts + sentinel + [target_file, wordlist_path] + mask_pos
    if attackmode == 7:
        return ['-a', '7'] + mask_opts + sentinel + [target_file] + mask_pos + [wordlist_path]
    raise ValueError(f'mask_attack_argv: not a mask attack mode: {attackmode!r}')

def build_hashcat_command(job_id, task_id, chunk=None, job_task_id=None):
    """Build the hashcat crack invocation as an argv LIST (list[str]).

    Returned as a token list — not a shell string — so free-form task fields
    (``hc_mask``, ``j_rule``, ``k_rule``) are literal argv elements the agent
    passes to ``subprocess`` with ``shell=False``; shell metacharacters in them
    cannot be interpreted (issue #297). Element 0 is the ``@HASHCATBINPATH@``
    placeholder the agent expands to its configured binary at run time.


    ``chunk`` (optional) is a chunk spec from
    ``hashview.utils.chunking.plan_chunks``:
      * ``{'skip': int, 'limit': int}`` -> append ``--skip``/``--limit`` (wordlist
        base-loop modes 0/1/6)
      * ``{'mask': str}``               -> run this sub-mask in place of
        ``task.hc_mask`` (mask base-loop modes 3/7)
    ``job_task_id`` (optional) keys the per-run temp files (target / outfile /
    potfile) so two chunks of the SAME task never collide; it must match the file
    names the agent uses. When omitted it falls back to ``task_id`` (the
    un-chunked, pre-existing naming).
    """

    hc_binpath = '@HASHCATBINPATH@'  # nosec B105 - placeholder token, not a password
    task = Tasks.query.get(task_id)
    job = Jobs.query.get(job_id)
    rules_file = Rules.query.get(task.rule_id)
    hashfilehashes_single_entry = HashfileHashes.query.filter_by(hashfile_id = job.hashfile_id).first()
    hashes_single_entry = Hashes.query.get(hashfilehashes_single_entry.hash_id)
    hash_type = hashes_single_entry.hash_type
    attackmode = task.hc_attackmode
    chunk = chunk or {}
    # A mask chunk overrides the task's mask with its sub-mask; otherwise the task's.
    mask = chunk.get('mask') or task.hc_mask
    # Per-run temp files are keyed on the JobTask (chunk) id when chunked so two
    # chunks of one task never share an outfile/potfile/target hashfile.
    file_key = job_task_id if job_task_id is not None else task_id

    # Combinator
    wordlist = Wordlists.query.get(task.wl_id)
    # if attackmode == 1:
        
    #     print('unsupported combinator')
    # else:
    #     wordlist = Wordlists.query.get(task.wl_id)

    target_file = 'control/hashes/hashfile_' + str(job.id) + '_' + str(file_key) + '.txt'
    crack_file = 'control/outfiles/hc_cracked_' + str(job.id) + '_' + str(file_key) + '.txt'
    # Per-jobtask potfile (replaces the old global --potfile-disable). --loopback
    # requires an enabled potfile; keeping it unique per job/task and living in
    # control/outfiles means the agent's data-retention sweep cleans it up too.
    potfile = 'control/outfiles/hc_potfile_' + str(job.id) + '_' + str(file_key) + '.pot'
    # Wordlists are stored compressed at rest; the agent keeps them compressed
    # and hashcat reads gzip directly. ensure_gz() applies the same '.gz' name
    # rule the agent uses, so the path emitted here matches the file on disk on
    # the agent: static -> '<hex>.gz', dynamic -> '<hex>.txt.gz'.
    if wordlist:
        relative_wordlist_path = 'control/wordlists/' + ensure_gz(wordlist.path.split('/')[-1])
    else:
        relative_wordlist_path = ''

    if attackmode == 1:
        wordlist_2 = Wordlists.query.get(task.wl_id_2)
        if wordlist_2:
            relative_wordlist_2_path = 'control/wordlists/' + ensure_gz(wordlist_2.path.split('/')[-1])
        else:
            relative_wordlist_2_path = ''

    if rules_file:
        relative_rules_path = 'control/rules/' + rules_file.path.split('/')[-1]
    else:
        relative_rules_path = ''

    session = secrets.token_hex(4)

    # Build the invocation as an argv LIST, never a shell string: the free-form
    # task fields (mask, j/k rules) become literal argv elements, so shell
    # metacharacters in them cannot be interpreted — the agent runs this with
    # shell=False (issue #297). Element 0 stays the @HASHCATBINPATH@ placeholder
    # the agent expands to its configured binary (+ HC_EXTRA_ARGS) at run time.
    argv = [hc_binpath,
            '-O', '-w', '3',
            '--session', session,
            '-m', str(hash_type),
            '--potfile-path', potfile,
            '--status', '--status-timer=15',
            '--outfile-format', '1,3',
            '--outfile', crack_file]
    # Chunk slice for wordlist base-loop modes: restrict this run to a word range.
    is_chunk_slice = 'skip' in chunk and 'limit' in chunk
    if is_chunk_slice:
        argv += ['--skip', str(chunk['skip']), '--limit', str(chunk['limit'])]

    # Loopback only applies to straight mode (-a 0) with a rule; hashcat rejects
    # it for other attack modes. It is ALSO mutually exclusive with --limit, so a
    # chunked slice (which carries --skip/--limit above) must never add it — the
    # chunk runs as a plain dict+rules slice instead. The server-side gate also
    # means a task flipped away from dict+rules never emits a stray --loopback.
    if attackmode == 0 and isinstance(task.rule_id, int) and task.loopback and not is_chunk_slice:
        argv.append('--loopback')

    # --hex-salt: the hashfile was marked as carrying hex-encoded salts. Gated on
    # a salted mode so we never pass it to an unsalted mode (hashcat would reject
    # it); the upload route only sets hex_salt for the hash_only / user_hash
    # formats, whose ciphertext keeps the colon-delimited salt hashcat parses.
    hashfile = Hashfiles.query.get(job.hashfile_id)
    if hashfile and hashfile.hex_salt and hash_type_uses_salt(hash_type):
        argv.append('--hex-salt')

    # Dictionary with optional rules
    if attackmode == 0:
        if isinstance(task.rule_id, int):
            argv += ['-r', relative_rules_path, target_file, relative_wordlist_path]
        else:
            argv += [target_file, relative_wordlist_path]
    # Combinator — j/k rules are literal argv elements (previously single-quoted
    # into the shell string, which a `'` in the field could break out of).
    elif attackmode == 1:
        argv += ['-a', '1', target_file, relative_wordlist_path]
        if isinstance(task.j_rule, str):
            argv += ['-j', task.j_rule]
        argv.append(relative_wordlist_2_path)
        if isinstance(task.k_rule, str):
            argv += ['-k', task.k_rule]
    # Maskmode / hybrids — the mask is a literal argv element (previously unquoted
    # in the shell string). mask_attack_argv also emits hashcat's '--' sentinel
    # when the mask would otherwise be read as an option; from_chunk tells it the
    # mask was generated by the chunker, so its first token is mask text.
    elif attackmode in (3, 6, 7):
        argv += mask_attack_argv(attackmode, target_file, relative_wordlist_path,
                                 mask, from_chunk=('mask' in chunk))

    return argv

# hashcat is handed --outfile control/outfiles/hc_cracked_<job>_<key>.txt, so the
# stored command is a direct statement of the temp-file key. Kept as a fallback
# for a command that is not a JSON argv list (an older row, or one hand-stamped
# by a test).
_CRACK_FILE_RE = re.compile(r'hc_cracked_\d+_([^/\\"\']+?)\.txt')
_CRACK_BASENAME_RE = re.compile(r'hc_cracked_\d+_(.+)\.txt\Z')


def file_key_from_command(command):
    """Read the temp-file key back out of a stored JobTasks.command, or None.

    Prefers indexing the argv list -- find the LAST '--outfile', take the token
    after it --
    over scanning the whole command, because free-form task fields (the mask, the
    j/k rules) are literal argv elements and a mask of 'hc_cracked_9_999.txt' would
    otherwise be picked up by a plain search. Those fields all land AFTER --outfile
    in build_hashcat_command today, so a search happens to be right, but it is
    right by argv ordering rather than by construction. Indexing is neither
    position- nor ordering-dependent.
    """
    if not command:
        return None
    try:
        argv = json.loads(command)
    except (TypeError, ValueError):
        argv = None
    if isinstance(argv, list):
        # LAST --outfile, not the first: hashcat overwrites the option on every
        # occurrence, so a repeated flag means the last one is where the cracks
        # actually land (verified against hashcat v6.2.6 -- given two --outfile
        # flags it writes the second and never creates the first). A command CAN
        # carry two: the Hashcat Mask task field is free-form and split on
        # whitespace into argv elements (split_mask_field), all of which land
        # AFTER this flag, so a mask of '?d?d --outfile /tmp/x.txt' emits one.
        # Taking the first would name a file hashcat never writes, and the agent
        # would read no cracks and upload nothing -- silently, forever.
        #
        # Deliberately reset to None when the last --outfile is unparseable: we
        # then do not know where hashcat writes, and answering with an earlier
        # flag's key would be a confident lie. None falls back to the caller's
        # own answer instead.
        #
        # 'arg', not 'token': bandit's B105 reads any name in its secret word
        # list (token, secret, pass, pwd, ...) compared against a string literal
        # as a hardcoded password and fails the build on it.
        found = None
        for i, arg in enumerate(argv):
            if arg == '--outfile' and i + 1 < len(argv):
                match = _CRACK_BASENAME_RE.match(str(argv[i + 1]).rsplit('/', 1)[-1])
                found = match.group(1) if match else None
        return found
    matches = _CRACK_FILE_RE.findall(command if isinstance(command, str) else str(command))
    return matches[-1] if matches else None


def job_task_file_key(job_task):
    """The key naming this row's target hashfile, crack outfile and potfile.

    Read back out of the row's OWN stored command rather than recomputed from its
    id. The command is what hashcat is actually handed, so it is the only
    statement of the key that cannot drift; anything derived independently is a
    second opinion, and when the two disagreed nothing raised. The agent simply
    saved the hashfile where hashcat never looked (FileNotFoundError) and read
    its cracks from a file hashcat never wrote -- silent, and permanent.

    Falls back to the row id, which is what _set_job_task_command bakes in, for a
    row whose command was never stamped or predates the --outfile convention.
    """
    return file_key_from_command(job_task.command) or job_task.id


# A JobTasks row whose temp files are keyed on its own id but which is NOT a
# chunk (a whole task) stores this in chunk_total. It exists purely so the
# agent's `job_task.get('chunk_total')` test stays truthy for every row we
# stamp -- see is_chunk_row() for why chunk_total is no longer that test's
# server-side counterpart. Non-zero because 0 is falsy in that expression, and
# negative because every real chunk count is >= 1, so `chunk_total < 0` cleanly
# identifies a row stamped by this server.
CHUNK_TOTAL_WHOLE = -1


def is_chunk_row(job_task):
    """True if this JobTasks row carries a chunk slice rather than a whole task.

    The slice IS the definition of a chunk, so this is derived from the slice
    columns rather than from chunk_total. chunk_total used to answer this, but it
    also had to answer 'how do I name this row's temp files?' -- a question the
    agent answers independently, with no error when the two sides disagree. That
    branch is gone (every row is now keyed on its own id), so chunk_total is a
    count and nothing more. Deriving from the slice is also vintage-agnostic: it
    is correct for rows queued by an older server as well as by this one.
    """
    return bool(_chunk_spec_from_row(job_task))


def _chunk_spec_from_row(job_task):
    """Reconstruct a chunk spec dict from a JobTasks row's stored slice."""
    if job_task.chunk_skip is not None and job_task.chunk_limit is not None:
        return {'skip': job_task.chunk_skip, 'limit': job_task.chunk_limit}
    if job_task.chunk_mask:
        return {'mask': job_task.chunk_mask}
    return {}


def hashfile_hash_type(hashfile_id):
    """A hashfile's representative hash type: the type of its first linked hash.

    Returns None when the hashfile has no hashes, or its first link points at a
    hash row that is gone. Callers that walk this chain inline reach both cases
    as an AttributeError -- /v1/jobs/add used to, and swallowed it into a generic
    "Failed to add job." 500.

    filter_by(hashfile_id=None) is a harmless ``WHERE ... IS NULL`` returning no
    row, so a missing id needs no separate guard (unlike Query.get(None)).
    """
    hfh = HashfileHashes.query.filter_by(hashfile_id=hashfile_id).first()
    if not hfh:
        return None
    h = Hashes.query.get(hfh.hash_id)
    return h.hash_type if h else None


def _job_hash_type(job):
    """Derive the job's hash type the same way build_hashcat_command does."""
    return hashfile_hash_type(job.hashfile_id)


def _set_job_task_command(job, row, spec, chunk_no=None, chunk_total=None):
    """Stamp a JobTasks row with its queue state, chunk slice, and built command."""
    row.status = 'Queued'
    # A re-queued row is a NEW attempt: last run's end time would otherwise sit
    # there describing an interval that has nothing to do with this one.
    row.ended_at = None
    row.priority = job.priority
    row.chunk_no = chunk_no
    # Every stamped row carries a truthy chunk_total: the real count for a chunk,
    # CHUNK_TOTAL_WHOLE for a whole task. The agent keys its temp files on
    # job_task['id'] whenever this is truthy, which now matches the server
    # unconditionally (below), so an un-upgraded agent stays correct.
    row.chunk_total = chunk_total if chunk_total else CHUNK_TOTAL_WHOLE
    row.chunk_skip = spec.get('skip')
    row.chunk_limit = spec.get('limit')
    row.chunk_mask = spec.get('mask')
    # Key temp files on this row's own id, always. The old conditional ("chunks
    # get per-jobtask names, whole tasks keep job+task names") had to be
    # evaluated identically here and in the agent, and when the two disagreed
    # nothing raised -- they just quietly shared a target hashfile, crack outfile
    # and potfile. A shared potfile makes hashcat skip hashes an earlier run
    # already potted, so the later run never re-emits them. Deleting the branch
    # is the fix. It also separates two whole rows of the same (job, task), which
    # jobs_assign_task legitimately creates for a dynamic wordlist and which
    # collide under the old naming.
    job_task_id = row.id
    # build_hashcat_command returns an argv list; persist it as JSON so the agent
    # can json.loads it back into a token list and run it with shell=False.
    row.command = json.dumps(build_hashcat_command(job.id, row.task_id, chunk=spec, job_task_id=job_task_id))


def task_fingerprint(task, wl, wl2, rule):
    """Digest of everything a task's keyspace depends on.

    A wordlist re-uploaded under the same id changes Wordlists.size, which
    silently invalidates every offset already computed against it -- the old code
    had no way to notice, so a re-queued job cracked the wrong ranges. Comparing
    this on re-queue detects that instead.
    """
    parts = (task.hc_attackmode, task.wl_id, (wl.size if wl else None),
             task.wl_id_2, (wl2.size if wl2 else None),
             task.rule_id, (rule.size if rule else None), task.hc_mask)
    return hashlib.sha256('|'.join(str(p) for p in parts).encode()).hexdigest()


def _ledger_keyspace(task, wl, wl2, rule):
    """(keyspace, amp, source) in hashcat base-loop units, or (None, 1, None).

    Known exactly for the wordlist base-loop modes: the base loop IS the left
    wordlist, so one unit is one word and the keyspace is its line count --
    verified against `hashcat --keyspace` for -a 0, -a 1 and -a 6.

    NOT computable for the mask modes. hashcat splits a mask between its own
    base and device loops based on the hash mode and on -S, not on the mask
    alone: `?a?a?a?a?a?a` reports 95**4 for fast modes, 95**5 for slow ones and
    95**6 under -S. An agent has to measure it. Until one does, the attack runs
    whole -- which emits no --skip/--limit and is therefore correct whatever the
    unit turns out to be.
    """
    if task.hc_attackmode in WORDLIST_MODES:
        size = wl.size if wl else None
        if size and size > 0:
            amp = wordlist_amplifier(task.hc_attackmode,
                                     wordlist2_size=(wl2.size if wl2 else None),
                                     rule_count=(rule.size if rule else 0),
                                     mask=task.hc_mask)
            return size, amp, 'exact'
    return None, 1, None


def _sync_job_ledger(job, assignments):
    """Rebuild a job's ledger rows from its assignments, in queue order.

    ``assignments`` is a list of (task_id, [rows]) in the order the operator
    queued them. Rebuilt wholesale rather than patched: queueing re-plans the job
    from scratch anyway, and a ledger that disagreed with the rows it describes is
    worse than none. Returns the ledger row per assignment index.
    """
    JobTaskLedger.query.filter_by(job_id=job.id).delete(synchronize_session=False)
    db.session.flush()

    dynamic_ids = dynamic_wordlist_ids()
    ledgers = []
    for position, (task_id, task_rows) in enumerate(assignments):
        task = Tasks.query.get(task_id)
        wl = Wordlists.query.get(task.wl_id) if (task and task.wl_id) else None
        wl2 = Wordlists.query.get(task.wl_id_2) if (task and task.wl_id_2) else None
        rule = Rules.query.get(task.rule_id) if (task and task.rule_id) else None

        chunkable = task is not None and is_chunkable(
            task.hc_attackmode, task.wl_id, task.wl_id_2, dynamic_ids)
        # Only record a keyspace for an attack that could actually use one. A
        # dynamic wordlist has a line count, but it is regenerated per run, so
        # storing it would pin offsets to a number that changes underneath them --
        # which is the same reason such a task is never chunked.
        if chunkable:
            keyspace, amp, source = _ledger_keyspace(task, wl, wl2, rule)
        else:
            keyspace, amp, source = None, 1, None

        if keyspace:
            # Ready to be split along a keyspace we know exactly.
            state = 'Ready'
        elif chunkable and task is not None and task.hc_attackmode in MASK_MODES:
            # Splittable in principle, but only once an agent measures it.
            state = 'Pending'
        else:
            state = 'Unmeasurable'

        max_chunks = DEFAULT_MAX_CHUNKS
        ledger = JobTaskLedger(
            job_id=job.id, task_id=task_id, position=position, state=state,
            keyspace=keyspace, keyspace_source=source, keyspace_pos=0, amp=amp,
            min_slice=(-(-keyspace // max_chunks) if keyspace else 1),
            issued_count=len(task_rows), chunkable=bool(chunkable),
            fingerprint=(task_fingerprint(task, wl, wl2, rule) if task else None),
            updated_at=utcnow(),
        )
        db.session.add(ledger)
        db.session.flush()
        ledgers.append(ledger)

        # The plan is still materialised in full at queue time, so everything the
        # ledger describes has already been issued. Recording that keeps
        # keyspace_pos meaning exactly one thing -- "units handed out" -- whether
        # the rows were created up front or on demand.
        covered = 0
        for row in task_rows:
            units = (row.chunk_limit if row.chunk_limit is not None
                     else (keyspace if keyspace else 1))
            row.chunk_keyspace = units
            row.ledger_id = ledger.id
            covered += units
        ledger.keyspace_pos = min(covered, keyspace) if keyspace else covered
    return ledgers


def task_job_references():
    """{task_id: {job_id, ...}} -- every task that any job references.

    Counts BOTH materialised JobTasks rows and JobTaskLedger entries. A ledger
    entry IS an attack, whether or not a row for it happens to exist right now,
    and under on-demand minting "no row right now" is the ordinary state between
    chunks. Reading rows alone therefore reports a live attack's task as unused:
    verified on the test app that with one ledger and zero rows the task-delete
    guard did not fire and the task was deleted, leaving the ledger pointing at a
    task that is gone -- the next mint then builds a hashcat command for it.
    """
    references = {}
    for task_id, job_id in db.session.query(
            JobTasks.task_id, JobTasks.job_id).distinct():
        references.setdefault(task_id, set()).add(job_id)
    for task_id, job_id in db.session.query(
            JobTaskLedger.task_id, JobTaskLedger.job_id).distinct():
        references.setdefault(task_id, set()).add(job_id)
    return references


def jobs_using_task(task_id):
    """Job ids referencing one task, from rows AND ledgers.

    Targeted form of task_job_references, which see for why the ledger counts.
    """
    rows = {job_id for (job_id,) in db.session.query(JobTasks.job_id)
            .filter(JobTasks.task_id == task_id).distinct()}
    entries = {job_id for (job_id,) in db.session.query(JobTaskLedger.job_id)
               .filter(JobTaskLedger.task_id == task_id).distinct()}
    return rows | entries


def renumber_ledger_positions(job_id, ordered_entry_ids=None):
    """Renumber a job's attacks to 0..N-1, in two passes.

    (job_id, position) is UNIQUE and the constraint is checked per row, not
    deferred to commit -- so assigning the final numbers directly fails the moment
    any two attacks swap places, because the first UPDATE collides with a position
    the second has not vacated yet. Park everything on negative positions first,
    which nothing else ever uses, then lay down the real ones.

    ``ordered_entry_ids`` gives the new order; omit it to compact the existing one.
    """
    ledgers = {ledger.id: ledger
               for ledger in JobTaskLedger.query.filter_by(job_id=job_id).all()}
    if ordered_entry_ids is None:
        order = [ledger.id for ledger in
                 sorted(ledgers.values(), key=lambda entry: (entry.position, entry.id))]
    else:
        order = [entry_id for entry_id in ordered_entry_ids if entry_id in ledgers]
        order += [ledger_id for ledger_id in ledgers if ledger_id not in order]

    for index, ledger_id in enumerate(order):
        ledgers[ledger_id].position = -(index + 1)
    db.session.flush()
    for index, ledger_id in enumerate(order):
        ledgers[ledger_id].position = index
    db.session.flush()


def derive_attack_status(chunk_statuses, state=None, keyspace=None,
                         keyspace_pos=0):
    """The status of one ATTACK, derived from its dispatch rows and its ledger.

    An attack has no status column of its own: it is a ledger row plus however
    many JobTasks rows have been issued against it so far. This is the single
    definition of how those collapse into one word, shared by the dashboard's
    per-task rows and the jobs list. Two hand-rolled copies would drift, and the
    precedence below was hard-won -- every arm of it is a fixed bug.

    Order, and why:

    * Running wins outright.
    * Then a row set that has never been queued reads 'Not Started'. Assignments
      exist before the job is ever started, and on the jobs list that is the
      common case; calling them 'Queued' would claim work is waiting on an agent.
    * Then the ledger: keyspace still unissued means the attack is BETWEEN
      slices, not done. Slices are minted on demand, so the row set legitimately
      empties mid-attack and a row-count test reads that gap as 'Completed'.
      'Pending' is the pre-measurement state, shown as 'Measuring'.
    * Then any pending row -> 'Queued'.
    * Only then the stopped states, and a single stopped row is enough. A stopped
      attack usually has chunks that finished before the stop (or a race that
      completed one mid-stop), so requiring expired/canceled == total would let
      that mix fall through to the else. 'Expired' outranks 'Canceled' because it
      is the more specific fact: the runtime cap is what stopped this attack, and
      an operator looking at a capped job needs to see that rather than a generic
      cancellation.
    * All rows Completed -> 'Completed'; anything else (e.g. a stray 'Importing')
      falls back to 'Queued'.

    `state`/`keyspace`/`keyspace_pos` are the ledger's; pass state=None for an
    attack that has no ledger row (queued by a pre-ledger server, or not yet
    queued at all) and the ledger arm is skipped.
    """
    statuses = list(chunk_statuses)
    total = len(statuses)
    completed = sum(1 for s in statuses if s == 'Completed')

    if any(s == 'Running' for s in statuses):
        return 'Running'
    if statuses and all(s == 'Not Started' for s in statuses):
        return 'Not Started'
    if state in ('Ready', 'Pending') and (keyspace is None
                                          or (keyspace_pos or 0) < keyspace):
        return 'Measuring' if state == 'Pending' else 'Queued'
    if any(s in ('Queued', 'Not Started') for s in statuses):
        return 'Queued'
    if any(s == 'Expired' for s in statuses):
        return 'Expired'
    if any(s == 'Canceled' for s in statuses):
        return 'Canceled'
    if completed == total:
        return 'Completed'
    return 'Queued'


def job_assignments(job_ids):
    """{job_id: [assignment, ...]} -- one entry per ATTACK, in queue order.

    An attack is a ledger row once the job has been queued, and a bare JobTasks
    row before that (assigned but not yet queued). Exactly one of the two
    represents it at any moment, never both, so the count is exact.

    This replaces three separate hand-rolled counts over raw JobTasks rows. All
    three were wrong in the same direction once a task could be split -- and two
    of them still are today -- but more importantly a raw row count stops being
    stable at all once chunks are issued on demand: it grows through a run, and a
    freshly queued job can have no rows yet.

    Each assignment is a dict of {entry_id, task_id, position, keyspace, state,
    chunkable, status}. entry_id is the ledger id, or the NEGATED JobTasks id for
    a not-yet-queued row, so the two can never collide in a form submission.
    'status' is the attack's derived status (derive_attack_status), collapsing
    however many dispatch rows it has issued into the one word the UI shows.
    """
    job_ids = list(job_ids)
    if not job_ids:
        return {}
    out = {job_id: [] for job_id in job_ids}
    by_ledger = {}
    for ledger in (JobTaskLedger.query
                   .filter(JobTaskLedger.job_id.in_(job_ids))
                   .order_by(JobTaskLedger.position.asc(), JobTaskLedger.id.asc())):
        entry = {
            'entry_id': ledger.id, 'task_id': ledger.task_id,
            'position': ledger.position, 'keyspace': ledger.keyspace,
            'state': ledger.state, 'chunkable': ledger.chunkable,
            'status': None,
        }
        out[ledger.job_id].append(entry)
        by_ledger[ledger.id] = (entry, ledger, [])
    ledgered = {job_id for job_id, entries in out.items() if entries}

    # No ledger for this job: either it has never been queued, or it was queued
    # by a pre-ledger server. Fall back to grouping the rows themselves, which is
    # what the old readers did -- a task's chunk rows collapse to one entry, and
    # a dynamic-wordlist task assigned twice stays two.
    #
    # The same pass collects each ledgered attack's row statuses. It is the same
    # query either way, so the status costs no extra round trip -- which is what
    # keeps the jobs list, rendering 20 of these, from going N+1.
    rows_by_job = {}
    for row in (JobTasks.query
                .filter(JobTasks.job_id.in_(job_ids))
                .order_by(JobTasks.id.asc())):
        if row.job_id in ledgered:
            if row.ledger_id in by_ledger:
                by_ledger[row.ledger_id][2].append(row.status)
            continue
        rows_by_job.setdefault(row.job_id, []).append(row)
    for entry, ledger, statuses in by_ledger.values():
        entry['status'] = derive_attack_status(
            statuses, state=ledger.state, keyspace=ledger.keyspace,
            keyspace_pos=ledger.keyspace_pos)
    for job_id, rows in rows_by_job.items():
        for position, (task_id, group) in enumerate(_group_assignments(rows)):
            out[job_id].append({
                'entry_id': -group[0].id, 'task_id': task_id,
                'position': position, 'keyspace': None,
                'state': 'Unqueued', 'chunkable': False,
                'status': derive_attack_status([r.status for r in group]),
            })
    return out


def _group_assignments(rows):
    """Group a job's JobTasks rows into ATTACKS, in queue order.

    A task split into N chunks is one attack; a dynamic-wordlist task assigned
    twice is two. Chunk rows are recognised by carrying a slice, which is what
    makes a row a chunk -- and unlike chunk_total that reads correctly for rows
    queued by either vintage of server.
    """
    assignments, by_task = [], {}
    for row in sorted(rows, key=lambda r: r.id):
        if row.ledger_id is not None and row.ledger_id in by_task:
            by_task[row.ledger_id][1].append(row)
            continue
        if is_chunk_row(row) and row.task_id in by_task:
            by_task[row.task_id][1].append(row)
            continue
        entry = (row.task_id, [row])
        assignments.append(entry)
        if is_chunk_row(row):
            by_task[row.task_id] = entry
        if row.ledger_id is not None:
            by_task[row.ledger_id] = entry
    return assignments


def task_total_candidates(task, wl, wl2, rule):
    """Total candidate guesses a task will try, or None if not computable.

    This the server CAN compute, for every mode -- it is just arithmetic over the
    wordlist line counts, the rule count and the mask. What it cannot compute is
    how hashcat splits that total between its base loop (what --skip/--limit
    index) and its device loop. The ratio between the two is the amplifier, and
    total / keyspace is always an exact integer -- which is what makes a reported
    keyspace checkable rather than merely trusted.
    """
    if task is None:
        return None
    mode = task.hc_attackmode
    if mode in WORDLIST_MODES:
        size = wl.size if wl else None
        if not size:
            return None
        return size * wordlist_amplifier(mode, wordlist2_size=(wl2.size if wl2 else None),
                                         rule_count=(rule.size if rule else 0),
                                         mask=task.hc_mask)
    if mode in MASK_MODES:
        mask_total = mask_keyspace(task.hc_mask) if task.hc_mask else None
        if not mask_total:
            return None
        if mode == 7:
            size = wl.size if wl else None
            if not size:
                return None
            return mask_total * size
        return mask_total
    return None


def build_keyspace_command(job_id, task_id):
    """argv for `hashcat --keyspace` on a task, or None if it is not measurable.

    Deliberately NOT the run command with flags stripped. `--keyspace` takes no
    hashfile positional at all -- passing one is a usage error -- so the argv has
    a different shape and is built directly.

    It does carry -m and the attack's positionals, because the answer depends on
    them: `?a?a?a?a?a?a` reports 95**4 under -m 0 and 95**5 under -m 1800.
    (Measured: -O and -w make no difference, and -S would -- 95**6 -- but Hashview
    never emits it.)
    """
    task = Tasks.query.get(task_id)
    job = Jobs.query.get(job_id)
    if task is None or job is None or task.hc_attackmode not in MASK_MODES:
        return None
    if not task.hc_mask:
        return None
    first_hash = HashfileHashes.query.filter_by(hashfile_id=job.hashfile_id).first()
    if first_hash is None:
        return None
    hashes_entry = Hashes.query.get(first_hash.hash_id)
    if hashes_entry is None:
        return None

    wordlist = Wordlists.query.get(task.wl_id) if task.wl_id else None
    wordlist_path = ('control/wordlists/' + ensure_gz(wordlist.path.split('/')[-1])
                     if wordlist else '')
    mask_tokens = mask_argv(task.hc_mask)

    argv = ['@HASHCATBINPATH@',  # nosec B105 - placeholder token, not a password
            '-O', '-w', '3',
            '-m', str(hashes_entry.hash_type),
            '-a', str(task.hc_attackmode)]
    argv += mask_tokens
    if task.hc_attackmode == 7:
        if not wordlist_path:
            return None
        argv.append(wordlist_path)
    argv.append('--keyspace')
    return argv


def record_keyspace_measurement(ledger, keyspace, hc_major):
    """Store an agent's measured keyspace, or mark the attack unmeasurable.

    Every rejection lands on the same safe outcome: the attack runs WHOLE. A whole
    run emits no --skip/--limit, so hashcat's unit of account is irrelevant to it
    and coverage is total by definition. Never chunk on a number we could not
    check.

    The check that does the work is `total % keyspace == 0`. The server knows the
    candidate total exactly, and hashcat's own split always divides it evenly, so
    a keyspace that does not is not a keyspace -- a parse artefact, a truncated
    read, or an agent reporting something else entirely.
    """
    task = Tasks.query.get(ledger.task_id)
    wl = Wordlists.query.get(task.wl_id) if (task and task.wl_id) else None
    wl2 = Wordlists.query.get(task.wl_id_2) if (task and task.wl_id_2) else None
    rule = Rules.query.get(task.rule_id) if (task and task.rule_id) else None
    total = task_total_candidates(task, wl, wl2, rule)

    def _unmeasurable(reason):
        ledger.state = 'Unmeasurable'
        ledger.closed_reason = reason
        ledger.rev = (ledger.rev or 0) + 1
        ledger.updated_at = utcnow()
        db.session.commit()
        return False

    try:
        keyspace = int(keyspace)
    except (TypeError, ValueError):
        return _unmeasurable('keyspace_not_an_integer')
    if keyspace <= 0 or keyspace > 2 ** 63 - 1:
        return _unmeasurable('keyspace_out_of_range')
    if not total:
        return _unmeasurable('total_unknown')
    if keyspace > total or total % keyspace != 0:
        # total / keyspace is the inner-loop amplifier and is always an exact
        # integer. A remainder means the number is not a keyspace.
        return _unmeasurable('keyspace_does_not_divide_total')

    # A measurement establishes the UNIT, so anything counted before it was
    # counted in a different one. An unmeasured attack parks its cursor at 1 (the
    # "one unit = the whole attack" placeholder used when no keyspace is known);
    # carrying that over would start the first real slice at 1 and unit 0 of the
    # keyspace would never be issued by anyone. Nothing has actually been handed
    # out at this point -- the attack is held back until it is measured -- so the
    # cursor and the rows reset together, keeping sum(chunk_keyspace) == keyspace_pos.
    ledger.keyspace_pos = 0
    ledger.issued_count = 0
    for row in JobTasks.query.filter_by(ledger_id=ledger.id).all():
        row.chunk_keyspace = None

    ledger.keyspace = keyspace
    ledger.amp = total // keyspace
    ledger.keyspace_source = 'measured'
    ledger.hc_major = hc_major
    ledger.min_slice = max(1, -(-keyspace // DEFAULT_MAX_CHUNKS))
    ledger.state = 'Ready'
    ledger.measure_expires = None
    ledger.rev = (ledger.rev or 0) + 1
    ledger.updated_at = utcnow()
    db.session.commit()
    return True


def benchmark_for(agent_id, hash_type):
    """One agent's measured speed (H/s) for a hash type, or None.

    None covers both "never benchmarked" and "benchmarked at 0", which is the
    tri-state meaning "this agent's hashcat cannot run this mode" -- a 0 must
    never reach a division or a chunk-size calculation.

    This is the per-agent counterpart to slowest_benchmark(), which takes the
    MINIMUM across the fleet. Sizing a slice from the slowest agent meant an agent
    50x faster than the floor still took 1/50th-sized bites of the keyspace.
    """
    row = AgentBenchmarks.query.filter_by(agent_id=agent_id, hash_type=hash_type).first()
    return row.speed if row and row.speed > 0 else None


def chunk_units(ledger, speed, target_seconds):
    """Base-loop units this agent should take to spend ~target_seconds cracking.

    The agent's speed is in candidates/sec and the cursor counts BASE-LOOP units,
    so the conversion is the amplifier: one unit costs `amp` candidates.

    Floored at 1 -- a zero-length slice advances nothing, produces a no-op hashcat
    run, and would make the cursor compare-and-swap write an unchanged value,
    which MySQL reports as rowcount 0 and we would read as "lost the race".
    Floored again at min_slice so DEFAULT_MAX_CHUNKS keeps bounding rows per
    attack. Clamped to whatever is left so the final slice never runs past the end.
    """
    remaining = ledger.keyspace - ledger.keyspace_pos
    if remaining <= 0:
        return 0
    if not speed or speed <= 0 or not target_seconds or target_seconds <= 0:
        units = ledger.min_slice
    else:
        candidates = int(speed) * int(target_seconds)
        units = -(-candidates // max(1, int(ledger.amp)))    # ceil division
    return max(1, min(max(units, ledger.min_slice or 1), remaining))


def ledger_is_mintable(ledger):
    """True if more of this attack's keyspace can still be handed out."""
    return (ledger is not None and ledger.state == 'Ready' and ledger.chunkable
            and ledger.keyspace and ledger.keyspace_pos < ledger.keyspace)


# Distinguishes "the caller did not scope this call" from "the caller scoped it
# to an attack that does not exist". Both used to arrive as None, so passing the
# ledger_id of a row that has none silently widened a request to stop ONE attack
# into stopping the whole job.
_UNSCOPED = object()


def close_ledger(job_id, reason, task_id=_UNSCOPED, ledger_id=_UNSCOPED,
                 cancel_rows=True):
    """Stop issuing any more of an attack, and terminate what is still live.

    THE single gate for cancellation, and the one thing that must never be
    bypassed. Every cancel path works by setting existing rows to 'Canceled',
    which under a fully-materialised plan is total -- there are no other rows. It
    is not total against a cursor: there are always more slices waiting to be
    born, so cancelling only the rows leaves the attack mintable and the very next
    heartbeat issues slice N+1, cancels it, issues N+2. One slice burned per agent
    per heartbeat, forever.

    Returns the number of ledger rows closed.
    """
    scoped = ledger_id is not _UNSCOPED or task_id is not _UNSCOPED
    if scoped and (ledger_id is None or (ledger_id is _UNSCOPED and task_id is None)):
        # Scoped at an attack that does not exist. Close nothing and cancel
        # nothing: widening to the whole job here is how a single-chunk stop
        # would take the entire job down with it.
        return 0

    query = JobTaskLedger.query.filter_by(job_id=job_id)
    if ledger_id is not _UNSCOPED:
        query = query.filter(JobTaskLedger.id == ledger_id)
    elif task_id is not _UNSCOPED:
        query = query.filter(JobTaskLedger.task_id == task_id)
    ledgers = query.all()
    for ledger in ledgers:
        ledger.state = 'Closed'
        ledger.closed_reason = reason
        ledger.rev = (ledger.rev or 0) + 1
        ledger.updated_at = utcnow()
    db.session.commit()

    if cancel_rows:
        rows = JobTasks.query.filter_by(job_id=job_id)
        if ledger_id is not _UNSCOPED:
            rows = rows.filter(JobTasks.ledger_id == ledger_id)
        elif task_id is not _UNSCOPED:
            # Scoped by task even when no ledger matched. Falling back to "every
            # row of the job" here would let a request to stop ONE attack cancel
            # the whole job.
            rows = rows.filter(JobTasks.task_id == task_id)
        terminal = ('Expired' if reason in _RUNTIME_CAP_REASONS else 'Canceled')
        for row in rows.all():
            if row.status in JOBTASK_ACTIVE_STATUSES:
                update_job_task_status(row.id, terminal, finalize=False)
        finalize_job_if_complete(job_id)
    return len(ledgers)


def ledger_coverage_gaps():
    """Ledgers whose issued slices do not account for their cursor.

    The accounting identity the whole design rests on:

        sum(chunk_keyspace over an attack's rows) == ledger.keyspace_pos

    It holds because the two writers keep both sides in step: issue_slice adds one
    row and advances the cursor by that row's own size, atomically; and the
    queue-time rebuild rewrites the rows and resets the cursor to zero together.
    Nothing else touches either -- re-claiming and reclaiming change agent_id and
    status, never the slice.

    A row coming back from here means base-loop units were handed out that no row
    accounts for, i.e. compute that will never run. Returns a list of
    (ledger, issued_units) so a caller can log or alert. Cheap enough to run on
    every reclaim sweep, and worth far more there than any amount of reasoning.
    """
    gaps = []
    totals = dict(db.session.query(JobTasks.ledger_id,
                                   db.func.coalesce(db.func.sum(JobTasks.chunk_keyspace), 0))
                  .filter(JobTasks.ledger_id.isnot(None))
                  .group_by(JobTasks.ledger_id).all())
    for ledger in JobTaskLedger.query.filter(JobTaskLedger.keyspace_pos > 0).all():
        issued = int(totals.get(ledger.id, 0) or 0)
        if issued != int(ledger.keyspace_pos or 0):
            gaps.append((ledger, issued))
    return gaps


def issue_slice(job, ledger, agent_id, hash_type, target_seconds, row=None):
    """Hand this agent the next slice of an attack. Returns the JobTasks row, or None.

    Creating the row and advancing the cursor happen in ONE transaction and by the
    SAME amount, so every base-loop unit below the cursor is accounted for by
    exactly one row: nothing is handed out without a row to run it, and no row
    exists for units never reserved.

    This is the only path that issues work at DISPATCH time. The queue-time
    rebuild (build_job_task_commands -> _sync_job_ledger) also writes slices and
    the cursor, but it rewrites both sides together for a whole job and resets the
    cursor to zero, so the identity holds across it too. Reclaim and re-dispatch
    touch agent_id/status/started_at and never the slice.

    The cursor is moved with a compare-and-swap rather than a read-then-write. A
    plain SELECT inside an open transaction is a snapshot read -- under MySQL's
    default REPEATABLE READ it cannot see another agent's committed advance -- so
    two agents would both read the same position, both write, and one slice of the
    keyspace would simply never be issued. An UPDATE ... WHERE is a current read,
    so exactly one of them can move it.

    A lost race is repaired by rollback(), which is NOT cleanup here: it is the
    only way to get a fresh snapshot for the retry, AND it discards the row work
    done speculatively in the same transaction. db.session.refresh() would not do
    -- it re-issues a SELECT inside the same read view and returns the same stale
    value, which is exactly why the old rechunk_queued_tasks_for_hashtype
    re-check never worked.

    ``row`` is an existing Queued row to fill in (the seed row, or one that came
    back from a reclaim); omit it to create a new one.
    """
    seed_row_id = row.id if row is not None else None
    for _ in range(3):
        if not ledger_is_mintable(ledger):
            return None
        start = int(ledger.keyspace_pos)
        units = chunk_units(ledger, benchmark_for(agent_id, hash_type), target_seconds)
        if units <= 0:
            return None
        end = start + units
        expected_rev = ledger.rev

        target = row
        if target is None:
            target = JobTasks(job_id=job.id, task_id=ledger.task_id, status='Queued',
                              ledger_id=ledger.id)
            db.session.add(target)
            db.session.flush()          # need the id: it names this run's temp files

        _set_job_task_command(job, target, {'skip': start, 'limit': units},
                              chunk_no=(ledger.issued_count or 0) + 1)
        target.ledger_id = ledger.id
        target.chunk_keyspace = units
        target.agent_id = agent_id
        target.status = 'Running'
        target.started_at = utcnow()
        target.ended_at = None

        claimed = (db.session.query(JobTaskLedger)
                   .filter(JobTaskLedger.id == ledger.id,
                           JobTaskLedger.state == 'Ready',
                           JobTaskLedger.keyspace_pos == start,
                           JobTaskLedger.rev == expected_rev)
                   .update({'keyspace_pos': end,
                            'issued_count': JobTaskLedger.issued_count + 1,
                            'rev': JobTaskLedger.rev + 1,
                            'updated_at': utcnow()},
                           synchronize_session=False))
        if claimed:
            db.session.commit()         # row and cursor commit together, or neither
            return target
        db.session.rollback()
        ledger = JobTaskLedger.query.get(ledger.id)
        if ledger is None:
            return None
        # Re-fetch rather than reuse: the rollback reverted our edits. A row we
        # created speculatively is gone entirely, but one the caller handed us
        # still exists and must be filled in rather than duplicated.
        row = JobTasks.query.get(seed_row_id) if seed_row_id is not None else None
        if seed_row_id is not None and (row is None or row.status != 'Queued'):
            return None                  # someone else claimed the seed row
    return None


def build_job_task_commands(job):
    """Queue-time: (re)build each of a job's JobTasks commands, splitting eligible
    tasks into per-agent chunks when Settings.enabled_chunking is on.

    On first queue, each whole JobTasks row (one per assigned task) is either left
    whole or expanded into N chunk rows (the original becomes chunk 1; N-1 new rows
    are added). Re-queueing an already-chunked job rebuilds commands in place from
    each row's stored slice (chunk_skip/limit/mask) without re-expanding, so
    start/stop/start is stable. Tasks that use a dynamic wordlist are never chunked.

    Sets status='Queued', priority, command and the chunk_* fields on every row;
    the caller owns job.status/queued_at and the final commit.
    """
    rows = JobTasks.query.filter_by(job_id=job.id).all()

    # A fresh run gets a fresh set of notifications. Rows are no longer deleted on
    # delivery, so without this a re-queued job would notify nobody -- which is
    # what the delete-on-send behaviour did silently.
    (db.session.query(JobNotifications)
     .filter(JobNotifications.job_id == job.id,
             JobNotifications.sent_at.isnot(None))
     .update({'sent_at': None}, synchronize_session=False))

    settings = Settings.current()
    chunking_on = bool(settings and settings.enabled_chunking)

    # Collapse each attack back to a single row. A re-queue of an already-run job
    # arrives carrying the previous run's slices; keeping them would leave the
    # cursor describing work from a run that is over, so the accounting identity
    # (sum of issued slices == cursor) would be false from the first heartbeat.
    # The lowest id is kept so the attack holds its place in the queue order.
    produced = []
    for task_id, group in _group_assignments(rows):
        keeper, extras = group[0], group[1:]
        for extra in extras:
            db.session.delete(extra)
        keeper.chunk_keyspace = None
        keeper.agent_id = None
        keeper.started_at = None
        produced.append((task_id, [keeper]))
    db.session.flush()

    # Every attack starts as exactly ONE queued row. A mintable attack has its
    # slice filled in when an agent claims it, sized from THAT agent's benchmark;
    # an attack that cannot be split keeps the whole-run command built here.
    #
    # The row is born carrying a valid whole-run command either way. That is the
    # safety floor: if minting ever fails to fill in a slice, what runs is the
    # whole attack -- a superset of its keyspace, so coverage is preserved -- and
    # never a row with no command for the agent to run.
    for _task_id, group in produced:
        _set_job_task_command(job, group[0], {})

    ledgers = _sync_job_ledger(job, produced)

    # A mintable attack has issued nothing yet: its cursor starts at zero and the
    # single queued row above is a placeholder waiting for a slice.
    for ledger in ledgers:
        if chunking_on and ledger.state == 'Ready' and ledger.chunkable and ledger.keyspace:
            ledger.keyspace_pos = 0
            ledger.issued_count = 0
            for row in JobTasks.query.filter_by(ledger_id=ledger.id).all():
                row.chunk_keyspace = None


# A JobTasks row in one of these states still owes compute. Everything else
# (Completed, Canceled) is terminal. Kept in sync with api.routes'
# _ACTIVE_JOBTASK_STATUSES, which gates cancellation over the same set.
#
# 'Not Started' is in here deliberately. jobs_assign_task can add a task to a
# job that is ALREADY running, and such a row is invisible to the dispatch query
# (which selects status == 'Queued'), so leaving it out of this set let a job
# roll up to Completed with a task that never ran a single candidate.
# finalize_job_if_complete queues those rows rather than hanging on them.
#
# 'Importing' is written nowhere in the server or the agent today, but an agent
# can POST any status string to /v1/jobtask/status, so it stays honoured.
JOBTASK_ACTIVE_STATUSES = ('Running', 'Queued', 'Not Started', 'Importing')

# Terminal statuses: a row in one of these owes no more compute. 'Expired' joins
# Completed and Canceled here -- it must NEVER be added to the active set above,
# or finalize_job_if_complete would wait forever for work nothing will finish.
JOBTASK_TERMINAL_STATUSES = ('Completed', 'Canceled', 'Expired')

# Which terminal status a closed attack's rows get. 'Expired' means a runtime cap
# stopped it; 'Canceled' means a person or the recovery short-circuit did. Keyed
# on the reason close_ledger is already given, so the two cap call sites need no
# new argument and no other caller can accidentally mint an Expired row.
_RUNTIME_CAP_REASONS = ('runtime_cap', 'job_runtime_cap')


def audit_auto_cancel(event, job_id, task_id=None, cap=None):
    """Record a cancellation the SYSTEM performed, with the cap that caused it.

    Actor is explicit. When this fires inside an agent heartbeat there IS a
    request context, but resolve_actor() returns (None, None) there -- the uuid
    cookie is an agent uuid and matches no user's api_key -- which would make an
    automatic cancellation read as an anonymous user action. From the scheduler
    there is no request context at all, which would do the same thing.

    Best-effort and never fatal: an audit write must not be able to stop a
    runtime cap from being enforced. log_event already swallows its own errors;
    this guards the name lookups it is given.
    """
    from flask import current_app

    from hashview.utils.audit import (
        SYSTEM_ACTOR,
        job_target,
        job_task_target,
        log_event,
    )
    try:
        job = Jobs.query.get(job_id)
        if job is None:
            return
        settings = Settings.current()
        hours = getattr(settings, cap, None) if settings else None
        detail = f'{cap} exceeded ({hours}h)' if hours else f'{cap} exceeded'
        if task_id is None:
            target = job_target(job)
        else:
            target = job_task_target(job, task=Tasks.query.get(task_id),
                                     task_id=task_id)
        log_event(event, target=target, detail=detail, actor=SYSTEM_ACTOR)
    except Exception:   # nosec B110 - auditing must never block enforcement
        current_app.logger.exception('Could not audit the automatic cancellation.')


def expire_job_over_runtime(job, max_runtime_hours, now=None):
    """Expire ``job`` if it has outlived Settings.max_runtime_jobs. True if it did.

    ONE implementation, called from two places that must not drift: the agent
    heartbeat, which evaluates the cap for the job it is about to hand work to,
    and the JOB_RUNTIME sweep, which evaluates it for every running job whether
    or not anyone is asking. The heartbeat alone is not enough -- it only ever
    reaches a job an agent is actively being dispatched to, so a job whose agents
    have all moved on to something higher-priority is not checked again until
    they come back, and sits on the dashboard in the meantime looking alive.

    The job's status is claimed FIRST, by conditional UPDATE, and everything else
    follows from whether that claim won. Two reasons, and the second is not
    obvious:

    * It settles the race. The sweep and a heartbeat can reach the same job at
      the same moment, and the debug reloader runs two scheduler instances in two
      processes. Exactly one caller claims it, so ended_at is stamped once and
      one audit entry is written. It is also the ONLY check that the job is still
      live -- an already-Completed or already-Canceled job simply fails to claim
      -- so there is no second status guard above to drift away from it.
    * Closing the ledger first does not work. close_ledger terminates the job's
      rows and then calls finalize_job_if_complete, which -- with every row now
      terminal -- rolls the job up to Completed. A claim made after that finds
      nothing in ('Queued', 'Running') to update, and the job a runtime cap just
      stopped is recorded as having finished normally. Claiming first makes that
      roll-up a no-op, because it claims on the same two statuses.

    Closing the ledger is what actually stops the work, so it still has to
    happen: cancelling rows alone leaves the attack mintable and the next
    heartbeat issues slice N+1, cancels it, issues N+2, forever. It is safe to do
    after the claim because dispatch skips any job not in ('Queued', 'Running'),
    so an Expired job cannot be handed a slice in the window between the two.

    The cap is measured against Jobs.processing_seconds -- time the job was
    actually being worked, credited one sweep interval at a time by
    scheduler._accrue_processing_time -- and NOT against wall-clock since
    job.started_at. The difference is a job that gets starved: a higher-priority
    job takes the whole fleet, this one sits with no agent on it, and under
    wall-clock it blows a cap it was never given the chance to spend. Under this
    clock, time nobody spent working on it costs it nothing.

    Worth stating plainly, because it is the trade: a job can now outlive its cap
    in wall-clock terms by an unbounded margin. That is the intended answer --
    "should this have been killed hours ago?" is no when it was waiting rather
    than running -- but it does mean max_runtime_jobs no longer bounds how long a
    job can sit in the system, only how much of the fleet's time it can consume.
    """
    if not max_runtime_hours or max_runtime_hours <= 0:
        return False
    if job is None:
        return False
    now = now or utcnow()
    if (job.processing_seconds or 0) < max_runtime_hours * 3600:
        return False

    claimed = (db.session.query(Jobs)
               .filter(Jobs.id == job.id, Jobs.status.in_(('Queued', 'Running')))
               .update({'status': 'Expired', 'ended_at': now},
                       synchronize_session=False))
    db.session.commit()
    if not claimed:
        return False

    # Terminates the job's still-active rows as 'Expired' too (close_ledger keys
    # the terminal status on the reason it is given), so the rows say what
    # stopped them rather than a generic cancellation.
    close_ledger(job.id, 'job_runtime_cap')
    audit_auto_cancel('job.auto_cancel', job.id, cap='max_runtime_jobs')
    return True


def queue_late_assignments(job_id):
    """Queue any 'Not Started' row on a job that is already queued or running.

    A task can be assigned to a job that has already started. Such a row is
    created 'Not Started', which the dispatch query (status == 'Queued') does not
    see -- so it never ran, while also being absent from the old "is this job
    done" check, which let the job roll up to Completed with an un-run task on it.

    Each row is run WHOLE. A late assignment is a rare, explicitly-requested
    action against a job already in flight, so the simple always-correct plan is
    the right one: a whole run covers the task's keyspace by definition, whatever
    the chunk planner would otherwise have decided.

    Returns the number of rows queued. The caller owns the commit.
    """
    job = Jobs.query.get(job_id)
    if job is None:
        return 0
    rows = JobTasks.query.filter_by(job_id=job.id, status='Not Started').all()
    if not rows:
        return 0
    runnable = job.status in ('Queued', 'Running')

    # Only give the late rows a ledger entry if this job already HAS a ledger.
    # job_assignments reads ledgers first and then skips every raw row of a job
    # that has any ledger at all, so minting one entry for a job queued by a
    # pre-ledger server would hide all of its other rows -- turning a gap in one
    # attack into a gap in every one of them.
    ledgered = (db.session.query(JobTaskLedger.id)
                .filter(JobTaskLedger.job_id == job.id).first() is not None)
    position = None
    if ledgered:
        highest = max(entry.position for entry in
                      JobTaskLedger.query.filter_by(job_id=job.id).all())
        position = highest + 1

    for row in rows:
        # Give it a ledger entry whatever the job's status. An assignment is part
        # of the job the moment it is made, and job_assignments hides a
        # ledger-less row on a ledgered job -- so adding a task to a Completed or
        # Canceled job (which keeps its ledger) left it invisible until the job
        # was next started. issued=runnable because only a row we actually queue
        # here has had its single whole-run unit handed out.
        if ledgered:
            _append_late_ledger(job, row, position, issued=runnable)
            position += 1
        if runnable:
            _set_job_task_command(job, row, {})
    return len(rows) if runnable else 0


def _append_late_ledger(job, row, position, issued=True):
    """Mint the ledger entry for one late assignment, appended to the queue.

    Shaped like _sync_job_ledger's unmeasurable case rather than reusing it:
    that function rebuilds a job's ledger WHOLESALE -- deleting every entry and
    resetting every cursor -- which is exactly the wrong thing mid-run.

    Without this the row was queued and dispatchable but had no ledger, and
    job_assignments skips the raw rows of any job that has a ledger. So the
    attack was INVISIBLE everywhere the UI looks (the tasks page, the job's
    attack count, the summary review step) while still being handed to an agent
    by the legacy ledger_id IS NULL dispatch branch: an operator added a task,
    the page looked unchanged, and an agent quietly started cracking it. There
    was also no card, so no per-task remove button -- nothing could clear it
    short of removing every task on the job.

    A late assignment runs whole (see queue_late_assignments), so the entry is
    unchunkable with no keyspace, and the single row it describes is its one
    issued unit -- matching what _sync_job_ledger records for the same shape.
    """
    task = Tasks.query.get(row.task_id)
    wl = Wordlists.query.get(task.wl_id) if (task and task.wl_id) else None
    wl2 = Wordlists.query.get(task.wl_id_2) if (task and task.wl_id_2) else None
    rule = Rules.query.get(task.rule_id) if (task and task.rule_id) else None

    ledger = JobTaskLedger(
        job_id=job.id, task_id=row.task_id, position=position,
        state='Unmeasurable', keyspace=None, keyspace_source=None,
        keyspace_pos=(1 if issued else 0), amp=1, min_slice=1,
        issued_count=(1 if issued else 0), chunkable=False,
        fingerprint=(task_fingerprint(task, wl, wl2, rule) if task else None),
        updated_at=utcnow(),
    )
    db.session.add(ledger)
    db.session.flush()
    row.ledger_id = ledger.id
    row.chunk_keyspace = 1 if issued else None
    return ledger


def _job_completion_outcome(rows, goal_met=False):
    """Terminal status for a job whose rows are all terminal: always 'Completed'.

    A job that reaches the end of its queue has run its course, and that holds
    whether every attack finished, some were stopped by the per-task runtime cap,
    or the operator cancelled a few along the way. The job itself was not cut
    short -- if it had been, the job-level cap would have stamped it 'Expired'
    and an operator stop would have stamped it 'Canceled', both written directly
    and neither reaching this function.

    So 'Incomplete' is no longer a roll-up outcome. It survives as exactly one
    thing: the status jobs_add gives a job created but never queued. That is a
    cleaner reading than the old one, where 'Incomplete' meant two unrelated
    things -- "never started" and "started, but something was cancelled" -- and
    it is what makes hiding Info and Analytics behind it correct, since a job
    that never ran has nothing to show.

    ``goal_met`` no longer changes the answer (every all-terminal row set is
    Completed now) but stays in the signature: callers pass it to say WHY the job
    ended, and _deliver_job_notifications still words its message from it.
    """
    return 'Completed'


def finalize_job_if_complete(job_id, goal_met=False):
    """Roll a job up to its terminal status once no task still owes compute.

    Returns True only if THIS call performed the transition.

    The transition is claimed with a conditional UPDATE rather than a read
    followed by a write. Two agents finishing a job's last two chunks at the same
    moment both used to observe "nothing is active" and both ran the completion
    block: two ended_at stamps, the runtime added to the hashfile twice, and two
    sets of notifications. Exactly one caller can win the UPDATE.

    Split out of update_job_task_status so it is directly testable without an
    agent round trip.
    """
    job = Jobs.query.get(job_id)
    if job is None:
        return False
    rows = JobTasks.query.filter_by(job_id=job.id).all()
    if not rows:
        return False

    # Heal a late assignment instead of hanging on it: queue it so dispatch can
    # see it, and report "not done" -- because it genuinely is not. The assign
    # routes already do this eagerly; this is the backstop for a row that reached
    # a running job some other way.
    if queue_late_assignments(job.id):
        db.session.commit()
        return False

    if any(r.status in JOBTASK_ACTIVE_STATUSES for r in rows):
        return False

    # No row is active -- but an attack with keyspace still unissued is not
    # finished, it is merely between slices. This is the case the old
    # absence-based predicate could not see: once slices are cut on demand there
    # are moments when an attack has no materialised row at all, and reading that
    # as "done" would complete the job, stamp ended_at and burn its notifications
    # while most of the keyspace had never been tried.
    for ledger in JobTaskLedger.query.filter_by(job_id=job.id).all():
        if ledger.state in ('Ready', 'Pending') and (
                ledger.keyspace is None or ledger.keyspace_pos < ledger.keyspace):
            return False

    outcome = _job_completion_outcome(rows, goal_met=goal_met)
    ended_at = utcnow()
    # Only a Running/Queued job may be finalised. A job already Canceled (the
    # operator stopped it) or already terminal must not be rewritten by a late
    # status POST from an agent that was still finishing when the stop landed.
    claimed = (db.session.query(Jobs)
               .filter(Jobs.id == job.id, Jobs.status.in_(('Running', 'Queued')))
               .update({'status': outcome, 'ended_at': ended_at},
                       synchronize_session=False))
    db.session.commit()
    if not claimed:
        return False

    started_at = job.started_at
    duration = abs(ended_at - started_at).seconds if (started_at and ended_at) else 0
    hashfile = Hashfiles.query.get(job.hashfile_id)
    if hashfile:
        hashfile.runtime += duration
        db.session.commit()

    _deliver_job_notifications(job, outcome, duration)
    return True


def _deliver_job_notifications(job, outcome, duration):
    """Send each of a job's notifications at most once per run.

    Each row is claimed with a conditional UPDATE on sent_at before anything is
    delivered, so a row can only be sent by whoever moves it from NULL. The rows
    are NOT deleted: a job's notification configuration outlives its runs, and
    build_job_task_commands clears sent_at when the job is queued again.
    """
    cracked_cnt = db.session.query(Hashes) \
        .outerjoin(HashfileHashes, Hashes.id == HashfileHashes.hash_id) \
        .filter(Hashes.cracked == '1') \
        .filter(HashfileHashes.hashfile_id == job.hashfile_id).count()
    uncracked_cnt = db.session.query(Hashes) \
        .outerjoin(HashfileHashes, Hashes.id == HashfileHashes.hash_id) \
        .filter(Hashes.cracked == '0') \
        .filter(HashfileHashes.hashfile_id == job.hashfile_id).count()
    total_cnt = cracked_cnt + uncracked_cnt
    # The old wording here was 'Finished Incomplete (some tasks did not run)',
    # which no job reaching this point can be any more: the roll-up returns
    # 'Completed' for every all-terminal row set, and a job stopped by a cap or a
    # person never reaches the roll-up at all. The branch is kept rather than
    # dropped so a future outcome does not silently inherit "Has Completed!".
    headline = 'Has Completed!' if outcome == 'Completed' else 'Has Finished'
    ran_for = ('It ran for ' + getTimeFormat(duration) + ' and recovered '
               + str(cracked_cnt) + ' out of ' + str(total_cnt) + ' hashes.')

    for job_notification in JobNotifications.query.filter_by(job_id=job.id).all():
        claimed = (db.session.query(JobNotifications)
                   .filter(JobNotifications.id == job_notification.id,
                           JobNotifications.sent_at.is_(None))
                   .update({'sent_at': utcnow()}, synchronize_session=False))
        db.session.commit()
        if not claimed:
            continue
        user = Users.query.get(job_notification.owner_id)
        if user is None:
            continue
        subject = 'Hashview Job: "' + job.name + '" ' + headline
        plain = 'Your job "' + job.name + '" has finished. ' + ran_for
        html = ('Your job has finished. ' + ran_for
                + ' <br /><br /> <a href="'
                + url_for('analytics.get_analytics', customer_id=job.customer_id,
                          hashfile_id=job.hashfile_id, _external=True)
                + '">View Analytics</a>')
        # Claimed above, then delivered. Claim-first makes a double-send
        # impossible, which is the failure being fixed; the cost is that a
        # delivery that throws is not retried. Contain it rather than letting it
        # escape: this runs inside POST /v1/jobtask/status, so an SMTP outage
        # used to turn an agent's "task finished" report into a 500.
        try:
            deliver_user_notification(user, job_notification.method, subject, plain,
                                      html_message=html)
        except Exception:
            current_app.logger.exception(
                'Job %s completion notification (%s) failed to deliver.',
                job.id, job_notification.method)


def mark_job_running(job_id):
    """Promote a Queued job to Running when its first slice actually goes out.

    The ONLY place that used to do this is update_job_task_status, and it fired
    because dispatch handed the agent a row still marked 'Queued' -- the agent's
    defensive "I'm running this" POST was what flipped the job.

    Ledger dispatch stamps the row 'Running' server-side at claim/mint time, so
    by the time that POST arrives the row already has the status it reports, and
    /v1/jobtask/status short-circuits it as idempotent without ever reaching
    update_job_task_status. The job therefore sat at 'Queued' for its whole run:
    the dashboard lists running work with Jobs.status == 'Running', so a job
    being actively cracked showed as queued, with no task and no progress.

    Promote where the work is actually issued instead -- CAS on 'Queued' so a
    concurrent heartbeat cannot double-stamp started_at, and clear ended_at,
    which is otherwise left over from the previous run of a re-queued job.
    Returns True if this call was the one that started it.

    The processing clock is reset here for the same reason: re-running a job is
    a new run, and it gets the whole of max_runtime_jobs to spend. Carrying the
    previous run's credit over would expire the re-run before it began, which is
    the cap's most confusing possible failure -- a job that dies instantly and
    reports a runtime it did not have.
    """
    started = (db.session.query(Jobs)
               .filter(Jobs.id == job_id, Jobs.status == 'Queued')
               .update({'status': 'Running', 'started_at': utcnow(),
                        'ended_at': None, 'processing_seconds': 0,
                        'last_counted_at': None}, synchronize_session=False))
    if started:
        db.session.commit()
    return bool(started)


def update_job_task_status(jobtask_id, status, finalize=True):
    """Function to update task status of a job

    ``finalize=False`` suppresses the job roll-up, for a caller that is changing
    several rows at once and wants to roll the job up itself, once, afterwards
    (see api.routes._cancel_job_active_tasks).
    """

    jobtask = JobTasks.query.get(jobtask_id)

    if jobtask is None:
        return False

    jobtask.status = status
    if status in JOBTASK_TERMINAL_STATUSES:
        # When this attempt stopped. Paired with started_at so the row describes a
        # closed interval; see JobTasks.ended_at for what that is for. Stamped for
        # every terminal status, not just Completed -- an attempt that was
        # cancelled or expired still occupied an agent for exactly as long as it
        # ran, and a runtime derived from intervals that silently omit those is
        # not a runtime.
        jobtask.ended_at = utcnow()
        # Clear the assigned agent's stale hashcat status BEFORE nulling agent_id.
        # Nulling first made the lookup Agents.query.get(None) -> None, so the agent
        # was never found and kept its stale hc_status forever (issue #237). The
        # None-guard also avoids the spurious "fully NULL primary key" SAWarning when
        # an unassigned task is cancelled.
        if jobtask.agent_id is not None:
            agent = Agents.query.get(jobtask.agent_id)
            if agent:
                agent.hc_status = ''
        jobtask.agent_id = None
    db.session.commit()

    job = Jobs.query.get(jobtask.job_id)
    if job is None:
        return True
    if job.status == 'Queued':
        job.status = 'Running'
        job.started_at = utcnow()
        db.session.commit()

    if finalize:
        finalize_job_if_complete(job.id)
    return True


# ---------------------------------------------------------------------------
# Hashfile validation
#
# Each validator returns an ERROR STRING when a line looks malformed, and
# False when the whole file passes (callers treat any truthy return as "has a
# problem"). Fixed formats/lengths come from hashcat --example-hashes for the
# modes the upload form offers. Variable components (usernames, realms, salts,
# client blobs) are intentionally left lenient — only the fixed-shape parts
# (hex lengths, field separators, magic prefixes) are enforced, so legitimate
# hashes are never rejected while typos/truncation/wrong-format are caught.
# ---------------------------------------------------------------------------

# Per-line length guard (garbage/DoS protection, not a correctness check). Big
# enough for the longest legitimate single-line hash hashcat emits — LUKS v1
# keyslot hashes ($luks$) reach ~513 KB.
_MAX_LINE_LEN = 1_048_576
_HEX_ONLY_RE = re.compile(r'^[0-9a-fA-F]+$')


def _is_hex(value, length=None):
    """True if value is non-empty hex (optionally of an exact length)."""
    if not value:
        return False
    if length is not None and len(value) != length:
        return False
    return _HEX_ONLY_RE.match(value) is not None


def _validate_hashfile(hashfile_path, line_validator):
    """Stream a hashfile and run line_validator(line, line_no) on each non-blank
    line; return the first error string, or False if every line passes.

    Centralises shared robustness: safe decoding (utf-8-sig with
    errors='replace' never raises on binary/garbage uploads), streaming (no
    whole-file load into memory),
    blank/whitespace-only line skipping, the per-line length cap, and an
    empty-file check.
    """
    count = 0
    try:
        # utf-8-sig transparently drops a leading BOM (common from Windows
        # editors) so the first hash isn't rejected; errors='replace' keeps the
        # "never raises on binary/garbage" guarantee.
        with open(hashfile_path, encoding='utf-8-sig', errors='replace') as handle:
            for line_no, raw in enumerate(handle, start=1):
                if len(raw) > _MAX_LINE_LEN:
                    return ('Error line ' + str(line_no) + ' is too long ('
                            + str(len(raw)) + ' chars). Max length is '
                            + str(_MAX_LINE_LEN) + ' chars.')
                line = raw.strip()
                if not line:
                    continue                          # skip blank / whitespace-only lines
                count += 1
                problem = line_validator(line, line_no)
                if problem:
                    return problem
    except OSError as exc:
        return 'Error: unable to read the hashfile (' + str(exc) + ').'
    if count == 0:
        return 'Error: the hashfile contains no hashes.'
    return False


def validate_pwdump_hashfile(hashfile_path, hash_type):
    """Validate a pwdump-format hashfile (username:rid:LM:NT:::, NTLM only)."""
    if str(hash_type) != '1000':
        return 'Sorry. The only Hash Type we support for PWDump files is NTLM (1000).'

    def check(line, line_no):
        fields = line.split(':')
        if len(fields) < 7:
            return ('Error line ' + str(line_no) + ' does not appear to be in pwdump '
                    'format (expected username:rid:LM:NT:::).')
        if not fields[0]:
            return 'Error line ' + str(line_no) + ' has an empty username.'
        lm_hash, nt_hash = fields[2], fields[3]
        if not _is_hex(nt_hash, 32):
            return ('Error line ' + str(line_no) + ': the NTLM hash (4th field) must be '
                    '32 hex characters.')
        if lm_hash and not _is_hex(lm_hash, 32):
            return ('Error line ' + str(line_no) + ': the LM hash (3rd field) must be '
                    'empty or 32 hex characters.')
        return None

    return _validate_hashfile(hashfile_path, check)

_NETNTLM_V1_TYPES = {'5500', '27000'}
_NETNTLM_V2_TYPES = {'5600', '27100'}


def _is_netntlmv1(fields):
    # user::domain:LMresp(48 hex):NTresp(48 hex):challenge(16 hex)
    return _is_hex(fields[3], 48) and _is_hex(fields[4], 48) and _is_hex(fields[5], 16)


def _is_netntlmv2(fields):
    # user::domain:srvchallenge(16 hex):HMAC-MD5(32 hex):blob(variable even-length hex)
    return (_is_hex(fields[3], 16) and _is_hex(fields[4], 32)
            and _is_hex(fields[5]) and len(fields[5]) % 2 == 0)


def validate_netntlm_hashfile(hashfile_path, hash_type=None):
    """Validate a NetNTLMv1/v2 hashfile (user::domain:...:...:...).

    ``hash_type`` (5500/27000 = v1, 5600/27100 = v2) is optional: when omitted
    the line is accepted if it matches EITHER the v1 or v2 structure.
    """
    hash_type = str(hash_type) if hash_type is not None else None
    seen = set()

    def check(line, line_no):
        fields = line.split(':')
        if len(fields) != 6:
            return ('Error line ' + str(line_no) + ' does not appear to be in NetNTLM '
                    'format (expected user::domain:...:...:... — 6 fields / 5 colons).')

        # Whole-file duplicate user/computer guard.
        key = (fields[0] + ':' + fields[2]).lower()
        if key in seen:
            return ('Error: duplicate username/computer found (' + key + '). '
                    'Please submit only unique username/computer entries.')
        seen.add(key)

        if hash_type in _NETNTLM_V1_TYPES:
            if not _is_netntlmv1(fields):
                return ('Error line ' + str(line_no) + ' is not a valid NetNTLMv1 hash '
                        '(fields 4 & 5 must be 48 hex chars, field 6 16 hex chars).')
        elif hash_type in _NETNTLM_V2_TYPES:
            if not _is_netntlmv2(fields):
                return ('Error line ' + str(line_no) + ' is not a valid NetNTLMv2 hash '
                        '(field 4 = 16 hex, field 5 = 32 hex, field 6 = hex blob).')
        else:
            if not (_is_netntlmv1(fields) or _is_netntlmv2(fields)):
                return ('Error line ' + str(line_no) + ' does not match a NetNTLMv1 or '
                        'NetNTLMv2 hash structure.')
        return None

    return _validate_hashfile(hashfile_path, check)

# Per-mode Kerberos structure (prefix + etype + fixed-length hex parts).
# Variable principal/realm/SPN/salt strings are matched leniently.
# Field lengths below were swept against hashcat 6.2.6 one character at a time
# rather than copied from its example hashes -- the examples are what these
# patterns were originally calibrated from, which is exactly why they used to
# reject real tool output. Accepted sets measured: 7500 tail exactly 104;
# 28800 exactly 32; 28900 exactly 64; 19800/19900 the inclusive window 104-112;
# and an edata2 floor of exactly 64 hex on 13100/18200/19600/19700 (odd lengths
# fine, no upper bound -- real blobs run 370-470). A too-loose pattern moves the
# failure from paste time, where the user can fix it, to job-run time, where the
# agent just reports "No hashes loaded".
_KERBEROS_RE = {
    '7500':  re.compile(r'^\$krb5pa\$23\$[^$]+\$[^$]*\$[^$]*\$[0-9a-fA-F]{104}$'),
    # \*[^*]+\* not \*.+\*: hashcat rejects a nested '*' inside the triple.
    '13100': re.compile(r'^\$krb5tgs\$23\$\*[^*]+\*\$[0-9a-fA-F]{32}\$[0-9a-fA-F]{64,}$'),
    # The etype field is optional: Rubeus and John emit $krb5asrep$user@REALM:...
    # with no `23$`, and hashcat accepts it and echoes it back unchanged. The
    # lookahead is what keeps the field optional without making it a wildcard:
    # `[^:]+` would otherwise swallow `17$user@dom` whole and let a wrong etype
    # through as part of the principal. `[^:]+` rather than `[^$:]+` so a
    # machine-account principal (`COMPUTER$@REALM`) still passes, as before.
    #
    # The inner `(?![@:])` matters: a machine account is `<name>$`, so a
    # computer named `18` gives `18$@REALM`, which a bare `(?![0-9]{1,3}\$)`
    # guard cannot tell from an etype and wrongly rejects. Digits followed by
    # `$@` or `$:` are therefore a principal, not an etype -- confirmed against
    # hashcat, which loads all of `18$@REALM`, `9$@REALM` and `123$@REALM`.
    '18200': re.compile(
        r'^\$krb5asrep\$(?:23\$)?(?![0-9]{1,3}\$(?![@:]))'
        r'[^:]+:[0-9a-fA-F]{32}\$[0-9a-fA-F]{64,}$'),
    # etype 17/18: impacket's GetUserSPNs.py emits the service principal name as
    # an extra star-wrapped field between the realm and the checksum, e.g.
    #   $krb5tgs$18$user$REALM$*MSSQLSvc/host.dom:1433*$<24 hex>$<edata2>
    # hashcat 6.2.6 accepts both that and its own SPN-less example shape, cracks
    # them identically, and echoes the hash back with the SPN dropped -- so the
    # segment is optional here rather than required. It is NOT the 13100-style
    # `*user$realm$spn*` triple: hashcat rejects that for 17/18 ("No hashes
    # loaded"), so the stars stay confined to their own field.
    #
    # The user/realm fields use [^$*] rather than [^$]: hashcat detects the
    # SPN form with strchr(line_buf + 13, '*'), so ANY asterisk anywhere after
    # the mode field puts its parser into SPN mode. An asterisk inside the
    # user or realm field then has no matching closing delimiter in the
    # expected place and hashcat rejects the whole line ("Separator
    # unmatched"/"Hash parsing error") -- measured on 7.1.2. [^$]+ let such
    # hashes validate at paste time and then die on the agent with "No hashes
    # loaded", exactly the too-loose failure class this pattern set out to fix.
    '19600': re.compile(
        r'^\$krb5tgs\$17\$[^$*]+\$[^$*]+\$(?:\*[^*]*\*\$)?[0-9a-fA-F]{24}\$[0-9a-fA-F]{64,}$'),
    '19700': re.compile(
        r'^\$krb5tgs\$18\$[^$*]+\$[^$*]+\$(?:\*[^*]*\*\$)?[0-9a-fA-F]{24}\$[0-9a-fA-F]{64,}$'),
    # 104-112, not exactly 112: the encrypted blob is confounder(16) + a
    # DER-encoded PA-ENC-TS-ENC whose length varies with the optional
    # microseconds field + HMAC(12), so a real 104-hex hash was being rejected.
    '19800': re.compile(r'^\$krb5pa\$17\$[^$]+\$[^$]+\$[0-9a-fA-F]{104,112}$'),
    '19900': re.compile(r'^\$krb5pa\$18\$[^$]+\$[^$]+\$[0-9a-fA-F]{104,112}$'),
    '28800': re.compile(r'^\$krb5db\$17\$[^$]+\$[^$]+\$[0-9a-fA-F]{32}$'),
    '28900': re.compile(r'^\$krb5db\$18\$[^$]+\$[^$]+\$[0-9a-fA-F]{64}$'),
}
# 35300/35400 are the NT-optimised variants of 13100/18200 with an identical
# on-the-wire hash format, so they reuse those patterns.
_KERBEROS_ALIAS = {'35300': '13100', '35400': '18200'}


def validate_kerberos_hashfile(hashfile_path, hash_type):
    """Validate a Kerberos hashfile ($krb5pa/$krb5tgs/$krb5asrep)."""
    hash_type = _KERBEROS_ALIAS.get(str(hash_type), str(hash_type))
    pattern = _KERBEROS_RE.get(hash_type)
    if pattern is None:
        return ('Sorry. The only supported Kerberos Hash Types are: 7500, 13100, '
                '18200, 19600, 19700, 19800, 19900, 28800, 28900, 35300 and 35400.')

    def check(line, line_no):
        if not pattern.match(line):
            return ('Error line ' + str(line_no) + ' does not match the expected '
                    'Kerberos format for hash type ' + hash_type + '.')
        return None

    return _validate_hashfile(hashfile_path, check)

# crypt(3) hash structure per shadow hash type (the hash itself, as found in
# the 2nd colon field of /etc/shadow or as a bare hash).
_SHADOW_RE = {
    '500':   re.compile(r'^\$1\$[./0-9A-Za-z]{0,8}\$[./0-9A-Za-z]{22}$'),       # md5crypt
    '1500':  re.compile(r'^[./0-9A-Za-z]{13}$'),                                # descrypt
    '1800':  re.compile(r'^\$6\$(rounds=[0-9]+\$)?[./0-9A-Za-z]{0,16}\$[./0-9A-Za-z]{86}$'),  # sha512crypt
    '3200':  re.compile(r'^\$2[abxy]\$[0-9]{2}\$[./0-9A-Za-z]{53}$'),           # bcrypt
    '7400':  re.compile(r'^\$5\$(rounds=[0-9]+\$)?[./0-9A-Za-z]{0,16}\$[./0-9A-Za-z]{43}$'),  # sha256crypt
    '12400': re.compile(r'^_[./0-9A-Za-z]{19}$'),                               # bsdicrypt (extended DES)
    '15100': re.compile(r'^\$sha1\$[0-9]+\$[./0-9A-Za-z]{0,64}\$[./0-9A-Za-z]{28}$'),  # sha1crypt
}
# Sentinels for locked / passwordless accounts — present in real shadow files
# but not crackable hashes.
_SHADOW_LOCKED = {'', '*', '!', '!!', 'x', '*LK*', '!*'}


def validate_shadow_hashfile(hashfile_path, hash_type):
    """Validate a Unix shadow hashfile (user:hash:... or a bare crypt hash)."""
    hash_type = str(hash_type)
    pattern = _SHADOW_RE.get(hash_type)
    if pattern is None:
        return ('Sorry. The only supported shadow Hash Types are: 500 ($1$ md5crypt), '
                '1500 (descrypt), 1800 ($6$ sha512crypt), 3200 ($2*$ bcrypt), '
                '7400 ($5$ sha256crypt), 12400 (bsdicrypt) and 15100 ($sha1$ sha1crypt).')

    def check(line, line_no):
        # A shadow line is user:hash:... ; a bare hash (no colon) is also accepted.
        token = line.split(':')[1] if ':' in line else line
        if token in _SHADOW_LOCKED:
            return ('Error line ' + str(line_no) + ' is a locked/passwordless account ('
                    + (token or 'empty') + '), not a crackable hash.')
        if not pattern.match(token):
            return ('Error line ' + str(line_no) + ' does not match the expected '
                    'format for shadow hash type ' + hash_type + '.')
        return None

    return _validate_hashfile(hashfile_path, check)

def validate_user_hash_hashfile(hashfile_path, hash_type=None):
    """Validate a user:hash hashfile — each line must contain a ':' separator.

    Accepts an optional (unused) hash_type so the API call site that passes one
    works; the sibling validators in that if/elif chain all take two args.
    """
    def check(line, line_no):
        if ':' not in line:
            return ('Error line ' + str(line_no) + ' is missing a : character; a '
                    'user:hash file needs one ":" per line.')
        return None

    return _validate_hashfile(hashfile_path, check)

# Per hash-type structure for "hash only" uploads, keyed by hashcat mode and
# derived from hashcat --example-hashes. Each entry is (compiled_regex,
# human-readable expected-format). Raw-hex types check exact hex length; salted
# types check the fixed hex prefix + ':<salt>' (salt left lenient); structured
# types check the magic prefix + fixed fields. Hex is accepted in either case.
# Modes not listed here are accepted as-is (cannot be safely constrained).
_HASH_ONLY_RULES = {
    # raw / unsalted hex (length-checked)
    '0':     (re.compile(r'^[0-9a-fA-F]{32}$'),  '32 hex characters (MD5)'),
    '900':   (re.compile(r'^[0-9a-fA-F]{32}$'),  '32 hex characters (MD4)'),
    '1000':  (re.compile(r'^[0-9a-fA-F]{32}$'),  '32 hex characters (NTLM)'),
    '9900':  (re.compile(r'^[0-9a-fA-F]{32}$'),  '32 hex characters (Radmin2)'),
    '100':   (re.compile(r'^[0-9a-fA-F]{40}$'),  '40 hex characters (SHA1)'),
    '300':   (re.compile(r'^[0-9a-fA-F]{40}$'),  '40 hex characters (MySQL4.1/5)'),
    '6000':  (re.compile(r'^[0-9a-fA-F]{40}$'),  '40 hex characters (RIPEMD-160)'),
    '1300':  (re.compile(r'^[0-9a-fA-F]{56}$'),  '56 hex characters (SHA-224)'),
    '1700':  (re.compile(r'^[0-9a-fA-F]{128}$'), '128 hex characters (SHA-512)'),
    '18000': (re.compile(r'^[0-9a-fA-F]{128}$'), '128 hex characters (Keccak-512)'),
    '122':   (re.compile(r'^[0-9a-fA-F]{48}$'),  '48 hex characters (macOS 10.4-10.6 salted SHA1)'),
    # MSSQL: '0x' + a 2-byte version tag + 4-byte salt + the digest(s). These are
    # the three modes a user is most likely to pick the wrong one of -- they are
    # the same product, and 131/132 even share the 0x0100 tag, so LENGTH is the
    # only thing separating those two. Verified against hashcat v6.2.6 rather
    # than derived from the format docs: the '0x' is mandatory and must be
    # lowercase ('0X...' and a bare '0100...' are both refused), while the hex
    # digits are case-insensitive. The matrix of all nine (contents, declared)
    # pairs was run through hashcat and only the diagonal loads, so these rules
    # reproduce its behaviour exactly instead of approximating it.
    #
    # The auto-generator could not cover these: its ('hex', N) spec needs the
    # whole string to be hex, which the leading '0x' breaks, and its prefix
    # specs were written for '$name$' tags.
    '131':   (re.compile(r'^0x0100[0-9a-fA-F]{88}$'),
              "'0x0100' + 8 hex salt + 80 hex digest, 94 chars (MSSQL 2000)"),
    '132':   (re.compile(r'^0x0100[0-9a-fA-F]{48}$'),
              "'0x0100' + 8 hex salt + 40 hex digest, 54 chars (MSSQL 2005)"),
    '1731':  (re.compile(r'^0x0200[0-9a-fA-F]{136}$'),
              "'0x0200' + 8 hex salt + 128 hex digest, 142 chars (MSSQL 2012/2014)"),
    # Same family of shape, same gap in the generator: a lowercase '0x' tag the
    # hex spec cannot express. Probed the same way -- the tag is literal and
    # case-sensitive ('0xC007' is refused), the digits are not, and 84/88 chars
    # are both refused, so the length is exact.
    '8000':  (re.compile(r'^0xc007[0-9a-fA-F]{80}$'),
              "'0xc007' + 16 hex salt + 64 hex digest, 86 chars (Sybase ASE)"),
    # salted raw: <hash_hex>:<salt> (salt lenient)
    '10':    (re.compile(r'^[0-9a-fA-F]{32}:.+$'),  'md5 hash:salt (32 hex, colon, salt)'),
    '20':    (re.compile(r'^[0-9a-fA-F]{32}:.+$'),  'md5 salt:hash (32 hex, colon, salt)'),
    '3800':  (re.compile(r'^[0-9a-fA-F]{32}:.+$'),  '32 hex, colon, salt'),
    '110':   (re.compile(r'^[0-9a-fA-F]{40}:.+$'),  'sha1 hash:salt (40 hex, colon, salt)'),
    '120':   (re.compile(r'^[0-9a-fA-F]{40}:.+$'),  'sha1 salt:hash (40 hex, colon, salt)'),
    '1410':  (re.compile(r'^[0-9a-fA-F]{64}:.+$'),  'sha256 hash:salt (64 hex, colon, salt)'),
    '1420':  (re.compile(r'^[0-9a-fA-F]{64}:.+$'),  'sha256 salt:hash (64 hex, colon, salt)'),
    '1710':  (re.compile(r'^[0-9a-fA-F]{128}:.+$'), 'sha512 hash:salt (128 hex, colon, salt)'),
    '1720':  (re.compile(r'^[0-9a-fA-F]{128}:.+$'), 'sha512 salt:hash (128 hex, colon, salt)'),
    # forum / cms (md5/sha1 + salt)
    '11':    (re.compile(r'^[0-9a-fA-F]{32}:.+$'),  '32 hex, colon, salt (Joomla)'),
    '21':    (re.compile(r'^[0-9a-fA-F]{32}:.+$'),  '32 hex, colon, salt (osCommerce)'),
    '2611':  (re.compile(r'^[0-9a-fA-F]{32}:.+$'),  '32 hex, colon, salt (vBulletin <3.8.5)'),
    '2711':  (re.compile(r'^[0-9a-fA-F]{32}:.+$'),  '32 hex, colon, salt (vBulletin >=3.8.5)'),
    '2811':  (re.compile(r'^[0-9a-fA-F]{32}:.+$'),  '32 hex, colon, salt (IPB/MyBB)'),
    '11000': (re.compile(r'^[0-9a-fA-F]{32}:.+$'),  '32 hex, colon, salt (PrestaShop)'),
    '121':   (re.compile(r'^[0-9a-fA-F]{40}:.+$'),  '40 hex, colon, salt (SMF)'),
    '4522':  (re.compile(r'^[0-9a-fA-F]{40}:.+$'),  '40 hex, colon, salt (PunBB)'),
    '13900': (re.compile(r'^[0-9a-fA-F]{40}:.+$'),  '40 hex, colon, salt (OpenCart)'),
    '124':   (re.compile(r'^sha1\$[^$]+\$[0-9a-fA-F]{40}$'), 'sha1$salt$40-hex (Django SHA1)'),
    # DCC / cisco / mac / db
    '1100':  (re.compile(r'^[0-9a-fA-F]{32}:.+$'),  '32 hex, colon, username (DCC/MS-Cache)'),
    '2100':  (re.compile(r'^\$DCC2\$[0-9]+#[^#]+#[0-9a-fA-F]{32}$'), '$DCC2$iterations#user#32-hex'),
    '2400':  (re.compile(r'^[./0-9A-Za-z]{16}$'),   '16 base64 characters (Cisco-PIX)'),
    '2410':  (re.compile(r'^[./0-9A-Za-z]{16}:.+$'),'16 base64 chars, colon, salt (Cisco-ASA)'),
    '8100':  (re.compile(r'^1[0-9a-fA-F]{48}$'),    "'1' followed by 48 hex (Citrix SHA1)"),
    '22200': (re.compile(r'^2[0-9a-fA-F]{136}$'),   "'2' followed by 136 hex (Citrix SHA512)"),
    '7100':  (re.compile(r'^\$ml\$[0-9]+\$[0-9a-fA-F]{64}\$[0-9a-fA-F]{128}$'),
              '$ml$iter$64-hex-salt$128-hex (macOS 10.8+)'),
    # unix crypt
    '500':   (re.compile(r'^\$1\$[./0-9A-Za-z]{0,8}\$[./0-9A-Za-z]{22}$'), '$1$salt$22-char (md5crypt)'),
    '1500':  (re.compile(r'^[./0-9A-Za-z]{13}$'),   '13 crypt-base64 characters (descrypt)'),
    '1800':  (re.compile(r'^\$6\$(rounds=[0-9]+\$)?[./0-9A-Za-z]{0,16}\$[./0-9A-Za-z]{86}$'),
              '$6$[rounds=N$]salt$86-char (sha512crypt)'),
    '3200':  (re.compile(r'^\$2[abxy]\$[0-9]{2}\$[./0-9A-Za-z]{53}$'), '$2a$cost$53-char (bcrypt)'),
    '7400':  (re.compile(r'^\$5\$(rounds=[0-9]+\$)?[./0-9A-Za-z]{0,16}\$[./0-9A-Za-z]{43}$'),
              '$5$[rounds=N$]salt$43-char (sha256crypt)'),
    '12400': (re.compile(r'^_[./0-9A-Za-z]{19}$'),  '_ + 19 crypt-base64 chars (bsdicrypt)'),
    '15100': (re.compile(r'^\$sha1\$[0-9]+\$[./0-9A-Za-z]{0,64}\$[./0-9A-Za-z]{28}$'),
              '$sha1$rounds$salt$28-char (sha1crypt)'),
    # base64 / token formats
    '22':    (re.compile(r'^[A-Za-z0-9+/]{30}:[0-9]+$'),    '30 base64 chars, colon, numeric salt (Juniper)'),
    '5700':  (re.compile(r'^[A-Za-z0-9./+]{43}$'),          '43 base64 characters (Cisco-IOS type4)'),
    '7000':  (re.compile(r'^AK1[A-Za-z0-9+/]{43}=$'),       "'AK1' + 44 base64 chars (FortiGate)"),
    '400':   (re.compile(r'^\$[PH]\$[./0-9A-Za-z]{31}$'),   '$P$/$H$ + 31 chars (phpass)'),
    '7900':  (re.compile(r'^\$S\$[./0-9A-Za-z]{52}$'),      '$S$ + 52 chars (Drupal7)'),
    '3711':  (re.compile(r'^\$B\$[^$]*\$[0-9a-fA-F]{32}$'), '$B$salt$32-hex (MediaWiki)'),
    '10000': (re.compile(r'^pbkdf2_sha256\$[0-9]+\$[^$]+\$[A-Za-z0-9+/]+={0,2}$'),
              'pbkdf2_sha256$iter$salt$base64 (Django PBKDF2)'),
    '10100': (re.compile(r'^[0-9a-fA-F]{16}:2:4:[0-9a-fA-F]{32}$'), '16-hex:2:4:32-hex (SipHash)'),
    '14000': (re.compile(r'^[0-9a-fA-F]{16}:[0-9a-fA-F]{16}$'),     '16-hex:16-hex (DES)'),
    # MS office (separator is '*'; verifier hash 40 hex for 2007, 64 for 2010/2013)
    '9400':  (re.compile(r'^\$office\$\*(2007|2010|2013)\*[0-9]+\*(128|256)\*16\*[0-9a-fA-F]{32}\*[0-9a-fA-F]{32}\*(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$'), '$office$* … (MS Office)'),
}
_HASH_ONLY_RULES['9500'] = _HASH_ONLY_RULES['9400']
_HASH_ONLY_RULES['9600'] = _HASH_ONLY_RULES['9400']
# bcrypt-wrapped KDFs (bcrypt(md5/sha1/sha512($pass))) are bcrypt-format: the
# version tag may be $2a$/$2b$/$2x$/$2y$ (auto-derived rule wrongly pinned $2a$).
for _bcrypt_mode in ('25600', '25800', '28400'):
    _HASH_ONLY_RULES[_bcrypt_mode] = (re.compile(r'^\$2[abxy]\$[0-9]{2}\$[./0-9A-Za-z]{53}$'),
                                      '$2a$/$2b$/$2y$ cost$53-char (bcrypt)')


def _build_auto_matcher(spec):
    """Compile a conservative auto-derived spec (from
    hashcat_modes.HASH_ONLY_AUTO_RULES) ONCE into (match_fn, description). Only
    the fixed-shape part is enforced so valid hashes aren't rejected."""
    kind = spec[0]
    if kind == 'hex':
        rx = re.compile(r'[0-9a-fA-F]{%d}' % spec[1])
        return (lambda s: rx.fullmatch(s) is not None, '%d hex characters' % spec[1])
    if kind == 'hexsalt':
        rx = re.compile(r'[0-9a-fA-F]{%d}:.+' % spec[1])
        return (lambda s: rx.match(s) is not None,
                '%d hex characters, a colon, then a salt' % spec[1])
    if kind == 'prefixes':
        # Several acceptable magic tags (str.startswith accepts a tuple). Used by
        # PKZIP, where hashcat accepts both the legacy '$pkzip$' and '$pkzip2$'.
        prefixes = tuple(spec[1])
        return (lambda s: s.startswith(prefixes),
                'a hash beginning with ' + ' or '.join("'%s'" % p for p in prefixes))
    # 'prefix' / 'litprefix'
    prefix = spec[1]
    return (lambda s: s.startswith(prefix), f"a hash beginning with '{prefix}'")


def validate_hash_only_hashfile(hashfile_path, hash_type):
    """Validate a file of bare hashes for the selected hashcat hash type.

    Returns an error string on the first malformed line, or False when the file
    passes. Curated rules (precise) take precedence; otherwise a conservative
    auto-derived rule (HASH_ONLY_AUTO_RULES, from hashcat's example hashes) is
    used; hash types with neither are accepted as-is (can't be safely
    constrained without risking rejection of valid hashes).
    """
    hash_type = str(hash_type)
    rule = _HASH_ONLY_RULES.get(hash_type)
    auto_matcher = None
    if rule is None:
        spec = HASH_ONLY_AUTO_RULES.get(hash_type)
        auto_matcher = _build_auto_matcher(spec) if spec else None

    def check(line, line_no):
        if rule is not None:
            ok, expected = (rule[0].match(line) is not None), rule[1]
        elif auto_matcher is not None:
            match_fn, expected = auto_matcher
            ok = match_fn(line)
        else:
            return None                       # unconstrainable type: accept
        if not ok:
            return ('Error line ' + str(line_no) + ' is not a valid hash for the selected '
                    'type — expected ' + expected + '.')
        return None

    return _validate_hashfile(hashfile_path, check)


# Modes whose hash is supplied as a colon-delimited "<hash>:<salt>" (or
# "<salt>:<hash>") pair -- the only modes for which hashcat's --hex-salt is
# meaningful. Derived from the existing rule sources so the set can't drift:
# the hexsalt auto-rules (hashcat_modes) plus the curated rules whose regex
# carries a salt colon. A few fixed-structure multi-field colon formats are
# excluded because the text after the first colon isn't a free salt (Juniper's
# numeric salt, SipHash's "<hex>:2:4:<hex>", DES's "<hex>:<hex>").
_SALTED_HASH_MODE_EXCLUDE = frozenset({'22', '10100', '14000'})
_SALTED_HASH_MODES = frozenset(
    {mode for mode, spec in HASH_ONLY_AUTO_RULES.items() if spec[0] == 'hexsalt'}
    | {mode for mode, (rx, _desc) in _HASH_ONLY_RULES.items() if ':' in rx.pattern}
) - _SALTED_HASH_MODE_EXCLUDE


def hash_type_uses_salt(hash_type):
    """True when the hashcat mode supplies its salt as a separate colon-delimited
    field (so --hex-salt applies). Unsalted modes (NTLM, raw MD5, ...) have no
    salt to check, so the --hex-salt validation + flag are gated on this."""
    return str(hash_type) in _SALTED_HASH_MODES


_HEX_SALT_RE = re.compile(r'^[0-9a-fA-F]+$')


def validate_hex_salt(hashfile_path, file_type, hash_type):
    """When the --hex-salt option is set, verify every line carries a hex salt.

    Salt position is format-dependent: ``hash_only`` is ``<hash>:<salt>`` (salt
    after the 1st ':'); ``user_hash`` is ``<user>:<hash>:<salt>`` (salt after the
    2nd ':', since import splits the username off the first colon). No-ops
    (returns False) for modes that don't use a salt — there's nothing to check.
    Returns an error string on the first offending line, else False (matching the
    sibling validate_*_hashfile contract)."""
    if not hash_type_uses_salt(hash_type):
        return False
    salt_index = 2 if file_type == 'user_hash' else 1

    def check(line, line_no):
        parts = line.split(':')
        if len(parts) <= salt_index or parts[salt_index] == '':
            return ('Error line ' + str(line_no) + ': --hex-salt is set but no salt '
                    'was found (expected <hash>:<salt>).')
        salt = ':'.join(parts[salt_index:])     # keep any further colons as part of the salt
        if not _HEX_SALT_RE.match(salt):
            return ('Error line ' + str(line_no) + ': salt ' + repr(salt) + ' is not hex '
                    '(only 0-9 a-f allowed when --hex-salt is set).')
        return None

    return _validate_hashfile(hashfile_path, check)

def getTimeFormat(total_runtime): # Runtime in seconds
    """Function to convert seconds into, minutes, hours, days or weeks"""

    if total_runtime >= 604800:
        return str(round(total_runtime/604800)) + " week(s)"
    elif total_runtime >= 86400:
        return str(round(total_runtime/86400)) + " day(s)"
    elif total_runtime >= 3600:
        return str(round(total_runtime/3600)) + " hour(s)"
    elif total_runtime >= 60:
        return str(round(total_runtime/60)) + " minute(s)"
    elif total_runtime < 60:
        return "less then 1 minute"

def apply_name_filter(query, column, search_term):
    """Narrow `query` to rows whose `column` contains `search_term`.

    Case-insensitive substring match, used by the listing pages so their filter
    box searches the whole table rather than only the rows the current page
    happened to render. An empty or whitespace-only term is a no-op.

    LIKE wildcards in the user's input are escaped, so typing a literal '%' or
    '_' matches that character instead of standing in for "anything".
    """
    term = (search_term or '').strip()
    if not term:
        return query
    escaped = term.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
    return query.filter(column.ilike('%' + escaped + '%', escape='\\'))
