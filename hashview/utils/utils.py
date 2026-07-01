"""Flask routes to handle utils"""
import _md5
import binascii
import gzip
import hashlib
import os
import re
import secrets
import struct
from datetime import datetime

import requests
from flask import current_app, url_for
from flask_mail import Message
from sqlalchemy.exc import SQLAlchemyError

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
    JobTasks,
    Rules,
    Settings,
    Tasks,
    Users,
    Wordlists,
    db,
)
from hashview.utils.chunking import is_chunkable, plan_chunks
from hashview.utils.hashcat_modes import HASH_ONLY_AUTO_RULES


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


def save_file(path, form_file):
    """Function to safe file from form submission"""

    random_hex = secrets.token_hex(8)
    file_name = random_hex + os.path.split(form_file.filename)[0] + '.txt'
    file_path = os.path.join(current_app.root_path, path, file_name)
    form_file.save(file_path)
    return file_path

def _count_generator(reader):
    b = reader(1024 * 1024)
    while b:
        yield b
        b = reader(1024 * 1024)

def get_linecount(filepath):
    """Function to return line count of file"""

    with open(filepath, 'rb') as fp:
        c_generator = _count_generator(fp.raw.read)
        count = sum(buffer.count(b'\n') for buffer in c_generator)
        return count + 1

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
    the SAME semantics as get_linecount (count of '\\n' + 1) so a wordlist's
    reported line count is identical whether it arrived as plain text or gzip.
    Raises on a malformed gzip stream (validation).
    """
    with gzip.open(filepath, 'rb') as f:
        count = sum(buffer.count(b'\n') for buffer in iter(lambda: f.read(_CHUNK), b''))
    return count + 1


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
    tmp_dir = os.path.join(current_app.root_path, 'control/tmp')
    final_gz = os.path.join(wordlists_dir, secrets.token_hex(8) + '.gz')

    if is_gzip(src_path):
        # Decompress to a temp file so we can hash the plaintext-equivalent and
        # re-compress at -9. gz_linecount also validates the gzip stream.
        tmp_plain = os.path.join(tmp_dir, secrets.token_hex(8))
        try:
            decompress_gz(src_path, tmp_plain)      # raises on bad gzip
            size = get_linecount(tmp_plain)
            compress_to_gz(tmp_plain, final_gz, 9)
        finally:
            if os.path.exists(tmp_plain):
                os.remove(tmp_plain)
    else:
        size = get_linecount(src_path)
        compress_to_gz(src_path, final_gz, 9)

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
        settings = Settings.query.first()
        if settings and settings.agent_timeout_minutes:
            return settings.agent_timeout_minutes
    except Exception:  # pragma: no cover - pre-migration / no DB
        return 60
    return 60

def notify_admins(subject, message):
    """Deliver an administrative notification (e.g. an agent error) to the admins
    who opted in, over each channel they selected and that is instance-enabled.

    Email/Pushover are delivered per-admin. Slack is different: admin alerts post
    to the single shared room (Settings.slack_admin_channel), so we post there ONCE
    when any opted-in admin selected Slack — never once per admin. Respects the
    instance-wide master switches (a disabled channel never sends)."""
    settings = Settings.query.first()
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

    settings = Settings.query.first()
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

    settings = Settings.query.first()
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
    falls back to the pure-Python MD4 above. surrogatepass mirrors the
    surrogateescape file read in the import endpoint so undecodable bytes
    round-trip.
    """
    pw_bytes = plaintext.encode('utf-16le', 'surrogatepass')
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

def md4_hex(plaintext):
    """Lowercase hex MD4 over the UTF-8 bytes of a plaintext string (hashcat mode
    900 -- raw MD4, NOT the UTF-16LE NTLM variant). Mirrors ntlm_hash_hex's
    hashlib-then-pure-Python fallback, since OpenSSL 3.x may drop md4."""
    pw_bytes = _u8(plaintext)
    try:
        # MD4 here IS the algorithm being verified, not a security control.
        digest = hashlib.new('md4', pw_bytes).digest()  # nosec B324
    except ValueError:
        digest = _md4_pure(pw_bytes)
    return binascii.hexlify(digest).decode('ascii').lower()

def mssql2012_hash_hex(plaintext, salt_bytes):
    """Lowercase hex SHA-512 of UTF-16LE(plaintext) + salt (hashcat mode 1731,
    MSSQL 2012/2014). surrogatepass mirrors ntlm_hash_hex so undecodable bytes
    round-trip; salt_bytes is the raw 4-byte salt extracted from the ciphertext."""
    return hashlib.sha512(plaintext.encode('utf-16le', 'surrogatepass') + salt_bytes).hexdigest()

def _verify_ntlm(pt, ct):
    """Case-insensitive verify of a plaintext against an NTLM (mode 1000) hash."""
    return ntlm_hash_hex(pt).lower() == ct.lower()

def _verify_md4(pt, ct):
    """Case-insensitive verify of a plaintext against a raw MD4 (mode 900) hash."""
    return md4_hex(pt) == ct.lower()

def _verify_md5(pt, ct):
    """Case-insensitive verify of a plaintext against an MD5 (mode 0) hash. md5
    here is the algorithm being verified, not a security control."""
    return hashlib.md5(_u8(pt)).hexdigest() == ct.lower()  # nosec B324

def _verify_sha1(pt, ct):
    """Case-insensitive verify of a plaintext against a SHA1 (mode 100) hash. sha1
    here is the algorithm being verified, not a security control."""
    return hashlib.sha1(_u8(pt)).hexdigest() == ct.lower()  # nosec B324

def _verify_sha256(pt, ct):
    """Case-insensitive verify of a plaintext against a SHA2-256 (mode 1400) hash."""
    return hashlib.sha256(_u8(pt)).hexdigest() == ct.lower()

def _verify_mysql41(pt, ct):
    """Case-insensitive verify against a MySQL4.1/5 (mode 300) hash:
    SHA1(SHA1(pw)). sha1 here is the algorithm being verified, not a control."""
    return hashlib.sha1(hashlib.sha1(_u8(pt)).digest()).hexdigest() == ct.lower()  # nosec B324

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

def import_hash_only(line, hash_type):
    """Function to import single hash"""

    hash = Hashes.query.filter_by(hash_type=hash_type, sub_ciphertext=get_md5_hash(line)).first()

    if hash:
        return hash.id

    new_hash = Hashes(hash_type=hash_type, sub_ciphertext=get_md5_hash(line), ciphertext=line, cracked=0)
    db.session.add(new_hash)
    db.session.commit()
    return new_hash.id

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

def import_hashfilehashes(hashfile_id, hashfile_path, file_type, hash_type):
    """Function to hashfile"""

    # Open file. errors='surrogateescape' so a non-UTF-8 hashfile never crashes
    # on read; each stored field is normalised to text via text_from_field().
    file = open(hashfile_path, encoding='utf-8', errors='surrogateescape')
    lines = file.readlines()

    # for line in file,
    for line in lines:
        # If line is empty:
        username = None
        if len(line) > 0:
            if file_type == 'hash_only':
                # forcing lower casing of hash as hashcat will return lower cased version of the has and we want to match what we imported.
                if hash_type in ('300', '1731', '1000'):
                    hash_id = import_hash_only(line=line.lower().rstrip(), hash_type=hash_type)
                elif hash_type == '2100':
                    line = line.lower().rstrip()
                    line = line.replace('$dcc2$', '$DCC2$')
                    hash_id = import_hash_only(line, hash_type)
                else:
                    hash_id = import_hash_only(line=line.rstrip(), hash_type=hash_type)
                # extract username from dcc2 hash
                if hash_type == '2100':
                    username = line.split('#')[1]
                else:
                    username = None
            elif file_type == 'user_hash':
                if ':' in line:
                    if hash_type == '300' or hash_type == '1731':
                        hash_id = import_hash_only(line=line.lower().rstrip(), hash_type=hash_type)
                        username = line.split(':')[0]
                    elif hash_type == '2100':
                        line = line.split(':',1)[1].rstrip()
                        line = line.lower()
                        line = line.replace('$dcc2$', '$DCC2$')
                        hash_id = import_hash_only(line, hash_type)
                        username = line.split(':')[0]
                    else:
                        # hashcat emits hex hashes (e.g. NTLM) lowercased, so store
                        # them lowercased too -- otherwise the md5(ciphertext) lookup
                        # on crack upload misses (mirrors the hash_only path above).
                        hash_value = line.split(':', 1)[1].rstrip()
                        if hash_type in ('300', '1731', '1000'):
                            hash_value = hash_value.lower()
                        hash_id = import_hash_only(line=hash_value, hash_type=hash_type)
                        username = line.split(':')[0]
                else:
                    return False
            elif file_type == 'shadow':
                hash_id= import_hash_only(line=line.split(':')[1], hash_type=hash_type)
                username = line.split(':')[0]
            elif file_type == 'pwdump':
                # do we let user select LM so that we crack those instead of NTLM?
                # First extracting usernames so we can filter out machine accounts
                if re.search(r"\$$", line.split(':')[0]) or "_history" in line.split(':')[0]:
                #if '$' in line.split(':')[0]:
                    continue
                else:
                    hash_id = import_hash_only(line=line.split(':')[3].lower(), hash_type='1000')
                    username = line.split(':')[0]
            elif file_type == 'kerberos':
                hash_id = import_hash_only(line=line.lower().rstrip(), hash_type=hash_type)
                if hash_type == '18200':
                    username = line.split('$')[3].split(':')[0]
                else:
                    username = line.split('$')[3]
            elif file_type == 'NetNTLM':
                # First extracting usernames so we can filter out machine accounts
                # 5600, domain is case sensitve. Hashcat returns username in upper case.
                if re.search(r"\$$", line.split(':')[0]):
                #if '$' in line.split(':')[0]:
                    continue
                else:
                    # uppercase uesrname in line
                    line_list = line.split(':')
                    # uppercase the username in line
                    line_list[0] = line_list[0].upper()
                    # lowercase the rest (except domain name) 3,4,5
                    line_list[3] = line_list[3].lower()
                    line_list[4] = line_list[4].lower()
                    line_list[5] = line_list[5].lower()
                    line = ':'.join(line_list)
                    hash_id = import_hash_only(line=line.rstrip(), hash_type=hash_type)
                    username = line.split(':', maxsplit=1)[0]
            else:
                return False
            if username is None:
                hashfilehashes = HashfileHashes(hash_id=hash_id, hashfile_id=hashfile_id)
            else:
                hashfilehashes = HashfileHashes(hash_id=hash_id, username=text_from_field(username), hashfile_id=hashfile_id)
            db.session.add(hashfilehashes)
            db.session.commit()

    return True

def _generate_website_keywords(wordlist, job_id):
    """Populate the (DYNAMIC) Website Keywords wordlist by crawling the job URL.

    The crawl result is written to a randomly-named file under control/tmp and
    then atomically moved onto ``wordlist.path`` — so concurrent crawls never
    collide on a filename or leave a partially-written live file. If no job URL
    can be resolved (e.g. a manual UI refresh with no running job), the existing
    file is left untouched.
    """
    settings = Settings.query.first()
    job = Jobs.query.get(job_id) if job_id else None
    target = job.crawl_url if (job and job.crawl_url) else None
    if not target:
        current_app.logger.warning(
            'Website Keywords update with no job URL (job_id=%s); leaving wordlist %s unchanged.',
            job_id, wordlist.id)
        return

    from hashview.utils.crawler import crawl_website_keywords
    words = crawl_website_keywords(target, settings)

    tmp_path = os.path.join(current_app.root_path, 'control/tmp', secrets.token_hex(8) + '.txt')
    with open(tmp_path, 'w') as tmp:
        for word in sorted(words):
            tmp.write(word + '\n')
    # Atomic on the same filesystem (control/tmp and control/wordlists are
    # siblings); fall back to a copy+remove move across filesystems.
    try:
        os.replace(tmp_path, wordlist.path)
    except OSError:
        import shutil
        shutil.move(tmp_path, wordlist.path)


def update_dynamic_wordlist(wordlist_id, job_id=None):
    """Function to update dynamic wordlist.

    ``job_id`` (resolved server-side from the requesting agent's running job)
    is used by crawl-based wordlists to read the per-job target URL.
    """

    wordlist = Wordlists.query.get(wordlist_id)

    if 'Website' in wordlist.name:
        # Crawl-based: generate into a random tmp file + atomic replace.
        _generate_website_keywords(wordlist, job_id)
    else:
        # DB-derived dynamic wordlists: rewrite wordlist.path in place.
        # Usernames/plaintext are stored as text now; write them directly
        # (UTF-8). $HEX[...] values are valid hashcat wordlist entries too.
        file = open(wordlist.path, 'w', encoding='utf-8')
        if 'Passwords' in wordlist.name:
            plains = Hashes.query.filter_by(cracked=True).distinct('plaintext').with_entities(Hashes.plaintext)
            for entry in plains:
                if entry.plaintext is not None:
                    file.write(entry.plaintext + '\n')
        elif 'Usernames' in wordlist.name:
            usernames = HashfileHashes.query.distinct('username')
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
            customers = Customers.query.distinct('name')
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
    wordlist.last_updated = datetime.today()
    db.session.commit()

def hashtypes_in_use():
    """Set of distinct hash_type values currently present in the hashes table.

    This is the canonical "what do we actually need benchmarks for" set used by
    the heartbeat (benchmark-first) and the chunk planner — far smaller than the
    ~485 modes hashcat supports.
    """
    rows = db.session.query(Hashes.hash_type).distinct().all()
    return {row[0] for row in rows if row[0] is not None}


def dynamic_wordlist_ids():
    """Set of Wordlists.id whose type is 'dynamic' (stored lower-case)."""
    rows = db.session.query(Wordlists.id).filter(Wordlists.type == 'dynamic').all()
    return {row[0] for row in rows}


def slowest_benchmark(hash_type):
    """Smallest agent benchmark (hashes/sec) for ``hash_type``, or None.

    Chunk sizes are computed from the SLOWEST agent so the weakest hardware still
    finishes a chunk in roughly the target duration. Returns None when no agent
    has benchmarked this hash type yet (caller then runs the task whole).
    """
    return db.session.query(db.func.min(AgentBenchmarks.speed)) \
        .filter(AgentBenchmarks.hash_type == hash_type).scalar()


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


def build_hashcat_command(job_id, task_id, chunk=None, job_task_id=None):
    """Function to build the main hashcat cmd we use to crack.

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

    hc_binpath = '@HASHCATBINPATH@'
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

    # Build cmd
    cmd = hc_binpath
    cmd += ' -O -w 3'
    cmd += ' --session ' + session
    cmd += ' -m ' + str(hash_type)
    cmd += ' --potfile-path ' + potfile
    cmd += ' --status --status-timer=15'
    cmd += ' --outfile-format 1,3'
    cmd += ' --outfile ' + crack_file
    # Chunk slice for wordlist base-loop modes: restrict this run to a word range.
    is_chunk_slice = 'skip' in chunk and 'limit' in chunk
    if is_chunk_slice:
        cmd += ' --skip ' + str(chunk['skip']) + ' --limit ' + str(chunk['limit'])

    # Loopback only applies to straight mode (-a 0) with a rule; hashcat rejects
    # it for other attack modes. It is ALSO mutually exclusive with --limit, so a
    # chunked slice (which carries --skip/--limit above) must never add it — the
    # chunk runs as a plain dict+rules slice instead. The server-side gate also
    # means a task flipped away from dict+rules never emits a stray --loopback.
    if attackmode == 0 and isinstance(task.rule_id, int) and task.loopback and not is_chunk_slice:
        cmd += ' --loopback'

    # --hex-salt: the hashfile was marked as carrying hex-encoded salts. Gated on
    # a salted mode so we never pass it to an unsalted mode (hashcat would reject
    # it); the upload route only sets hex_salt for the hash_only / user_hash
    # formats, whose ciphertext keeps the colon-delimited salt hashcat parses.
    hashfile = Hashfiles.query.get(job.hashfile_id)
    if hashfile and hashfile.hex_salt and hash_type_uses_salt(hash_type):
        cmd += ' --hex-salt'

    # Dictionary with optional rules
    if attackmode == 0:
        if isinstance(task.rule_id, int):
            cmd += ' -r ' + relative_rules_path + ' ' + target_file + ' ' + relative_wordlist_path
        else:
            cmd += ' ' + target_file + ' ' + relative_wordlist_path
    # combinator
    elif attackmode == 1:
        if isinstance(task.j_rule, str):
            j_rule = " -j '" + task.j_rule + "' "
        else:
            j_rule = ' '
        
        if isinstance(task.k_rule, str):
            k_rule = " -k '" + task.k_rule + "' "
        else:
            k_rule = ' '
        cmd += ' ' + ' -a 1 ' + target_file + ' ' + relative_wordlist_path + j_rule + relative_wordlist_2_path + k_rule
    # maskmode
    elif attackmode == 3:
        cmd += ' ' + ' -a 3 ' + target_file + ' ' + mask
    # Hybrid (Wordlist + Mask)
    elif attackmode == 6:
        cmd += ' ' + ' -a 6 ' + target_file + ' ' + relative_wordlist_path + ' ' + mask
    elif attackmode == 7:
        cmd += ' ' + ' -a 7 ' + target_file + ' ' + mask + ' ' + relative_wordlist_path

    # Mask mode
    #if attackmode == 'bruteforce':
    #    cmd = hc_binpath + ' -O -w 3 ' + ' --session ' + session + ' -m ' + str(hash_type) + ' --potfile-disable' + ' --status --status-timer=15' + ' --outfile-format 1,3' + ' --outfile ' + crack_file + ' ' + ' -a 3 ' + target_file
    # elif attackmode == 'maskmode':
    #     cmd = hc_binpath + ' -O -w 3 ' + ' --session ' + session + ' -m ' + str(hash_type) + ' --potfile-disable' + ' --status --status-timer=15' + ' --outfile-format 1,3' + ' --outfile ' + crack_file + ' ' + ' -a 3 ' + target_file + ' ' + mask
    # elif attackmode == 'dictionary':
    #     if isinstance(task.rule_id, int):
    #         cmd = hc_binpath + ' -O -w 3 ' + ' --session ' + session + ' -m ' + str(hash_type) + ' --potfile-disable' + ' --status --status-timer=15' + ' --outfile-format 1,3' + ' --outfile ' + crack_file + ' ' + ' -r ' + relative_rules_path + ' ' + target_file + ' ' + relative_wordlist_path
    #     else:
    #         cmd = hc_binpath + ' -O -w 3 ' + ' --session ' + session + ' -m ' + str(hash_type) + ' --potfile-disable' + ' --status --status-timer=15' + ' --outfile-format 1,3' + ' --outfile ' + crack_file + ' ' + target_file + ' ' + relative_wordlist_path
    # elif attackmode == 'combinator':
    #   cmd = hc_binpath + ' -O -w 3 ' + ' --session ' + session + ' -m ' + str(hash_type) + ' --potfile-disable' + ' --status --status-timer=15' + ' --outfile-format 1,3' + ' --outfile ' + crack_file + ' ' + ' -a 1 ' + target_file + ' ' + wordlist_one.path + ' ' + ' ' + wordlist_two.path + ' ' + relative_rules_path

    return cmd

def _chunk_spec_from_row(job_task):
    """Reconstruct a chunk spec dict from a JobTasks row's stored slice."""
    if job_task.chunk_skip is not None and job_task.chunk_limit is not None:
        return {'skip': job_task.chunk_skip, 'limit': job_task.chunk_limit}
    if job_task.chunk_mask:
        return {'mask': job_task.chunk_mask}
    return {}


def _job_hash_type(job):
    """Derive the job's hash type the same way build_hashcat_command does."""
    hfh = HashfileHashes.query.filter_by(hashfile_id=job.hashfile_id).first()
    if not hfh:
        return None
    h = Hashes.query.get(hfh.hash_id)
    return h.hash_type if h else None


def _set_job_task_command(job, row, spec, chunk_no=None, chunk_total=None):
    """Stamp a JobTasks row with its queue state, chunk slice, and built command."""
    row.status = 'Queued'
    row.priority = job.priority
    row.chunk_no = chunk_no
    row.chunk_total = chunk_total
    row.chunk_skip = spec.get('skip')
    row.chunk_limit = spec.get('limit')
    row.chunk_mask = spec.get('mask')
    # Whole (un-chunked) tasks keep the legacy job+task temp-file naming so
    # existing agents keep working without an upgrade; only chunks need the
    # per-jobtask naming to avoid collisions between chunks of the same task.
    job_task_id = row.id if chunk_total else None
    row.command = build_hashcat_command(job.id, row.task_id, chunk=spec, job_task_id=job_task_id)


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

    # Re-queue: already chunked once -> rebuild from each row's stored slice.
    if any(row.chunk_total for row in rows):
        for row in rows:
            _set_job_task_command(job, row, _chunk_spec_from_row(row),
                                  chunk_no=row.chunk_no, chunk_total=row.chunk_total)
        return

    settings = Settings.query.first()
    chunking_on = bool(settings and settings.enabled_chunking)
    target_seconds = (settings.chunk_target_duration
                      if settings and settings.chunk_target_duration else 3600)
    dynamic_ids = dynamic_wordlist_ids() if chunking_on else set()
    hash_type = _job_hash_type(job) if chunking_on else None

    for job_task in rows:
        task = Tasks.query.get(job_task.task_id)
        specs = [{}]
        if (chunking_on and task is not None and is_chunkable(
                task.hc_attackmode, task.wl_id, task.wl_id_2, dynamic_ids)):
            wl = Wordlists.query.get(task.wl_id) if task.wl_id else None
            wl2 = Wordlists.query.get(task.wl_id_2) if task.wl_id_2 else None
            rule = Rules.query.get(task.rule_id) if task.rule_id else None
            specs = plan_chunks(
                task.hc_attackmode,
                wordlist_size=(wl.size if wl else None),
                wordlist2_size=(wl2.size if wl2 else None),
                rule_count=(rule.size if rule else 0),
                mask=task.hc_mask,
                slowest_speed=(slowest_benchmark(hash_type) if hash_type is not None else None),
                target_seconds=target_seconds,
            )

        total = len(specs)
        for idx, spec in enumerate(specs):
            if idx == 0:
                row = job_task
            else:
                row = JobTasks(job_id=job.id, task_id=job_task.task_id, status='Queued')
                db.session.add(row)
                db.session.flush()   # assign row.id so per-chunk file names are unique
            if total > 1:
                _set_job_task_command(job, row, spec, chunk_no=idx + 1, chunk_total=total)
            else:
                _set_job_task_command(job, row, spec)


def rechunk_queued_tasks_for_hashtype(hash_type):
    """Split still-queued whole tasks of `hash_type` now that a benchmark exists.

    Chunk plans are built at queue time from the benchmarks available THEN. If a
    job is queued for a brand-new hash type while every agent is busy, no
    benchmark exists yet and its tasks fall back to whole (un-chunked) runs. Once
    the first benchmark for that hash type lands (agent goes idle -> BENCHMARK ->
    reports), this re-plans any of those tasks that are still safe to split:
    status 'Queued', no agent assigned, not already chunked. Tasks already picked
    up by an agent are left alone. Preserves the queue-built-upfront model.
    """
    settings = Settings.query.first()
    if not (settings and settings.enabled_chunking):
        return
    slowest = slowest_benchmark(hash_type)
    if not slowest:
        return
    target_seconds = (settings.chunk_target_duration
                      if settings.chunk_target_duration else 3600)
    dynamic_ids = dynamic_wordlist_ids()

    candidates = (JobTasks.query
                  .filter(JobTasks.status == 'Queued',
                          JobTasks.agent_id.is_(None),
                          JobTasks.chunk_total.is_(None))
                  .all())
    changed = False
    for jt in candidates:
        # Re-check the row is still safe to re-plan (an agent may have grabbed it
        # between the query and now); skip if it was taken.
        if jt.status != 'Queued' or jt.agent_id is not None or jt.chunk_total is not None:
            continue
        job = Jobs.query.get(jt.job_id)
        if job is None or job.status not in ('Queued', 'Running'):
            continue
        if _job_hash_type(job) != hash_type:
            continue
        task = Tasks.query.get(jt.task_id)
        if task is None or not is_chunkable(
                task.hc_attackmode, task.wl_id, task.wl_id_2, dynamic_ids):
            continue
        wl = Wordlists.query.get(task.wl_id) if task.wl_id else None
        wl2 = Wordlists.query.get(task.wl_id_2) if task.wl_id_2 else None
        rule = Rules.query.get(task.rule_id) if task.rule_id else None
        specs = plan_chunks(
            task.hc_attackmode,
            wordlist_size=(wl.size if wl else None),
            wordlist2_size=(wl2.size if wl2 else None),
            rule_count=(rule.size if rule else 0),
            mask=task.hc_mask,
            slowest_speed=slowest,
            target_seconds=target_seconds,
        )
        if len(specs) <= 1:
            continue  # still not worth splitting at this speed/size

        total = len(specs)
        for idx, spec in enumerate(specs):
            if idx == 0:
                row = jt                                   # reuse the whole row as chunk 1
            else:
                row = JobTasks(job_id=jt.job_id, task_id=jt.task_id, status='Queued')
                db.session.add(row)
                db.session.flush()
            _set_job_task_command(job, row, spec, chunk_no=idx + 1, chunk_total=total)
        changed = True

    if changed:
        db.session.commit()


def update_job_task_status(jobtask_id, status):
    """Function to update task status of a job"""

    jobtask = JobTasks.query.get(jobtask_id)

    if jobtask is None:
        return False

    jobtask.status = status
    if status == 'Completed' or status == 'Canceled':
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

    # Update Jobs
    # TODO
    # Shouldn't we be changing the job stats to match the jobtask status?
    # Add started at time
    job = Jobs.query.get(jobtask.job_id)
    if job.status == 'Queued':
        job.status = 'Running'
        job.started_at = datetime.now()
        db.session.commit()

    # TODO
    # This is such a janky way of doing this. Instead of having the agent tell us its done, we're just assuming
    # That if no other tasks are active we must be done
    done = True
    jobtasks = JobTasks.query.filter_by(job_id=job.id).all()
    for jobtask in jobtasks:
        if jobtask.status == 'Queued' or jobtask.status == 'Running' or jobtask.status == 'Importing':
            done = False

    if done:
        job.status = 'Completed'
        job.ended_at = datetime.now()
        db.session.commit()

        start_time = job.started_at          # DateTime columns are already datetime objects
        end_time = job.ended_at
        durration = abs(end_time - start_time).seconds if (start_time and end_time) else 0  # So dumb you cant conver this to minutes, only resolution is seconds or days :(

        hashfile = Hashfiles.query.get(job.hashfile_id)
        hashfile.runtime += durration
        db.session.commit()

        # TODO
        # mark all jobtasks as completed
        job_notifications = JobNotifications.query.filter_by(job_id = job.id)

        # Send Notifications
        for job_notification in job_notifications:
            user = Users.query.get(job_notification.owner_id)
            cracked_cnt = db.session.query(Hashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '1').filter(HashfileHashes.hashfile_id==job.hashfile_id).count()
            uncracked_cnt = db.session.query(Hashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '0').filter(HashfileHashes.hashfile_id==job.hashfile_id).count()
            subject = 'Hashview Job: "' + job.name + '" Has Completed!'
            plain = ('Your job "' + job.name + '" has completed. It ran for ' + getTimeFormat(durration)
                     + ' and recovered ' + str(cracked_cnt) + ' out of ' + str(cracked_cnt + uncracked_cnt) + ' hashes.')
            html = ('Your job has completed. It ran for ' + getTimeFormat(durration) + ' and resulted in a total of '
                    + str(cracked_cnt) + ' out of ' + str(cracked_cnt + uncracked_cnt) + ' hashes being recovered!'
                    + ' <br /><br /> <a href="' + url_for('analytics.get_analytics', customer_id=job.customer_id, hashfile_id=job.hashfile_id, _external=True) + '">View Analytics</a>')
            deliver_user_notification(user, job_notification.method, subject, plain, html_message=html)
            db.session.delete(job_notification)
            db.session.commit()

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

    Centralises shared robustness: safe decoding (latin-1 never raises on
    binary/garbage uploads), streaming (no whole-file load into memory),
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
_KERBEROS_RE = {
    '7500':  re.compile(r'^\$krb5pa\$23\$[^$]+\$[^$]*\$[^$]*\$[0-9a-fA-F]+$'),
    '13100': re.compile(r'^\$krb5tgs\$23\$\*.+\*\$[0-9a-fA-F]{32}\$[0-9a-fA-F]+$'),
    '18200': re.compile(r'^\$krb5asrep\$23\$[^:]+:[0-9a-fA-F]{32}\$[0-9a-fA-F]+$'),
    '19600': re.compile(r'^\$krb5tgs\$17\$[^$]+\$[^$]+\$[0-9a-fA-F]{24}\$[0-9a-fA-F]+$'),
    '19700': re.compile(r'^\$krb5tgs\$18\$[^$]+\$[^$]+\$[0-9a-fA-F]{24}\$[0-9a-fA-F]+$'),
    '19800': re.compile(r'^\$krb5pa\$17\$[^$]+\$[^$]+\$[0-9a-fA-F]{112}$'),
    '19900': re.compile(r'^\$krb5pa\$18\$[^$]+\$[^$]+\$[0-9a-fA-F]{112}$'),
    '28800': re.compile(r'^\$krb5db\$17\$[^$]+\$[^$]+\$[0-9a-fA-F]+$'),
    '28900': re.compile(r'^\$krb5db\$18\$[^$]+\$[^$]+\$[0-9a-fA-F]+$'),
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
