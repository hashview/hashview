import os
import secrets
import shutil

from flask import current_app
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy

from hashview.models import Hashes, HashfileHashes, Rules, Settings, Tasks, Users, Wordlists
from hashview.utils.utils import (
    bytes_to_text,
    compress_to_gz,
    decompress_gz,
    dynamic_password_length_wordlists,
    get_filehash,
    get_filesize,
    get_linecount,
    gz_linecount,
    is_gzip,
)

# The seed files shipped in the install tree. Resolved relative to the REPO ROOT
# (the parent of the Flask app's root_path), not the process CWD: spelled bare,
# 'install/rockyou.txt.gz' only resolves when the server happens to have been
# started from the repo root, an implicit requirement nothing states or
# enforces. The bare spelling stays as a fallback so any layout that worked
# before still works.
SEED_WORDLIST_GZ = 'install/rockyou.txt.gz'
SEED_RULE_GZ = 'install/best64.rule.gz'

# The names those two seeds are stored under. They are how add_default_tasks
# finds them, so they live in one place: a rename here that did not reach the
# lookup would leave the starter tasks silently pointing at nothing, which is a
# quieter version of the bug that made this a constant (#396).
ROCKYOU_WORDLIST_NAME = 'Rockyou.txt'
BEST64_RULE_NAME = 'Best64 Rule'


def _seed_source(relative_path):
    """Absolute path to a shipped seed file, falling back to the bare path."""
    candidate = os.path.join(os.path.dirname(current_app.root_path), relative_path)
    return candidate if os.path.exists(candidate) else relative_path


def _control_dir(name):
    """Absolute path to control/<name>, created if it isn't there yet.

    Always derived from app.root_path, never from the CWD, so the seeded file
    lands where the download route serves from -- it serves by basename out of
    this directory.
    """
    path = os.path.join(current_app.root_path, 'control', name)
    os.makedirs(path, exist_ok=True)
    return path

# Bumped when the recomputation logic for backfilled `.size` values changes, so
# a fixed-but-still-wrong backfill can be re-run once against installs that
# already have the (stale) marker from an earlier version of this pass.
LINECOUNT_BACKFILL_MARKER = '.linecount_backfill_v1_done'

DEFAULT_PASSWORD = 'hashview'


def default_tasks_need_added(db :SQLAlchemy) -> bool:
    return (0 == db.session.query(Tasks).count())


def add_default_tasks(db :SQLAlchemy):
    """Seed the three starter tasks, resolving their wordlist and rule BY NAME.

    The ids used to be written in as literals -- wl_id '2' and '3', rule_id '1'
    -- which were right when three dynamic wordlists were seeded ahead of
    Rockyou and have not been right since. _DYNAMIC_WORDLISTS yields NINE rows
    today (four canonical plus five length buckets), so Rockyou lands at id 10
    and the two tasks named after it pointed at "(DYNAMIC) All Usernames" and
    "(DYNAMIC) All Customers" instead (#396). Those are empty placeholders on a
    fresh install, so the first thing a new user is invited to run finished
    successfully having tried nothing at all -- and said so.

    A name is the only thing here that is actually stable. The insert order is
    not, nothing enforced it, and the count it depended on has changed twice.

    All-or-nothing on purpose. Seeding the wordlist and the rule is best-effort
    (both are wrapped in try/except by the caller), so either can be absent.
    default_tasks_need_added asks whether ANY task exists, so seeding just the
    mask task here would close that gate forever and the two that matter would
    never arrive. Adding none leaves the gate open for a later boot to finish
    the job, and says why in the log each time.
    """
    rockyou = db.session.query(Wordlists).filter_by(
        name=ROCKYOU_WORDLIST_NAME).first()
    best64 = db.session.query(Rules).filter_by(name=BEST64_RULE_NAME).first()
    if rockyou is None or best64 is None:
        missing = ', '.join(
            name for name, row in ((ROCKYOU_WORDLIST_NAME, rockyou),
                                   (BEST64_RULE_NAME, best64)) if row is None)
        current_app.logger.warning(
            'Default tasks not seeded: %s missing. They will be retried on the '
            'next startup once it exists.', missing)
        return

    task = Tasks(
        name          = 'Rockyou Wordlist',
        owner_id      = '1',
        wl_id         = rockyou.id,
        rule_id       = None,
        hc_attackmode = 0,
    )
    db.session.add(task)

    task = Tasks(
        name          = 'Rockyou Wordlist + Best64 Rules',
        owner_id      = '1',
        wl_id         = rockyou.id,
        rule_id       = best64.id,
        hc_attackmode = 0,
    )
    db.session.add(task)

    # mask mode of all 8 characters
    task = Tasks(
        name          = '?a?a?a?a?a?a?a?a [8]',
        owner_id      = '1',
        wl_id         = None,
        rule_id       = None,
        hc_attackmode = 3,
        hc_mask       = '?a?a?a?a?a?a?a?a',
    )
    db.session.add(task)

    db.session.commit()


def default_rules_need_added(db :SQLAlchemy) -> bool:
    return (0 == db.session.query(Rules).count())


def add_default_rules(db :SQLAlchemy):
    """Seed the Best64 rule from the shipped install/best64.rule.gz.

    Decompressed in-process (utils.decompress_gz -- gzip.open, streamed) STRAIGHT
    into control/rules. What this replaces failed two different ways (#395):

      * `os.system('gzip -d -k ...')` threw its exit status away, so a missing
        gzip binary, or gzip refusing because the output already existed from a
        half-finished earlier boot, was indistinguishable from success. The next
        line then raised FileNotFoundError, which the caller swallows and logs
        identically to every other failure.
      * `os.replace` is a rename, and a rename cannot cross a filesystem
        boundary. Mount control/ as a volume -- which is the recommended fix for
        the data loss in #383 -- and install/ and control/ are on different
        devices, so seeding died with EXDEV on the first boot and on every boot
        after it, since the "do I need this?" predicate stays True.

    Writing to the destination removes the rename entirely: nothing crosses a
    device, and no decompressed copy is left behind in install/ for the next
    boot to trip over. Rules stay plaintext at rest, unlike wordlists.

    The stored path is absolute, matching what rules_add records for an uploaded
    rule; the relative one this used to write only resolved while the process
    CWD happened to be the repo root.
    """
    rules_path = os.path.join(_control_dir('rules'), 'best64.rule')
    decompress_gz(_seed_source(SEED_RULE_GZ), rules_path)
    rule = Rules(
        name     = BEST64_RULE_NAME,
        owner_id = 1,
        path     = rules_path,
        checksum = get_filehash(rules_path),
        size     = get_linecount(rules_path),
    )
    db.session.add(rule)
    db.session.commit()


def default_static_wordlist_need_added(db :SQLAlchemy) -> bool:
    return (0 == db.session.query(Wordlists).filter_by(type='static').count())


def add_default_static_wordlist(db :SQLAlchemy):
    """Seed Rockyou from the shipped install/rockyou.txt.gz, left COMPRESSED.

    Static wordlists are stored gzip-at-rest under a '<hex>.gz' name, so the
    shipped archive is copied into the wordlists dir as-is rather than unpacked.
    The old form decompressed 53 MB into 130 MB of plaintext, renamed it across
    directories, and then compress_existing_wordlists_if_needed -- which runs a
    few lines later on the very same boot -- compressed it straight back at
    gzip -9. Copying the bytes skips a decompress and a recompress of the
    largest file the installer touches, and lands the row in its final shape, so
    that pass has nothing left to do but confirm it.

    Same two failure modes fixed as in add_default_rules (#395): no shell, so no
    discarded exit status, and no rename, so no EXDEV when control/ is a mount.

    The DB row is written exactly as the compression pass would have left it --
    absolute '<hex>.gz' path, checksum over the COMPRESSED file (the contract
    the agent verifies after downloading it), line count of the decompressed
    text, byte_size of what is on disk -- because anything else would be
    silently re-derived, or worse, left inconsistent with every other wordlist.
    """
    wordlist_path = os.path.join(_control_dir('wordlists'),
                                 secrets.token_hex(8) + '.gz')
    with open(_seed_source(SEED_WORDLIST_GZ), 'rb') as src, \
            open(wordlist_path, 'wb') as dst:
        shutil.copyfileobj(src, dst)
    wordlist = Wordlists(
        name      = ROCKYOU_WORDLIST_NAME,
        owner_id  = 1,
        type      = 'static',
        path      = wordlist_path,
        checksum  = get_filehash(wordlist_path),   # sha256 of the .gz
        size      = gz_linecount(wordlist_path),   # lines of decompressed text
        byte_size = get_filesize(wordlist_path),
    )
    db.session.add(wordlist)
    db.session.commit()


def compress_existing_wordlists_if_needed(db :SQLAlchemy):
    """One-time-per-row migration to compressed-at-rest wordlist storage.

    Wordlists are now stored gzip-compressed (gzip -9). Installs that predate
    this change have uncompressed static wordlists on disk; this brings them
    in line on startup:

      - static + not gzip  -> compress to '<hex>.gz', set checksum = sha256 of
        the COMPRESSED file (the contract the agent verifies), recompute the
        line count with the SAME semantics as before (no drift), record
        byte_size, commit, THEN delete the old plaintext (write->commit->delete
        is crash-safe). The default Rockyou.txt seeded just before this runs is
        compressed by this same pass.
      - static + already gzip -> idempotent skip; only backfill byte_size if NULL.
      - dynamic -> never compressed (kept uncompressed on the server); only
        backfill byte_size if NULL.

    Also self-heals path drift from older installs: a wordlist.path may be
    RELATIVE (e.g. 'hashview/control/wordlists/<hex>.gz'), which only resolves
    when the process CWD happens to be the repo root. Such a path is normalized
    to its absolute on-disk location, and newly-compressed files are written
    into the absolute wordlists dir (never derived from a possibly-relative
    dirname), so a wordlist can't get stranded where the download route -- which
    serves by basename from the wordlists dir -- can't find it.

    Idempotent (the gzip magic-byte check makes re-runs no-ops) and resilient:
    each row is handled in its own try/except with a per-row commit, a truly
    missing file is logged and skipped (never deletes the DB row), and any
    failure is contained so it can never abort startup.

    Also does a ONE-TIME backfill (#435) of `.size` for rows whose stored
    line count was computed with the old off-by-one get_linecount/gz_linecount
    (which always added 1, even for newline-terminated files). This can't be a
    migration -- reaching the wordlist/rule files on disk needs an app context
    and real paths, which Alembic doesn't have -- so it rides this same
    startup pass instead:
      - static + already gzip: recompute `.size` from the existing .gz via
        gz_linecount (previously this branch only backfilled byte_size).
      - Rules: recompute `.size` from the rule file via get_linecount.
    Recomputing from the actual file (rather than blindly subtracting 1) is
    correct for both terminated and unterminated files. Guarded by a marker
    file in the wordlists dir so a 14M-line rockyou.txt.gz is only ever
    re-counted once, not on every boot.
    """
    logger = current_app.logger
    wordlists_dir = os.path.join(current_app.root_path, 'control/wordlists')
    linecount_backfill_marker = os.path.join(wordlists_dir, LINECOUNT_BACKFILL_MARKER)
    needs_linecount_backfill = not os.path.exists(linecount_backfill_marker)

    def _resolve(path):
        """Locate a wordlist file, tolerating a relative/legacy stored path.

        Deliberately NOT utils.resolve_control_file: this one is for RELOCATION
        (find a stray file so it can be normalized into the canonical dir), so
        its fallback to the path as-stored is load-bearing. resolve_control_file
        is the detection counterpart and is basename-confined on purpose.
        Prefer the canonical wordlists dir (where the download route serves
        from); fall back to the path as-stored. Returns an absolute path, or
        None when the file genuinely can't be found."""
        if not path:
            return None
        for cand in (os.path.join(wordlists_dir, os.path.basename(path)), path):
            if os.path.exists(cand):
                return os.path.abspath(cand)
        return None

    for wordlist in db.session.query(Wordlists).all():
        try:
            resolved = _resolve(wordlist.path)
            if resolved is None:
                logger.warning('Wordlist %s file not found (path=%s); leaving the DB row '
                               'untouched. Re-upload the wordlist to restore it.',
                               wordlist.id, wordlist.path)
                continue

            # Normalize a relative/legacy path to the absolute on-disk location so
            # the download route and cracking commands find it regardless of the
            # process CWD.
            if wordlist.path != resolved:
                logger.info('Normalized wordlist %s path %r -> %r', wordlist.id, wordlist.path, resolved)
                wordlist.path = resolved
                db.session.commit()

            if wordlist.type == 'dynamic':
                # Dynamic wordlists stay uncompressed; just backfill byte_size.
                if wordlist.byte_size is None:
                    wordlist.byte_size = get_filesize(resolved)
                    db.session.commit()
                continue

            # static
            if is_gzip(resolved):
                # Already compressed (new uploads, or a prior run). No-op aside
                # from backfilling byte_size if it was never recorded, and the
                # one-time #435 line-count recompute below.
                changed = False
                if wordlist.byte_size is None:
                    wordlist.byte_size = get_filesize(resolved)
                    changed = True
                if needs_linecount_backfill:
                    wordlist.size = gz_linecount(resolved)
                    changed = True
                if changed:
                    db.session.commit()
                continue

            # static + uncompressed: compress into the absolute wordlists dir (so
            # the file always lands where the download route serves from) and
            # store an absolute path.
            line_count = get_linecount(resolved)
            new_gz = os.path.join(wordlists_dir, secrets.token_hex(8) + '.gz')
            compress_to_gz(resolved, new_gz, 9)

            # write -> commit -> delete: only remove the old plaintext after the
            # new path/checksum are durably committed.
            wordlist.path = new_gz
            wordlist.size = line_count
            wordlist.checksum = get_filehash(new_gz)     # sha256 of the .gz
            wordlist.byte_size = get_filesize(new_gz)
            db.session.commit()

            if os.path.exists(resolved) and os.path.abspath(resolved) != os.path.abspath(new_gz):
                os.remove(resolved)
            logger.info('Compressed static wordlist %s -> %s', wordlist.id, new_gz)
        except Exception:
            db.session.rollback()
            logger.exception('Failed to process wordlist %s; leaving it untouched.', getattr(wordlist, 'id', '?'))

    if needs_linecount_backfill:
        for rule in db.session.query(Rules).all():
            try:
                if not rule.path or not os.path.exists(rule.path):
                    logger.warning('Rule %s file not found (path=%s); leaving the DB row '
                                   'untouched.', rule.id, rule.path)
                    continue
                rule.size = get_linecount(rule.path)
                db.session.commit()
            except Exception:
                db.session.rollback()
                logger.exception('Failed to recompute line count for rule %s; leaving it untouched.',
                                 getattr(rule, 'id', '?'))

        # Mark the one-time #435 line-count backfill done so a 14M-line
        # rockyou.txt.gz (or a large rule file) isn't re-counted on every boot.
        try:
            os.makedirs(wordlists_dir, exist_ok=True)
            with open(linecount_backfill_marker, 'w') as fh:
                fh.write('done')
        except OSError:
            logger.exception('Failed to write line-count backfill marker %s; the backfill '
                             'may re-run on next startup.', linecount_backfill_marker)


def _decode_hex_column(db, model, col_name, logger):
    """Page through `model` by id, decoding the hex-stored `col_name` to text
    (UTF-8, or $HEX[...] for non-UTF-8 bytes). Commits per page so a very large
    table doesn't load into memory or hold one giant transaction. Values that
    aren't valid hex (already text) are left untouched."""
    col = getattr(model, col_name)
    max_len = getattr(col.type, 'length', None)   # VARCHAR(n) limit, if any
    last_id = 0
    converted = 0
    while True:
        rows = (db.session.query(model)
                .filter(model.id > last_id, col.isnot(None))
                .order_by(model.id).limit(2000).all())
        if not rows:
            break
        for row in rows:
            last_id = row.id
            value = getattr(row, col_name)
            try:
                decoded = bytes_to_text(bytes.fromhex(value))
            except (ValueError, TypeError):
                continue                      # already text / not hex -> leave it
            if decoded == value:
                continue
            # A non-UTF-8 value becomes $HEX[...] (6 + 2*nbytes chars), which can
            # outgrow the column. Leave the original hex rather than overflow the
            # column (MySQL strict mode would 1406 and stall the whole one-time
            # backfill in a retry loop) -- no crash, no data loss.
            if max_len is not None and len(decoded) > max_len:
                logger.warning('Leaving %s.%s id=%s hex-encoded: decoded value (%d chars) '
                               'exceeds column limit %d.', model.__tablename__, col_name,
                               row.id, len(decoded), max_len)
                continue
            setattr(row, col_name, decoded)
            converted += 1
        db.session.commit()
    return converted


def decode_legacy_hex_if_needed(db :SQLAlchemy):
    """One-time conversion of legacy hex-encoded usernames + plaintext to text.

    These columns used to hold latin-1 (usernames / manual NTLM) or raw-bytes
    (agent hex_plain) hex; they're now stored as plain UTF-8 text ($HEX[...] for
    non-UTF-8). This decodes every existing row once. Gated by
    ``Settings.passwords_decoded`` (migration sets existing rows to False -> run;
    fresh installs default True -> skip). The flag is set only after a full pass,
    so a crash re-runs; the per-page commits make progress durable and the
    not-valid-hex guard makes re-runs largely a no-op on already-decoded rows."""
    logger = current_app.logger

    settings = Settings.current()
    if not settings or settings.passwords_decoded:
        return

    logger.info('Decoding legacy hex usernames/plaintext to text (one-time)...')
    n_users = _decode_hex_column(db, HashfileHashes, 'username', logger)
    n_plain = _decode_hex_column(db, Hashes, 'plaintext', logger)
    settings.passwords_decoded = True
    db.session.commit()
    logger.info('Legacy hex decode complete: %s usernames, %s plaintext converted.', n_users, n_plain)


# The canonical dynamic wordlists. Order matters only for the seed-file
# layout; the dispatcher in hashview/utils/utils.py:update_dynamic_wordlist
# routes by substring (Passwords/Usernames/Customers/NTLM).
_DYNAMIC_WORDLISTS = (
    ('(DYNAMIC) All Recovered Passwords', 'hashview/control/wordlists/dynamic-all.txt'),
    ('(DYNAMIC) All Usernames',           'hashview/control/wordlists/dynamic-usernames.txt'),
    ('(DYNAMIC) All Customers',           'hashview/control/wordlists/dynamic-customers.txt'),
    ('(DYNAMIC) All NTLM Hashes',         'hashview/control/wordlists/dynamic-ntlm.txt'),
    # Recovered passwords split into fixed length buckets (0-5, 6, 7, 8, 9+).
    *dynamic_password_length_wordlists(),
)


def default_dynamic_wordlists_need_added(db :SQLAlchemy) -> bool:
    """True when any of the canonical (DYNAMIC) wordlists is missing.

    Replaces the previous all-or-nothing gate (count==0) so existing
    installs that already have the older 3 dynamic wordlists still get the
    new "(DYNAMIC) All NTLM Hashes" entry on next startup.
    """
    wanted = {name for name, _ in _DYNAMIC_WORDLISTS}
    present = {
        w.name for w in
        db.session.query(Wordlists).filter(Wordlists.name.in_(wanted)).all()
    }
    return bool(wanted - present)


def add_default_dynamic_wordlists(db :SQLAlchemy):
    """Ensure each canonical (DYNAMIC) wordlist exists; idempotent per name.

    Skips entries that are already in the DB so this can run safely on every
    startup. The previous implementation always inserted every row, which is why
    the gate had to be all-or-nothing.

    How many rows that is has changed twice and will change again:
    _DYNAMIC_WORDLISTS is four literal entries plus however many
    dynamic_password_length_wordlists() yields (five today). Nothing downstream
    may depend on the count, or on the ids these take -- see add_default_tasks
    for what happened when something did (#396).
    """
    for name, path in _DYNAMIC_WORDLISTS:
        if db.session.query(Wordlists).filter_by(name=name).first() is not None:
            continue
        # 'w' opens for writing and truncates — fine for a placeholder seed.
        with open(path, mode='w'):
            pass
        db.session.add(Wordlists(
            name     = name,
            owner_id = 1,
            type     = 'dynamic',
            path     = path,
            checksum = get_filehash(path),
            size     = 0,
        ))
    db.session.commit()


def admin_user_needs_added(db :SQLAlchemy) -> bool:
    return (0 >= db.session.query(Users).filter_by(admin=True).count())


def add_admin_user(db :SQLAlchemy, bcrypt :Bcrypt):
    default_password_hash = bcrypt.generate_password_hash(DEFAULT_PASSWORD).decode('utf-8')
    user = Users(
        first_name    = 'admin',
        last_name     = 'user',
        email_address = '',
        password      = default_password_hash,
        admin         = True,
    )
    db.session.add(user)
    db.session.commit()


def admin_pass_needs_changed(db :SQLAlchemy, bcrypt :Bcrypt) -> bool:
    result = db.session.query(Users.password).filter_by(id=1).first()
    if result is None:
        return True
    current_password_hash, *_ = result

    # bcrypt.check_password_hash runs a full cost-12 KDF (~250ms of CPU). This gate
    # fires on every non-static request (it is wired as a before_request hook), so
    # cache the verdict keyed on the stored admin hash and only re-run the KDF when
    # that hash actually changes (i.e. the admin password was changed). Keying on
    # the hash value means no explicit cache invalidation is needed and every
    # transition (default -> changed -> default) stays correct. Cached on app
    # config so it never leaks across app instances (tests) or worker processes.
    from flask import has_app_context
    app = current_app._get_current_object() if has_app_context() else None
    if app is not None:
        cached = app.config.get('_ADMIN_PASS_DEFAULT_CACHE')
        if cached is not None and cached[0] == current_password_hash:
            return cached[1]

    needs_changed = bool(bcrypt.check_password_hash(current_password_hash, DEFAULT_PASSWORD))
    if app is not None:
        app.config['_ADMIN_PASS_DEFAULT_CACHE'] = (current_password_hash, needs_changed)
    return needs_changed


def settings_needs_added(db :SQLAlchemy) -> bool:
    settings = Settings.current()
    return settings is None
