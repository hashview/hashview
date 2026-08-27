import os
import secrets

from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy

from hashview.models import Hashes, HashfileHashes, Rules, Settings, Tasks, Users, Wordlists
from hashview.utils.utils import (
    bytes_to_text,
    compress_to_gz,
    dynamic_password_length_wordlists,
    get_filehash,
    get_filesize,
    get_linecount,
    is_gzip,
)

DEFAULT_PASSWORD = 'hashview'


def default_tasks_need_added(db :SQLAlchemy) -> bool:
    return (0 == db.session.query(Tasks).count())


def add_default_tasks(db :SQLAlchemy):
    task = Tasks(
        name          = 'Rockyou Wordlist',
        owner_id      = '1',
        wl_id         = '2',
        rule_id       = None,
        hc_attackmode = 0,
    )
    db.session.add(task)

    task = Tasks(
        name          = 'Rockyou Wordlist + Best64 Rules',
        owner_id      = '1',
        wl_id         = '3',
        rule_id       = '1',
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
    os.system('gzip -d -k install/best64.rule.gz')
    rules_path = 'hashview/control/rules/best64.rule'
    os.replace('install/best64.rule', rules_path)
    rule = Rules(
        name     = 'Best64 Rule',
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
    os.system('gzip -d -k install/rockyou.txt.gz')
    wordlist_path = 'hashview/control/wordlists/rockyou.txt'
    os.replace('install/rockyou.txt', wordlist_path)
    wordlist = Wordlists(
        name     = 'Rockyou.txt',
        owner_id = 1,
        type     = 'static',
        path     = wordlist_path,                # Can we make this a relative path?
        checksum = get_filehash(wordlist_path),
        size     = get_linecount(wordlist_path),
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
    """
    from flask import current_app
    logger = current_app.logger
    wordlists_dir = os.path.join(current_app.root_path, 'control/wordlists')

    def _resolve(path):
        """Locate a wordlist file, tolerating a relative/legacy stored path.
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
                # from backfilling byte_size if it was never recorded.
                if wordlist.byte_size is None:
                    wordlist.byte_size = get_filesize(resolved)
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
    from flask import current_app
    logger = current_app.logger

    settings = Settings.query.first()
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
    # Recovered passwords split into fixed length buckets (0-5, 6..8, 9+).
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
    startup. The previous implementation always inserted all four rows,
    which is why the gate had to be all-or-nothing.
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
    from flask import current_app, has_app_context
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
    settings = db.session.query(Settings).first()
    return settings is None
