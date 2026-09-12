"""Function file to scheduler"""
from functools import partial
from logging import Logger

from flask import Flask, current_app
from flask_apscheduler import APScheduler
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy

scheduler = APScheduler()


def try_send_email(user, subject :str, plaintext_body :str, mailer :Mail) -> bool:
    """ try to send an email, returning an error message on failure """

    error = 'unknown error'
    try:
        error = f"failed to get user's email address from user: {user!r}"
        address = user.email_address

        error = f"failed to create message from: {subject} | {address} | {plaintext_body}"
        message = Message(
            subject    = subject,
            recipients = [ address, ],
            body       = plaintext_body,
        )

        error = f"failed to send message with mailer: {mailer!r}"
        mailer.send(message)

    except Exception:
        return error

    return None


# Retention deletes are committed in batches of this many rows.
#
# The point is not throughput, it is lock scope and duration. Deleting one
# hashfile used to be a single transaction: one
# `DELETE FROM hashfile_hashes WHERE hashfile_id = ?` plus every orphaned `hashes`
# row, committed once at the end.
#
# ix_hashfile_hashes_hashfile_id holds only 6 distinct values across ~1M rows, so
# for a large hashfile the optimizer abandons it. Measured with EXPLAIN on
# production data:
#
#   hashfile 10   691,589 rows (67.2% of the table)   type=ALL    key=NULL
#   hashfile 2    302,654 rows (29.4%)                type=ALL    key=NULL
#   hashfile 9     34,447 rows ( 3.3%)                type=range  key=...hashfile_id
#
# type=ALL is a full table scan, so under REPEATABLE-READ that DELETE takes
# next-key locks on EVERY row in hashfile_hashes -- including rows belonging to
# hashfiles nobody is purging. Concurrent inserts anywhere in the table block,
# which is exactly what an agent uploading cracked hashes does.
#
# Everything else then queued behind it. A blocked query holds its pooled
# connection for up to innodb_lock_wait_timeout (50s), which is longer than the
# pool will wait to hand one out (pool_timeout 30s), so the 15-connection pool
# emptied and every new request -- agents and pages alike -- died in
# before_request with "QueuePool limit of size 5 overflow 10 reached".
#
# Deleting a page of primary keys instead is bounded by construction:
#
#   DELETE FROM hashfile_hashes WHERE id IN (<5000 pks>)   type=range key=PRIMARY rows=5000
#
# It cannot escalate to a table lock however large the hashfile is. Committing per
# batch also caps lock duration at one batch rather than one hashfile, and makes
# the purge resumable: an interrupted run keeps its committed progress instead of
# rolling back an hour of work.
#
# 5,000 is the batch because the page SELECT stays index-only -- InnoDB appends the
# primary key to every secondary index, so (hashfile_id, id) is already in id order
# and ORDER BY id needs no filesort. Measured at 6ms per page, ~0.8s of paging for
# the 139 batches of the largest hashfile.
_RETENTION_DELETE_BATCH = 5000


def _delete_hashfile_links(db :SQLAlchemy, hashfile_id :int, logger :Logger) -> int:
    """Delete one hashfile's ``hashfile_hashes`` rows in committed batches.

    Each pass selects a bounded page of primary keys and deletes exactly those,
    so every statement is a short PK-range delete rather than one scan of the
    whole hashfile. No cursor is needed: the rows are gone once committed, so the
    next SELECT returns the next page.

    Returns the number of rows removed.
    """
    from hashview.models import HashfileHashes

    removed = 0
    while True:
        ids = [row[0] for row in (
            db.session.query(HashfileHashes.id)
            .filter(HashfileHashes.hashfile_id == hashfile_id)
            .order_by(HashfileHashes.id)
            .limit(_RETENTION_DELETE_BATCH)
            .all()
        )]
        if not ids:
            break
        deleted = HashfileHashes.query.filter(
            HashfileHashes.id.in_(ids)).delete(synchronize_session=False)
        db.session.commit()
        if not deleted:
            # The SELECT saw these ids but the DELETE matched nothing, so
            # something else removed them concurrently. Stop rather than spin.
            logger.debug(
                'DataRetention: hashfile %s links vanished mid-batch; stopping early.',
                hashfile_id)
            break
        removed += deleted
        logger.debug('DataRetention: removed %s link rows from hashfile %s (%s so far)',
                     deleted, hashfile_id, removed)
    return removed


def _delete_exclusive_hashes(db :SQLAlchemy, hash_ids :list, logger :Logger) -> int:
    """Delete the given ``hashes`` rows, and their notifications, in batches.

    ``hash_ids`` was computed before the link rows were removed, so each batch
    re-checks the two preconditions against the row itself instead of trusting
    the list: the hash must still be uncracked, and must no longer be referenced
    by ANY hashfile. Between the two phases an import can link one of these
    hashes to another hashfile and an agent can crack it, and either makes the
    hash worth keeping -- so a stale id is skipped, never deleted blind.

    Checking first and deleting by id also keeps the notification rows honest:
    only hashes that are actually being removed lose their notifications.

    Returns the number of hashes removed.
    """
    from hashview.models import Hashes, HashfileHashes, HashNotifications

    removed = 0
    for start in range(0, len(hash_ids), _RETENTION_DELETE_BATCH):
        chunk = hash_ids[start:start + _RETENTION_DELETE_BATCH]
        deletable = [row[0] for row in (
            db.session.query(Hashes.id)
            .filter(
                Hashes.id.in_(chunk),
                Hashes.cracked == 0,
                ~db.session.query(HashfileHashes.id).filter(
                    HashfileHashes.hash_id == Hashes.id).exists(),
            )
            .all()
        )]
        if deletable:
            HashNotifications.query.filter(
                HashNotifications.hash_id.in_(deletable)).delete(
                    synchronize_session=False)
            removed += Hashes.query.filter(
                Hashes.id.in_(deletable)).delete(synchronize_session=False)
        db.session.commit()
        if len(deletable) != len(chunk):
            logger.debug(
                'DataRetention: kept %s of %s candidate hashes (re-shared or cracked '
                'since the scan).', len(chunk) - len(deletable), len(chunk))
    return removed


def _data_retention_cleanup_inner(db :SQLAlchemy, mailer :Mail, logger :Logger):
    """ description needed """

    import time
    from datetime import datetime, timedelta
    from pathlib import Path
    from textwrap import dedent

    from sqlalchemy.orm import aliased

    from hashview.models import (
        Hashes,
        HashfileHashes,
        Hashfiles,
        JobNotifications,
        Jobs,
        JobTasks,
        Settings,
        Users,
    )

    try_send_email_ = partial(try_send_email, mailer=mailer)

    logger.debug('I am retaining all the data: %s', datetime.now())

    setting = Settings.query.get('1')
    retention_period = setting.retention_period
    filter_after = datetime.today() - timedelta(days = retention_period)

    # Remove job, job tasks and job notifications
    jobs = Jobs.query.filter(Jobs.created_at < filter_after).all()
    for job in jobs:
        # Send email saying we've deleted their job
        user = Users.query.get(job.owner_id)
        subject = f'Hashview removed an old job: {job.name}'
        message = dedent(f'''\
            Hello {user.first_name},

            In accordance to the data retention policy of {retention_period} days,
            your job "{job.name}" was deleted.
        ''')
        if (error := try_send_email_(user, subject, message)):
            logger.error(error)

        JobTasks.query.filter_by(job_id=job.id).delete()
        JobNotifications.query.filter_by(job_id=job.id).delete()

        db.session.delete(job)
        db.session.commit()

        logger.debug("Job Name: %s  Owner ID: %s has been Deleted", job.name, job.owner_id)

    # Remove Hashfiles (jobs younger than the retention period that reference
    # these hashfiles get removed too). Each hashfile is handled in its own
    # try/except so one bad hashfile can't abort the whole run, and the
    # "removed" email is sent only AFTER a successful commit so a failure can't
    # spam the owner once an hour (the original bug).
    hashfiles = Hashfiles.query.filter(Hashfiles.uploaded_at < filter_after).all()
    for hashfile in hashfiles:
        try:
            # Job, jobtask and job notifications
            jobs = Jobs.query.filter_by(hashfile_id = hashfile.id).all()
            for job in jobs:
                logger.debug("Hashfile->jobs: Job Name: %s", job.name)
                user = Users.query.get(job.owner_id)
                subject = f'Hashview removed a job that was associated to an old hash file: {job.name}'
                message = dedent(f'''\
                    Hello {user.first_name},

                    In accordance to the data retention policy of {retention_period} days,
                    your hashfile "{hashfile.name}" was associated with a job "{job.name}".
                    This job was deleted.
                ''')
                if (error := try_send_email_(user, subject, message)):
                    logger.error(error)

                JobTasks.query.filter_by(job_id=job.id).delete()
                JobNotifications.query.filter_by(job_id=job.id).delete()

                db.session.delete(job)
                db.session.commit()

                logger.debug(
                    "Job Name: %s  Owner ID: %s has been Deleted, "
                    "it was associated with Hashfile ID: %s, Hashfile Name: %s",
                    job.name, job.owner_id, hashfile.id, hashfile.name,
                )

            # Hashfiles, HashfileHashes and Hash notifications.
            #
            # The old code deleted HashfileHashes one row at a time (delete +
            # flush + a COUNT(*) per row), so a large hashfile (e.g. 400k hashes)
            # meant ~800k round-trips inside a single transaction that never
            # finished/committed -> the hashfile was never actually deleted and
            # the owner got re-emailed every hour. This does the same work in a
            # handful of set-based statements instead.
            logger.debug('Hashfile Name: %s    Owner ID: %s', hashfile.name, hashfile.owner_id)
            logger.debug('Hashfile ID: %s', hashfile.id)

            # Uncracked hashes that belong to THIS hashfile and to no other are
            # safe to delete; cracked recoveries (kept for reporting) and hashes
            # shared with another hashfile are preserved. Materialize the ids
            # (one SELECT with a correlated NOT EXISTS) and delete in chunks -
            # deleting via a subquery that also SELECTs from `hashes` would trip
            # MySQL error 1093 ("can't specify target table ... in FROM").
            other = aliased(HashfileHashes)
            exclusive_ids = [row[0] for row in (
                db.session.query(HashfileHashes.hash_id)
                .join(Hashes, Hashes.id == HashfileHashes.hash_id)
                .filter(HashfileHashes.hashfile_id == hashfile.id, Hashes.cracked == 0)
                .filter(~db.session.query(other.id).filter(
                    other.hash_id == HashfileHashes.hash_id,
                    other.hashfile_id != hashfile.id,
                ).exists())
                .distinct()
                .all()
            )]
            # That SELECT is the single longest step left: measured at 7s returning
            # 567,654 ids for the largest hashfile on production, and slower than
            # that from cold. It takes no row locks -- it is
            # a consistent read -- but it opens a transaction, and leaving that
            # open would pin a REPEATABLE-READ snapshot across the whole purge, so
            # the re-checks in phase two would be reading pre-purge data. Close it
            # here and let each batch below run in its own fresh transaction.
            db.session.commit()

            # This hashfile's associations go first, in committed batches, so the
            # hashes below have no referencing rows left -> FK-safe whether or not
            # the hashfile_hashes -> hashes FK cascades, and the orphan re-check in
            # phase two can trust what it reads.
            removed_links = _delete_hashfile_links(db, hashfile.id, logger)
            removed_hashes = _delete_exclusive_hashes(db, exclusive_ids, logger)

            # The hashfile row itself goes last. An interrupted purge therefore
            # leaves the hashfile in place with some or all of its links already
            # gone, and the next hourly run finishes it -- cheaply, because the
            # work already committed does not come back. The owner is only
            # emailed once the row is actually gone, so a resumed purge does not
            # notify twice.
            db.session.delete(hashfile)
            db.session.commit()

            logger.info(
                'DataRetention: hashfile id=%s name=%s removed (%s link rows, %s hashes).',
                hashfile.id, hashfile.name, removed_links, removed_hashes)

            # Email only AFTER the hashfile is actually gone, so a failed/rolled-back
            # deletion never notifies (and never spams hourly).
            user = Users.query.get(hashfile.owner_id)
            subject = f'Hashview removed an old Hashfile: {hashfile.name}'
            message = dedent(f'''\
                Hello {user.first_name},

                In accordance to the data retention policy of {retention_period} days,
                your hashfile "{hashfile.name}" was removed.
            ''')
            if (error := try_send_email_(user, subject, message)):
                logger.error(error)

            logger.debug(
                "Hashfile ID: %s  Hashfile Name: %s has been Deleted",
                hashfile.id, hashfile.name,
            )
        except Exception:
            # Roll back the partial work, log it (so a real failure is no longer
            # silent), and move on to the next hashfile instead of aborting the
            # whole retention run.
            db.session.rollback()
            logger.exception(
                'DataRetention: failed to delete hashfile id=%s name=%s; skipping.',
                hashfile.id, hashfile.name,
            )
            continue

    # Clean temp folder of files older than RETENTION PERIOD.
    # Build the path from current_app.root_path (we always run inside an app
    # context) rather than a CWD-relative literal, so the sweep finds control/tmp
    # regardless of the process working directory (issue #226). The old relative
    # path silently swept nothing when CWD wasn't the repo root.
    tmp_directory = Path(current_app.root_path, 'control', 'tmp').resolve()
    retention_limit = time.time() - retention_period * 86400
    # Encrypted one-time DB backups are single-use and contain the whole
    # database; reap them within an hour regardless of the (day-granular)
    # retention period so an un-downloaded backup never lingers.
    backup_limit = time.time() - 3600
    for child in tmp_directory.iterdir():
        if '.gitignore' == child.name:
            logger.debug(
                'DataRetentionCleanup.TempFile Progressing with StepResult(Ignored: %s).',
                child,
            )
            continue

        limit = backup_limit if child.name.endswith('.sql.gz.enc') else retention_limit
        if child.stat().st_mtime < limit:
            child.unlink()
            logger.debug(
                'DataRetentionCleanup.TempFile Progressing with StepResult(Removed: %s).',
                child,
            )
            continue

        logger.debug(
            'DataRetentionCleanup.TempFile Progressing with StepResult(LeftAlone: %s).',
            child,
        )


def _agent_health_check_inner(db :SQLAlchemy, logger :Logger):
    """Notify admins when an agent stops checking in, and again when it recovers.

    "Offline" = a stale check-in, older than Settings.agent_timeout_minutes (the
    same cutoff the UI uses). The per-agent ``offline_notified`` flag makes this a
    ONE-shot alert per offline episode (no repeats while it stays down) and lets us
    fire a single "recovered" alert when it checks back in. Agents that never
    checked in are skipped — they never "went offline"."""
    from datetime import datetime, timedelta

    from sqlalchemy import text

    from hashview.models import Agents
    from hashview.utils.audit import log_event
    from hashview.utils.utils import get_agent_timeout_minutes, notify_admins

    # Derive the cutoff from the DB clock (last_checkin is stamped with func.now()),
    # so the comparison is timezone-independent regardless of this process's TZ.
    try:
        db_now = db.session.execute(text("SELECT NOW()")).scalar()
        if isinstance(db_now, str):
            db_now = datetime.strptime(db_now[:19], '%Y-%m-%d %H:%M:%S')
    except Exception:
        db_now = None
    cutoff = (db_now or datetime.utcnow()) - timedelta(minutes=get_agent_timeout_minutes())

    for agent in Agents.query.filter(Agents.last_checkin.isnot(None)).all():
        offline = agent.last_checkin < cutoff
        if offline and not agent.offline_notified:
            logger.info('AgentHealthCheck: agent %s is offline; notifying admins.', agent.name)
            notify_admins(
                'Agent offline: ' + str(agent.name),
                'Hashview agent "' + str(agent.name) + '" has not checked in since '
                + str(agent.last_checkin) + ' and is now considered offline.')
            # System-generated event (no request actor) -> audit log.
            log_event('agent.offline', target=f'agent:{agent.id} {agent.name!r}',
                      detail=f'last_checkin={agent.last_checkin}', actor=('system', None))
            agent.offline_notified = True
            db.session.commit()
        elif not offline and agent.offline_notified:
            logger.info('AgentHealthCheck: agent %s recovered; notifying admins.', agent.name)
            notify_admins(
                'Agent recovered: ' + str(agent.name),
                'Hashview agent "' + str(agent.name) + '" is back online (last check-in '
                + str(agent.last_checkin) + ').')
            log_event('agent.recovered', target=f'agent:{agent.id} {agent.name!r}',
                      detail=f'last_checkin={agent.last_checkin}', actor=('system', None))
            agent.offline_notified = False
            db.session.commit()


# Caps on the aggregated alert body: notify_admins fans out to email, a Pushover
# PHONE PUSH and Slack, so a catalog-wide failure must not produce a 50 KB push.
_ALERT_MAX_ROWS = 20
_ALERT_MAX_TASK_IDS = 10


def _catalog_alert_lines(rows, task_ids_by_id, kind):
    """Plain-text body lines for one kind ('rule'/'wordlist') of missing row."""
    import os

    lines = []
    for row in rows[:_ALERT_MAX_ROWS]:
        # Basename, not the raw stored path: the stored value is server-internal
        # and often relative, and the basename is what the operator sees on disk.
        lines.append('  - %s %s "%s"  (path: %s)'
                     % (kind, row.id, row.name, os.path.basename(row.path or '') or '(no path)'))
        task_ids = sorted(task_ids_by_id.get(row.id, ()))
        if not task_ids:
            lines.append('      not referenced by any task')
            continue
        shown = ', '.join(str(t) for t in task_ids[:_ALERT_MAX_TASK_IDS])
        extra = len(task_ids) - _ALERT_MAX_TASK_IDS
        lines.append('      used by %d task(s): %s%s'
                     % (len(task_ids), shown, f' (+{extra} more)' if extra > 0 else ''))
    if len(rows) > _ALERT_MAX_ROWS:
        lines.append('  ... and %d more.' % (len(rows) - _ALERT_MAX_ROWS))
    return lines


def _catalog_task_references(rule_ids, wordlist_ids):
    """(rule_id -> {task ids}, wordlist_id -> {task ids}) in two batched queries.

    Which tasks reference a row is the field that decides the admin's next move:
    an unreferenced stale row is housekeeping, one behind a queued job is an
    incident. wl_id_2 counts -- a combinator task's second wordlist is a real
    reference (see build_hashcat_command)."""
    from sqlalchemy import or_

    from hashview.models import Tasks

    by_rule, by_wordlist = {}, {}
    if rule_ids:
        for task_id, rule_id in Tasks.query.with_entities(
                Tasks.id, Tasks.rule_id).filter(Tasks.rule_id.in_(rule_ids)).all():
            by_rule.setdefault(rule_id, set()).add(task_id)
    if wordlist_ids:
        for task_id, wl_id, wl_id_2 in Tasks.query.with_entities(
                Tasks.id, Tasks.wl_id, Tasks.wl_id_2).filter(
                    or_(Tasks.wl_id.in_(wordlist_ids),
                        Tasks.wl_id_2.in_(wordlist_ids))).all():
            for candidate in (wl_id, wl_id_2):
                if candidate in wordlist_ids:
                    by_wordlist.setdefault(candidate, set()).add(task_id)
    return by_rule, by_wordlist


def _catalog_health_check_inner(db :SQLAlchemy, logger :Logger):
    """Alert admins when a rule/wordlist row outlives its file, and on recovery.

    The per-row ``file_missing_notified`` flag makes this a ONE-shot alert per
    episode (no repeats while the file stays gone) and lets us fire a single
    "restored" alert when it comes back -- the same shape as
    _agent_health_check_inner's offline_notified.

    Unlike that one, the notification is AGGREGATED: one message per sweep per
    direction, not one per row. notify_admins fans out to email, a Pushover
    phone push and Slack, and these failures are almost always correlated (a
    volume move, a botched restore, a manual rm), so N separate pushes for one
    incident is a pager storm with no extra information. The audit log still
    gets one event per row, because that is the durable per-entity record and
    the Logs viewer parses `target` into entity/id/name.

    Issue #383."""
    import os

    from flask import current_app

    # Function-local, and load-bearing: tests monkeypatch
    # hashview.utils.utils.notify_admins, which only takes effect because the
    # name is resolved at call time. Do not hoist these to module scope.
    from hashview.models import Rules, Wordlists
    from hashview.utils.audit import log_event
    from hashview.utils.utils import notify_admins, rule_file_missing, wordlist_file_missing

    # Circuit breaker: an unmounted or renamed control volume would otherwise
    # flag the ENTIRE catalog, send one huge alert, latch every row, and fire an
    # equally huge "restored" alert on remount. Skipping is the only safe answer;
    # the error log is the operator's signal.
    for subdir in ('rules', 'wordlists'):
        path = os.path.join(current_app.root_path, 'control', subdir)
        if not os.path.isdir(path):
            logger.error('CatalogHealthCheck: %s is not a directory; skipping the sweep '
                         'so an unreadable volume is not reported as a missing catalog.',
                         path)
            return

    missing_rules, restored_rules = [], []
    for rule in Rules.query.all():
        if rule_file_missing(rule):
            if not rule.file_missing_notified:
                missing_rules.append(rule)
        elif rule.file_missing_notified:
            restored_rules.append(rule)

    missing_wordlists, restored_wordlists = [], []
    # Dynamic rows are filtered out by wordlist_file_missing (their file is a
    # regenerable cache), so they can never enter either list.
    for wordlist in Wordlists.query.all():
        if wordlist_file_missing(wordlist):
            if not wordlist.file_missing_notified:
                missing_wordlists.append(wordlist)
        elif wordlist.file_missing_notified:
            restored_wordlists.append(wordlist)

    if not (missing_rules or missing_wordlists or restored_rules or restored_wordlists):
        logger.info('CatalogHealthCheck: no catalog file changes to report.')
        return

    if missing_rules or missing_wordlists:
        by_rule, by_wordlist = _catalog_task_references(
            {r.id for r in missing_rules}, {w.id for w in missing_wordlists})
        total = len(missing_rules) + len(missing_wordlists)
        body = [
            'These Hashview rule/wordlist entries have a database row but no file on disk.',
            'Agents cannot download them, and any task that uses one will fail at run time.',
            '',
        ]
        if missing_rules:
            body.append('Rules:')
            body += _catalog_alert_lines(missing_rules, by_rule, 'rule')
            body.append('')
        if missing_wordlists:
            body.append('Wordlists:')
            body += _catalog_alert_lines(missing_wordlists, by_wordlist, 'wordlist')
            body.append('')
        body += [
            'Fix: re-upload the file from the Rules / Wordlists page (it restores in',
            'place, so tasks keep working), or delete the entry. Deleting is refused',
            'while a task still references it.',
        ]
        logger.info('CatalogHealthCheck: %d catalog file(s) missing; notifying admins.', total)
        # notify_admins fans out to email, Pushover and Slack, and only send_email
        # swallows its own errors: send_pushover does a bare requests.post +
        # .json(). A timeout on one transport would otherwise propagate AFTER the
        # emails were already delivered, skipping the latch below and the single
        # commit at the end -- so the identical aggregated alert would re-send
        # every hour until that transport recovered. Treat a delivery failure as
        # "told": a duplicate-free log line beats an hourly pager storm.
        try:
            notify_admins(
                'Hashview: %d catalog file%s missing on disk' % (total, '' if total == 1 else 's'),
                '\n'.join(body))
        except Exception:
            logger.exception(
                'CatalogHealthCheck: admin notification partially failed; latching anyway.')
        for rule in missing_rules:
            log_event('rule.file_missing', target=f'rule:{rule.id} {rule.name!r}',
                      detail=f'path={rule.path} tasks={len(by_rule.get(rule.id, ()))}',
                      actor=('system', None))
            rule.file_missing_notified = True
        for wordlist in missing_wordlists:
            log_event('wordlist.file_missing', target=f'wordlist:{wordlist.id} {wordlist.name!r}',
                      detail=f'path={wordlist.path} tasks={len(by_wordlist.get(wordlist.id, ()))}',
                      actor=('system', None))
            wordlist.file_missing_notified = True

    if restored_rules or restored_wordlists:
        # Sent as its own message rather than folded into the one above: a
        # "3 missing, 2 restored" Pushover title reads badly, and the two
        # directions call for different operator action (none, vs. go fix it).
        total = len(restored_rules) + len(restored_wordlists)
        # Real task references, not {}: _catalog_alert_lines prints "not
        # referenced by any task" whenever the map has no entry, so an empty one
        # told the admins that every recovered row was unused. The task list is
        # the line that decides whether anything still needed fixing.
        re_by_rule, re_by_wordlist = _catalog_task_references(
            {r.id for r in restored_rules}, {w.id for w in restored_wordlists})
        body = ['These Hashview rule/wordlist files are back on disk:', '']
        body += _catalog_alert_lines(restored_rules, re_by_rule, 'rule')
        body += _catalog_alert_lines(restored_wordlists, re_by_wordlist, 'wordlist')
        logger.info('CatalogHealthCheck: %d catalog file(s) restored; notifying admins.', total)
        try:
            notify_admins(
                'Hashview: %d catalog file%s restored' % (total, '' if total == 1 else 's'),
                '\n'.join(body))
        except Exception:
            logger.exception(
                'CatalogHealthCheck: restored-notification partially failed; un-latching anyway.')
        for rule in restored_rules:
            log_event('rule.file_restored', target=f'rule:{rule.id} {rule.name!r}',
                      detail=f'path={rule.path}', actor=('system', None))
            rule.file_missing_notified = False
        for wordlist in restored_wordlists:
            log_event('wordlist.file_restored', target=f'wordlist:{wordlist.id} {wordlist.name!r}',
                      detail=f'path={wordlist.path}', actor=('system', None))
            wordlist.file_missing_notified = False

    # One commit for the whole batch: the alert is aggregated, so the batch is
    # the unit of work. Committing before the send would risk latching rows the
    # admins were never told about; this order retries the whole set next sweep.
    db.session.commit()


def register_default_jobs(app :Flask):
    """Register Hashview's default scheduled jobs on the shared scheduler.

    Single source of truth, called from BOTH create_app (setup_defaults_if_needed)
    and the hashview.py entry point — keeping them in lockstep so a job can't be
    registered in one place and silently wiped by the other's remove_all_jobs()
    (which is exactly how AGENT_HEALTH went missing). ``app`` must be the real
    Flask app object, not the current_app proxy: jobs run in a context-less
    background thread, so the proxy would raise inside ``with app.app_context()``."""
    scheduler.remove_all_jobs()
    scheduler.add_job(
        id='DATA_RETENTION',
        func=partial(data_retention_cleanup, app),
        trigger='cron',
        hour='*',
    )
    # Agent offline / recovery admin alerts (one-shot per episode).
    scheduler.add_job(
        id='AGENT_HEALTH',
        func=partial(agent_health_check, app),
        trigger='interval',
        minutes=5,
    )
    # Rule/wordlist rows whose file vanished (issue #383). Hourly, not the
    # 5-minute cadence above: an offline agent is a transient condition worth
    # catching early, while a missing file is a step condition created only by
    # explicit user action, and the fix is a human re-uploading. Sub-hour
    # latency buys nothing and costs 12x the scheduler log volume.
    scheduler.add_job(
        id='CATALOG_HEALTH',
        func=partial(catalog_health_check, app),
        trigger='cron',
        hour='*',
    )


def agent_health_check(app :Flask):
    """Scheduled job: alert admins on agent offline / recovery (see inner)."""
    with app.app_context():
        try:
            app.logger.info('AgentHealthCheck ScheduledJob Progressing.')
            from hashview.models import db
            _agent_health_check_inner(db, app.logger)
        except Exception:
            app.logger.exception(
                'AgentHealthCheck ScheduledJob is Complete with Result(Failure).')
        else:
            app.logger.info(
                'AgentHealthCheck ScheduledJob is Complete with Result(Success).')


def data_retention_cleanup(app :Flask):
    """ Function to manage retention cleanup """
    with app.app_context():
        try:
            app.logger.info('DataRetentionCleanup ScheduledJob Progressing.')

            # db is already registered on the app in create_app(); re-running
            # db.init_app(app) here raises in Flask-SQLAlchemy 3.x
            # ("instance has already been registered"), which aborted the whole
            # cleanup every hour. The app_context above is all that's needed.
            from hashview.models import db

            mailer = app.extensions['mail']
            logger = app.logger
            _data_retention_cleanup_inner(db, mailer, logger)

        except Exception:
            app.logger.exception(
                'DataRetentionCleanup ScheduledJob is Complete with Result(Failure).')

        else:
            app.logger.info(
                'DataRetentionCleanup ScheduledJob is Complete with Result(Success).')

        finally:
            # This job is the one known pool antagonist -- it is what emptied the
            # pool once already -- so record the pool's state as it finishes. Read
            # alongside the request errors in error.log, it says whether a stall
            # overlapped a retention run and how much of the pool was in use.
            from hashview.utils.audit import pool_snapshot
            snapshot = pool_snapshot()
            if snapshot:
                app.logger.info('DataRetentionCleanup pool state: %s', snapshot)


def catalog_health_check(app :Flask):
    """Scheduled job: alert admins on catalog file missing / restored (see inner)."""
    with app.app_context():
        try:
            app.logger.info('CatalogHealthCheck ScheduledJob Progressing.')
            from hashview.models import db
            _catalog_health_check_inner(db, app.logger)
        except Exception:
            app.logger.exception(
                'CatalogHealthCheck ScheduledJob is Complete with Result(Failure).')
        else:
            app.logger.info(
                'CatalogHealthCheck ScheduledJob is Complete with Result(Success).')
