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
        HashNotifications,
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

            # Remove this hashfile's associations first so the now-orphaned hashes
            # below have no referencing rows -> FK-safe whether or not the
            # hashfile_hashes -> hashes FK cascades.
            HashfileHashes.query.filter_by(hashfile_id=hashfile.id).delete(
                synchronize_session=False)
            for start in range(0, len(exclusive_ids), 5000):
                chunk = exclusive_ids[start:start + 5000]
                HashNotifications.query.filter(
                    HashNotifications.hash_id.in_(chunk)).delete(synchronize_session=False)
                Hashes.query.filter(
                    Hashes.id.in_(chunk)).delete(synchronize_session=False)

            db.session.delete(hashfile)
            db.session.commit()

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
