"""Function file to scheduler"""
from logging import Logger
from functools import partial

from flask import Flask
from flask_mail import Mail
from flask_mail import Message
from flask_sqlalchemy import SQLAlchemy
from flask_apscheduler import APScheduler


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

    except:
        return error

    else:
        return None


def _data_retention_cleanup_inner(db :SQLAlchemy, mailer :Mail, logger :Logger):
    """ description needed """

    from pathlib import Path
    from datetime import datetime
    from datetime import timedelta
    from textwrap import dedent

    from hashview.models import Users, Settings, Jobs, JobTasks, JobNotifications, HashfileHashes, HashNotifications, Hashes, Hashfiles

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

            In accordance to the data retention policy of {retention_period} days, your job "{job.name}" was deleted.
        ''')
        if (error := try_send_email_(user, subject, message)):
            logger.error(error)

        JobTasks.query.filter_by(job_id=job.id).delete()
        JobNotifications.query.filter_by(job_id=job.id).delete()

        db.session.delete(job)
        db.session.commit()

        logger.debug("Job Name: %s  Owner ID: %s has been Deleted", job.name, job.owner_id)

    # Remove Hashfiles (note hashfiles might be associated to a job thats < retention period. Those jobs should be removed too)
    hashfiles = Hashfiles.query.filter(Hashfiles.uploaded_at < filter_after).all()
    for hashfile in hashfiles:
        # Job, jobtask and job notifications
        jobs = Jobs.query.filter_by(hashfile_id = hashfile.id).all()
        for job in jobs:
            logger.debug("Hashfile->jobs: Job Name: %s", job.name)
            user = Users.query.get(job.owner_id)
            subject = f'Hashview removed a job that was associated to an old hash file: {job.name}'
            message = dedent(f'''\
                Hello ' + str(user.first_name) + ',

                In accordance to the data retention policy of {retention_period} days, your hashfile "{hashfile.name}" was associated with a job "{job.name}". This job was deleted.
            ''')
            if (error := try_send_email_(user, subject, message)):
                logger.error(error)

            JobTasks.query.filter_by(job_id=job.id).delete()
            JobNotifications.query.filter_by(job_id=job.id).delete()

            db.session.delete(job)
            db.session.commit()

            logger.debug("Job Name: %s  Owner ID: %s has been Deleted, it was associated with Hashfile ID: %s, Hashfile Name: %s", job.name, job.owner_id, hashfile.id, hashfile.name)

        # Hashfiles, HashfileHashes and Hash notifications
        logger.debug('Hashfile Name: %s    Owner ID: %s', hashfile.name, hashfile.owner_id)
        logger.debug('Hashfile ID: %s', hashfile.id)
        user = Users.query.get(hashfile.owner_id)
        subject = f'Hashview removed an old Hashfile: {hashfile.name}'
        message = dedent(f'''\
            Hello {user.first_name},

            In accordance to the data retention policy of {retention_period} days, your hashfile "{hashfile.name}" was removed.
        ''')
        if (error := try_send_email_(user, subject, message)):
            logger.error(error)

        hashfile_hashes = HashfileHashes.query.filter_by(hashfile_id = hashfile.id).all()
        for hashfile_hash in hashfile_hashes:
            hashes = Hashes.query.filter_by(id=hashfile_hash.hash_id).filter_by(cracked=0).all()
            for hash in hashes:
                # Check to see if our hashfile is the ONLY hashfile that has this hash
                # if duplicates exist, they can still be removed. Once the hashfile_hash entry is remove,
                # the total number of matching hash_id's will be reduced to < 2 and then can be deleted
                hashfile_cnt = HashfileHashes.query.filter_by(hash_id=hash.id).distinct('hashfile_id').count()
                if hashfile_cnt < 2:
                    db.session.delete(hash)
                    db.session.commit()
                    HashNotifications.query.filter_by(hash_id=hashfile_hash.hash_id).delete()
            db.session.delete(hashfile_hash)
        db.session.delete(hashfile)
        db.session.commit()

        logger.debug("Hashfile ID: %s  Hashfile Name: %s has been Deleted", hashfile.id, hashfile.name)

    # Clean temp folder of files older than RETENTION PERIOD
    tmp_directory = Path('hashview/control/tmp').resolve()
    retention_limit = datetime.time() - retention_period * 86400
    for child in tmp_directory.iterdir():
        if '.gitignore' == child.name:
            logger.debug('DataRetentionCleanup.TempFile Progressing with StepResult(Ignored: %s).', child)
            continue

        if child.stat().st_mtime < retention_limit:
            child.unlink()
            logger.debug('DataRetentionCleanup.TempFile Progressing with StepResult(Removed: %s).', child)
            continue

        else:
            logger.debug('DataRetentionCleanup.TempFile Progressing with StepResult(LeftAlone: %s).', child)


def data_retention_cleanup(app :Flask):
    """ Function to manage retention cleanup """
    with app.app_context():
        try:
            app.logger.info('DataRetentionCleanup ScheduledJob Progressing.')

            from hashview.models import db
            db.init_app(app)

            mailer = app.extensions['mail']
            logger = app.logger
            _data_retention_cleanup_inner(db, mailer, logger)

        except:
            app.logger.exception('DataRetentionCleanup ScheduledJob is Complete with Result(Failure).')

        else:
            app.logger.info('DataRetentionCleanup ScheduledJob is Complete with Result(Success).')
