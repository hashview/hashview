#!/usr/bin/python3
import os
import sys
import logging
import argparse
import builtins
import traceback

from typing import Optional
from functools import partial

from hashview import create_app


def ensure_authlib():
    try:
        from authlib import jose
    except:
        print('\nPlease make sure that your dependencies are up to date (including installing authlib).')
        exit(1)


def ensure_requests():
    try:
        import requests
    except:
        print('\nPlease make sure that your dependencies are up to date (including installing requests).')
        exit(1)


def ensure_flask_bcrypt():
    try:
        import flask_bcrypt
        if ('1.0.1' >=flask_bcrypt.__version__):
            raise Exception('old version')
    except:
        print('\nPlease make sure that your dependencies are up to date (including replacing Flask-Bcrypt with Bcrypt-Flask).')
        exit(1)


def ensure_admin_account(db, bcrypt):
    '''
    If no admins exist prompt user to generate new admin account
    '''
    from getpass import getpass

    from hashview.models import Users

    admin_user_count = Users.query.filter_by(admin='1').count()
    if (0 < admin_user_count):
        print('✓ Admin user exists in database.')
        return

    else:
        print('\nInitial setup detected. Hashview will now prompt you to setup an Administrative account.\n')
        admin_email = input('Enter Email address for the Administrator account. You will use this to log into the app: ')
        while len(admin_email) == 0:
            print('Error: You must provide an email address.')
            admin_email = input("Invalid email address. Try again: ")

        admin_password = getpass('Enter a password for the Administrator account: ')
        admin_password_verify = getpass('Re-Enter the password for the Administrator account: ')

        while len(admin_password) < 14 or admin_password != admin_password_verify:
            if len(admin_password) < 14:
                print('Error: Password must be more than 14 characters.')
            else:
                print('Error: Passwords do not match.')
            admin_password = getpass('Enter a password for the Administrator account: ')
            admin_password_verify = getpass('Re-Enter the password for the Administrator account: ')

        admin_firstname = input('Enter Administrator\'s first name: ')
        while len(admin_firstname) == 0:
            print('Error: Firstname must be at least 1 character long')
            admin_firstname = input('Enter Administrator\'s first name: ')

        admin_lastname = input('Enter Administrator\'s last name: ')
        while len(admin_lastname) == 0:
            print('Error: Firstname must be at least 1 character long')
            admin_lastname = input('Enter Administrator\'s last name: ')

        print('\nProvisioning account in database.')
        hashed_password = bcrypt.generate_password_hash(admin_password).decode('utf-8')

        user = Users(first_name=admin_firstname, last_name=admin_lastname, email_address=admin_email, password=hashed_password, admin=True)
        db.session.add(user)
        db.session.commit()


def ensure_settings(db):
    from hashview.models import Settings

    if Settings.query.first():
        print('✓ Settings exist in database.')
        return

    else:
        retention_period_int :int = 0
        retention_period_raw :Optional[str] = None
        while (1 > retention_period_int > 65535):
            if retention_period_raw:
                print('Error: Retention must be between 1 day and 65535 days')
            retention_period_raw = input("Enter how long data should be retained in DB in days. (note: cracked hashes->plaintext will be be safe from retention culling): ")
            retention_period_int = int(retention_period_raw)

        max_runtime_tasks_int :int = 0
        max_runtime_jobs_int :int = 0

        settings = Settings(
            retention_period = retention_period_int,
            max_runtime_tasks = max_runtime_tasks_int,
            max_runtime_jobs = max_runtime_jobs_int
        )
        db.session.add(settings)
        db.session.commit()


def ensure_dynamic_wordlist(db):
    from hashview.models import Wordlists
    from hashview.utils.utils import get_filehash

    dynamic_wordlist_count = Wordlists.query.filter_by(type='dynamic').filter_by(name='All Recovered Hashes').count()
    if (0 < dynamic_wordlist_count):
        print(f'✓ Dynamic Wordlist exist in database. Count({dynamic_wordlist_count})')
        return

    else:
        print('\nSetting up dynamic wordlist.')
        wordlist_path = 'hashview/control/wordlists/dynamic-all.txt'
        with open(wordlist_path, 'w'):
            # 'w' => open for writing, truncating the file first
            pass
        wordlist = Wordlists(
            name     = 'All Recovered Hashes',
            owner_id = '1',
            type     = 'dynamic',
            path     = wordlist_path,               # Can we make this a relative path?
            checksum = get_filehash(wordlist_path),
            size     = 0,
        )
        db.session.add(wordlist)
        db.session.commit()


def ensure_static_wordlist(db):
    from hashview.models import Wordlists
    from hashview.utils.utils import get_filehash
    from hashview.utils.utils import get_linecount

    static_wordlist_count = Wordlists.query.filter_by(type='static').count()
    if (0 < static_wordlist_count):
        print(f'✓ Static Wordlist exist in database. Count({static_wordlist_count})')
        return

    else:
        print('\nSetting up static wordlist rockyou.')
        os.system("gzip -d -k install/rockyou.txt.gz")
        wordlist_path = 'hashview/control/wordlists/rockyou.txt'
        os.replace('install/rockyou.txt', wordlist_path)
        wordlist = Wordlists(
            name     = 'Rockyou.txt',
            owner_id = '1',
            type     = 'static',
            path     = wordlist_path,                # Can we make this a relative path?
            checksum = get_filehash(wordlist_path),
            size     = get_linecount(wordlist_path),
        )
        db.session.add(wordlist)
        db.session.commit()


def ensure_rules(db):
    from hashview.models import Rules
    from hashview.utils.utils import get_filehash
    from hashview.utils.utils import get_linecount

    rule_count = Rules.query.count()
    if (0 < rule_count):
        print(f'✓ Rules exist in database. Count({rule_count})')
        return

    else:
        print('\nSetting up best64.rules')
        os.system("gzip -d -k install/best64.rule.gz")
        rules_path = 'hashview/control/rules/best64.rule'
        os.replace('install/best64.rule', rules_path)
        rule = Rules(
            name     = 'Best64 Rule',
            owner_id = '1',
            path     = rules_path,
            checksum = get_filehash(rules_path),
            size     = get_linecount(rules_path),
        )
        db.session.add(rule)
        db.session.commit()


def ensure_tasks(db):
    from hashview.models import Tasks

    task_count = Tasks.query.count()
    if (0 < task_count):
        print(f'✓ Tasks exist in database. Count({task_count})')
        return

    else:
        print('\nSetting up default tasks.')

        task = Tasks(
            name          = 'Rockyou Wordlist',
            owner_id      = '1',
            wl_id         = '1',
            rule_id       = None,
            hc_attackmode = 'dictionary',
        )
        db.session.add(task)

        task = Tasks(
            name          = 'Rockyou Wordlist + Best64 Rules',
            owner_id      = '1',
            wl_id         = '1',
            rule_id       = '1',
            hc_attackmode = 'dictionary',
        )
        db.session.add(task)

        # mask mode of all 8 characters
        task = Tasks(
            name          = '?a?a?a?a?a?a?a?a [8]',
            owner_id      = '1',
            wl_id         = None,
            rule_id       = None,
            hc_attackmode = 'maskmode',
            hc_mask       = '?a?a?a?a?a?a?a?a',
        )
        db.session.add(task)

        db.session.commit()


def ensure_version_alignment():
    from flask_migrate import upgrade
    upgrade()


def data_retention_cleanup(app):
    with app.app_context():
        import os

        from datetime import datetime, timedelta

        from hashview.models import db
        db.init_app(app)

        from hashview.models import Users, Settings, Jobs, JobTasks, JobNotifications, HashfileHashes, HashNotifications, Hashes, Hashfiles
        from hashview.utils.utils import send_email

        print('[DEBUG] Im retaining all the data: ' + str(datetime.now()))

        setting = Settings.query.get('1')
        retention_period = setting.retention_period
        filter_after = datetime.today() - timedelta(days = retention_period)

        # Remove job, job tasks and job notifications
        jobs = Jobs.query.filter(Jobs.created_at < filter_after).all()
        for job in jobs:
            # Send email saying we've deleted their job
            user = Users.query.get(job.owner_id)
            subject = 'Hashview removed an old job: ' + str(job.name)
            message = 'Hello ' + str(user.first_name) + ', \n\n In accordance to the data retention policy of ' + str(retention_period) + ' days, your job "' + str(job.name) + '" was deleted.'
            send_email(user, subject, message)

            JobTasks.query.filter_by(job_id=job.id).delete()
            JobNotifications.query.filter_by(job_id=job.id).delete()

            db.session.delete(job)
            db.session.commit()

            print("[DEBUG] Job Name: " + str(job.name) + '  Owner ID: ' + str(job.owner_id))

        # Remove Hashfiles (note hashfiles might be associated to a job thats < retention period. Those jobs should be removed too)
        hashfiles = Hashfiles.query.filter(Hashfiles.uploaded_at < filter_after).all()
        for hashfile in hashfiles:

            # Job, jobtask and job notifications
            jobs = Jobs.query.filter_by(hashfile_id = hashfile.id).all()
            for job in jobs:
                print("[DEBUG] Hashfile->jobs: Job Name: " +str(job.name))
                user = Users.query.get(job.owner_id)
                subject = 'Hashview removed a job that was associated to an old hash file: ' + str(job.name)
                message = 'Hello ' + str(user.first_name) + ', \n\n In accordance to the data retention policy of ' + str(retention_period) + ' days, your hashfile "' + str(hashfile.name) + '" was associated with a job "' + str(job.name) + '". This job was deleted.'
                send_email(user, subject, message)

                JobTasks.query.filter_by(job_id=job.id).delete()
                JobNotifications.query.filter_by(job_id=job.id).delete()

                db.session.delete(job)
                db.session.commit()

            # Hashfiles, HashfileHashes and Hash notifications
            print('[DEBUG] Hashfile Name: ' + str(hashfile.name) + '    Owner ID: ' + str(hashfile.owner_id))
            print('[DEBUG] Hashfile ID: ' + str(hashfile.id))
            user = Users.query.get(hashfile.owner_id)
            subject = 'Hashview removed an old Hashfile: ' + str(hashfile.name)
            message = 'Hello ' + str(user.first_name) + ', \n\n In accordance to the data retention policy of ' + str(retention_period) + ' days, your hashfile "' + str(hashfile.name) + '" was removed.'
            send_email(user, subject, message)

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

        # Clean temp folder of files older than RETENTION PERIOD
        for file in os.listdir('hashview/control/tmp'):
            print('[DEBUG] hashview.py->data_retention_cleanup() ' + file)
            if file == '.gitignore':
                print('Found Git Ignore!')
            if os.stat('hashview/control/tmp/' + file).st_mtime < time.time() - retention_period * 86400 and file != '.gitignore':
                os.remove('hashview/control/tmp/' + file)
                print('[DEBUG] hashview.py->data_retention_cleanup() Removed: hashview/control/tmp/' + file)

        print('[DEBUG] ==============')


def cli(args) -> int:
    try:
        #if (__file__ == args[0]):
        #    args = args[1:]
        parser = argparse.ArgumentParser()
        parser.add_argument("--debug", action="store_true", help="increase output verbosity")
        parser.add_argument("--no-ssl", action="store_true", help="disable use of ssl")
        args = parser.parse_args()
        #args = parser.parse_args(args)

        ensure_authlib()
        ensure_requests()
        ensure_flask_bcrypt()

        app = create_app()

        with app.app_context():
            ensure_version_alignment()

            from hashview.models import db
            from hashview.users.routes import bcrypt

            ensure_admin_account(db, bcrypt)
            ensure_settings(db)
            ensure_dynamic_wordlist(db)
            ensure_static_wordlist(db)
            ensure_rules(db)
            ensure_tasks(db)

            print('Done! Running Hashview! Enjoy.')

            scheduler = app.apscheduler
            scheduler.remove_all_jobs()
            #scheduler.add_job(id='DATA_RETENTION', func=partial(data_retention_cleanup, app), trigger='cron', minute='*') #hour=1
            scheduler.add_job(id='DATA_RETENTION', func=partial(data_retention_cleanup, app), trigger='cron', hour='*')

        if args.debug:
            builtins.state = 'debug'

        else:
            builtins.state = 'normal'
            log = logging.getLogger('werkzeug')
            log.setLevel(logging.ERROR)

        if args.no_ssl:
            app.run(debug=args.debug)

        else:
            app.run(host='0.0.0.0', port=8443, ssl_context=('./hashview/ssl/cert.pem', './hashview/ssl/key.pem'), debug=args.debug)

    except:
        print('Exception!:')
        traceback.print_exc()
        return 1

    else:
        return 0


if __name__ == '__main__':
    exit(cli(sys.argv))
