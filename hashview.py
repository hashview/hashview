#!/usr/bin/env python3
"""Main Entry Point when running as standalone script"""
import argparse
import builtins
import logging
import os
import sys
import time
import traceback
from pathlib import Path

from hashview import create_app


def ensure_authlib():
    """Ensuring authlib module is installed"""
    import importlib.util
    if importlib.util.find_spec('authlib.jose') is None:
        print('\nPlease make sure that your dependencies are up to date '
              '(including installing authlib).')
        sys.exit(1)


def ensure_requests():
    """Ensuring requests module is installed"""
    import importlib.util
    if importlib.util.find_spec('requests') is None:
        print('\nPlease make sure that your dependencies are up to date '
              '(including installing requests).')
        sys.exit(1)


def ensure_flask_bcrypt():
    """Ensuring flask_bcrypt module is installed"""

    try:
        import flask_bcrypt
        if '1.0.1' >= flask_bcrypt.__version__:
            raise RuntimeError('old version')
    except Exception:
        print('\nPlease make sure that your dependencies are up to date '
              '(including replacing Flask-Bcrypt with Bcrypt-Flask).')
        #sys.exit(1)


def ensure_admin_account_cli(db, bcrypt):
    '''
    If no admins exist prompt user to generate new admin account
    '''
    from getpass import getpass

    from hashview.models import Users
    from hashview.setup import admin_user_needs_added

    if not admin_user_needs_added(db):
        print('✓ Admin user exists in database.')
        return

    else:
        print('\nInitial setup detected. Hashview will now prompt you to setup '
              'an Administrative account.\n')
        admin_email = input(
            'Enter Email address for the Administrator account. '
            'You will use this to log into the app: ')
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

        user = Users(
            first_name=admin_firstname,
            last_name=admin_lastname,
            email_address=admin_email,
            password=hashed_password,
            admin=True,
        )
        db.session.add(user)
        db.session.commit()


def ensure_settings_cli(db):
    from hashview.models import Settings
    from hashview.setup import settings_needs_added

    if settings_needs_added(db):
        print('✓ Settings exist in database.')
        return

    else:
        retention_period_int :int = 0
        retention_period_raw :str | None = None
        while 1 > retention_period_int > 65535:
            if retention_period_raw:
                print('Error: Retention must be between 1 day and 65535 days')
            retention_period_raw = input(
                "Enter how long data should be retained in DB in days. "
                "(note: cracked hashes->plaintext will be safe from retention culling): ")
            retention_period_int = int(retention_period_raw)

        max_runtime_tasks_int :int = 0
        max_runtime_jobs_int :int = 0

        settings = Settings(
            retention_period  = retention_period_int,
            max_runtime_tasks = max_runtime_tasks_int,
            max_runtime_jobs  = max_runtime_jobs_int
        )
        db.session.add(settings)
        db.session.commit()


def ensure_dynamic_wordlist(db):
    """Ensure each canonical (DYNAMIC) wordlist exists; idempotent per name.

    Mirrors hashview/setup/__init__.py:add_default_dynamic_wordlists so the
    CLI-style setup path covers the same four wordlists the auto-setup path
    creates: Recovered Passwords, Usernames, Customers, NTLM Hashes.
    """
    from hashview.models import Wordlists
    from hashview.utils.utils import get_filehash

    wanted = [
        ('(DYNAMIC) All Recovered Passwords', 'hashview/control/wordlists/dynamic-all.txt'),
        ('(DYNAMIC) All Usernames',           'hashview/control/wordlists/dynamic-usernames.txt'),
        ('(DYNAMIC) All Customers',           'hashview/control/wordlists/dynamic-customers.txt'),
        ('(DYNAMIC) All NTLM Hashes',         'hashview/control/wordlists/dynamic-ntlm.txt'),
        ('(DYNAMIC) Website Keywords',        'hashview/control/wordlists/dynamic-website-keywords.txt'),
    ]
    added = 0
    for name, path in wanted:
        if Wordlists.query.filter_by(name=name).first() is not None:
            continue
        with open(path, 'w'):
            # 'w' => open for writing, truncating the file first
            pass
        db.session.add(Wordlists(
            name     = name,
            owner_id = '1',
            type     = 'dynamic',
            path     = path,
            checksum = get_filehash(path),
            size     = 0,
        ))
        added += 1
    db.session.commit()
    if added == 0:
        print('✓ Dynamic Wordlists already present.')
    else:
        print(f'\nAdded {added} missing dynamic wordlist(s).')


def ensure_static_wordlist(db):
    from hashview.models import Wordlists
    from hashview.utils.utils import get_filehash, get_linecount

    static_wordlist_count = Wordlists.query.filter_by(type='static').count()
    if static_wordlist_count > 0:
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
    from hashview.utils.utils import get_filehash, get_linecount

    rule_count = Rules.query.count()
    if rule_count > 0:
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
    if task_count > 0:
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
        from datetime import datetime, timedelta

        from hashview.models import db
        db.init_app(app)

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
            message = (
                f'Hello {user.first_name}, \n\n In accordance to the data '
                f'retention policy of {retention_period} days, your job '
                f'"{job.name}" was deleted.'
            )
            send_email(user, subject, message)

            JobTasks.query.filter_by(job_id=job.id).delete()
            JobNotifications.query.filter_by(job_id=job.id).delete()

            db.session.delete(job)
            db.session.commit()

            print("[DEBUG] Job Name: " + str(job.name) + '  Owner ID: ' + str(job.owner_id))

        # Remove Hashfiles (jobs younger than retention period that reference
        # these hashfiles get removed too).
        hashfiles = Hashfiles.query.filter(Hashfiles.uploaded_at < filter_after).all()
        for hashfile in hashfiles:

            # Job, jobtask and job notifications
            jobs = Jobs.query.filter_by(hashfile_id = hashfile.id).all()
            for job in jobs:
                print("[DEBUG] Hashfile->jobs: Job Name: " +str(job.name))
                user = Users.query.get(job.owner_id)
                subject = (
                    'Hashview removed a job that was associated to an old hash file: '
                    + str(job.name)
                )
                message = (
                    f'Hello {user.first_name}, \n\n In accordance to the data '
                    f'retention policy of {retention_period} days, your hashfile '
                    f'"{hashfile.name}" was associated with a job '
                    f'"{job.name}". This job was deleted.'
                )
                send_email(user, subject, message)

                JobTasks.query.filter_by(job_id=job.id).delete()
                JobNotifications.query.filter_by(job_id=job.id).delete()

                db.session.delete(job)
                db.session.commit()

            # Hashfiles, HashfileHashes and Hash notifications
            print(
                f'[DEBUG] Hashfile Name: {hashfile.name}    '
                f'Owner ID: {hashfile.owner_id}'
            )
            print('[DEBUG] Hashfile ID: ' + str(hashfile.id))
            user = Users.query.get(hashfile.owner_id)
            subject = 'Hashview removed an old Hashfile: ' + str(hashfile.name)
            message = (
                f'Hello {user.first_name}, \n\n In accordance to the data '
                f'retention policy of {retention_period} days, your hashfile '
                f'"{hashfile.name}" was removed.'
            )
            send_email(user, subject, message)

            hashfile_hashes = HashfileHashes.query.filter_by(hashfile_id = hashfile.id).all()
            for hashfile_hash in hashfile_hashes:
                hashes = Hashes.query.filter_by(id=hashfile_hash.hash_id).filter_by(cracked=0).all()
                for hash_entry in hashes:
                    # Only delete this hash if it isn't shared with another
                    # hashfile. Duplicates drop to < 2 once the hashfile_hash
                    # entry is removed, allowing later deletion.
                    hashfile_cnt = (
                        HashfileHashes.query.filter_by(hash_id=hash_entry.id)
                        .distinct('hashfile_id').count()
                    )
                    if hashfile_cnt < 2:
                        db.session.delete(hash_entry)
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
            tmp_path = 'hashview/control/tmp/' + file
            age_limit = time.time() - retention_period * 86400
            if os.stat(tmp_path).st_mtime < age_limit and file != '.gitignore':
                os.remove(tmp_path)
                print('[DEBUG] hashview.py->data_retention_cleanup() '
                      f'Removed: {tmp_path}')

        print('[DEBUG] ==============')


def cli(args) -> int:
    """
        takes in command line args, and returns an exit code
    """
    # conforming to the standard command line interface provides for easier testing
    try:
        # sometimes when called, the first argument is the name of the script,
        # this does not need to be parsed, and should be removed from the args
        if Path(__file__).resolve() == Path(args[0]).resolve():
            args = args[1:]

        parser = argparse.ArgumentParser()
        parser.add_argument("--debug",  action="store_true", help="increase output verbosity")
        parser.add_argument("--no-ssl", action="store_true", help="disable use of ssl")
        parsed_args = parser.parse_args(args)

        ensure_authlib()
        ensure_requests()
        ensure_flask_bcrypt()

        app = create_app()
        with app.app_context():
            from hashview.models import db
            from hashview.scheduler import register_default_jobs
            from hashview.users.routes import bcrypt

            ensure_settings_cli(db)
            ensure_admin_account_cli(db, bcrypt)

            print('Done! Running Hashview! Enjoy.')

            # Register all default scheduled jobs (DATA_RETENTION + AGENT_HEALTH)
            # from the single source so the entry point and create_app can't drift.
            register_default_jobs(app)

        if parsed_args.debug:
            builtins.state = 'debug'

        else:
            builtins.state = 'normal'
            werkzeug_logger = logging.getLogger('werkzeug')
            werkzeug_logger.setLevel(logging.ERROR)

        if parsed_args.no_ssl:
            app.run(debug=parsed_args.debug)

        else:
            app.run(
                host='0.0.0.0',
                port=8443,
                ssl_context=('./hashview/ssl/cert.pem',
                             './hashview/ssl/key.pem'),
                debug=parsed_args.debug,
            )

    except Exception as ex:
        print(f'Exception!: {ex}', file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return 1

    else:
        return 0


if __name__ == '__main__':
    sys.exit(cli(sys.argv))
