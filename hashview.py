"""Main Entry Point when running as standalone script"""
#!/usr/bin/python3
import sys
import logging
import argparse
import builtins
import traceback

from pathlib import Path
from typing import Optional
from functools import partial

from hashview import create_app


def ensure_authlib():
    """Ensuring authlib module is installed"""

    try:
        from authlib import jose
    except:
        print('\nPlease make sure that your dependencies are up to date (including installing authlib).')
        exit(1)


def ensure_requests():
    """Ensuring requests module is installed"""

    try:
        import requests
    except:
        print('\nPlease make sure that your dependencies are up to date (including installing requests).')
        exit(1)


def ensure_flask_bcrypt():
    """Ensuring flask_bcrypt module is installed"""

    try:
        import flask_bcrypt
        if '1.0.1' >=flask_bcrypt.__version__:
            raise Exception('old version')
    except:
        print('\nPlease make sure that your dependencies are up to date (including replacing Flask-Bcrypt with Bcrypt-Flask).')
        exit(1)


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


def ensure_settings_cli(db):
    from hashview.models import Settings
    from hashview.setup import settings_needs_added

    if settings_needs_added(db):
        print('✓ Settings exist in database.')
        return

    else:
        retention_period_int :int = 0
        retention_period_raw :Optional[str] = None
        while 1 > retention_period_int > 65535:
            if retention_period_raw:
                print('Error: Retention must be between 1 day and 65535 days')
            retention_period_raw = input("Enter how long data should be retained in DB in days. (note: cracked hashes->plaintext will be be safe from retention culling): ")
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
            from hashview.users.routes import bcrypt
            from hashview.scheduler import data_retention_cleanup

            ensure_settings_cli(db)
            ensure_admin_account_cli(db, bcrypt)

            print('Done! Running Hashview! Enjoy.')

            scheduler = app.apscheduler
            scheduler.remove_all_jobs()
            #scheduler.add_job(id='DATA_RETENTION', func=partial(data_retention_cleanup, app), trigger='cron', minute='*') #hour=1
            scheduler.add_job(id='DATA_RETENTION', func=partial(data_retention_cleanup, app), trigger='cron', hour='*')

        if parsed_args.debug:
            builtins.state = 'debug'

        else:
            builtins.state = 'normal'
            werkzeug_logger = logging.getLogger('werkzeug')
            werkzeug_logger.setLevel(logging.ERROR)

        if parsed_args.no_ssl:
            app.run(debug=parsed_args.debug)

        else:
            app.run(host='0.0.0.0', port=8443, ssl_context=('./hashview/ssl/cert.pem', './hashview/ssl/key.pem'), debug=parsed_args.debug)

    except Exception as ex:
        print(f'Exception!: {ex}', file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return 1

    else:
        return 0


if __name__ == '__main__':
    sys.exit(cli(sys.argv))
