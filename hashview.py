#!/usr/bin/env python3
"""Main Entry Point when running as standalone script"""
import argparse
import builtins
import logging
import os
import sys
import traceback
from pathlib import Path

from hashview import create_app
from hashview.utils.tls import server_ssl_context


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
    from hashview.utils.utils import dynamic_password_length_wordlists, get_filehash

    wanted = [
        ('(DYNAMIC) All Recovered Passwords', 'hashview/control/wordlists/dynamic-all.txt'),
        ('(DYNAMIC) All Usernames',           'hashview/control/wordlists/dynamic-usernames.txt'),
        ('(DYNAMIC) All Customers',           'hashview/control/wordlists/dynamic-customers.txt'),
        ('(DYNAMIC) All NTLM Hashes',         'hashview/control/wordlists/dynamic-ntlm.txt'),
        # Recovered passwords split into fixed length buckets (0-5, 6..8, 9+).
        *dynamic_password_length_wordlists(),
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
            # A context object rather than the (cert, key) tuple werkzeug
            # would otherwise build: werkzeug wraps the LISTENING socket, so the
            # TLS handshake runs inline on the accept thread with no deadline,
            # and a single client that connects without sending a ClientHello
            # stops the server accepting anything at all. See utils/tls.py.
            app.run(
                host='0.0.0.0',
                port=8443,
                ssl_context=server_ssl_context('./hashview/ssl/cert.pem',
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
