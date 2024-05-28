import os

from pathlib import Path

from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy

from hashview.models import Rules
from hashview.models import Tasks
from hashview.models import Users
from hashview.models import Settings
from hashview.models import Wordlists
from hashview.utils.utils import get_filehash
from hashview.utils.utils import get_linecount


DEFAULT_PASSWORD = 'hashview'


def default_tasks_need_added(db :SQLAlchemy) -> bool:
    return (0 == db.session.query(Tasks).count())


def add_default_tasks(db :SQLAlchemy):
    task = Tasks(
        name          = 'Rockyou Wordlist',
        owner_id      = '1',
        wl_id         = '2',
        rule_id       = None,
        hc_attackmode = 'dictionary',
    )
    db.session.add(task)

    task = Tasks(
        name          = 'Rockyou Wordlist + Best64 Rules',
        owner_id      = '1',
        wl_id         = '3',
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


def default_dynamic_wordlist_need_added(db :SQLAlchemy) -> bool:
    return (0 == db.session.query(Wordlists).filter_by(type='dynamic').filter_by(name='All Recovered Hashes').count())


def add_default_dynamic_wordlist(db :SQLAlchemy):
    wordlist_path = 'hashview/control/wordlists/dynamic-all.txt'
    with open(wordlist_path, mode='w'):
        # 'w' => open for writing, truncating the file first
        pass
    wordlist = Wordlists(
        name     = 'All Recovered Hashes',
        owner_id = 1,
        type     = 'dynamic',
        path     = wordlist_path,               # Can we make this a relative path?
        checksum = get_filehash(wordlist_path),
        size     = 0,
    )
    db.session.add(wordlist)
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
    current_password_hash, *_ = db.session.query(Users.password).filter_by(id=1).first()
    return bcrypt.check_password_hash(current_password_hash, DEFAULT_PASSWORD)


def settings_needs_added(db :SQLAlchemy) -> bool:
    settings = db.session.query(Settings).first()
    return (settings is None)
