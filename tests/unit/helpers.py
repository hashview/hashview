"""Shared seeding/login helpers for unit route tests.

The login pattern mirrors tests/unit/test_delete_idempotency.py: create a row,
then set Flask-Login's session keys directly so no password/CSRF dance is
needed. Constructors match hashview/models.py (non-nullable columns supplied).
"""

import gzip
import os
import secrets

from flask import current_app

from hashview.models import Customers, Rules, Users, Wordlists, db
from hashview.utils.utils import get_filehash, get_filesize, get_linecount


def make_admin(email="admin@example.com"):
    u = Users(first_name="Ad", last_name="Min", email_address=email,
              password="x" * 60, admin=True)
    db.session.add(u)
    db.session.commit()
    return u


def make_user(email="user@example.com"):
    u = Users(first_name="Plain", last_name="User", email_address=email,
              password="x" * 60, admin=False)
    db.session.add(u)
    db.session.commit()
    return u


def login(client, user):
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True


def make_customer(name="Test Customer"):
    c = Customers(name=name)
    db.session.add(c)
    db.session.commit()
    return c


# --- file-backed catalog rows -------------------------------------------------
#
# Issue #383 makes the task pickers drop any rule/wordlist whose file is gone
# from disk, so a test that POSTs to /tasks/add or /tasks/edit needs a row whose
# file REALLY exists. These helpers build one.
#
# The files land in the app's real control/{rules,wordlists} directories -- the
# same ones the download routes serve from, guaranteed to exist by conftest's
# `control_dirs` fixture -- because that is the only place the detection helper
# looks (see utils.resolve_control_file, which is basename-confined). Names are
# randomised and every file is registered for teardown by conftest's autouse
# `cleanup_control_files` fixture, so a test run leaves nothing behind.

_CREATED_CONTROL_FILES = []


def _control_path(subdir, suffix):
    """Absolute path to a fresh, uniquely-named file under control/<subdir>."""
    name = secrets.token_hex(8) + suffix
    path = os.path.join(current_app.root_path, 'control', subdir, name)
    _CREATED_CONTROL_FILES.append(path)
    return path


def cleanup_control_files():
    """Unlink every file these helpers created. Best effort; never raises."""
    while _CREATED_CONTROL_FILES:
        path = _CREATED_CONTROL_FILES.pop()
        try:
            os.remove(path)
        except OSError:
            pass


def make_rule_with_file(owner_id, name="test-rule", content=b"$1\n$2\n"):
    """A Rules row whose file really exists under control/rules.

    Rules are PLAINTEXT at rest (only wordlists are gzipped), so the bytes are
    written verbatim and the checksum is of that plaintext -- matching
    rules_add / POST /v1/rules/add.
    """
    path = _control_path('rules', '.txt')
    with open(path, 'wb') as fh:
        fh.write(content)
    rule = Rules(name=name, owner_id=owner_id, path=path,
                 size=get_linecount(path), checksum=get_filehash(path))
    db.session.add(rule)
    db.session.commit()
    return rule


def make_wordlist_with_file(owner_id, name="test-wordlist",
                            content=b"alpha\nbravo\n", wl_type="static"):
    """A Wordlists row whose file really exists under control/wordlists.

    Static lists are gzip-at-rest and their checksum is of the COMPRESSED file
    (the contract the agent verifies), matching ingest_static_wordlist_file.
    Dynamic lists stay uncompressed -- and are never reported missing anyway,
    since they are regenerated from the DB on every download.
    """
    if wl_type == 'static':
        path = _control_path('wordlists', '.gz')
        with gzip.open(path, 'wb', compresslevel=9) as fh:
            fh.write(content)
    else:
        path = _control_path('wordlists', '.txt')
        with open(path, 'wb') as fh:
            fh.write(content)
    wordlist = Wordlists(name=name, owner_id=owner_id, type=wl_type, path=path,
                         size=content.count(b'\n'), byte_size=get_filesize(path),
                         checksum=get_filehash(path))
    db.session.add(wordlist)
    db.session.commit()
    return wordlist
