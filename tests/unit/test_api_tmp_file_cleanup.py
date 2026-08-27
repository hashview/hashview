"""Regression tests for #226: control/tmp files must not accumulate.

The rules/wordlist download endpoints gzip into ``control/tmp`` and the
hashfile endpoint generates a plaintext file there. Each response must remove
its own temp file so the directory does not grow without bound.
"""

import os

from hashview.models import Hashes, HashfileHashes, Hashfiles, Rules, Users, Wordlists, db

DOMAIN = "localhost.test"


def _api_user():
    user = Users(first_name="A", last_name="B", email_address="a@e.com",
                 password="x", admin=True, api_key="test-api-key")
    db.session.add(user)
    db.session.commit()
    return user


def _tmp_listing(app):
    return set(os.listdir(os.path.join(app.root_path, "control", "tmp")))


def test_rules_download_removes_temp_gz(app, client):
    user = _api_user()
    src = os.path.join(app.root_path, "control", "rules", "cleanup_rule.txt")
    with open(src, "wb") as fh:
        fh.write(b"body\n")
    rule = Rules(name="r", owner_id=user.id,
                 path="control/rules/cleanup_rule.txt", checksum="x")
    db.session.add(rule)
    db.session.commit()
    client.set_cookie("uuid", "test-api-key", domain=DOMAIN)
    before = _tmp_listing(app)
    try:
        resp = client.get(f"/v1/rules/{rule.id}")
        assert resp.status_code == 200
        assert resp.data
        assert _tmp_listing(app) == before
    finally:
        for path in (src, os.path.join(app.root_path, "control", "tmp",
                                       "cleanup_rule.txt.gz")):
            if os.path.exists(path):
                os.remove(path)


def test_wordlist_download_removes_temp_gz(app, client):
    user = _api_user()
    src = os.path.join(app.root_path, "control", "wordlists", "cleanup_wl.txt")
    with open(src, "wb") as fh:
        fh.write(b"body\n")
    wordlist = Wordlists(name="w", owner_id=user.id, type="dynamic", size=1,
                         path="control/wordlists/cleanup_wl.txt", checksum="x")
    db.session.add(wordlist)
    db.session.commit()
    client.set_cookie("uuid", "test-api-key", domain=DOMAIN)
    before = _tmp_listing(app)
    try:
        resp = client.get(f"/v1/wordlists/{wordlist.id}")
        assert resp.status_code == 200
        assert resp.data
        assert _tmp_listing(app) == before
    finally:
        if os.path.exists(src):
            os.remove(src)
        for name in _tmp_listing(app) - before:
            os.remove(os.path.join(app.root_path, "control", "tmp", name))


def test_hashfile_download_removes_temp_file(app, client):
    user = _api_user()
    hashfile = Hashfiles(name="h", owner_id=user.id, customer_id=1)
    db.session.add(hashfile)
    db.session.commit()
    hash_row = Hashes(hash_type=1000, cracked=False, sub_ciphertext="",
                      ciphertext="aad3b435b51404eeaad3b435b51404ee")
    db.session.add(hash_row)
    db.session.commit()
    db.session.add(HashfileHashes(hashfile_id=hashfile.id, hash_id=hash_row.id))
    db.session.commit()
    client.set_cookie("uuid", "test-api-key", domain=DOMAIN)
    before = _tmp_listing(app)
    try:
        resp = client.get(f"/v1/hashfiles/{hashfile.id}")
        assert resp.status_code == 200
        assert b"aad3b435b51404eeaad3b435b51404ee" in resp.data
        assert _tmp_listing(app) == before
    finally:
        for name in _tmp_listing(app) - before:
            os.remove(os.path.join(app.root_path, "control", "tmp", name))
