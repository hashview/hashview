"""Restoring a rule/wordlist file IN PLACE (issue #383).

The remedy for the hard case: a row that outlived its file while tasks already
reference it. Re-uploading through rules_add / wordlists_add always mints a new
row and a new path, so it orphans the stale reference further instead of fixing
it. Restore keeps the row's id and path basename, so every Tasks.rule_id /
wl_id / wl_id_2, every already-materialized JobTasks.command and every
Hashes.task_id attribution stays valid.
"""

import gzip
import io
import os

import pytest

from hashview.models import Rules, Tasks, Wordlists, db
from hashview.utils.utils import rule_file_missing, wordlist_file_missing
from tests.unit.helpers import (
    login,
    make_admin,
    make_rule_with_file,
    make_user,
    make_wordlist_with_file,
)


def _gone_rule(owner_id, tmp_path, name="gone-rule"):
    rule = Rules(name=name, owner_id=owner_id, path=str(tmp_path / "gone.rule"),
                 size=7, checksum="c" * 64)
    db.session.add(rule)
    db.session.commit()
    return rule


def _upload(data, filename):
    return (io.BytesIO(data), filename)


# --------------------------------------------------- rules_view as restore

def test_rules_view_get_tolerates_a_missing_file(app, client, tmp_path):
    """It used to flash "Error reading file" and redirect, making the write
    branch -- and therefore the restore -- unreachable."""
    admin = make_admin()
    login(client, admin)
    rule = _gone_rule(admin.id, tmp_path)

    resp = client.get(f"/rules/edit/{rule.id}")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "file missing on disk" in body
    assert "Restore rule file" in body


def test_rules_view_post_recreates_a_missing_file_in_place(app, client, tmp_path):
    admin = make_admin()
    login(client, admin)
    rule = _gone_rule(admin.id, tmp_path)
    task = Tasks(name="uses-rule", hc_attackmode=0, owner_id=admin.id, rule_id=rule.id)
    db.session.add(task)
    db.session.commit()
    rule_id, basename = rule.id, os.path.basename(rule.path)

    resp = client.post(f"/rules/edit/{rule.id}", data={"content": ":\nl\nu\n"},
                       follow_redirects=True)
    assert b"Rule file restored" in resp.data

    restored = Rules.query.get(rule_id)
    assert restored.id == rule_id                       # same row
    assert os.path.basename(restored.path) == basename  # same filename
    assert rule_file_missing(restored) is False
    assert restored.size == 3
    assert Tasks.query.get(task.id).rule_id == rule_id  # reference intact
    os.remove(restored.path)


def test_rules_view_write_is_confined_to_the_control_dir(app, client, tmp_path):
    """The route can now CREATE a file, so a crafted/legacy stored path must not
    be able to write outside control/rules -- and the row self-heals to the
    normalized absolute path."""
    admin = make_admin()
    login(client, admin)
    outside = tmp_path / "escape.rule"
    rule = Rules(name="escapee", owner_id=admin.id, path=str(outside),
                 size=1, checksum="c" * 64)
    db.session.add(rule)
    db.session.commit()

    client.post(f"/rules/edit/{rule.id}", data={"content": "$1\n"})

    restored = Rules.query.get(rule.id)
    assert not outside.exists()
    assert restored.path == os.path.join(app.root_path, 'control/rules', 'escape.rule')
    os.remove(restored.path)


def test_rules_view_post_on_a_present_file_is_still_an_edit(app, client):
    """The normal edit path keeps its own flash and audit verb."""
    admin = make_admin()
    login(client, admin)
    rule = make_rule_with_file(admin.id, content=b"$1\n")

    resp = client.post(f"/rules/edit/{rule.id}", data={"content": "$1\n$2\n"},
                       follow_redirects=True)
    assert b"Rule file updated" in resp.data
    assert Rules.query.get(rule.id).size == 2


# ------------------------------------------------------ POST /rules/<id>/restore

def test_rules_restore_upload_keeps_row_id_and_path(app, client, tmp_path):
    admin = make_admin()
    login(client, admin)
    rule = _gone_rule(admin.id, tmp_path)
    rule_id, basename = rule.id, os.path.basename(rule.path)

    resp = client.post(f"/rules/{rule.id}/restore",
                       data={"rules": _upload(b"$1\n$2\n$3\n", "anything.rule")},
                       content_type="multipart/form-data", follow_redirects=True)
    assert b"Rule file restored" in resp.data

    restored = Rules.query.get(rule_id)
    assert os.path.basename(restored.path) == basename
    assert rule_file_missing(restored) is False
    assert restored.size == 3
    os.remove(restored.path)


@pytest.mark.security
def test_rules_restore_denied_for_a_non_owner(app, client, tmp_path):
    owner = make_admin()
    other = make_user()
    login(client, other)
    rule = _gone_rule(owner.id, tmp_path)

    resp = client.post(f"/rules/{rule.id}/restore",
                       data={"rules": _upload(b"$1\n", "x.rule")},
                       content_type="multipart/form-data", follow_redirects=True)
    assert b"Unauthorized action!" in resp.data
    assert rule_file_missing(Rules.query.get(rule.id)) is True


def test_rules_restore_missing_row_flashes_and_redirects(app, client):
    admin = make_admin()
    login(client, admin)
    resp = client.post("/rules/999999/restore",
                       data={"rules": _upload(b"$1\n", "x.rule")},
                       content_type="multipart/form-data", follow_redirects=True)
    assert b"Rule not found" in resp.data


def test_rules_restore_without_a_file_is_refused(app, client, tmp_path):
    admin = make_admin()
    login(client, admin)
    rule = _gone_rule(admin.id, tmp_path)

    resp = client.post(f"/rules/{rule.id}/restore", data={},
                       content_type="multipart/form-data", follow_redirects=True)
    assert b"Please choose a .rule file" in resp.data
    assert rule_file_missing(Rules.query.get(rule.id)) is True


# -------------------------------------------------- POST /wordlists/<id>/restore

def test_wordlists_restore_upload_keeps_row_id_and_path(app, client):
    """The .gz basename is preserved, which is what keeps build_hashcat_command
    emitting the identical agent-side path across a restore."""
    admin = make_admin()
    login(client, admin)
    wl = make_wordlist_with_file(admin.id, content=b"old\n")
    task = Tasks(name="uses-wl", hc_attackmode=0, owner_id=admin.id, wl_id=wl.id)
    db.session.add(task)
    db.session.commit()
    wl_id, basename = wl.id, os.path.basename(wl.path)
    os.remove(wl.path)                                   # strand it
    assert wordlist_file_missing(Wordlists.query.get(wl_id)) is True

    resp = client.post(f"/wordlists/{wl_id}/restore",
                       data={"wordlist": _upload(b"a\nb\nc\n", "rockyou.txt")},
                       content_type="multipart/form-data", follow_redirects=True)
    assert b"Wordlist file restored" in resp.data

    restored = Wordlists.query.get(wl_id)
    assert os.path.basename(restored.path) == basename
    assert wordlist_file_missing(restored) is False
    assert restored.size == 3
    assert restored.byte_size == os.path.getsize(restored.path)
    with gzip.open(restored.path, "rb") as fh:           # stored compressed
        assert fh.read() == b"a\nb\nc\n"
    assert Tasks.query.get(task.id).wl_id == wl_id       # reference intact


def test_wordlists_restore_accepts_a_gzip_upload(app, client):
    admin = make_admin()
    login(client, admin)
    wl = make_wordlist_with_file(admin.id)
    gz = gzip.compress(b"x\ny\n")

    client.post(f"/wordlists/{wl.id}/restore",
                data={"wordlist": _upload(gz, "words.gz")},
                content_type="multipart/form-data", follow_redirects=True)
    assert Wordlists.query.get(wl.id).size == 2


def test_wordlists_restore_invalid_gzip_leaves_the_old_file_intact(app, client):
    """Staged under control/tmp and os.replace()d, so a rejected upload can
    never destroy a file that is still good."""
    admin = make_admin()
    login(client, admin)
    wl = make_wordlist_with_file(admin.id, content=b"keepme\n")
    before = open(wl.path, "rb").read()
    # gzip magic but a truncated/corrupt body
    bad = b"\x1f\x8b" + b"\x00" * 20

    resp = client.post(f"/wordlists/{wl.id}/restore",
                       data={"wordlist": _upload(bad, "bad.gz")},
                       content_type="multipart/form-data", follow_redirects=True)
    assert b"could not be restored" in resp.data
    assert open(wl.path, "rb").read() == before


def test_wordlists_restore_refuses_a_dynamic_list(app, client):
    """A dynamic list is generated from the database; there is nothing to restore."""
    admin = make_admin()
    login(client, admin)
    wl = make_wordlist_with_file(admin.id, name="(DYNAMIC) All Customers",
                                 content=b"", wl_type="dynamic")

    resp = client.post(f"/wordlists/{wl.id}/restore",
                       data={"wordlist": _upload(b"a\n", "x.txt")},
                       content_type="multipart/form-data", follow_redirects=True)
    assert b"can not be restored" in resp.data


@pytest.mark.security
def test_wordlists_restore_denied_for_a_non_owner(app, client):
    owner = make_admin()
    other = make_user()
    login(client, other)
    wl = make_wordlist_with_file(owner.id, content=b"keepme\n")
    before = open(wl.path, "rb").read()

    resp = client.post(f"/wordlists/{wl.id}/restore",
                       data={"wordlist": _upload(b"pwned\n", "x.txt")},
                       content_type="multipart/form-data", follow_redirects=True)
    assert b"Unauthorized Action!" in resp.data
    assert open(wl.path, "rb").read() == before


def test_wordlists_restore_missing_row_flashes_and_redirects(app, client):
    admin = make_admin()
    login(client, admin)
    resp = client.post("/wordlists/999999/restore",
                       data={"wordlist": _upload(b"a\n", "x.txt")},
                       content_type="multipart/form-data", follow_redirects=True)
    assert b"Wordlist not found" in resp.data
