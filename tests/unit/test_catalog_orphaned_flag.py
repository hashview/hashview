"""`orphaned` on the /v1 catalog listings: missing AND unreferenced (#494).

The flag a scripted cleanup needs, and the same predicate the scheduler's prune
uses — one shared implementation in utils, so the API can never disagree with
what the sweep is about to delete.

Additive key alongside `missing`, so no agent version bump: an old agent ignores
it exactly as it ignored `missing` before 5194dab.
"""
import secrets

from hashview.models import Rules, Tasks, Wordlists
from hashview.models import db as _db
from hashview.utils.utils import (
    catalog_task_references,
    orphaned_rule_ids,
    orphaned_wordlist_ids,
)
from tests.unit.helpers import make_admin, make_rule_with_file, make_wordlist_with_file


def _gone_rule(owner_id, tmp_path, name="gone.rule"):
    rule = Rules(name=name, owner_id=owner_id, path=str(tmp_path / name),
                 size=1, checksum="c" * 64)
    _db.session.add(rule)
    _db.session.commit()
    return rule


def _gone_wordlist(owner_id, tmp_path, name="gone.gz", wl_type="static"):
    wl = Wordlists(name=name, owner_id=owner_id, type=wl_type,
                   path=str(tmp_path / name), size=1, byte_size=1, checksum="c" * 64)
    _db.session.add(wl)
    _db.session.commit()
    return wl


def _task(**kwargs):
    task = Tasks(name="t", hc_attackmode="dictionary", hc_mask="", owner_id=1, **kwargs)
    _db.session.add(task)
    _db.session.commit()
    return task


def _api_client(client):
    admin = make_admin()
    admin.api_key = "api-key-" + secrets.token_hex(4)
    _db.session.commit()
    client.set_cookie("uuid", admin.api_key, domain="localhost.test")
    return admin


# ------------------------------------------------------------ the shared helper

def test_task_references_include_wl_id_2(app, tmp_path):
    admin = make_admin()
    first = _gone_wordlist(admin.id, tmp_path, name="a.gz")
    second = _gone_wordlist(admin.id, tmp_path, name="b.gz")
    task = _task(wl_id=first.id, wl_id_2=second.id)

    _, by_wordlist = catalog_task_references(wordlist_ids={first.id, second.id})
    assert by_wordlist[first.id] == {task.id}
    assert by_wordlist[second.id] == {task.id}


def test_orphaned_is_missing_and_unreferenced(app, tmp_path):
    admin = make_admin()
    orphan = _gone_rule(admin.id, tmp_path, name="orphan.rule")
    referenced = _gone_rule(admin.id, tmp_path, name="used.rule")
    present = make_rule_with_file(admin.id)
    _task(rule_id=referenced.id)

    ids = orphaned_rule_ids()
    assert orphan.id in ids
    assert referenced.id not in ids          # a task still needs a decision
    assert present.id not in ids             # nothing wrong with it


def test_a_dynamic_wordlist_is_never_orphaned(app, tmp_path):
    """Its file is a regenerable cache, so it is never 'missing' to begin with."""
    admin = make_admin()
    wl = _gone_wordlist(admin.id, tmp_path, wl_type="dynamic")
    assert wl.id not in orphaned_wordlist_ids()


def test_no_queries_when_nothing_is_missing(app, monkeypatch):
    """The listings call this on every GET; a healthy catalog must not pay for a
    task scan it can skip."""
    admin = make_admin()
    make_rule_with_file(admin.id)
    called = []
    monkeypatch.setattr("hashview.utils.utils.catalog_task_references",
                        lambda *a, **kw: called.append(1) or ({}, {}))
    assert orphaned_rule_ids() == set()
    assert called == []


# ---------------------------------------------------------------- the /v1 rows

def test_v1_rules_flags_orphaned(app, client, tmp_path):
    admin = _api_client(client)
    orphan = _gone_rule(admin.id, tmp_path, name="orphan.rule")
    referenced = _gone_rule(admin.id, tmp_path, name="used.rule")
    present = make_rule_with_file(admin.id)
    _task(rule_id=referenced.id)

    rows = {r["id"]: r for r in client.get("/v1/rules").get_json()["rules"]}
    assert rows[orphan.id]["missing"] is True and rows[orphan.id]["orphaned"] is True
    assert rows[referenced.id]["missing"] is True and rows[referenced.id]["orphaned"] is False
    assert rows[present.id]["missing"] is False and rows[present.id]["orphaned"] is False


def test_v1_wordlists_flags_orphaned(app, client, tmp_path):
    admin = _api_client(client)
    orphan = _gone_wordlist(admin.id, tmp_path, name="orphan.gz")
    referenced = _gone_wordlist(admin.id, tmp_path, name="used.gz")
    present = make_wordlist_with_file(admin.id, name="present.gz")
    _task(wl_id_2=referenced.id)                       # the combinator trap

    rows = {r["id"]: r for r in client.get("/v1/wordlists").get_json()["wordlists"]}
    assert rows[orphan.id]["orphaned"] is True
    assert rows[referenced.id]["orphaned"] is False
    assert rows[present.id]["orphaned"] is False
