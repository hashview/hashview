"""Regression tests for small-module helpers + routes (function-coverage batch).

Covers rules._rule_ttype/rules_add, wordlists._wl_ttype/dynamicwordlist_update,
settings._human_size + the two SettingsForm validators, and the hashfiles
_runtime nested helper (exercised by rendering /hashfiles).
"""

import io

import pytest
from wtforms.validators import ValidationError

from hashview.models import Hashfiles, Jobs, Rules, Tasks, Wordlists, db
from tests.unit.helpers import login, make_admin, make_customer


class _FakeTask:
    def __init__(self, hc_attackmode, rule_id=None):
        self.hc_attackmode = hc_attackmode
        self.rule_id = rule_id


# --- rules._rule_ttype / wordlists._wl_ttype --------------------------------

def test_rule_ttype_labels():
    from hashview.rules.routes import _rule_ttype
    assert _rule_ttype(_FakeTask(0, rule_id=5)) == "DICT + RULE"
    assert _rule_ttype(_FakeTask(0)) == "DICTIONARY"
    assert _rule_ttype(_FakeTask(1)) == "COMBINATOR"
    assert _rule_ttype(_FakeTask(3)) == "MASK"
    assert _rule_ttype(_FakeTask(6)) == "HYBRID"
    assert _rule_ttype(_FakeTask(99)) == "?"


def test_wl_ttype_labels():
    from hashview.wordlists.routes import _wl_ttype
    assert _wl_ttype(_FakeTask(0, rule_id=5)) == "DICT + RULE"
    assert _wl_ttype(_FakeTask(0)) == "DICTIONARY"
    assert _wl_ttype(_FakeTask(7)) == "HYBRID"
    assert _wl_ttype(_FakeTask(42)) == "?"


# --- settings._human_size ---------------------------------------------------

def test_settings_human_size():
    from hashview.settings.routes import _human_size
    assert _human_size(0) == "0 B"
    assert _human_size(512) == "512 B"
    assert _human_size(1024) == "1 KB"
    assert _human_size(1536) == "1.5 KB"
    assert _human_size(1024 * 1024) == "1 MB"


# --- SettingsForm validators ------------------------------------------------

def test_validate_rention_period_range(app):
    from hashview.settings.forms import HashviewSettingsForm
    form = HashviewSettingsForm()

    class _F:
        def __init__(self, v):
            self.data = v

    with pytest.raises(ValidationError):
        form.validate_rention_period(_F(0))
    with pytest.raises(ValidationError):
        form.validate_rention_period(_F(70000))
    assert form.validate_rention_period(_F(30)) is None


def test_validate_max_runtime_range(app):
    from hashview.settings.forms import HashviewSettingsForm
    form = HashviewSettingsForm()
    with pytest.raises(ValidationError):
        form.validate_max_runtime(-1, 0)
    with pytest.raises(ValidationError):
        form.validate_max_runtime(0, 70000)
    assert form.validate_max_runtime(5, 5) is None


# --- rules_add (upload) -----------------------------------------------------

def test_rules_add_creates_rule(app, client):
    admin = make_admin()
    login(client, admin)
    resp = client.post("/rules/add", data={
        "name": "MyRule",
        "rules": (io.BytesIO(b":\n$1\n"), "my.rule"),
        "submit": "upload",
    }, content_type="multipart/form-data", follow_redirects=False)
    assert resp.status_code in (301, 302)
    rule = Rules.query.filter_by(name="MyRule").first()
    assert rule is not None


# --- dynamicwordlist_update -------------------------------------------------

def test_dynamicwordlist_update_triggers_regen(app, client, monkeypatch):
    admin = make_admin()
    login(client, admin)
    wl = Wordlists(name="(DYNAMIC) All Usernames", owner_id=admin.id, type="dynamic",
                   path="/nonexistent/dyn.txt", size=0, checksum="0" * 64)
    db.session.add(wl)
    db.session.commit()
    calls = []
    monkeypatch.setattr("hashview.wordlists.routes.update_dynamic_wordlist",
                        lambda wid: calls.append(wid))
    resp = client.get(f"/wordlists/update/{wl.id}", follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert calls == [wl.id]


def test_dynamicwordlist_update_rejects_static(app, client, monkeypatch):
    admin = make_admin()
    login(client, admin)
    wl = Wordlists(name="static-wl", owner_id=admin.id, type="static",
                   path="/nonexistent/s.gz", size=1, checksum="0" * 64)
    db.session.add(wl)
    db.session.commit()
    calls = []
    monkeypatch.setattr("hashview.wordlists.routes.update_dynamic_wordlist",
                        lambda wid: calls.append(wid))
    resp = client.get(f"/wordlists/update/{wl.id}", follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert calls == []  # static wordlists are not regenerated


# --- hashfiles._runtime (nested helper) -------------------------------------

def test_hashfiles_list_runs_runtime_helper(app, client):
    from datetime import datetime
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    hf = Hashfiles(name="rf", customer_id=cust.id, owner_id=admin.id)
    db.session.add(hf)
    db.session.commit()
    # A job referencing this hashfile with a start time drives _runtime(j).
    job = Jobs(name="rj", status="Running", customer_id=cust.id, owner_id=admin.id,
               hashfile_id=hf.id, started_at=datetime(2024, 1, 1, 10, 0, 0))
    db.session.add(job)
    db.session.commit()
    resp = client.get("/hashfiles")
    assert resp.status_code == 200


def test_hashfiles_list_batched_stats(app, client):
    """/hashfiles computes per-hashfile cracked/total in ONE grouped query.
    Pin the numbers (1 of 4 -> '/ 4 recovered', 25%) and that an empty hashfile
    still renders (UNKNOWN, 0 total) without error."""
    from hashview.models import Hashes, HashfileHashes
    admin = make_admin()
    login(client, admin)
    cust = make_customer()

    hf = Hashfiles(name="hf-stats", customer_id=cust.id, owner_id=admin.id)
    empty = Hashfiles(name="hf-empty", customer_id=cust.id, owner_id=admin.id)
    db.session.add_all([hf, empty])
    db.session.commit()
    for i in range(4):
        h = Hashes(sub_ciphertext=("s" + str(i)).ljust(8, "0")[:8], ciphertext="c",
                   hash_type=1000, cracked=(i == 0), plaintext="pw" if i == 0 else None)
        db.session.add(h)
        db.session.commit()
        db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    db.session.commit()

    resp = client.get("/hashfiles")
    assert resp.status_code == 200
    assert b"/ 4 recovered" in resp.data   # total from the batched COUNT
    assert b"(25%)" in resp.data           # pct from the batched cracked SUM
    assert b"hf-empty" in resp.data        # empty hashfile still rendered
    assert b"UNKNOWN" in resp.data         # ... with the no-hashes type fallback
