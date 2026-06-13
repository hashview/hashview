"""Behavior-pinning tests for the per-attack-mode branches of ``task_edit``.

``tasks_edit`` has a separate persistence block for each hashcat attack mode
(0 straight, 1 combinator, 3 mask, 6/7 hybrid). The guard tests in
``test_tasks_routes_guards.py`` only exercise mode 0; the other branches were
uncovered. These tests drive an edit POST in each mode and assert the task row
is persisted correctly, plus the GET pre-population path.

Tests only — no production code is changed. The known combinator ``j_rule`` /
``k_rule`` bug (trailing commas at routes.py store a 1-tuple instead of the
submitted string) is captured as an ``xfail`` so the suite stays green while
documenting the defect; remove the marker once the route is fixed.
"""

import pytest

from hashview.models import Rules, Tasks, Users, Wordlists, db


def _user(admin=False, email="owner@example.com"):
    u = Users(first_name="Ed", last_name="Itor", email_address=email,
              password="x" * 60, admin=admin)
    db.session.add(u)
    db.session.commit()
    return u


def _login(client, user):
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True


def _wordlist(owner_id, name):
    wl = Wordlists(name=name, owner_id=owner_id, type="static",
                   path=f"control/wordlists/{name}.gz", size=10,
                   checksum="0" * 64)
    db.session.add(wl)
    db.session.commit()
    return wl


def _rule(owner_id, name="rule-edit"):
    r = Rules(name=name, owner_id=owner_id, path="control/rules/r.rule",
              checksum="1" * 64, size=1)
    db.session.add(r)
    db.session.commit()
    return r


def _task(owner_id, **kw):
    defaults = dict(name="orig", hc_attackmode=0, wl_id=None, rule_id=None,
                    loopback=False)
    defaults.update(kw)
    t = Tasks(owner_id=owner_id, **defaults)
    db.session.add(t)
    db.session.commit()
    return t


# ----------------------------------------------------- mode 0 (straight) edit

def test_edit_mode0_with_rule_and_loopback(app, client):
    user = _user()
    _login(client, user)
    wl = _wordlist(user.id, "wl0")
    rule = _rule(user.id)
    task = _task(user.id, name="m0", wl_id=wl.id, hc_attackmode=0)

    resp = client.post(
        f"/tasks/edit/{task.id}",
        data={"name": "m0-edited", "hc_attackmode": "0", "wl_id": str(wl.id),
              "wl_id_2": str(wl.id), "rule_id": str(rule.id), "loopback": "y"},
        follow_redirects=False,
    )
    assert resp.status_code in (301, 302)
    edited = Tasks.query.get(task.id)
    assert edited.name == "m0-edited"
    assert edited.wl_id == wl.id
    assert str(edited.rule_id) == str(rule.id)
    assert edited.hc_attackmode == 0
    assert edited.hc_mask is None
    assert edited.loopback is True


# ----------------------------------------------------- mode 1 (combinator) edit

@pytest.mark.xfail(
    reason="Combinator edit is broken in tasks/routes.py: the trailing commas in "
           "`task.j_rule=tasksForm.j_rule.data,` / `task.k_rule=...,` assign a "
           "1-tuple to a String(25) column, so the commit raises (sqlite: "
           "ProgrammingError 'type tuple is not supported'; MySQL fails likewise) "
           "and the whole edit POST 500s. Production fix is out of scope for this "
           "tests-only change; remove this marker once routes.py drops the commas.",
    strict=True,
)
def test_edit_mode1_combinator_persists(app, client):
    """Intended behavior: editing a task to combinator mode persists wordlists
    and the -j/-k rules as plain strings. Currently raises on commit (see xfail)."""
    user = _user()
    _login(client, user)
    wl1 = _wordlist(user.id, "wlA")
    wl2 = _wordlist(user.id, "wlB")
    task = _task(user.id, name="m1", wl_id=wl1.id, hc_attackmode=0)

    resp = client.post(
        f"/tasks/edit/{task.id}",
        data={"name": "m1-edited", "hc_attackmode": "1", "wl_id": str(wl1.id),
              "wl_id_2": str(wl2.id), "rule_id": "None",
              "j_rule": "$-", "k_rule": "$!"},
        follow_redirects=False,
    )
    assert resp.status_code in (301, 302)
    edited = Tasks.query.get(task.id)
    assert edited.name == "m1-edited"
    assert edited.hc_attackmode == 1
    assert edited.wl_id == wl1.id
    assert edited.wl_id_2 == wl2.id
    assert edited.j_rule == "$-"
    assert edited.k_rule == "$!"


# ---------------------------------------------------------- mode 3 (mask) edit

def test_edit_mode3_mask(app, client):
    user = _user()
    _login(client, user)
    wl = _wordlist(user.id, "wl3")
    task = _task(user.id, name="m3", wl_id=wl.id, hc_attackmode=0)

    resp = client.post(
        f"/tasks/edit/{task.id}",
        data={"name": "m3-edited", "hc_attackmode": "3", "wl_id": str(wl.id),
              "wl_id_2": str(wl.id), "rule_id": "None", "mask": "?a?a?a?a"},
        follow_redirects=False,
    )
    assert resp.status_code in (301, 302)
    edited = Tasks.query.get(task.id)
    assert edited.name == "m3-edited"
    assert edited.hc_attackmode == 3
    assert edited.hc_mask == "?a?a?a?a"
    assert edited.wl_id is None
    assert edited.rule_id is None
    assert edited.loopback is False


# ---------------------------------------------- modes 6 / 7 (hybrid) edit

@pytest.mark.parametrize("mode", ["6", "7"])
def test_edit_hybrid_modes(app, client, mode):
    user = _user(email=f"hy{mode}@example.com")
    _login(client, user)
    wl = _wordlist(user.id, f"wl{mode}")
    task = _task(user.id, name=f"m{mode}", wl_id=wl.id, hc_attackmode=0)

    resp = client.post(
        f"/tasks/edit/{task.id}",
        data={"name": f"m{mode}-edited", "hc_attackmode": mode,
              "wl_id": str(wl.id), "wl_id_2": str(wl.id), "rule_id": "None",
              "mask": "?d?d?d"},
        follow_redirects=False,
    )
    assert resp.status_code in (301, 302)
    edited = Tasks.query.get(task.id)
    assert edited.name == f"m{mode}-edited"
    assert edited.hc_attackmode == int(mode)
    assert edited.wl_id == wl.id
    assert edited.hc_mask == "?d?d?d"
    assert edited.rule_id is None
    assert edited.loopback is False


# ------------------------------------------------------------- GET (pre-fill)

def test_edit_get_prefills_form(app, client):
    user = _user()
    _login(client, user)
    wl = _wordlist(user.id, "wlget")
    task = _task(user.id, name="prefill-me", wl_id=wl.id, hc_attackmode=0)

    resp = client.get(f"/tasks/edit/{task.id}")
    assert resp.status_code == 200
    assert b"prefill-me" in resp.data
