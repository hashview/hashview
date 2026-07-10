"""Regression tests for tasks routes + form (function-coverage batch)."""

import pytest
from wtforms.validators import ValidationError

from hashview.models import Tasks, Wordlists, db
from hashview.tasks.forms import TasksForm
from tests.unit.helpers import login, make_admin


def _wordlist(owner, name="wl"):
    wl = Wordlists(name=name, owner_id=owner.id, type="static",
                   path="/nonexistent/wl.gz", size=1, checksum="0" * 64)
    db.session.add(wl)
    db.session.commit()
    return wl


def test_human_size_formats():
    from hashview.tasks.routes import _human_size
    assert _human_size(0) == "0 B"
    assert _human_size(512) == "512 B"
    assert _human_size(1024) == "1 KB"
    assert _human_size(1536) == "1.5 KB"
    assert _human_size(1024 * 1024) == "1 MB"


def test_tasks_list_renders(app, client):
    admin = make_admin()
    login(client, admin)
    t = Tasks(name="ListedTask", hc_attackmode=0, owner_id=admin.id)
    db.session.add(t)
    db.session.commit()
    resp = client.get("/tasks")
    assert resp.status_code == 200
    assert b"ListedTask" in resp.data


def test_tasks_add_creates_straight_task(app, client):
    admin = make_admin()
    login(client, admin)
    wl = _wordlist(admin)
    # Both wordlist selects render with a chosen option in the real form, so a
    # valid submission carries wl_id and wl_id_2 even for a straight attack.
    resp = client.post("/tasks/add", data={
        "name": "StraightTask", "hc_attackmode": "0",
        "wl_id": str(wl.id), "wl_id_2": str(wl.id),
        "rule_id": "None", "submit": "Create",
    }, follow_redirects=False)
    assert resp.status_code in (301, 302)
    task = Tasks.query.filter_by(name="StraightTask").first()
    assert task is not None
    assert task.hc_attackmode == 0
    assert task.wl_id == wl.id
    assert task.rule_id is None


def test_tasks_add_mask_mode(app, client):
    admin = make_admin()
    login(client, admin)
    wl = _wordlist(admin)
    resp = client.post("/tasks/add", data={
        "name": "MaskTask", "hc_attackmode": "3",
        "wl_id": str(wl.id), "wl_id_2": str(wl.id),
        "mask": "?d?d?d?d", "rule_id": "None", "submit": "Create",
    }, follow_redirects=False)
    assert resp.status_code in (301, 302)
    task = Tasks.query.filter_by(name="MaskTask").first()
    assert task is not None and task.hc_attackmode == 3
    assert task.hc_mask == "?d?d?d?d"


def test_validate_task_rejects_duplicate(app):
    admin = make_admin()
    db.session.add(Tasks(name="Dup", hc_attackmode=0, owner_id=admin.id))
    db.session.commit()
    form = TasksForm()

    class _Field:
        data = "Dup"

    with pytest.raises(ValidationError):
        form.validate_name(_Field())
