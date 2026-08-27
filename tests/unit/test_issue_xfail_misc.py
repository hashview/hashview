"""Tests documenting GitHub issues (open ones as xfail, fixed ones as guards).

Tests for still-open issues assert the DESIRED behavior and are marked
``xfail(strict=False)`` so the suite stays green whether the bug is still
present (XFAIL) or has been fixed in the meantime (XPASS). Once an issue is
fixed and closed, its marker is dropped and the test runs as a plain
regression guard. They must always *collect* and *run* — never error — so
seeding is kept minimal and self-contained.

Style mirrors tests/unit/test_task_groups_routes.py / test_searches_routes.py.
"""

from configparser import ConfigParser

import pytest

from hashview.models import (
    Hashes,
    HashfileHashes,
    Hashfiles,
    Jobs,
    JobTasks,
    TaskGroups,
    Tasks,
    db,
)
from tests.unit.helpers import login, make_admin, make_customer


def _task(owner, name="t"):
    t = Tasks(name=name, hc_attackmode=0, owner_id=owner.id)
    db.session.add(t)
    db.session.commit()
    return t


# ---------------------------------------------------------------------------
# Issue #100 (closed) — "Rename Task Group after creation"
# ---------------------------------------------------------------------------
def test_task_group_can_be_renamed_after_creation(app, client):
    """POSTing the edit form persists a new TaskGroups.name.

    The rename/edit route lives at hashview/task_groups/routes.py
    (``task_groups_edit`` at ~line 86, ``POST /task_groups/edit``).
    Regression guard for closed issue #100.
    """
    admin = make_admin()
    login(client, admin)
    t = _task(admin, "member")
    tg = TaskGroups(name="OldName", owner_id=admin.id, tasks=str([t.id]))
    db.session.add(tg)
    db.session.commit()
    tg_id = tg.id

    resp = client.post("/task_groups/edit", data={
        "group_id": tg_id,
        "name": "NewName",
        "task_ids": str(t.id),
        "submit": "Save",
    }, follow_redirects=False)
    assert resp.status_code in (301, 302)

    assert TaskGroups.query.get(tg_id).name == "NewName"


# ---------------------------------------------------------------------------
# Issue #57 — "DB password can not contain % character"
# ---------------------------------------------------------------------------
@pytest.mark.xfail(reason="issue #57: DB password cannot contain % character",
                   strict=False)
def test_db_password_with_percent_is_parsed():
    """A literal '%' in the DB password must survive ConfigParser parsing.

    hashview/config.py (lines ~5, ~19-24) builds a plain ``ConfigParser()``
    (which performs ``%`` interpolation) and then concatenates
    ``file_config['database']['password']`` straight into the SQLAlchemy URI.
    A literal '%' in the password trips ``InterpolationSyntaxError`` on read.

    This reproduces config.py's exact read path; do NOT modify config.py.
    Expected to XFAIL until config.py uses a raw/interpolation-free parser.
    """
    parser = ConfigParser()
    parser.read_dict({
        "database": {
            "username": "hashview",
            "password": "pa%word",
            "host": "localhost",
        },
    })

    # config.py concatenates this value directly — the access itself raises
    # configparser.InterpolationSyntaxError when the value contains a lone '%'.
    password = parser["database"]["password"]
    assert password == "pa%word"


# ---------------------------------------------------------------------------
# Issue #364 — "Move hashfile import to the background"
# ---------------------------------------------------------------------------
@pytest.mark.xfail(reason="issue #364: no persisted hashfile import status",
                   strict=True)
def test_hashfile_exposes_persisted_import_status(app):
    """The Hashfiles model should persist the state of a running import.

    Import runs synchronously inside the upload POST today, so progress is
    reported only by the client-side modal (guarded in
    test_jobs_assigned_hashfile.py). Once #364 moves the work to a
    background thread the response returns first and that modal can no
    longer observe the import — item 2 of #364 adds
    ``Hashfiles.import_status`` ('importing' -> 'ready' / 'failed') so job
    dispatch can gate on 'ready' and a poll endpoint can drive real
    progress.

    Strict so it fails loudly the moment the column lands, prompting a
    rewrite into a real assertion rather than lingering as a stale XPASS
    (which is exactly how the earlier #176 version of this test rotted).
    """
    hf = Hashfiles(name="big.txt", customer_id=1, owner_id=1)
    db.session.add(hf)
    db.session.commit()

    assert hasattr(hf, "import_status")


# ---------------------------------------------------------------------------
# Issue #99 (closed) — "Long task list not scrollable"
# ---------------------------------------------------------------------------
def test_job_task_selection_lists_all_tasks(app, client):
    """The job task-selection page renders every available task.

    Renders ``jobs_list_tasks`` (hashview/jobs/routes.py ~449,
    ``GET /jobs/<id>/tasks``) with ~25 seeded Tasks and asserts each task
    name appears, i.e. no server-side truncation of the list.

    NOTE: the real issue #99 was a CSS/scroll-container problem in the
    template — a front-end concern only partially unit-testable; this
    guards the server-side half (the full set of task names is emitted).
    Regression guard for closed issue #99.
    """
    admin = make_admin()
    login(client, admin)

    names = [f"task_{i:02d}" for i in range(25)]
    for n in names:
        _task(admin, n)

    job = Jobs(name="J", status="Ready", customer_id=1, owner_id=admin.id)
    db.session.add(job)
    db.session.commit()

    resp = client.get(f"/jobs/{job.id}/tasks")
    assert resp.status_code == 200
    for n in names:
        assert n.encode() in resp.data


# ---------------------------------------------------------------------------
# Issue #379 — "'I'm Feeling Lucky — top 5' button actually adds top 10 tasks"
#
# Resolved as: the button label was wrong, not the backend. The backend's
# limit(10) plus flash message ("Successfully Added Top 10 Tasks") were
# already the intended behavior — display the top 10 historically effective
# tasks, or fewer if fewer exist. The button label was updated from "top 5"
# to "top 10" (jobs_assigned_tasks.html.j2) to match. This test locks in the
# "fewer than 10 available -> assign all of them" case with a count (7)
# between the previous mismatched labels (5 and 10), complementing the
# 2-task case in test_lucky_and_one_and_done.py and the 12-task overflow
# case in test_lucky_caps_at_ten_tasks_when_more_are_effective.
# ---------------------------------------------------------------------------
def test_lucky_assigns_all_when_fewer_than_ten_effective_tasks_exist(app, client):
    """``POST /jobs/<id>/assign_task/lucky`` assigns all effective tasks when
    fewer than 10 exist, rather than requiring exactly 10.

    Seeds 7 historically effective tasks (more than 5, fewer than the
    limit(10) in jobs/routes.py ~620) for the job's hash_type and asserts
    all 7 are assigned.
    """
    admin = make_admin()
    login(client, admin)
    cust = make_customer()

    hf = Hashfiles(name="hf", customer_id=cust.id, owner_id=admin.id)
    db.session.add(hf)
    db.session.commit()

    target_hash = Hashes(
        sub_ciphertext="0" * 32,
        ciphertext="AAA",
        hash_type=1000,
        cracked=False,
    )
    db.session.add(target_hash)
    db.session.commit()

    db.session.add(HashfileHashes(hash_id=target_hash.id, hashfile_id=hf.id))
    db.session.commit()

    # Seven distinct tasks, each with a decreasing but distinct crack count
    # of hash_type=1000, so the "most effective" ordering is unambiguous.
    tasks = [_task(admin, f"T{i}") for i in range(7)]
    for rank, t in enumerate(tasks):
        crack_count = 7 - rank
        for i in range(crack_count):
            db.session.add(
                Hashes(
                    sub_ciphertext=f"{rank}{i:031x}",
                    ciphertext=f"T{rank}-CT-{i}",
                    hash_type=1000,
                    cracked=True,
                    task_id=t.id,
                )
            )
    db.session.commit()

    job = Jobs(
        name="J",
        owner_id=admin.id,
        customer_id=cust.id,
        hashfile_id=hf.id,
        status="Ready",
    )
    db.session.add(job)
    db.session.commit()

    resp = client.post(
        f"/jobs/{job.id}/assign_task/lucky",
        follow_redirects=False,
    )
    assert resp.status_code in (301, 302, 303, 307, 308)

    job_tasks = JobTasks.query.filter_by(job_id=job.id).all()
    assert len(job_tasks) == 7
    assert {jt.task_id for jt in job_tasks} == {t.id for t in tasks}
