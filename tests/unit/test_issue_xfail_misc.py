"""xfail tests documenting open GitHub issues.

Each test asserts the DESIRED behavior and is marked ``xfail(strict=False)``
so the suite stays green whether the bug is still present (XFAIL) or has been
fixed in the meantime (XPASS). They must always *collect* and *run* — never
error — so seeding is kept minimal and self-contained.

Style mirrors tests/unit/test_task_groups_routes.py / test_searches_routes.py.
"""

from configparser import ConfigParser

import pytest

from hashview.models import (
    Hashes,
    HashfileHashes,
    Hashfiles,
    JobTasks,
    Jobs,
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
# Issue #100 — "Rename Task Group after creation"
# ---------------------------------------------------------------------------
@pytest.mark.xfail(reason="issue #100: rename task group after creation",
                   strict=False)
def test_task_group_can_be_renamed_after_creation(app, client):
    """POSTing the edit form should persist a new TaskGroups.name.

    The rename/edit route lives at hashview/task_groups/routes.py
    (``task_groups_edit`` at ~line 86, ``POST /task_groups/edit``). This is
    implemented today, so the test is expected to XPASS.
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
# Issue #99 — "Long task list not scrollable"
# ---------------------------------------------------------------------------
@pytest.mark.xfail(reason="issue #99: long task list not scrollable",
                   strict=False)
def test_job_task_selection_lists_all_tasks(app, client):
    """The job task-selection page should render every available task.

    Renders ``jobs_list_tasks`` (hashview/jobs/routes.py ~449,
    ``GET /jobs/<id>/tasks``) with ~25 seeded Tasks and asserts each task
    name appears, i.e. no server-side truncation of the list.

    NOTE: the real issue #99 is a CSS/scroll-container problem in the
    template — the long list overflows without a scrollbar. That is a
    front-end concern and only partially unit-testable; here we can only
    verify the server emits the full set of task names. Expected to XPASS.
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
# Issue #176 — "Status indicator for large hashfile imports"
# ---------------------------------------------------------------------------
@pytest.mark.xfail(reason="issue #176: status indicator for large hashfile imports",
                   strict=False)
def test_hashfile_exposes_import_status(app):
    """The Hashfiles model should expose an import status/progress field.

    Today the Hashfiles model (hashview/models.py ~197-205) has only
    id/name/uploaded_at/runtime/customer_id/owner_id — there is no column
    surfacing the progress of a long-running import, so the UI has nothing
    to render a status indicator from. Expected to XFAIL until such a field
    is added (and a corresponding indicator wired into the upload UI).
    """
    hf = Hashfiles(name="big.txt", customer_id=1, owner_id=1)
    db.session.add(hf)
    db.session.commit()

    assert any(hasattr(hf, attr)
               for attr in ("status", "import_status", "progress"))


# ---------------------------------------------------------------------------
# Issue #379 — "'I'm Feeling Lucky — top 5' button actually adds top 10 tasks"
# ---------------------------------------------------------------------------
@pytest.mark.xfail(
    reason="issue #379: lucky button says 'top 5' but backend limit(10) adds up to 10",
    strict=False,
)
def test_lucky_task_assignment_adds_at_most_five_tasks(app, client):
    """``POST /jobs/<id>/assign_task/lucky`` should honor the "top 5" label.

    hashview/jobs/routes.py ~598 (``jobs_assign_lucky_task_group``) queries
    the most effective historical tasks with ``.limit(10)`` (~line 620) and
    even flashes "Successfully Added Top 10 Tasks" (~line 634), while the
    button in jobs_assigned_tasks.html.j2:73 promises "top 5". Seed 7
    historically effective tasks (more than 5, within today's limit of 10)
    for the job's hash_type and assert only 5 get assigned. Expected to
    XFAIL until the button label, query limit, and flash message agree.
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
    assert len(job_tasks) == 5
