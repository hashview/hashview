"""The jobs list's per-job info modal lists the job's assigned tasks.

Two things are being pinned here. The obvious one: every attack assigned to a
job shows up in that job's modal, with a status. The load-bearing one: that
status comes from the SAME derivation the dashboard uses for its per-task rows
(utils.derive_attack_status), so one attack can never read 'Canceled' on
/dashboard and 'Completed' on /jobs. The precedence in that ladder is a pile of
fixed bugs; a second hand-rolled copy on this page would re-introduce them one at
a time.
"""

import pytest
from sqlalchemy import event

from hashview.main.routes import _job_task_groups
from hashview.models import (
    Agents,
    Customers,
    Jobs,
    JobTaskLedger,
    JobTasks,
    Tasks,
    db,
)
from hashview.utils.utils import job_assignments
from tests.unit.helpers import login, make_admin, make_customer


def _job(owner, customer, status="Ready", name="j1"):
    job = Jobs(name=name, status=status, owner_id=owner.id,
               customer_id=customer.id)
    db.session.add(job)
    db.session.commit()
    return job


def _task(owner, name):
    t = Tasks(name=name, hc_attackmode=0, owner_id=owner.id)
    db.session.add(t)
    db.session.commit()
    return t


def _attack(job, task, statuses, position=0, state="Closed",
            keyspace=100, keyspace_pos=100):
    """One queued attack: a ledger row plus a dispatch row per status."""
    ledger = JobTaskLedger(job_id=job.id, task_id=task.id, position=position,
                           state=state, keyspace=keyspace,
                           keyspace_pos=keyspace_pos, chunkable=True)
    db.session.add(ledger)
    db.session.commit()
    for n, status in enumerate(statuses, start=1):
        db.session.add(JobTasks(job_id=job.id, task_id=task.id, status=status,
                                priority=3, ledger_id=ledger.id, chunk_no=n,
                                chunk_skip=(n - 1) * 10, chunk_limit=10,
                                chunk_keyspace=10))
    db.session.commit()
    return ledger


def _modal_status(job):
    """The status the modal renders for this job's single attack."""
    return job_assignments([job.id])[job.id][0]["status"]


def _dashboard_status(job):
    groups = _job_task_groups([job], JobTasks.query.filter_by(job_id=job.id).all(),
                              {t.id: t for t in Tasks.query.all()},
                              {a.id: a for a in Agents.query.all()}, {}, {})
    return groups[job.id]["groups"][0]["status"]


def test_the_modal_lists_every_assigned_task_by_name(app, client):
    admin = make_admin()
    login(client, admin)
    job = _job(admin, make_customer(), name="listing-job")
    for name in ("Rockyou Straight", "Eight Digit Mask", "Combinator Pass"):
        db.session.add(JobTasks(job_id=job.id, task_id=_task(admin, name).id,
                                status="Not Started", priority=3))
    db.session.commit()

    body = client.get("/jobs").get_data(as_text=True)

    for name in ("Rockyou Straight", "Eight Digit Mask", "Combinator Pass"):
        assert name in body, f"{name} is assigned to the job but absent from its modal"


def test_an_unqueued_assignment_reads_not_started_not_queued(app, client):
    # The jobs list is the first page that shows attacks BEFORE the job is
    # started -- the dashboard only ever renders running jobs. Calling a row that
    # no agent has ever been offered 'Queued' claims work is waiting on the fleet.
    admin = make_admin()
    login(client, admin)
    # The JOB reads 'Ready', so the only thing on the page that can render a
    # NOT STARTED badge is the attack row itself.
    job = _job(admin, make_customer(), status="Ready", name="fresh-job")
    db.session.add(JobTasks(job_id=job.id, task_id=_task(admin, "Untouched").id,
                            status="Not Started", priority=3))
    db.session.commit()

    assert _modal_status(job) == "Not Started"
    assert "NOT STARTED" in client.get("/jobs").get_data(as_text=True)


def test_the_rendered_row_carries_the_derived_status_not_the_row_status(app, client):
    # End to end: a stopped attack whose chunks mostly finished first. The job
    # reads RUNNING and three of its four rows read Completed, so a CANCELED
    # badge on the page can only have come from the shared derivation.
    admin = make_admin()
    login(client, admin)
    job = _job(admin, make_customer(), status="Running", name="stopped-attack")
    _attack(job, _task(admin, "Stopped Attack"),
            ["Completed", "Completed", "Completed", "Canceled"])

    body = client.get("/jobs").get_data(as_text=True)

    assert "CANCELED" in body
    assert "COMPLETE" not in body.split("Stopped Attack")[1].split("</dialog>")[0]


@pytest.mark.parametrize("statuses, expected", [
    # The mixes that a naive count gets wrong. Each is a bug the dashboard ladder
    # already fixed once; the modal must inherit every one of them.
    (["Completed", "Completed", "Canceled"], "Canceled"),
    (["Completed", "Expired"], "Expired"),
    (["Canceled", "Expired"], "Expired"),
    (["Running", "Canceled"], "Running"),
    (["Queued", "Expired"], "Queued"),
    (["Completed", "Completed"], "Completed"),
])
def test_the_modal_status_is_the_dashboard_status(app, db_session, statuses, expected):
    owner = make_admin(email=f"{abs(hash(tuple(statuses)))}@e.com")
    cust = Customers(name=f"c{abs(hash(tuple(statuses)))}")
    db.session.add(cust)
    db.session.commit()
    job = _job(owner, cust, status="Running", name="drift")
    _attack(job, _task(owner, "T"), statuses)

    assert _modal_status(job) == expected
    assert _dashboard_status(job) == expected


def test_an_attack_between_slices_is_not_reported_complete(app, db_session):
    # Slices are minted on demand, so an attack's row set legitimately empties
    # mid-run. Reading that gap off the rows alone says 'Completed' and the modal
    # would report a job's work finished while most of its keyspace is un-run.
    owner = make_admin()
    cust = make_customer()
    job = _job(owner, cust, status="Running", name="midflight")
    _attack(job, _task(owner, "T"), ["Completed"], state="Ready",
            keyspace=100, keyspace_pos=40)

    assert _modal_status(job) == "Queued"
    assert _dashboard_status(job) == "Queued"


def test_a_long_task_list_is_capped_and_says_how_many_it_hid(app, client):
    # A task group can assign thousands of attacks, and this page renders 20
    # modals. Uncapped, one job's task list can be the whole response.
    admin = make_admin()
    login(client, admin)
    job = _job(admin, make_customer(), name="huge")
    for n in range(30):
        db.session.add(JobTasks(job_id=job.id,
                                task_id=_task(admin, "Attack %02d" % n).id,
                                status="Not Started", priority=3))
    db.session.commit()

    body = client.get("/jobs").get_data(as_text=True)

    assert "Attack 24" in body          # the 25th, last one shown
    assert "Attack 25" not in body      # the 26th, hidden
    assert "5 more" in body


def test_the_task_lists_do_not_go_n_plus_1(app, client):
    # 20 modals per page, each with its own task list: a per-job query here is 20
    # round trips on a page that already had its N+1 removed once.
    admin = make_admin()
    login(client, admin)
    cust = make_customer()

    def seed(n):
        job = _job(admin, cust, status="Running", name=f"job-{n}")
        _attack(job, _task(admin, f"T{n}"), ["Running", "Completed"])

    def selects():
        # Warm up first: flask_login's user lookup hits SQL only when the
        # identity map is cold, which would otherwise show up as a one-query
        # difference between the two measurements and has nothing to do with
        # how many jobs are on the page.
        client.get("/jobs")
        seen = []

        def record(conn, cursor, statement, parameters, context, executemany):
            seen.append(" ".join(statement.split()).lower())

        event.listen(db.engine, "before_cursor_execute", record)
        try:
            assert client.get("/jobs").status_code == 200
        finally:
            event.remove(db.engine, "before_cursor_execute", record)
        return len([s for s in seen if s.startswith("select")])

    for n in range(2):
        seed(n)
    with_two = selects()
    for n in range(2, 10):
        seed(n)
    with_ten = selects()

    assert with_ten == with_two, (
        f"/jobs issued {with_two} SELECTs for 2 jobs but {with_ten} for 10 -- "
        "the per-job task list is querying in a loop"
    )
