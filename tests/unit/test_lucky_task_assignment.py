"""A deleted task must never be assigned to a job.

`hashes.task_id` has no foreign key and outlives the task it names: tasks_delete
refuses only while the task is still referenced by a job or a task group, never
for the hashes it cracked. So the column routinely points at tasks that no longer
exist -- the reference instance has one such id carrying 224 cracked rows.

That id is read back by the "assign the top 10 tasks" action in both the web UI
and the API, and whatever it returns is written straight into JobTasks. The
listing and Wrapped pages deliberately label such a task "deleted" because they
only display it; here it must not appear at all. These tests pin that split, so
relaxing the INNER JOIN in top_effective_task_ids to surface deleted names cannot
pass unnoticed.
"""

import json

from hashview.models import (
    Customers,
    Hashes,
    HashfileHashes,
    Hashfiles,
    Jobs,
    JobTasks,
    TaskGroups,
    Tasks,
    Users,
    db,
)
from hashview.utils.utils import get_md5_hash, top_effective_task_ids

DELETED_TASK_ID = 4242          # never inserted into `tasks`


def _user(admin=True, email="a@e.com"):
    user = Users(first_name="A", last_name="B", email_address=email,
                 password="x" * 60, admin=admin, api_key=f"key-{email}")
    db.session.add(user)
    db.session.commit()
    return user


def _login(client, user):
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True


def _task(owner_id, name):
    task = Tasks(name=name, owner_id=owner_id, wl_id=None, rule_id=None,
                 hc_attackmode=0, loopback=False)
    db.session.add(task)
    db.session.commit()
    return task


def _recoveries(task_id, count, hash_type=1000, tag=""):
    """`count` cracked hashes attributed to `task_id`."""
    rows = []
    for i in range(count):
        ct = f"{tag}{task_id}-{i:05d}"
        rows.append(Hashes(sub_ciphertext=get_md5_hash(ct), ciphertext=ct,
                           hash_type=hash_type, cracked=True, plaintext="pw",
                           task_id=task_id))
    db.session.add_all(rows)
    db.session.commit()


def _job_with_hashfile(owner_id, hash_type=1000):
    cust = Customers(name="Acme")
    db.session.add(cust)
    db.session.commit()
    hf = Hashfiles(name="hf.txt", customer_id=cust.id, owner_id=owner_id)
    db.session.add(hf)
    db.session.commit()
    h = Hashes(sub_ciphertext=get_md5_hash("target"), ciphertext="target",
               hash_type=hash_type, cracked=False)
    db.session.add(h)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    job = Jobs(name="job", owner_id=owner_id, customer_id=cust.id,
               hashfile_id=hf.id, status="Not Started")
    db.session.add(job)
    db.session.commit()
    return job


#############################################
# The query itself
#############################################

def test_top_tasks_omits_a_task_that_no_longer_exists(app):
    """The deleted task is the most effective by a wide margin, so if the join
    ever stops excluding it, it lands at the top of the list."""
    user = _user()
    live = _task(user.id, "live")
    _recoveries(DELETED_TASK_ID, 50)          # deleted, but the biggest cracker
    _recoveries(live.id, 5)

    ids = top_effective_task_ids(1000)

    assert DELETED_TASK_ID not in ids
    assert ids == [live.id]


def test_top_tasks_orders_by_recoveries_and_honours_the_limit(app):
    """Guards against a fix that excludes deleted tasks by breaking the ranking."""
    user = _user()
    tasks = [_task(user.id, f"t{i}") for i in range(4)]
    for i, task in enumerate(tasks):
        _recoveries(task.id, (i + 1) * 3)
    _recoveries(DELETED_TASK_ID, 999)

    assert top_effective_task_ids(1000) == [t.id for t in reversed(tasks)]
    assert top_effective_task_ids(1000, limit=2) == [tasks[3].id, tasks[2].id]


def test_a_deleted_task_does_not_consume_one_of_the_ten_slots(app):
    """A deleted task must not cost the caller a slot.

    The join filters candidates BEFORE the GROUP BY and LIMIT, so the limit
    applies to surviving tasks only and the next-best live task backfills. Had it
    been written the other way round -- take the top 10 by count, then drop the
    deleted ones in Python -- this would return 9.
    """
    user = _user()
    # 11 live tasks, descending recoveries: live[0] is the strongest.
    live = [_task(user.id, f"live{i}") for i in range(11)]
    for i, task in enumerate(live):
        _recoveries(task.id, 100 - i)
    # a deleted task that out-cracks every one of them
    _recoveries(DELETED_TASK_ID, 500)

    ids = top_effective_task_ids(1000, limit=10)

    assert len(ids) == 10, f"a deleted task cost a slot: got {len(ids)}"
    assert DELETED_TASK_ID not in ids
    # exactly the ten strongest live tasks, in order; the 11th is the one dropped
    assert ids == [t.id for t in live[:10]]
    assert live[10].id not in ids


def test_fewer_than_ten_is_returned_only_when_that_is_all_there_is(app):
    """The flip side: the count is capped by how many live tasks have recovered
    anything, so a short list means a short candidate set, not silent truncation.
    """
    user = _user()
    live = [_task(user.id, f"live{i}") for i in range(3)]
    for i, task in enumerate(live):
        _recoveries(task.id, 10 - i)
    _recoveries(DELETED_TASK_ID, 500)

    assert top_effective_task_ids(1000, limit=10) == [t.id for t in live]


def test_top_tasks_is_scoped_to_the_hash_type(app):
    user = _user()
    ntlm = _task(user.id, "ntlm")
    krb = _task(user.id, "krb")
    _recoveries(ntlm.id, 4, hash_type=1000)
    _recoveries(krb.id, 9, hash_type=13100, tag="k")

    assert top_effective_task_ids(1000) == [ntlm.id]
    assert top_effective_task_ids(13100) == [krb.id]


def test_top_tasks_ignores_uncracked_and_null_task_ids(app):
    user = _user()
    live = _task(user.id, "live")
    _recoveries(live.id, 2)
    db.session.add_all([
        Hashes(sub_ciphertext=get_md5_hash("u"), ciphertext="u", hash_type=1000,
               cracked=False, task_id=live.id),                       # not cracked
        Hashes(sub_ciphertext=get_md5_hash("n"), ciphertext="n", hash_type=1000,
               cracked=True, plaintext="p", task_id=None),            # never attributed
    ])
    db.session.commit()

    assert top_effective_task_ids(1000) == [live.id]


def test_top_tasks_omits_a_task_that_has_recovered_nothing(app):
    """A task with hashes attributed to it but none cracked must not appear at all.
    Asserting only on a count would not catch a missing `cracked` filter, since an
    uncracked row merely inflates a task already in the list.
    """
    user = _user()
    live = _task(user.id, "live")
    barren = _task(user.id, "barren")
    _recoveries(live.id, 2)
    db.session.add_all([
        Hashes(sub_ciphertext=get_md5_hash(f"b{i}"), ciphertext=f"b{i}",
               hash_type=1000, cracked=False, task_id=barren.id)
        for i in range(50)                      # would rank first if counted
    ])
    db.session.commit()

    ids = top_effective_task_ids(1000)
    assert barren.id not in ids
    assert ids == [live.id]


def test_top_tasks_ignores_the_zero_sentinel_even_if_a_task_row_exists(app):
    """`task_id = 0` is the historical "not attributed" sentinel, and the explicit
    filter is what excludes it. Seed an actual task row with id 0 so the INNER
    JOIN cannot do the excluding -- otherwise this passes for the wrong reason and
    the filter is untested.
    """
    user = _user()
    zero = Tasks(id=0, name="id-zero", owner_id=user.id, wl_id=None, rule_id=None,
                 hc_attackmode=0, loopback=False)
    db.session.add(zero)
    db.session.commit()
    assert Tasks.query.get(0) is not None, "seeding a task with id 0 did not work"

    live = _task(user.id, "live")
    _recoveries(0, 50, tag="z")          # the sentinel out-cracks everything
    _recoveries(live.id, 2)

    assert top_effective_task_ids(1000) == [live.id]


def test_top_tasks_is_empty_when_nothing_has_been_recovered(app):
    _user()
    assert top_effective_task_ids(1000) == []


#############################################
# The web route
#############################################

def test_lucky_route_never_assigns_a_deleted_task(app, client):
    user = _user()
    _login(client, user)
    job = _job_with_hashfile(user.id)
    live = _task(user.id, "live")
    _recoveries(DELETED_TASK_ID, 50)
    _recoveries(live.id, 5)

    resp = client.post(f"/jobs/{job.id}/assign_task/lucky")
    assert resp.status_code == 302

    assigned = {jt.task_id for jt in JobTasks.query.filter_by(job_id=job.id).all()}
    assert assigned == {live.id}
    assert DELETED_TASK_ID not in assigned


def test_lucky_route_reports_when_only_deleted_tasks_qualify(app, client):
    """With nothing but a deleted task's recoveries the list is empty, which must
    read as "not enough data" rather than assigning an unrunnable task."""
    user = _user()
    _login(client, user)
    job = _job_with_hashfile(user.id)
    _recoveries(DELETED_TASK_ID, 50)

    client.post(f"/jobs/{job.id}/assign_task/lucky")

    assert JobTasks.query.filter_by(job_id=job.id).count() == 0
    with client.session_transaction() as sess:
        flashes = sess.get("_flashes", [])
    assert any("Not enough data" in msg for _cat, msg in flashes)


def test_lucky_route_does_not_duplicate_an_already_assigned_task(app, client):
    user = _user()
    _login(client, user)
    job = _job_with_hashfile(user.id)
    live = _task(user.id, "live")
    _recoveries(live.id, 5)
    db.session.add(JobTasks(job_id=job.id, task_id=live.id, status='Not Started'))
    db.session.commit()

    client.post(f"/jobs/{job.id}/assign_task/lucky")

    assert JobTasks.query.filter_by(job_id=job.id, task_id=live.id).count() == 1


#############################################
# The other assignment paths
#############################################

def test_single_assign_refuses_a_task_that_no_longer_exists(app, client):
    user = _user()
    _login(client, user)
    job = _job_with_hashfile(user.id)

    resp = client.post(f"/jobs/{job.id}/assign_task/{DELETED_TASK_ID}")
    assert resp.status_code == 302
    assert JobTasks.query.filter_by(job_id=job.id).count() == 0
    with client.session_transaction() as sess:
        flashes = sess.get("_flashes", [])
    assert any("no longer exists" in msg for _cat, msg in flashes)


def test_single_assign_still_works_for_a_live_task(app, client):
    user = _user()
    _login(client, user)
    job = _job_with_hashfile(user.id)
    live = _task(user.id, "live")

    client.post(f"/jobs/{job.id}/assign_task/{live.id}")

    assert JobTasks.query.filter_by(job_id=job.id, task_id=live.id).count() == 1


def test_task_group_assign_skips_entries_whose_task_is_gone(app, client):
    """task_groups.tasks is a JSON id list with no foreign key. A stale id in it
    must be skipped, not turned into an unrunnable JobTasks row."""
    user = _user()
    _login(client, user)
    job = _job_with_hashfile(user.id)
    live = _task(user.id, "live")
    group = TaskGroups(name="grp", owner_id=user.id,
                       tasks=json.dumps([live.id, DELETED_TASK_ID]))
    db.session.add(group)
    db.session.commit()

    client.post(f"/jobs/{job.id}/assign_task_group/{group.id}")

    assigned = {jt.task_id for jt in JobTasks.query.filter_by(job_id=job.id).all()}
    assert assigned == {live.id}
    with client.session_transaction() as sess:
        flashes = sess.get("_flashes", [])
    assert any("no longer exist" in msg for _cat, msg in flashes)
