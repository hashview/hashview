"""Unit tests for POST /v1/jobs/add's priority + three task-assignment modes,
and for POST /v1/jobs/stop/<id>.

Background (#351): /v1/jobs/add could only populate a job from the "top 10 most
effective tasks" heuristic, which ranks by cracked hashes carrying a task_id.
/v1/hashes/import never sets a task_id, so API-imported cracks were never
ranking evidence and the endpoint refused forever on a fresh system -- a
dependency an API-only client could not break out of. Modes `tasks` and
`task_group` are the way out, and neither needs crack history.

Conventions follow tests/unit/test_api_task_groups.py: local fixtures (api_key
is required, which helpers.make_admin does not set), the security marker, and
cookie auth against domain="localhost.test".
"""

import json

import pytest

from hashview.models import (
    Customers,
    Hashes,
    HashfileHashes,
    Hashfiles,
    Jobs,
    JobTasks,
    Settings,
    TaskGroups,
    Tasks,
    Users,
    Wordlists,
)
from hashview.models import db as _db
from hashview.utils.utils import MAX_TASKS_PER_GROUP, get_md5_hash

DOMAIN = "localhost.test"


@pytest.fixture()
def admin_user(app):
    user = Users(first_name="Ad", last_name="Min", email_address="admin@example.test",
                 password="x" * 60, admin=True, api_key="jobs-add-admin-key")
    _db.session.add(user)
    _db.session.commit()
    return user


@pytest.fixture()
def other_user(app):
    user = Users(first_name="Oth", last_name="Er", email_address="other@example.test",
                 password="x" * 60, admin=False, api_key="jobs-add-other-key")
    _db.session.add(user)
    _db.session.commit()
    return user


def _auth(client, key):
    client.set_cookie("uuid", key, domain=DOMAIN)


def _body(resp):
    return json.loads(resp.get_data(as_text=True))


def _weights(enabled):
    _db.session.add(Settings(retention_period=30, max_runtime_jobs=0, max_runtime_tasks=0,
                             enabled_job_weights=enabled))
    _db.session.commit()


def _wordlist(owner, kind="static", name="wl"):
    wl = Wordlists(name=name, owner_id=owner.id, type=kind, path=f"/tmp/{name}",
                   size=1, checksum="c" * 64)
    _db.session.add(wl)
    _db.session.commit()
    return wl


def _task(owner, name="t", wl_id=None):
    task = Tasks(name=name, hc_attackmode=0, owner_id=owner.id, wl_id=wl_id)
    _db.session.add(task)
    _db.session.commit()
    return task


def _hashfile(owner, hash_type=1000, with_hash=True):
    cust = Customers(name=f"C{owner.id}-{hash_type}")
    _db.session.add(cust)
    _db.session.commit()
    hf = Hashfiles(name="hf.txt", customer_id=cust.id, owner_id=owner.id)
    _db.session.add(hf)
    _db.session.commit()
    if with_hash:
        h = Hashes(sub_ciphertext=get_md5_hash(f"t{hf.id}"), ciphertext=f"t{hf.id}",
                   hash_type=hash_type, cracked=False)
        _db.session.add(h)
        _db.session.commit()
        _db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
        _db.session.commit()
    return cust, hf


def _crack_history(owner, hash_type, tasks_and_counts):
    """Seed cracked hashes attributed to tasks so `lucky` has something to rank."""
    n = 0
    for task, count in tasks_and_counts:
        for _ in range(count):
            n += 1
            ct = f"h{hash_type}-{n:05d}"
            _db.session.add(Hashes(sub_ciphertext=get_md5_hash(ct), ciphertext=ct,
                                   hash_type=hash_type, cracked=True, plaintext="pw",
                                   task_id=task.id))
    _db.session.commit()


def _post(client, cust, hf, **extra):
    payload = {"name": "job", "hashfile_id": hf.id, "customer_id": cust.id}
    payload.update(extra)
    return client.post("/v1/jobs/add", data=json.dumps(payload),
                       content_type="application/json")


def _queue(job_id):
    """Assigned task ids in queue order (insertion order == JobTasks.id order)."""
    return [jt.task_id for jt in
            JobTasks.query.filter_by(job_id=job_id).order_by(JobTasks.id).all()]


#############################################
# Priority
#############################################

@pytest.mark.security
def test_priority_defaults_to_normal_when_omitted(client, admin_user):
    cust, hf = _hashfile(admin_user)
    task = _task(admin_user, "eff")
    _crack_history(admin_user, 1000, [(task, 3)])
    _auth(client, admin_user.api_key)

    body = _body(_post(client, cust, hf))

    assert body["status"] == 200
    assert Jobs.query.get(body["job_id"]).priority == 3


@pytest.mark.security
@pytest.mark.parametrize("value", [1, 5, "5"])
def test_priority_applied_when_weights_enabled(client, admin_user, value):
    _weights(True)
    cust, hf = _hashfile(admin_user)
    task = _task(admin_user, "eff")
    _crack_history(admin_user, 1000, [(task, 3)])
    _auth(client, admin_user.api_key)

    body = _body(_post(client, cust, hf, priority=value))

    assert body["status"] == 200
    assert Jobs.query.get(body["job_id"]).priority == int(value)


@pytest.mark.security
@pytest.mark.parametrize("value", [0, 6, -1, "high", 3.5, True])
def test_priority_out_of_range_rejected_without_creating_a_job(client, admin_user, value):
    """True is included deliberately: bool is an int in Python, so a bare
    isinstance check would accept it as priority 1."""
    _weights(True)
    cust, hf = _hashfile(admin_user)
    _auth(client, admin_user.api_key)

    body = _body(_post(client, cust, hf, priority=value))

    assert body["status"] == 400
    assert "priority must be an integer" in body["msg"]
    assert Jobs.query.count() == 0


@pytest.mark.security
def test_priority_rejected_when_weights_disabled(client, admin_user):
    """The admin switch that hides the control in the web UI binds API callers
    too -- an api_key is a user. Refuse rather than silently substituting 3."""
    _weights(False)
    cust, hf = _hashfile(admin_user)
    _auth(client, admin_user.api_key)

    body = _body(_post(client, cust, hf, priority=5))

    assert body["status"] == 400
    assert "disabled by the administrator" in body["msg"]
    assert Jobs.query.count() == 0


@pytest.mark.security
def test_priority_omitted_still_works_when_weights_disabled(client, admin_user):
    _weights(False)
    cust, hf = _hashfile(admin_user)
    task = _task(admin_user, "eff")
    _crack_history(admin_user, 1000, [(task, 3)])
    _auth(client, admin_user.api_key)

    body = _body(_post(client, cust, hf))

    assert body["status"] == 200
    assert Jobs.query.get(body["job_id"]).priority == 3


@pytest.mark.security
def test_priority_rejected_when_no_settings_row_exists(client, admin_user):
    """A bare install has no Settings row; treat that as weights-disabled rather
    than raising (hashview/jobs/routes.py would AttributeError here)."""
    cust, hf = _hashfile(admin_user)
    _auth(client, admin_user.api_key)

    body = _body(_post(client, cust, hf, priority=4))

    assert body["status"] == 400
    assert Jobs.query.count() == 0


#############################################
# Mode: lucky (the default, unchanged behaviour)
#############################################

@pytest.mark.security
def test_lucky_is_the_default_and_assigns_in_rank_order(client, admin_user):
    cust, hf = _hashfile(admin_user)
    weak, strong = _task(admin_user, "weak"), _task(admin_user, "strong")
    _crack_history(admin_user, 1000, [(weak, 2), (strong, 9)])
    _auth(client, admin_user.api_key)

    body = _body(_post(client, cust, hf))

    assert body["status"] == 200
    assert _queue(body["job_id"]) == [strong.id, weak.id]
    assert body["tasks_assigned"] == 2 and body["tasks_skipped"] == 0


@pytest.mark.security
def test_explicit_lucky_mode_matches_the_default(client, admin_user):
    cust, hf = _hashfile(admin_user)
    task = _task(admin_user, "eff")
    _crack_history(admin_user, 1000, [(task, 4)])
    _auth(client, admin_user.api_key)

    body = _body(_post(client, cust, hf, mode="lucky"))

    assert body["status"] == 200
    assert _queue(body["job_id"]) == [task.id]


@pytest.mark.security
def test_lucky_with_no_effective_tasks_keeps_its_message_and_creates_nothing(client, admin_user):
    """The message prefix is pinned: clients and three existing tests substring
    match it. The no-orphan assertion is the new part -- the job used to be
    committed before this gate was evaluated."""
    cust, hf = _hashfile(admin_user)
    _auth(client, admin_user.api_key)

    body = _body(_post(client, cust, hf))

    assert body["status"] == 500
    assert body["msg"].startswith("Not enough data to determine effective tasks for this hash type.")
    assert Jobs.query.count() == 0
    assert JobTasks.query.count() == 0


@pytest.mark.security
def test_lucky_message_points_at_the_explicit_modes(client, admin_user):
    """The dead end in #351 -- tell the caller what to do instead."""
    cust, hf = _hashfile(admin_user)
    _auth(client, admin_user.api_key)

    assert 'mode "tasks"' in _body(_post(client, cust, hf))["msg"]


@pytest.mark.security
def test_lucky_with_unresolvable_hash_type_reports_it_and_creates_nothing(client, admin_user):
    """A hashfile with no hashes used to raise AttributeError on a chained
    lookup and be swallowed into the generic "Failed to add job."."""
    cust, hf = _hashfile(admin_user, with_hash=False)
    _auth(client, admin_user.api_key)

    body = _body(_post(client, cust, hf))

    assert body["status"] == 500
    assert "Could not determine a hash type" in body["msg"]
    assert Jobs.query.count() == 0


#############################################
# Mode: tasks
#############################################

@pytest.mark.security
def test_task_ids_assigned_in_submitted_order(client, admin_user):
    cust, hf = _hashfile(admin_user)
    a, b, c = (_task(admin_user, n) for n in "abc")
    _auth(client, admin_user.api_key)

    body = _body(_post(client, cust, hf, mode="tasks", task_ids=[c.id, a.id, b.id]))

    assert body["status"] == 200
    assert _queue(body["job_id"]) == [c.id, a.id, b.id]
    assert body["tasks_assigned"] == 3


@pytest.mark.security
def test_reversing_the_list_reverses_the_queue(client, admin_user):
    """Order is not incidental: JobTasks has no position column, so insertion
    order IS queue order and dispatch reads min(JobTasks.id) per task."""
    cust, hf = _hashfile(admin_user)
    a, b, c = (_task(admin_user, n) for n in "abc")
    _auth(client, admin_user.api_key)

    forward = _body(_post(client, cust, hf, mode="tasks", task_ids=[a.id, b.id, c.id]))
    reverse = _body(_post(client, cust, hf, mode="tasks", task_ids=[c.id, b.id, a.id]))

    assert _queue(forward["job_id"]) == [a.id, b.id, c.id]
    assert _queue(reverse["job_id"]) == [c.id, b.id, a.id]


@pytest.mark.security
def test_task_ids_needs_no_crack_history(client, admin_user):
    """The point of #351: a fresh system with zero cracked hashes can still
    create a runnable job."""
    cust, hf = _hashfile(admin_user)
    task = _task(admin_user, "only")
    _auth(client, admin_user.api_key)
    assert Hashes.query.filter_by(cracked=True).count() == 0

    body = _body(_post(client, cust, hf, mode="tasks", task_ids=[task.id]))

    assert body["status"] == 200
    assert _queue(body["job_id"]) == [task.id]


@pytest.mark.security
def test_duplicate_static_task_rejected(client, admin_user):
    static = _wordlist(admin_user, "static")
    cust, hf = _hashfile(admin_user)
    task = _task(admin_user, "static-task", wl_id=static.id)
    _auth(client, admin_user.api_key)

    body = _body(_post(client, cust, hf, mode="tasks", task_ids=[task.id, task.id]))

    assert body["status"] == 400
    assert "more than once" in body["msg"]
    assert Jobs.query.count() == 0


@pytest.mark.security
def test_duplicate_dynamic_task_allowed(client, admin_user):
    """The one exception to the rule: a dynamic wordlist's contents change
    between runs, so repeating the task is meaningful."""
    dynamic = _wordlist(admin_user, "dynamic", name="dyn")
    cust, hf = _hashfile(admin_user)
    task = _task(admin_user, "dyn-task", wl_id=dynamic.id)
    _auth(client, admin_user.api_key)

    body = _body(_post(client, cust, hf, mode="tasks", task_ids=[task.id, task.id]))

    assert body["status"] == 200
    assert _queue(body["job_id"]) == [task.id, task.id]


@pytest.mark.security
def test_task_with_no_wordlist_is_not_repeatable(client, admin_user):
    """A mask/brute-force task has wl_id NULL -- not dynamic, so not repeatable."""
    cust, hf = _hashfile(admin_user)
    task = _task(admin_user, "mask", wl_id=None)
    _auth(client, admin_user.api_key)

    assert _body(_post(client, cust, hf, mode="tasks",
                       task_ids=[task.id, task.id]))["status"] == 400


@pytest.mark.security
@pytest.mark.parametrize("ids", [[999999], [1, 999999], ["abc"], [None], [True]])
def test_unknown_or_malformed_task_id_rejected(client, admin_user, ids):
    cust, hf = _hashfile(admin_user)
    _task(admin_user, "real")
    _auth(client, admin_user.api_key)

    body = _body(_post(client, cust, hf, mode="tasks", task_ids=ids))

    assert body["status"] == 400
    assert "Invalid task id" in body["msg"]
    assert Jobs.query.count() == 0


@pytest.mark.security
@pytest.mark.parametrize("value", [[], "not-a-list", {}, 5])
def test_task_ids_must_be_a_non_empty_list(client, admin_user, value):
    """An empty list is a caller mistake, never "fall back to the heuristic"."""
    cust, hf = _hashfile(admin_user)
    _auth(client, admin_user.api_key)

    body = _body(_post(client, cust, hf, mode="tasks", task_ids=value))

    assert body["status"] == 400
    assert Jobs.query.count() == 0


@pytest.mark.security
def test_task_ids_over_the_cap_rejected(client, admin_user):
    cust, hf = _hashfile(admin_user)
    task = _task(admin_user, "one")
    _auth(client, admin_user.api_key)

    body = _body(_post(client, cust, hf, mode="tasks",
                       task_ids=[task.id] * (MAX_TASKS_PER_GROUP + 1)))

    assert body["status"] == 400
    assert "at most" in body["msg"]
    assert Jobs.query.count() == 0


#############################################
# Mode: task_group
#############################################

def _group(owner, task_ids, name="grp"):
    tg = TaskGroups(name=name, owner_id=owner.id, tasks=json.dumps(list(task_ids)))
    _db.session.add(tg)
    _db.session.commit()
    return tg


@pytest.mark.security
def test_task_group_assigned_in_stored_order(client, admin_user):
    cust, hf = _hashfile(admin_user)
    a, b = _task(admin_user, "a"), _task(admin_user, "b")
    group = _group(admin_user, [b.id, a.id])
    _auth(client, admin_user.api_key)

    body = _body(_post(client, cust, hf, mode="task_group", task_group_id=group.id))

    assert body["status"] == 200
    assert _queue(body["job_id"]) == [b.id, a.id]
    assert body["tasks_skipped"] == 0


@pytest.mark.security
def test_task_group_skips_and_counts_deleted_members(client, admin_user):
    """Lenient where mode `tasks` is strict, and for the inverse reason: the
    caller named a group, so its stale membership is not theirs to fix."""
    cust, hf = _hashfile(admin_user)
    alive = _task(admin_user, "alive")
    group = _group(admin_user, [alive.id, 999999])
    _auth(client, admin_user.api_key)

    body = _body(_post(client, cust, hf, mode="task_group", task_group_id=group.id))

    assert body["status"] == 200
    assert _queue(body["job_id"]) == [alive.id]
    assert body["tasks_assigned"] == 1 and body["tasks_skipped"] == 1


@pytest.mark.security
@pytest.mark.parametrize("members", [[], [999999], "not json"])
def test_task_group_with_nothing_assignable_rejected(client, admin_user, members):
    """Never create a taskless job -- /v1/jobs/start requires `job and job_tasks`,
    so it could never be started."""
    cust, hf = _hashfile(admin_user)
    tg = TaskGroups(name="empty", owner_id=admin_user.id,
                    tasks=members if isinstance(members, str) else json.dumps(members))
    _db.session.add(tg)
    _db.session.commit()
    _auth(client, admin_user.api_key)

    body = _body(_post(client, cust, hf, mode="task_group", task_group_id=tg.id))

    assert body["status"] == 400
    assert "no assignable tasks" in body["msg"]
    assert Jobs.query.count() == 0


@pytest.mark.security
def test_unknown_task_group_rejected(client, admin_user):
    """The web route 500s here; the API answers cleanly."""
    cust, hf = _hashfile(admin_user)
    _auth(client, admin_user.api_key)

    body = _body(_post(client, cust, hf, mode="task_group", task_group_id=999999))

    assert body["status"] == 400
    assert "Invalid task_group_id" in body["msg"]
    assert Jobs.query.count() == 0


@pytest.mark.security
def test_task_group_duplicate_static_member_is_skipped(client, admin_user):
    """A hand-edited or legacy group can list the same id twice; that must not
    make the group unusable, unlike an explicit task_ids list."""
    static = _wordlist(admin_user, "static")
    cust, hf = _hashfile(admin_user)
    task = _task(admin_user, "s", wl_id=static.id)
    group = _group(admin_user, [task.id, task.id])
    _auth(client, admin_user.api_key)

    body = _body(_post(client, cust, hf, mode="task_group", task_group_id=group.id))

    assert body["status"] == 200
    assert _queue(body["job_id"]) == [task.id]
    assert body["tasks_skipped"] == 1


#############################################
# Mode selection
#############################################

@pytest.mark.security
def test_unknown_mode_rejected(client, admin_user):
    cust, hf = _hashfile(admin_user)
    _auth(client, admin_user.api_key)

    body = _body(_post(client, cust, hf, mode="magic"))

    assert body["status"] == 400
    assert "mode must be one of" in body["msg"]


@pytest.mark.security
@pytest.mark.parametrize("mode,field", [
    ("lucky", "task_ids"), ("lucky", "task_group_id"),
    ("tasks", "task_group_id"), ("task_group", "task_ids"),
])
def test_companion_field_under_the_wrong_mode_rejected(client, admin_user, mode, field):
    """Ignoring it would reproduce the #351 failure shape: the caller believes
    they chose their own tasks and silently gets the heuristic."""
    cust, hf = _hashfile(admin_user)
    task = _task(admin_user, "t")
    value = [task.id] if field == "task_ids" else 1
    _auth(client, admin_user.api_key)

    body = _body(_post(client, cust, hf, mode=mode, **{field: value}))

    assert body["status"] == 400
    assert "only valid with mode" in body["msg"]
    assert Jobs.query.count() == 0


@pytest.mark.security
def test_missing_companion_field_rejected(client, admin_user):
    cust, hf = _hashfile(admin_user)
    _auth(client, admin_user.api_key)

    assert _body(_post(client, cust, hf, mode="tasks"))["status"] == 400
    assert _body(_post(client, cust, hf, mode="task_group"))["status"] == 400
    assert Jobs.query.count() == 0


#############################################
# POST /v1/jobs/stop/<id>
#############################################

def _running_job(owner, status="Running", agent_id=None):
    cust = Customers(name=f"stop-{owner.id}-{status}")
    _db.session.add(cust)
    _db.session.commit()
    job = Jobs(name="running", status=status, customer_id=cust.id, owner_id=owner.id)
    _db.session.add(job)
    _db.session.commit()
    _db.session.add(JobTasks(job_id=job.id, task_id=1, status="Queued", agent_id=agent_id))
    _db.session.commit()
    return job


@pytest.mark.security
def test_stop_cancels_the_job_and_its_tasks(client, admin_user):
    job = _running_job(admin_user)
    _auth(client, admin_user.api_key)

    body = _body(client.post(f"/v1/jobs/stop/{job.id}"))

    assert body["status"] == 200 and body["job_id"] == job.id
    assert Jobs.query.get(job.id).status == "Canceled"
    assert Jobs.query.get(job.id).ended_at is not None
    assert [jt.status for jt in JobTasks.query.filter_by(job_id=job.id)] == ["Canceled"]


@pytest.mark.security
def test_stop_clears_the_agent_so_work_is_not_redispatched(client, admin_user):
    job = _running_job(admin_user, agent_id=None)
    jt = JobTasks.query.filter_by(job_id=job.id).first()
    jt.agent_id = 7
    _db.session.commit()
    _auth(client, admin_user.api_key)

    client.post(f"/v1/jobs/stop/{job.id}")

    assert JobTasks.query.filter_by(job_id=job.id).first().agent_id is None


@pytest.mark.security
@pytest.mark.parametrize("status", ["Running", "Queued"])
def test_stop_accepts_both_active_states(client, admin_user, status):
    job = _running_job(admin_user, status=status)
    _auth(client, admin_user.api_key)

    assert _body(client.post(f"/v1/jobs/stop/{job.id}"))["status"] == 200


@pytest.mark.security
@pytest.mark.parametrize("status", ["Ready", "Completed", "Canceled", "Incomplete"])
def test_stop_refuses_an_inactive_job(client, admin_user, status):
    job = _running_job(admin_user, status=status)
    _auth(client, admin_user.api_key)

    body = _body(client.post(f"/v1/jobs/stop/{job.id}"))

    assert body["status"] == 400
    assert "not actively running" in body["msg"]
    assert Jobs.query.get(job.id).status == status


@pytest.mark.security
def test_stop_requires_owner_or_admin(client, admin_user, other_user):
    job = _running_job(admin_user)
    _auth(client, other_user.api_key)

    body = _body(client.post(f"/v1/jobs/stop/{job.id}"))

    assert body["status"] == 403
    assert "do not have rights" in body["msg"]
    assert Jobs.query.get(job.id).status == "Running"


@pytest.mark.security
def test_stop_allows_the_owner_who_is_not_admin(client, other_user):
    job = _running_job(other_user)
    _auth(client, other_user.api_key)

    assert _body(client.post(f"/v1/jobs/stop/{job.id}"))["status"] == 200


@pytest.mark.security
def test_stop_admin_may_stop_another_users_job(client, admin_user, other_user):
    job = _running_job(other_user)
    _auth(client, admin_user.api_key)

    assert _body(client.post(f"/v1/jobs/stop/{job.id}"))["status"] == 200


@pytest.mark.security
def test_stop_unknown_job_returns_real_404(client, admin_user):
    _auth(client, admin_user.api_key)
    resp = client.post("/v1/jobs/stop/999999")
    assert resp.status_code == 404
    assert _body(resp)["status"] == 404


@pytest.mark.security
def test_stop_rejects_an_agent_cookie(client, admin_user, app):
    from hashview.models import Agents
    agent = Agents(name="a", src_ip="127.0.0.1", uuid="agent-uuid", status="Authorized")
    _db.session.add(agent)
    _db.session.commit()
    job = _running_job(admin_user)
    _auth(client, agent.uuid)

    resp = client.post(f"/v1/jobs/stop/{job.id}")

    assert 300 <= resp.status_code < 400
    assert Jobs.query.get(job.id).status == "Running"
