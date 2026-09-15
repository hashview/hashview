"""xfail tests documenting GitHub issue #392.

Feature request: add a live, client-side filter/search field to the job
task-assignment wizard step (``GET /jobs/<id>/tasks``, rendered by
``templates/jobs_assigned_tasks.html.j2``) so the selectable **Add Task** and
**Add Task Group** lists can be narrowed by name — mirroring the filter that
already exists on the ``/tasks`` listing page (``hvFilterTasks`` in
``tasks.html.j2``) and inside the task-group builder (``hvGmFilter`` in
``task_groups.html.j2``).

Each test asserts the DESIRED end state and is marked
``@pytest.mark.xfail(strict=False)`` so it documents the request without
breaking the suite. When the feature lands these XPASS and become regression
guards.

Scope note: this is a purely client-side (template + JS) enhancement, so these
render-level tests verify the *scaffolding* the JS filter needs — a filter
input per list and a "no match" empty-state element per list, each scoped to
the correct drawer. The live keystroke-by-keystroke filtering behavior is JS
and belongs in an e2e/Playwright test; that can be added once the feature is
implemented. The scaffolding contract here mirrors the two existing in-tree
reference implementations.
"""

import re

import pytest

from hashview.models import (
    Customers,
    Jobs,
    TaskGroups,
    Tasks,
    Users,
    db,
)

# Distinctive names so substring assertions can't collide with boilerplate.
TASK_NAME = "ZZTopFilterProbe"
GROUP_NAME = "QXGroupFilterProbe"


def _login(client, user_id):
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user_id)
        sess["_fresh"] = True


def _seed_job_with_task_and_group():
    """Seed an admin, customer, a job, one assignable Task and one TaskGroup.

    Returns the job id. The task and group use distinctive names so the
    rendered ``/jobs/<id>/tasks`` page shows exactly one selectable entry in
    each of the Add Task / Add Task Group drawers.
    """
    admin = Users(
        first_name="A",
        last_name="D",
        email_address="admin@example.com",
        password="x" * 60,
        admin=True,
        api_key="k",
    )
    db.session.add(admin)
    db.session.commit()

    cust = Customers(name="FilterCo")
    db.session.add(cust)
    db.session.commit()

    task = Tasks(name=TASK_NAME, owner_id=admin.id, hc_attackmode=0)
    db.session.add(task)
    db.session.commit()

    # TaskGroups.tasks is a non-nullable comma-joined id string (see models.py).
    group = TaskGroups(name=GROUP_NAME, owner_id=admin.id, tasks=str(task.id))
    db.session.add(group)
    db.session.commit()

    job = Jobs(
        name="FilterJob",
        owner_id=admin.id,
        customer_id=cust.id,
        status="Not Started",
    )
    db.session.add(job)
    db.session.commit()

    return admin.id, job.id


def _details_blocks(html):
    """Return each top-level ``<details>...</details>`` block from the page.

    The Add Task and Add Task Group drawers are non-nested ``<details>``
    elements, so a non-greedy DOTALL match cleanly separates them.
    """
    return re.findall(r"<details\b.*?</details>", html, re.DOTALL | re.IGNORECASE)


def _add_task_block(html):
    """The drawer whose forms POST to /assign_task/<id> (NOT /assign_task_group/)."""
    for block in _details_blocks(html):
        if "/assign_task/" in block and "/assign_task_group/" not in block:
            return block
    return None


def _add_task_group_block(html):
    """The drawer whose forms POST to /assign_task_group/<id>."""
    for block in _details_blocks(html):
        if "/assign_task_group/" in block:
            return block
    return None


def _has_filter_input(block):
    """True if ``block`` contains a text ``<input>`` that looks like a filter box.

    Matches the existing convention (a text input with a ``placeholder`` whose
    text mentions "filter", e.g. ``placeholder="filter tasks…"``). Naming of
    id/handler is left to the implementer, so we key off the placeholder.
    """
    for tag in re.findall(r"<input\b[^>]*>", block, re.IGNORECASE):
        ph = re.search(r'placeholder\s*=\s*"([^"]*)"', tag, re.IGNORECASE)
        if ph and "filter" in ph.group(1).lower():
            return True
    return False


def _render_job_tasks_page(app, client):
    admin_id, job_id = _seed_job_with_task_and_group()
    _login(client, admin_id)
    resp = client.get(f"/jobs/{job_id}/tasks")
    assert resp.status_code == 200
    return resp.get_data(as_text=True)


@pytest.mark.xfail(
    reason="issue #392: no filter/search field on the Add Task list of jobs/<id>/tasks",
    strict=False,
)
def test_add_task_drawer_has_live_filter_input(app, client):
    """The Add Task drawer should expose a filter input to narrow the list.

    DESIRED: mirroring the /tasks page, the selectable-task list on
    jobs/<id>/tasks carries a text filter input (placeholder mentions
    "filter"). Currently there is none, so this xfails.
    """
    html = _render_job_tasks_page(app, client)
    block = _add_task_block(html)
    assert block is not None, "Add Task drawer (forms -> /assign_task/) not found"
    assert _has_filter_input(block), (
        "Add Task drawer has no filter input; expected a text <input> with a "
        'placeholder mentioning "filter" (see hvFilterTasks in tasks.html.j2).'
    )


@pytest.mark.xfail(
    reason="issue #392: Add Task list has no 'no results' empty state for filtering",
    strict=False,
)
def test_add_task_drawer_has_no_match_empty_state(app, client):
    """The Add Task drawer should include a hidden 'no match' placeholder.

    DESIRED: like tasks.html.j2's ``#task-no-match`` row ("No tasks match that
    filter."), the client filter needs an element to reveal when nothing
    matches. We assert the drawer contains a "match that filter" message.
    """
    html = _render_job_tasks_page(app, client)
    block = _add_task_block(html)
    assert block is not None, "Add Task drawer (forms -> /assign_task/) not found"
    assert "match that filter" in block.lower(), (
        "Add Task drawer has no empty-state element for the filter; expected a "
        'message like "No tasks match that filter." (cf. #task-no-match).'
    )


@pytest.mark.xfail(
    reason="issue #392: no filter/search field on the Add Task Group list of jobs/<id>/tasks",
    strict=False,
)
def test_add_task_group_drawer_has_live_filter_input(app, client):
    """The Add Task Group drawer should expose its own filter input.

    DESIRED: the Add Task Group list is the same unbounded, scrolling drawer as
    Add Task (TaskGroups.query.all()), so it should get an equivalent filter
    input. Currently there is none, so this xfails.
    """
    html = _render_job_tasks_page(app, client)
    block = _add_task_group_block(html)
    assert block is not None, (
        "Add Task Group drawer (forms -> /assign_task_group/) not found"
    )
    assert _has_filter_input(block), (
        "Add Task Group drawer has no filter input; expected a text <input> "
        'with a placeholder mentioning "filter".'
    )


@pytest.mark.xfail(
    reason="issue #392: Add Task Group list has no 'no results' empty state for filtering",
    strict=False,
)
def test_add_task_group_drawer_has_no_match_empty_state(app, client):
    """The Add Task Group drawer should include a hidden 'no match' placeholder."""
    html = _render_job_tasks_page(app, client)
    block = _add_task_group_block(html)
    assert block is not None, (
        "Add Task Group drawer (forms -> /assign_task_group/) not found"
    )
    assert "match that filter" in block.lower(), (
        "Add Task Group drawer has no empty-state element for the filter; "
        'expected a message like "No task groups match that filter."'
    )


def test_seeded_entries_render_without_filter(app, client):
    """Sanity guard (NOT xfail): the seeded task and group already render in
    their drawers today. This proves the seeding + drawer-scoping helpers work,
    so the xfails above fail for the right reason (missing filter UI) rather
    than because the page never showed the entries.
    """
    html = _render_job_tasks_page(app, client)
    task_block = _add_task_block(html)
    group_block = _add_task_group_block(html)
    assert task_block is not None and TASK_NAME in task_block
    assert group_block is not None and GROUP_NAME in group_block
