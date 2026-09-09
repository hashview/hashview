"""e2e (Playwright) spec for GitHub issue #392.

Exercises the DESIRED live, client-side filtering behavior of the **Add Task**
drawer on the job task-assignment step (``/jobs/<id>/tasks``): typing in the
filter box narrows the selectable-task list, a non-matching query reveals a
"no match" empty state, and clearing restores the full list.

Marked ``@pytest.mark.xfail(strict=False)`` because the feature is not
implemented yet: today there is no filter input, so the test fails at the
"filter input exists" step and reports XFAIL. Once the feature lands it runs
the full behavior and XPASSes, becoming a real regression guard.

This complements the render-level unit tests in
``tests/unit/test_issue_xfail_job_task_filter.py`` (which assert the static
scaffolding) by verifying the JavaScript actually filters in a real browser.

Requires the standard e2e prerequisites (HASHVIEW_E2E_BASE_URL + a seeded,
logged-in session). It drives the seeded job from ``seed_e2e_db.py``
(HASHVIEW_E2E_JOB_ID), whose Add Task drawer lists the default boot tasks.
"""

import os

import pytest
from playwright.sync_api import expect

# A query no task name will contain, used to force the empty ("no match") state.
NO_MATCH_QUERY = "zzz-no-such-task-zzz-392"


def _open_add_task_drawer(page):
    """Open the <details> drawer that holds the /assign_task/ forms."""
    drawer = page.locator("details:has(form[action*='/assign_task/'])").first
    drawer.evaluate("el => { el.open = true; }")
    return drawer


def _visible_task_buttons(drawer):
    """Locator for the per-task submit buttons in the Add Task drawer.

    action*='/assign_task/' matches the task forms but NOT the task-group
    forms (those are '/assign_task_group/', which has no '/assign_task/'
    substring), so this never picks up a group entry.
    """
    return drawer.locator("form[action*='/assign_task/'] button[type=submit]")


@pytest.mark.e2e
@pytest.mark.xfail(
    reason="issue #392: Add Task list on jobs/<id>/tasks has no live filter yet",
    strict=False,
)
def test_add_task_filter_narrows_selectable_tasks(page, live_server, login):
    login()
    if not page.get_by_role("link", name="Jobs").is_visible():
        pytest.skip("Login failed against external server; set HASHVIEW_E2E_EMAIL/PASSWORD.")

    job_id = os.getenv("HASHVIEW_E2E_JOB_ID")
    if not job_id:
        pytest.skip("Set HASHVIEW_E2E_JOB_ID (seed_e2e_db.py seeds this job).")

    page.goto(f"{live_server}/jobs/{job_id}/tasks", wait_until="domcontentloaded")
    expect(page.get_by_role("heading", name="Task Library")).to_be_visible()

    drawer = _open_add_task_drawer(page)
    buttons = _visible_task_buttons(drawer)
    total = buttons.count()
    if total == 0:
        pytest.skip("No assignable tasks in the Add Task drawer to filter.")

    # The filter input is the feature under test. Its absence is exactly the
    # xfail condition — locating/using it fails today and passes once added.
    filter_box = drawer.locator("input[placeholder*='filter']").first
    expect(filter_box).to_be_visible()

    # Capture a real task name and derive a substring that identifies it.
    first_name = (buttons.first.inner_text()).strip()
    assert first_name, "expected the first task button to have a visible label"
    probe = first_name[: max(3, len(first_name) // 2)]

    # 1) A non-matching query hides every task entry and shows the empty state.
    filter_box.fill(NO_MATCH_QUERY)
    for i in range(total):
        expect(buttons.nth(i)).to_be_hidden()
    expect(drawer.get_by_text("match that filter", exact=False)).to_be_visible()

    # 2) A matching query brings back the matching task (and hides non-matches
    #    when there is more than one task to distinguish).
    filter_box.fill(probe)
    matching = drawer.locator(
        f"form[action*='/assign_task/']:has-text(\"{first_name}\") button[type=submit]"
    ).first
    expect(matching).to_be_visible()
    if total > 1:
        visible_now = sum(
            1 for i in range(total) if buttons.nth(i).is_visible()
        )
        assert visible_now < total, (
            "matching filter query should hide at least one non-matching task"
        )

    # 3) Clearing the filter restores the full list.
    filter_box.fill("")
    for i in range(total):
        expect(buttons.nth(i)).to_be_visible()
