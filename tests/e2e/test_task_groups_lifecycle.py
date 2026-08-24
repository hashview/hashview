"""End-to-end coverage for the Task Groups feature.

Task Groups had no e2e coverage at all: the New-group modal, the task picker
that builds the hidden ``task_ids`` field in JavaScript, and the delete
confirmation were all untested, so a break in any of them shipped silently.
"""

import pytest
from playwright.sync_api import expect

GROUP_NAME = "E2E Lifecycle Group"


def _group_card(page, name):
    return page.locator("div.card").filter(has_text=name)


@pytest.mark.e2e
def test_task_group_create_with_task_then_delete(page, live_server, login):
    login()
    page.goto(f"{live_server}/task_groups", wait_until="domcontentloaded")

    # The listing shows "New group" once groups exist and a different
    # call-to-action on the empty state; both open the same modal.
    new_group = page.get_by_role("button", name="New group")
    if not new_group.is_visible():
        new_group = page.get_by_role("button", name="Create a New Task Group")
    new_group.click()

    modal = page.locator("#new-group-modal")
    expect(modal).to_be_visible()
    modal.locator("#ng-name").fill(GROUP_NAME)

    # Attach the first available task. This exercises hvGmAdd(), which is what
    # populates the hidden task_ids the POST handler parses.
    add_first_task = modal.locator(".gm-avail-row button[title='Add to group']").first
    expect(add_first_task).to_be_visible()
    add_first_task.click()
    expect(modal.locator("#ng-task-ids")).not_to_have_value("")

    modal.get_by_role("button", name="Create group").click()
    page.wait_for_load_state("domcontentloaded")

    card = _group_card(page, GROUP_NAME)
    expect(card).to_be_visible()
    expect(card).to_contain_text("1 task")

    # Delete it again so the test is re-runnable against a persistent instance.
    card.locator("button[title='Delete group']").click()
    confirm = page.locator("dialog[open]")
    expect(confirm).to_contain_text(f"Delete {GROUP_NAME}?")
    confirm.get_by_role("button", name="Delete", exact=True).click()
    page.wait_for_load_state("domcontentloaded")

    expect(_group_card(page, GROUP_NAME)).to_have_count(0)
