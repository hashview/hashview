"""End-to-end coverage of editing a task via the /tasks edit modal.

Editing is a client-side modal (opened from each row's Edit button and
pre-filled from the task's data), not a separate /tasks/edit/<id> page.

Exercises that:
  * the edit modal opens pre-filled for an existing task,
  * editing the task name persists,
  * switching the attack mode (Straight -> Brute-force/mask) and saving works.
"""

import re
import uuid
from pathlib import Path

import pytest
from playwright.sync_api import expect

EXAMPLE_WORDLIST = Path(__file__).parent / "example_wordlist.txt"


def _row_with_text(page, text: str):
    return page.locator("tr", has=page.locator("td", has_text=text)).first


def _add_static_wordlist(page, live_server, name: str) -> None:
    page.goto(f"{live_server}/wordlists/add", wait_until="domcontentloaded")
    expect(page.get_by_role("heading", name=re.compile(r"Add Wordlist"))).to_be_visible()
    page.locator("input[name='name']").fill(name)
    page.set_input_files("input[name='wordlist']", str(EXAMPLE_WORDLIST))
    page.get_by_role("button", name="upload", exact=True).click()
    expect(page).to_have_url(re.compile(r".*/wordlists/?$"))


def _delete_wordlist(page, live_server, name: str) -> None:
    page.goto(f"{live_server}/wordlists", wait_until="domcontentloaded")
    row = _row_with_text(page, name)
    if row.count() == 0:
        return
    row.locator("button.act-del").click()
    modal = page.locator("dialog.hv-dialog[open]")
    expect(modal).to_be_visible()
    modal.locator("form[action*='/wordlists/delete/'] [type='submit']").first.click()
    expect(page).to_have_url(re.compile(r".*/wordlists/?$"))


def _delete_task(page, live_server, name: str) -> None:
    page.goto(f"{live_server}/tasks", wait_until="domcontentloaded")
    row = _row_with_text(page, name)
    if row.count() == 0:
        return
    row.locator("button.act-del").click()
    modal = page.locator("dialog.hv-dialog[open]")
    expect(modal).to_be_visible()
    modal.locator("form[action*='/tasks/delete/'] button[type='submit']").first.click()
    expect(page).to_have_url(re.compile(r".*/tasks/?$"))


def _create_task(page, live_server, name, mode_value, wl_name):
    page.goto(f"{live_server}/tasks/add", wait_until="domcontentloaded")
    page.locator("#name").fill(name)
    page.locator("#hc_attackmode").select_option(mode_value)
    if mode_value == "0":
        page.locator("#wl_id").select_option(label=wl_name)
    elif mode_value == "3":
        page.locator("#mask").fill("?l?l?l?l")
    page.get_by_role("button", name=re.compile(r"^Create$", re.I)).click()
    expect(page).to_have_url(re.compile(r".*/tasks/?$"))


@pytest.mark.e2e
def test_tasks_edit_page_renders_for_existing_task(page, live_server, login):
    """Open the edit modal for a freshly-created Straight task and confirm it
    opens pre-filled with no template/server errors leaked into the page.
    """
    login()
    suffix = uuid.uuid4().hex[:6]
    wl_name = f"e2e-wl-{suffix}"
    task_name = f"e2e-edit-render-{suffix}"

    _add_static_wordlist(page, live_server, wl_name)
    try:
        _create_task(page, live_server, task_name, "0", wl_name)

        page.goto(f"{live_server}/tasks", wait_until="domcontentloaded")
        row = _row_with_text(page, task_name)
        expect(row).to_be_visible()
        row.locator("button[title='Edit']").click()

        # Editing is a client-side modal pre-filled from the task's data.
        modal = page.locator("#edit-task-modal")
        expect(modal).to_be_visible()
        expect(modal.locator("#etk-name")).to_have_value(task_name)
        body = page.content()
        assert "UndefinedError" not in body
        assert "Traceback" not in body
        assert "Internal Server Error" not in body
    finally:
        _delete_task(page, live_server, task_name)
        _delete_wordlist(page, live_server, wl_name)


@pytest.mark.e2e
def test_tasks_edit_change_name_persists(page, live_server, login):
    """Renaming a task in the edit modal should be visible on /tasks afterwards."""
    login()
    suffix = uuid.uuid4().hex[:6]
    wl_name = f"e2e-wl-{suffix}"
    original_name = f"e2e-edit-name-{suffix}"
    new_name = f"e2e-edit-renamed-{suffix}"

    _add_static_wordlist(page, live_server, wl_name)
    final_task_name = original_name
    try:
        _create_task(page, live_server, original_name, "0", wl_name)

        page.goto(f"{live_server}/tasks", wait_until="domcontentloaded")
        row = _row_with_text(page, original_name)
        expect(row).to_be_visible()
        row.locator("button[title='Edit']").click()
        modal = page.locator("#edit-task-modal")
        expect(modal).to_be_visible()

        modal.locator("#etk-name").fill(new_name)
        modal.get_by_role("button", name=re.compile(r"Save changes", re.I)).click()
        expect(page).to_have_url(re.compile(r".*/tasks/?$"))
        final_task_name = new_name

        page.goto(f"{live_server}/tasks", wait_until="domcontentloaded")
        expect(_row_with_text(page, new_name)).to_be_visible()
    finally:
        _delete_task(page, live_server, final_task_name)
        _delete_wordlist(page, live_server, wl_name)


@pytest.mark.e2e
def test_tasks_edit_attack_mode_change(page, live_server, login):
    """Switch a Straight task to Brute-force (mask) in the edit modal."""
    login()
    suffix = uuid.uuid4().hex[:6]
    wl_name = f"e2e-wl-{suffix}"
    task_name = f"e2e-edit-mode-{suffix}"

    _add_static_wordlist(page, live_server, wl_name)
    try:
        _create_task(page, live_server, task_name, "0", wl_name)

        page.goto(f"{live_server}/tasks", wait_until="domcontentloaded")
        row = _row_with_text(page, task_name)
        expect(row).to_be_visible()
        row.locator("button[title='Edit']").click()
        modal = page.locator("#edit-task-modal")
        expect(modal).to_be_visible()

        modal.locator("#etk-t-mask").click()      # switch to Brute-force (mask) tab
        modal.locator("#etk-mask").fill("?l?l?l?l")
        modal.get_by_role("button", name=re.compile(r"Save changes", re.I)).click()
        expect(page).to_have_url(re.compile(r".*/tasks/?$"))

        page.goto(f"{live_server}/tasks", wait_until="domcontentloaded")
        expect(_row_with_text(page, task_name)).to_be_visible()
    finally:
        _delete_task(page, live_server, task_name)
        _delete_wordlist(page, live_server, wl_name)
