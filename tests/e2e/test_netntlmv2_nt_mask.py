"""E2E coverage for hashcat modes 27000/27100 (NetNTLMv1/v2 (NT)).

These modes crack the captured NT hash itself, so hashcat forces the
"password" to be exactly 32 characters -- the one attack that makes sense
against them is a brute-force mask covering all 32 positions, e.g.
'?h' * 32 (64 characters). tasks.hc_mask used to be VARCHAR(50), so that
mask was rejected by TasksForm's db_length validator before it ever reached
hashcat -- no mask-attack task against 27000/27100 could be created through
the UI at all. Fixed by widening the column to VARCHAR(255)
(migrations/versions/8662da4377b9_widen_tasks_hc_mask.py).
"""

import re
import uuid

import pytest
from playwright.sync_api import expect

# The mask hashcat requires to brute-force a mode-27100/27000 target: 32
# positions, hex charset, i.e. the full space of a 16-byte NT hash rendered
# as 32 hex characters. 64 characters total -- past the old 50-char cap.
FULL_NT_HEX_MASK = "?h" * 32


def _row_with_text(page, text: str):
    return page.locator("tr", has=page.locator("td", has_text=text)).first


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


@pytest.mark.e2e
def test_full_length_mask_task_for_netntlmv2_nt(page, live_server, login):
    """A full 32-position mask (64 chars) must be accepted, not truncated or
    rejected -- this is the only realistic attack against 27000/27100."""
    login()
    suffix = uuid.uuid4().hex[:6]
    task_name = f"e2e-netntlmv2nt-mask-{suffix}"

    page.goto(f"{live_server}/tasks/add", wait_until="domcontentloaded")
    page.locator("#name").fill(task_name)
    page.locator("#hc_attackmode").select_option("3")  # Brute-force (Mask)
    page.locator("#mask").fill(FULL_NT_HEX_MASK)
    page.get_by_role("button", name=re.compile(r"^Create$", re.I)).click()

    # A rejected mask re-renders /tasks/add with a validation error instead of
    # redirecting -- assert the redirect happened, not just the absence of text,
    # so a future truncating fix (accepted but silently shortened) still fails.
    expect(page).to_have_url(re.compile(r".*/tasks/?$"))
    expect(page.get_by_text("cannot be longer than", exact=False)).not_to_be_visible()

    try:
        expect(_row_with_text(page, task_name)).to_be_visible()

        # The mask must round-trip whole, not truncated to the old 50-char cap.
        # The edit form is a modal pre-filled client-side from the task's own
        # row (button title="Edit"), not a separate page -- see tasks.html.j2.
        page.goto(f"{live_server}/tasks", wait_until="domcontentloaded")
        row = _row_with_text(page, task_name)
        row.get_by_title("Edit").click()
        expect(page.locator("#edit-task-modal")).to_be_visible()
        expect(page.locator("#etk-mask")).to_have_value(FULL_NT_HEX_MASK)
    finally:
        _delete_task(page, live_server, task_name)
        assert _row_with_text(page, task_name).count() == 0, (
            f"Task {task_name!r} still present after delete"
        )
