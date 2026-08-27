"""End-to-end coverage of task creation/deletion for each hashcat attack mode.

Sets up a fresh static wordlist and a fresh rule file at module scope, then
creates and deletes a task for each of the supported attack modes (0, 1, 3,
6, 7). Wordlist and rule are cleaned up at the end.

Attack-mode values come from `hashview/tasks/forms.py`:
    0 = Straight (Wordlist + Rules)
    1 = Combination (Wordlist1 + j-rule, Wordlist2 + k-rule)
    3 = Brute-force (Mask)
    6 = Hybrid (Wordlist + Mask)
    7 = Hybrid (Mask + Wordlist)
"""

import re
import uuid
from pathlib import Path

import pytest
from playwright.sync_api import expect

EXAMPLE_WORDLIST = Path(__file__).parent / "example_wordlist.txt"
EXAMPLE_RULE = Path(__file__).parent / "example_rule.rule"

ATTACK_MODES = [
    ("0", "Straight"),
    ("1", "Combination"),
    ("3", "BruteForce"),
    ("6", "HybridWlMask"),
    ("7", "HybridMaskWl"),
]


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


def _add_rule(page, live_server, name: str) -> None:
    page.goto(f"{live_server}/rules/add", wait_until="domcontentloaded")
    expect(page.get_by_role("heading", name=re.compile(r"Add Rules"))).to_be_visible()
    page.locator("input[name='name']").fill(name)
    page.set_input_files("input[name='rules']", str(EXAMPLE_RULE))
    page.get_by_role("button", name="upload", exact=True).click()
    expect(page).to_have_url(re.compile(r".*/rules/?$"))


def _delete_rule(page, live_server, name: str) -> None:
    page.goto(f"{live_server}/rules", wait_until="domcontentloaded")
    row = _row_with_text(page, name)
    if row.count() == 0:
        return
    row.locator("button.act-del").click()
    modal = page.locator("dialog.hv-dialog[open]")
    expect(modal).to_be_visible()
    modal.locator("form[action*='/rules/delete/'] button[type='submit']").first.click()
    expect(page).to_have_url(re.compile(r".*/rules/?$"))


def _create_task(page, live_server, name: str, mode_value: str,
                 wl_name: str, wl2_name: str, rule_name: str) -> None:
    """Fill the /tasks/add form for the given attack mode and submit."""
    page.goto(f"{live_server}/tasks/add", wait_until="domcontentloaded")
    page.locator("#name").fill(name)
    page.locator("#hc_attackmode").select_option(mode_value)

    if mode_value == "0":  # Straight: needs wordlist + (optional) rule
        page.locator("#wl_id").select_option(label=wl_name)
        # rule_id is a select; if our rule is in the list, pick it
        if page.locator(f"#rule_id option:has-text('{rule_name}')").count() > 0:
            page.locator("#rule_id").select_option(label=rule_name)
    elif mode_value == "1":  # Combination: two wordlists + j-/k- rules
        page.locator("#wl_id").select_option(label=wl_name)
        page.locator("#wl_id_2").select_option(label=wl2_name)
        page.locator("#j_rule").fill("$1")
        page.locator("#k_rule").fill("$!")
    elif mode_value == "3":  # Brute-force: mask only
        page.locator("#mask").fill("?l?l?l?l")
    elif mode_value in {"6", "7"}:  # Hybrid: wordlist + mask
        page.locator("#wl_id").select_option(label=wl_name)
        page.locator("#mask").fill("?d?d?d?d")
    else:
        raise AssertionError(f"Unhandled attack mode {mode_value!r}")

    page.get_by_role("button", name=re.compile(r"^Create$", re.I)).click()
    # Successful create redirects to /tasks; failed validation stays on /tasks/add.
    expect(page).to_have_url(re.compile(r".*/tasks/?$"))


def _delete_task(page, live_server, name: str) -> None:
    page.goto(f"{live_server}/tasks", wait_until="domcontentloaded")
    row = _row_with_text(page, name)
    expect(row).to_be_visible()
    row.locator("button.act-del").click()
    modal = page.locator("dialog.hv-dialog[open]")
    expect(modal).to_be_visible()
    modal.locator("form[action*='/tasks/delete/'] button[type='submit']").first.click()
    expect(page).to_have_url(re.compile(r".*/tasks/?$"))


@pytest.mark.e2e
def test_create_and_delete_task_for_each_attack_mode(page, live_server, login):
    """For each attack mode 0/1/3/6/7: create the task then delete it.

    A static wordlist (also reused as the second combinator wordlist) and a
    rule file are created up-front and removed at the end.
    """
    login()
    suffix = uuid.uuid4().hex[:6]
    wl_name = f"e2e-wl-{suffix}"
    wl2_name = f"e2e-wl2-{suffix}"
    rule_name = f"e2e-rule-{suffix}"

    _add_static_wordlist(page, live_server, wl_name)
    _add_static_wordlist(page, live_server, wl2_name)
    _add_rule(page, live_server, rule_name)

    created_tasks = []
    try:
        for mode_value, mode_label in ATTACK_MODES:
            task_name = f"e2e-task-{mode_label}-{suffix}"
            _create_task(page, live_server, task_name, mode_value,
                         wl_name, wl2_name, rule_name)
            # Confirm the task shows in the list.
            page.goto(f"{live_server}/tasks", wait_until="domcontentloaded")
            expect(_row_with_text(page, task_name)).to_be_visible()
            created_tasks.append(task_name)

            _delete_task(page, live_server, task_name)
            assert _row_with_text(page, task_name).count() == 0, (
                f"Task {task_name!r} still present after delete"
            )
    finally:
        # Best-effort cleanup: any task we created but didn't delete, then
        # the wordlists and rule file.
        for task_name in created_tasks:
            page.goto(f"{live_server}/tasks", wait_until="domcontentloaded")
            row = _row_with_text(page, task_name)
            if row.count() > 0:
                try:
                    _delete_task(page, live_server, task_name)
                except Exception:
                    pass
        _delete_rule(page, live_server, rule_name)
        _delete_wordlist(page, live_server, wl2_name)
        _delete_wordlist(page, live_server, wl_name)
