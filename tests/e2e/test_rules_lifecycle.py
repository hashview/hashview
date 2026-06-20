"""End-to-end coverage of the rules-file lifecycle: upload then delete.

The flow exercised:
    GET  /rules/add  -> upload file with a unique name
    GET  /rules      -> verify the new rule row exists
    POST /rules/delete/<id>  (via the in-page delete modal)
    GET  /rules      -> verify the row is gone
"""

import re
import uuid
from pathlib import Path

import pytest
from playwright.sync_api import expect


EXAMPLE_RULE = Path(__file__).parent / "example_rule.rule"

# Form submits here POST then redirect+reload. Playwright's click auto-waits for
# that navigation to finish; the default 5s action timeout is too tight on a
# loaded CI runner, so give navigation-bound steps a generous explicit budget.
NAV_TIMEOUT = 15_000


def _open_rules_list(page, live_server):
    page.goto(f"{live_server}/rules", wait_until="domcontentloaded")
    expect(page.get_by_role("heading", name=re.compile(r"Rules"))).to_be_visible()


def _row_for_rule(page, name: str):
    return page.locator("tr", has=page.locator("td", has_text=name)).first


def _add_rule(page, live_server, name: str) -> None:
    page.goto(f"{live_server}/rules/add", wait_until="domcontentloaded")
    expect(page.get_by_role("heading", name=re.compile(r"Add Rules"))).to_be_visible()
    page.locator("input[name='name']").fill(name)
    page.set_input_files("input[name='rules']", str(EXAMPLE_RULE))
    page.get_by_role("button", name="upload", exact=True).click(timeout=NAV_TIMEOUT)
    expect(page).to_have_url(re.compile(r".*/rules/?$"), timeout=NAV_TIMEOUT)
    expect(page.get_by_text("Rules File created!", exact=False)).to_be_visible(timeout=NAV_TIMEOUT)


def _delete_rule_via_modal(page, name: str) -> None:
    row = _row_for_rule(page, name)
    expect(row).to_be_visible()
    row.locator("button.act-del").click()
    modal = page.locator("dialog.hv-dialog[open]")
    expect(modal).to_be_visible()
    modal.locator("form[action*='/rules/delete/'] button[type='submit']").first.click(timeout=NAV_TIMEOUT)
    expect(page).to_have_url(re.compile(r".*/rules/?$"), timeout=NAV_TIMEOUT)
    expect(page.get_by_text("Rule file has been deleted!", exact=False)).to_be_visible(timeout=NAV_TIMEOUT)


@pytest.mark.e2e
def test_rule_add_then_delete(page, live_server, login):
    """Upload a new rule file, then delete it and confirm it is gone."""
    login()
    name = f"e2e-rule-{uuid.uuid4().hex[:8]}"

    _add_rule(page, live_server, name)

    _open_rules_list(page, live_server)
    expect(_row_for_rule(page, name)).to_be_visible()

    _delete_rule_via_modal(page, name)

    _open_rules_list(page, live_server)
    assert _row_for_rule(page, name).count() == 0, (
        f"Rule '{name}' still present after delete"
    )
