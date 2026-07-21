"""End-to-end (browser) coverage of the wordlist-provider UI.

Flows exercised through the real rendered pages:
    Settings -> Wordlist providers tab -> add a provider -> it appears in the
      table, its secret is never shown, then delete it and confirm it's gone.
    A registered provider shows up as a (DYNAMIC) option in the task wordlist
      dropdown (where a wordlist is actually bound to an attack).

Server-side/route coverage lives in tests/unit/test_provider_settings_routes.py;
rendered-markup coverage in tests/unit/test_provider_ui_render.py. These add the
real-browser layer (custom tab JS, form submit + CSRF, confirm() dialog).
"""
import re
import uuid

import pytest
from playwright.sync_api import expect

NAV_TIMEOUT = 15_000


def _open_providers_tab(page, live_server):
    page.goto(f"{live_server}/settings", wait_until="domcontentloaded")
    page.locator('button[data-tab="providers"]').click()
    expect(page.locator('[data-pane="providers"]')).to_be_visible()


def _add_provider(page, live_server, name, secret):
    _open_providers_tab(page, live_server)
    page.locator("#prov-name").fill(name)
    page.locator("#prov-url").fill("https://api.example.com/hv")
    page.locator("#prov-secret").fill(secret)
    page.locator("#prov-submit").click(timeout=NAV_TIMEOUT)
    expect(page).to_have_url(re.compile(r".*/settings/?$"), timeout=NAV_TIMEOUT)
    expect(page.get_by_text("Wordlist provider added.", exact=False)).to_be_visible(timeout=NAV_TIMEOUT)


@pytest.mark.e2e
def test_add_provider_then_delete(page, live_server, login):
    """Register a provider through the UI, confirm it lists without leaking the
    secret, then delete it and confirm it's gone."""
    login()
    name = f"e2e-prov-{uuid.uuid4().hex[:8]}"
    secret = f"secret-{uuid.uuid4().hex}"

    _add_provider(page, live_server, name, secret)

    # it now appears in the registered-providers table
    _open_providers_tab(page, live_server)
    row = page.locator("tr", has=page.locator("td", has_text=name)).first
    expect(row).to_be_visible()
    # write-only: the secret value must never render anywhere on the page
    expect(page.get_by_text(secret, exact=False)).to_have_count(0)

    # delete it (the row's delete form fires a confirm() dialog)
    page.on("dialog", lambda d: d.accept())
    row.locator("button.act-del").click(timeout=NAV_TIMEOUT)
    expect(page).to_have_url(re.compile(r".*/settings/?$"), timeout=NAV_TIMEOUT)
    expect(page.get_by_text("Wordlist provider deleted.", exact=False)).to_be_visible(timeout=NAV_TIMEOUT)

    _open_providers_tab(page, live_server)
    assert page.locator("tr", has=page.locator("td", has_text=name)).count() == 0


@pytest.mark.e2e
def test_provider_wordlist_selectable_on_task_form(page, live_server, login):
    """A registered provider becomes a (DYNAMIC) option in the task wordlist
    dropdown — the screen where a wordlist is bound to an attack."""
    login()
    name = f"e2e-provsel-{uuid.uuid4().hex[:8]}"
    _add_provider(page, live_server, name, "s3cr3t")

    page.goto(f"{live_server}/tasks/add", wait_until="domcontentloaded")
    # the option is present in the wordlist <select> even while its div is hidden
    option = page.locator("#wl_id option", has_text=f"(DYNAMIC) {name}")
    expect(option).to_have_count(1)
