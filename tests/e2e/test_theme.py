import re

import pytest
from playwright.sync_api import expect


def _open_account_modal(page):
    page.evaluate("document.getElementById('account-settings-modal').showModal()")
    expect(page.locator("#account-settings-modal")).to_be_visible()


def _theme_attr(page):
    return page.evaluate("document.documentElement.getAttribute('data-theme')")


@pytest.mark.e2e
def test_toggle_applies_live(page, live_server, login):
    login()
    if not page.get_by_role("link", name="Jobs").is_visible():
        pytest.skip("Login failed against external server; set HASHVIEW_E2E_EMAIL/PASSWORD.")
    _open_account_modal(page)
    for value in ["light-paper", "light-invert", "light-clean", "dark"]:
        page.locator(f'.hv-theme-opt[data-theme-value="{value}"]').click()
        page.wait_for_timeout(200)
        assert _theme_attr(page) == value


@pytest.mark.e2e
def test_persistence_across_reload_no_flash(page, live_server, login):
    login()
    if not page.get_by_role("link", name="Jobs").is_visible():
        pytest.skip("Login failed against external server; set HASHVIEW_E2E_EMAIL/PASSWORD.")
    _open_account_modal(page)
    page.locator('.hv-theme-opt[data-theme-value="light-paper"]').click()
    page.wait_for_timeout(500)
    resp = page.goto(f"{live_server}/", wait_until="domcontentloaded")
    assert 'data-theme="light-paper"' in resp.text()
    assert _theme_attr(page) == "light-paper"


@pytest.mark.e2e
def test_persistence_across_sessions(page, live_server, login):
    login()
    if not page.get_by_role("link", name="Jobs").is_visible():
        pytest.skip("Login failed against external server; set HASHVIEW_E2E_EMAIL/PASSWORD.")
    _open_account_modal(page)
    page.locator('.hv-theme-opt[data-theme-value="light-invert"]').click()
    page.wait_for_timeout(500)
    page.goto(f"{live_server}/logout", wait_until="domcontentloaded")
    page.evaluate("try{localStorage.removeItem('hv_theme')}catch(e){}")
    login()
    resp = page.goto(f"{live_server}/", wait_until="domcontentloaded")
    assert 'data-theme="light-invert"' in resp.text()


@pytest.mark.e2e
def test_auto_follows_os(page, live_server, login):
    login()
    if not page.get_by_role("link", name="Jobs").is_visible():
        pytest.skip("Login failed against external server; set HASHVIEW_E2E_EMAIL/PASSWORD.")
    _open_account_modal(page)
    page.locator('.hv-theme-opt[data-theme-value="auto"]').click()
    page.wait_for_timeout(500)
    page.emulate_media(color_scheme="light")
    page.goto(f"{live_server}/", wait_until="domcontentloaded")
    assert _theme_attr(page) == "light-paper"
    page.emulate_media(color_scheme="dark")
    page.goto(f"{live_server}/", wait_until="domcontentloaded")
    assert _theme_attr(page) == "dark"


@pytest.mark.e2e
def test_unauthenticated_login_page_honors_localstorage(page, live_server):
    page.goto(f"{live_server}/login", wait_until="domcontentloaded")
    page.evaluate("try{localStorage.setItem('hv_theme','light-paper')}catch(e){}")
    page.goto(f"{live_server}/login", wait_until="domcontentloaded")
    assert _theme_attr(page) == "light-paper"
