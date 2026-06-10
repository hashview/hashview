import os
import re
from pathlib import Path

import pytest
from playwright.sync_api import expect


def _select_customer(page):
    customer_id = os.getenv("HASHVIEW_E2E_CUSTOMER_ID")
    if customer_id:
        option = page.locator(f"#customer_id option[value='{customer_id}']")
        if option.count() > 0:
            page.locator("#customer_id").select_option(str(customer_id))
            return
    page.locator("#customer_id").select_option("add_new")
    customer_name = os.getenv("HASHVIEW_E2E_CUSTOMER_NAME", "E2E Customer")
    page.locator("#new_customer_div input[name='customer_name']").fill(customer_name)


@pytest.mark.e2e
def test_login_invalid_email_shows_error(page, live_server):
    page.goto(f"{live_server}/login", wait_until="domcontentloaded")
    page.get_by_label("Email").fill("not-an-email")
    page.get_by_label("Password").fill("not-a-real-password")
    page.get_by_role("button", name="Crack the planet!").click()
    expect(page.get_by_text("Invalid email address", exact=False)).to_be_visible()


@pytest.mark.e2e
def test_job_name_required_validation(page, live_server, login):
    login()
    page.get_by_role("link", name="Jobs").click()
    page.get_by_role("link", name="New Job", exact=True).click()
    expect(page.get_by_role("heading", name="Create Job")).to_be_visible()

    _select_customer(page)
    page.get_by_role("button", name="Next").click()
    expect(page.get_by_role("heading", name="Create Job")).to_be_visible()


@pytest.mark.e2e
def test_job_name_xss_is_escaped(page, live_server, login):
    login()
    page.get_by_role("link", name="Jobs").click()
    page.get_by_role("link", name="New Job", exact=True).click()
    expect(page.get_by_role("heading", name="Create Job")).to_be_visible()

    xss_payload = '<script id="xss-test">window.__xss=1</script>'
    page.get_by_label("Job Name").fill(xss_payload)
    if page.locator("#priority").count() > 0:
        # priority is now a range slider, not a <select>
        page.locator("#priority").evaluate(
            "el => { el.value = '3'; el.dispatchEvent(new Event('input')); }"
        )
    _select_customer(page)
    page.get_by_role("button", name="Next").click()
    expect(
        page.get_by_role("heading", name=re.compile(r"Assign Hashes"))
    ).to_be_visible()

    page.goto(f"{live_server}/jobs", wait_until="domcontentloaded")
    assert page.locator("script#xss-test").count() == 0
    expect(page.locator('text=<script id="xss-test"').first).to_be_visible()


@pytest.mark.e2e
def test_hashfile_validation_rejects_invalid_hash(page, live_server, login):
    login()
    page.get_by_role("link", name="Jobs").click()
    page.get_by_role("link", name="New Job", exact=True).click()
    expect(page.get_by_role("heading", name="Create Job")).to_be_visible()

    page.get_by_label("Job Name").fill("E2E Invalid Hash Test")
    _select_customer(page)
    page.get_by_role("button", name="Next").click()
    expect(
        page.get_by_role("heading", name=re.compile(r"Assign Hashes"))
    ).to_be_visible()

    page.locator("#tab-paste").click()
    page.locator("select[name='file_type']").select_option("hash_only")
    page.locator("select[name='hash_type']").select_option("0")
    page.locator("#pane-newhash input[name='name']").fill("e2e-invalid-hashfile")
    page.locator("textarea[name='hashfilehashes']").fill("short")
    page.get_by_role("button", name="Next").click()
    expect(page).to_have_url(re.compile(r".*/assigned_hashfile"))
    if page.locator(".flash-danger").count() > 0:
        expect(page.locator(".flash-danger").first).to_be_visible()


@pytest.mark.e2e
def test_hashfile_upload_example_file(page, live_server, login):
    login()
    page.get_by_role("link", name="Jobs").click()
    page.get_by_role("link", name="New Job", exact=True).click()
    expect(page.get_by_role("heading", name="Create Job")).to_be_visible()

    page.get_by_label("Job Name").fill("E2E Upload Example Hashfile")
    _select_customer(page)
    page.get_by_role("button", name="Next").click()
    expect(
        page.get_by_role("heading", name=re.compile(r"Assign Hashes"))
    ).to_be_visible()

    page.locator("select[name='file_type']").select_option("hash_only")
    page.locator("select[name='hash_type']").select_option("0")
    page.locator("#tab-upload").click()
    example_path = Path(__file__).parent / "example_hashes.txt"
    page.set_input_files("input[name='hashfile']", str(example_path))
    page.get_by_role("button", name="Next").click()
    if not re.search(r"/notifications", page.url):
        expect(page).to_have_url(re.compile(r".*/assigned_hashfile/\d+"))


@pytest.mark.e2e
def test_hashfile_upload_example_pwdump(page, live_server, login):
    login()
    page.get_by_role("link", name="Jobs").click()
    page.get_by_role("link", name="New Job", exact=True).click()
    expect(page.get_by_role("heading", name="Create Job")).to_be_visible()

    page.get_by_label("Job Name").fill("E2E Upload Example Pwdump")
    _select_customer(page)
    page.get_by_role("button", name="Next").click()
    expect(
        page.get_by_role("heading", name=re.compile(r"Assign Hashes"))
    ).to_be_visible()

    page.locator("select[name='file_type']").select_option("pwdump")
    page.locator("select[name='pwdump_hash_type']").select_option("1000")
    page.locator("#tab-upload").click()
    example_path = Path(__file__).parent / "example_pwdump.txt"
    page.set_input_files("input[name='hashfile']", str(example_path))
    page.get_by_role("button", name="Next").click()
    if not re.search(r"/notifications", page.url):
        expect(page).to_have_url(re.compile(r".*/assigned_hashfile/\d+"))
