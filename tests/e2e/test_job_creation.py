import os
import re

import pytest
from playwright.sync_api import expect


@pytest.mark.e2e
def test_job_creation_flow(page, live_server, login):
    login()
    customer_id = os.getenv("HASHVIEW_E2E_CUSTOMER_ID")
    hashfile_id = os.getenv("HASHVIEW_E2E_HASHFILE_ID")
    task_id = os.getenv("HASHVIEW_E2E_TASK_ID")
    task_name = os.getenv("HASHVIEW_E2E_TASK_NAME")
    if not all([customer_id, hashfile_id, task_id, task_name]):
        pytest.skip(
            "Set HASHVIEW_E2E_CUSTOMER_ID, HASHVIEW_E2E_HASHFILE_ID, "
            "HASHVIEW_E2E_TASK_ID, HASHVIEW_E2E_TASK_NAME."
        )
    page.get_by_role("link", name="Jobs").click()
    page.get_by_role("link", name="New Job", exact=True).click()
    expect(page.get_by_role("heading", name="Create Job")).to_be_visible()

    page.get_by_label("Job Name").fill("E2E Job")
    if page.locator("#priority").count() > 0:
        # priority is now a range slider, not a <select>
        page.locator("#priority").evaluate(
            "el => { el.value = '3'; el.dispatchEvent(new Event('input')); }"
        )
    customer_option = page.locator(f"#customer_id option[value='{customer_id}']")
    if customer_option.count() == 0:
        page.locator("#customer_id").select_option("add_new")
        customer_name = os.getenv("HASHVIEW_E2E_CUSTOMER_NAME", "E2E Customer")
        page.locator("#new_customer_div input[name='customer_name']").fill(
            customer_name
        )
    else:
        page.locator("#customer_id").select_option(str(customer_id))
    page.get_by_role("button", name="Next").click()

    expect(
        page.get_by_role("heading", name=re.compile(r"Assign Hashes"))
    ).to_be_visible()
    # Existing-hashfile picker is now a radio-row table under the "Use existing" tab.
    page.locator("#tab-existing").click()
    radio = page.locator(
        f"#pane-existing input[name='hashfile_id'][value='{hashfile_id}']"
    )
    if radio.count() == 0:
        pytest.skip("HASHVIEW_E2E_HASHFILE_ID not present in existing hashfiles list.")
    radio.check(force=True)
    page.locator("#hf_next").click()

    # Notifications step: leave all alert toggles off (= no notifications) and continue.
    expect(page.get_by_role("heading", name="Job completion")).to_be_visible()
    page.get_by_role("button", name="Next").click()

    # Tasks step — the wizard's task library / queue.
    expect(page.get_by_role("heading", name="Task Library")).to_be_visible()
    match = re.search(r"/jobs/(\d+)/tasks", page.url)
    assert match, f"Unexpected tasks URL: {page.url}"
    job_id = match.group(1)
    page.goto(
        f"{live_server}/jobs/{job_id}/assign_task/{task_id}",
        wait_until="domcontentloaded",
    )
    expect(page.get_by_role("cell", name=task_name, exact=True)).to_be_visible()
