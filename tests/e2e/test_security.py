import os
import re
import uuid

import pytest
from playwright.sync_api import expect


def _xss_payload(label: str):
    token = uuid.uuid4().hex[:8]
    element_id = f"xss-{label}-{token}"
    payload = f'<script id="{element_id}">window.__xss=1</script>'
    return element_id, payload


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


def _login(page, live_server, email, password):
    page.goto(f"{live_server}/login", wait_until="domcontentloaded")
    page.get_by_label("Email").fill(email)
    page.get_by_label("Password").fill(password)
    page.get_by_role("button", name="Crack the planet!").click()
    if not page.get_by_role("link", name="Jobs").is_visible():
        pytest.skip("Login failed against external server.")


@pytest.mark.e2e
def test_customer_name_xss_is_escaped(page, live_server, login):
    login()
    payload = "<svg onload=alert(1)>"

    page.get_by_role("link", name="Jobs").click()
    page.get_by_role("link", name="New Job", exact=True).click()
    expect(page.get_by_role("heading", name="Create Job")).to_be_visible()

    page.locator("input[name='name']").fill(f"E2E XSS Customer {uuid.uuid4().hex[:6]}")
    if page.locator("#priority").count() > 0:
        # priority is now a range slider, not a <select>
        page.locator("#priority").evaluate(
            "el => { el.value = '3'; el.dispatchEvent(new Event('input')); }"
        )
    customer_select = page.locator("#customer_id")
    customer_select.select_option("add_new")
    if customer_select.input_value() != "add_new":
        page.evaluate(
            "const el=document.querySelector('#customer_id');"
            "if(el){el.value='add_new';el.dispatchEvent(new Event('change'));}"
        )
    page.locator("input[name='customer_name']").fill(payload)
    page.get_by_role("button", name="Next").click()
    try:
        expect(
            page.get_by_role("heading", name=re.compile(r"Assign Hashes"))
        ).to_be_visible()
    except AssertionError:
        pytest.skip("Job creation failed; customer not created.")

    page.goto(f"{live_server}/customers", wait_until="domcontentloaded")
    content = page.content()
    assert "<svg onload=alert(1)>" not in content
    assert "&lt;svg onload=alert(1)&gt;" in content


@pytest.mark.e2e
def test_task_name_xss_is_escaped(page, live_server, login):
    login()
    element_id, payload = _xss_payload("task")

    page.goto(f"{live_server}/tasks/add", wait_until="domcontentloaded")
    page.locator("#name").fill(payload)

    attack_mode = page.locator("#hc_attackmode")
    if attack_mode.count() == 0:
        pytest.skip("Task attack mode selector not found.")

    # Attack-mode <option> values are numeric (see hashview/tasks/forms.py):
    # 3 = Brute-force (mask), which needs only a mask — no pre-existing wordlist —
    # so this XSS-escaping check stays self-contained.
    if attack_mode.locator("option[value='3']").count() == 0:
        pytest.skip("Brute-force (mask) attack mode not available.")
    attack_mode.select_option("3")
    page.locator("#mask").fill("?l?l?l?l?l?l")

    page.get_by_role("button", name=re.compile(r"^Create$", re.I)).click()
    # A successful create redirects to /tasks; failed validation stays on /tasks/add.
    expect(page).to_have_url(re.compile(r".*/tasks/?$"))

    assert page.locator(f"script#{element_id}").count() == 0
    content = page.content()
    assert f'<script id="{element_id}">' not in content
    assert f'&lt;script id="{element_id}"' in content


@pytest.mark.e2e
def test_agent_name_xss_is_escaped(page, live_server, login):
    login()
    element_id, payload = _xss_payload("agent")

    agent_uuid = f"agent-{uuid.uuid4()}"
    page.context.add_cookies(
        [
            {"name": "uuid", "value": agent_uuid, "url": live_server},
            {"name": "agent_version", "value": "0.8.2", "url": live_server},
            {"name": "name", "value": payload, "url": live_server},
        ]
    )
    response = page.request.post(
        f"{live_server}/v1/agents/heartbeat",
        data="{}",
        headers={"Content-Type": "application/json"},
    )
    assert response.ok

    page.goto(f"{live_server}/agents", wait_until="domcontentloaded")
    if page.get_by_text("Forbidden", exact=False).count() > 0:
        pytest.skip("Agents page requires admin access.")
    assert page.locator(f"script#{element_id}").count() == 0
    content = page.content()
    assert f'<script id="{element_id}">' not in content
    assert f'&lt;script id="{element_id}"' in content


@pytest.mark.e2e
def test_login_next_param_not_open_redirect(page, live_server, test_user_credentials):
    page.goto(
        f"{live_server}/login?next=https://example.com",
        wait_until="domcontentloaded",
    )
    page.get_by_label("Email").fill(test_user_credentials["email"])
    page.get_by_label("Password").fill(test_user_credentials["password"])
    page.get_by_role("button", name="Crack the planet!").click()
    # The crafted off-site ?next= must be ignored: login redirects through the
    # same-site guard, so the user always lands back on the app, never on
    # example.com. (Previously xfail — fixed in login_post via _safe_next.)
    assert page.url.startswith(live_server), (
        f"login honored an off-site next= (open redirect): {page.url}"
    )


@pytest.mark.e2e
def test_job_idor_access_denied_for_other_user(
    page, live_server, test_user_credentials
):
    second_email = os.getenv("HASHVIEW_E2E_SECOND_EMAIL")
    second_password = os.getenv("HASHVIEW_E2E_SECOND_PASSWORD")
    if not second_email or not second_password:
        pytest.skip("Set HASHVIEW_E2E_SECOND_EMAIL and HASHVIEW_E2E_SECOND_PASSWORD.")
    if os.getenv("HASHVIEW_E2E_SECOND_IS_ADMIN", "0") in {"1", "true", "yes"}:
        pytest.skip("Second user is admin; IDOR check requires non-admin user.")

    _login(
        page,
        live_server,
        test_user_credentials["email"],
        test_user_credentials["password"],
    )
    page.get_by_role("link", name="Jobs").click()
    page.get_by_role("link", name="New Job", exact=True).click()
    expect(page.get_by_role("heading", name="Create Job")).to_be_visible()

    page.get_by_label("Job Name").fill("E2E IDOR Job")
    _select_customer(page)
    page.get_by_role("button", name="Next").click()
    match = re.search(r"/jobs/(\d+)/assigned_hashfile", page.url)
    if not match:
        pytest.skip("Could not determine job id for IDOR test.")
    job_id = match.group(1)

    page.goto(f"{live_server}/logout", wait_until="domcontentloaded")
    _login(page, live_server, second_email, second_password)

    # Hashview uses a shared-jobs model: every authenticated user may VIEW any
    # job (the jobs list is org-wide), so authorization is enforced on
    # MUTATIONS, not views. The IDOR check therefore verifies a non-owner,
    # non-admin user cannot STOP another user's job. jobs_stop gates on
    # `current_user.admin or job.owner_id == current_user.id`, so a successful
    # denial proves the ownership guard holds.
    #
    # jobs_stop is declared methods=['POST'] (hashview/jobs/routes.py:952) and
    # calls FlaskForm().validate_on_submit(), so a GET would 405 and a POST
    # without a valid CSRF token would be rejected before the ownership guard is
    # ever reached. We therefore scrape a session-bound CSRF token from the
    # rendered /jobs list (jobs.html.j2 renders
    # `<input type="hidden" name="csrf_token" ...>`) and POST as the non-owner
    # via page.request, which shares this browser context's session cookies.
    page.goto(f"{live_server}/jobs", wait_until="domcontentloaded")
    token = page.locator("input[name='csrf_token']").first.get_attribute("value")
    resp = page.request.post(
        f"{live_server}/jobs/stop/{job_id}",
        form={"csrf_token": token},
    )
    body = resp.text().lower()
    assert "do not have rights to stop this job" in body, (
        "Second user was not denied when stopping another user's job; possible IDOR."
    )
