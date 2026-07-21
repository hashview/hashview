"""Rendered-HTML UI tests for the wordlist-provider interface.

These drive the Flask test client and assert on the actual rendered markup, so
they catch template/context regressions (missing tab, broken form action, a
secret leaking into the page, the wizard step not rendering) that the pure
route/DB tests in test_provider_settings_routes.py don't see. They run in the
standard unit environment (SQLite + create_all), no browser required.

Browser-level coverage of the same flows lives in tests/e2e/test_wordlist_providers.py.
"""
import pytest

from hashview.models import (
    Customers,
    JobTasks,
    Jobs,
    Settings,
    Tasks,
    WordlistProviders,
    Wordlists,
    db,
)
from tests.unit.helpers import login, make_admin, make_user


def _settings_row():
    """settings_list() reads Settings.query.first(); give it a row to render."""
    s = Settings(retention_period=30, max_runtime_jobs=0, max_runtime_tasks=0)
    db.session.add(s)
    db.session.commit()
    return s


def _add_payload(**over):
    data = dict(name="Weakpass", description="breach-derived", base_url="https://api.example.com/hv",
                auth_type="bearer", username="", provider_secret="TOP-SECRET-TOKEN",
                verify_tls="y", enabled="y")
    data.update(over)
    return data


# ---------------- Settings: Wordlist Providers section ----------------

@pytest.mark.security
def test_settings_page_renders_providers_tab_and_add_form(app, client):
    _settings_row()
    login(client, make_admin())

    html = client.get("/settings").get_data(as_text=True)

    # the tab and its pane
    assert 'data-tab="providers"' in html
    assert 'data-pane="providers"' in html
    assert "Wordlist providers" in html
    # the add form points at the add route and exposes the key fields
    assert 'action="/settings/providers/add"' in html
    for field in ('name="name"', 'name="base_url"', 'name="auth_type"', 'name="provider_secret"'):
        assert field in html, field


@pytest.mark.security
def test_settings_page_lists_registered_provider_without_leaking_secret(app, client):
    _settings_row()
    login(client, make_admin())
    client.post("/settings/providers/add", data=_add_payload(), follow_redirects=False)

    html = client.get("/settings").get_data(as_text=True)

    # the provider is listed by name + base url ...
    assert "Weakpass" in html
    assert "https://api.example.com/hv" in html
    # ... but its secret is write-only and must never reach the page
    assert "TOP-SECRET-TOKEN" not in html


@pytest.mark.security
def test_settings_providers_tab_hidden_from_non_admin(app, client):
    _settings_row()
    login(client, make_user())
    resp = client.get("/settings")
    # settings_list aborts 403 for non-admins
    assert resp.status_code == 403


# ---------------- Job wizard: Provider Input step ----------------

def _job_with_provider_task():
    provider = WordlistProviders(name="Weakpass", base_url="https://api.example.com/hv",
                                 auth_type="bearer", provider_secret="s", verify_tls=True,
                                 enabled=True, owner_id=1)
    db.session.add(provider)
    db.session.commit()
    wl = Wordlists(name="(DYNAMIC) Weakpass", owner_id=1, type="dynamic",
                   path="hashview/control/wordlists/provider-x.txt", checksum="", size=0,
                   provider_id=provider.id)
    db.session.add(Customers(name="c"))
    db.session.add(wl)
    db.session.commit()
    job = Jobs(name="j", status="Ready", customer_id=1, owner_id=1)
    db.session.add(job)
    db.session.commit()
    task = Tasks(name="t", hc_attackmode=0, owner_id=1, wl_id=wl.id)
    db.session.add(task)
    db.session.commit()
    db.session.add(JobTasks(job_id=job.id, task_id=task.id, status="Not Started"))
    db.session.commit()
    return job


@pytest.mark.security
def test_wizard_provider_input_step_renders_for_provider_job(app, client):
    login(client, make_admin())
    job = _job_with_provider_task()

    html = client.get(f"/jobs/{job.id}/provider_input").get_data(as_text=True)

    assert "Wordlist Provider Input" in html
    assert 'name="provider_input"' in html
    # the conditional stepper step is revealed
    assert "show-prov" in html
    assert "Provider Input" in html


@pytest.mark.security
def test_wizard_provider_input_step_skipped_without_provider_task(app, client):
    login(client, make_admin())
    db.session.add(Customers(name="c"))
    db.session.commit()
    job = Jobs(name="j", status="Ready", customer_id=1, owner_id=1)
    db.session.add(job)
    db.session.commit()

    resp = client.get(f"/jobs/{job.id}/provider_input", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith(f"/jobs/{job.id}/summary")


@pytest.mark.security
def test_provider_only_job_reaches_provider_input_via_website_step(app, client):
    """A job that uses a provider wordlist but NOT website keywords enters the
    wizard at /website. The website step must hand off to /provider_input rather
    than skipping straight to /summary, or the operator never gets to enter the
    provider input."""
    login(client, make_admin())
    job = _job_with_provider_task()   # provider wordlist assigned, no website keywords

    resp = client.get(f"/jobs/{job.id}/website", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith(f"/jobs/{job.id}/provider_input")


@pytest.mark.security
def test_plain_job_falls_through_website_and_provider_input_to_summary(app, client):
    """A job using neither website keywords nor a provider wordlist must fall
    straight through the chain: /website -> /provider_input -> /summary, each
    conditional step self-skipping (existing flow unbroken)."""
    login(client, make_admin())
    db.session.add(Customers(name="c"))
    db.session.commit()
    job = Jobs(name="j", status="Ready", customer_id=1, owner_id=1)
    db.session.add(job)
    db.session.commit()

    r1 = client.get(f"/jobs/{job.id}/website", follow_redirects=False)
    assert r1.status_code == 302 and r1.headers["Location"].endswith(f"/jobs/{job.id}/provider_input")

    r2 = client.get(f"/jobs/{job.id}/provider_input", follow_redirects=False)
    assert r2.status_code == 302 and r2.headers["Location"].endswith(f"/jobs/{job.id}/summary")


# ---------------- Wordlists list: provider badge ----------------

@pytest.mark.security
def test_wordlists_list_shows_provider_badge(app, client):
    login(client, make_admin())
    provider = WordlistProviders(name="Weakpass", base_url="https://api.example.com/hv",
                                 auth_type="bearer", provider_secret="s", verify_tls=True,
                                 enabled=True, owner_id=1)
    db.session.add(provider)
    db.session.commit()
    prov_wl = Wordlists(name="(DYNAMIC) Weakpass", owner_id=1, type="dynamic",
                        path="hashview/control/wordlists/provider-y.txt", checksum="", size=0,
                        provider_id=provider.id)
    plain_wl = Wordlists(name="(DYNAMIC) Website Keywords", owner_id=1, type="dynamic",
                         path="hashview/control/wordlists/dynamic-website-keywords.txt",
                         checksum="", size=0)
    db.session.add_all([prov_wl, plain_wl])
    db.session.commit()

    html = client.get("/wordlists").get_data(as_text=True)

    assert "(DYNAMIC) Weakpass" in html
    # the provider-backed row carries the cyan "provider" badge (exact chip markup)
    assert '<span class="badge cyan" title="Materialized from a remote wordlist provider">provider</span>' in html
    # exactly one badge -> the plain dynamic row does NOT get one
    assert html.count(">provider</span>") == 1
