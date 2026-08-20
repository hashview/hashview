"""Reachability coverage for every authenticated top-level page.

Before this file the e2e suite only visited the pages a handful of workflow
tests happened to pass through, so whole features (Users, Settings, Search,
Task Groups, Hashfiles, Logs, Notifications, API Docs) could 500 on every
request and CI would still be green.

Two layers:

* ``test_page_renders`` walks a fixed list of pages and asserts each one
  actually renders its own page for a logged-in admin.
* ``test_sidebar_nav_links_are_all_covered`` scrapes the sidebar and fails if a
  nav entry has no case in that list, so new pages can't quietly skip coverage.
"""

from urllib.parse import urlparse

import pytest
from playwright.sync_api import expect

# Substrings that only ever appear when a view blew up. Flask's debug pages and
# Jinja render errors both surface here.
ERROR_MARKERS = (
    "Internal Server Error",
    "Traceback (most recent call last)",
    "UndefinedError",
    "ZeroDivisionError",
    "werkzeug.exceptions",
)

# (path, expected <h1 class="page-title"> text). Every full page in the app
# renders exactly one of these headings, which makes it a reliable assertion
# that we landed on the intended page rather than a redirect or an error shell.
PAGES = [
    ("/", "Operations Dashboard"),
    ("/jobs", "Jobs"),
    ("/jobs/add", "Create Job"),
    ("/tasks", "Tasks"),
    ("/tasks/add", "Add Task"),
    ("/task_groups", "Task Groups"),
    ("/task_groups/add", "Create Task Group"),
    ("/hashfiles", "Hashfiles"),
    ("/wordlists", "Wordlists"),
    ("/wordlists/add", "Add Wordlist"),
    ("/rules", "Rules"),
    ("/rules/add", "Add Rules"),
    ("/analytics", "Analytics"),
    ("/search", "Search"),
    ("/notifications", "Notifications"),
    ("/api/docs", "API Docs"),
    ("/wrapped", "Wrapped"),
    ("/customers", "Customers"),
    ("/agents", "Agents"),
    ("/users", "Users"),
    ("/logs", "Logs"),
    ("/settings", "Settings"),
]


@pytest.mark.e2e
@pytest.mark.parametrize("path,heading", PAGES, ids=[p for p, _ in PAGES])
def test_page_renders(page, live_server, login, path, heading):
    login()
    page.goto(f"{live_server}{path}", wait_until="domcontentloaded")

    landed = urlparse(page.url).path
    assert landed.rstrip("/") == path.rstrip("/"), (
        f"{path} redirected to {landed}; expected to stay on the page"
    )

    content = page.content()
    for marker in ERROR_MARKERS:
        assert marker not in content, f"{marker!r} found in {path} response"

    expect(page.locator("h1.page-title")).to_have_text(heading)


@pytest.mark.e2e
def test_sidebar_nav_links_are_all_covered(page, live_server, login):
    """Every sidebar destination must have a ``test_page_renders`` case.

    The sidebar is data-driven (``_console_nav.html.j2``), so adding a feature
    is a one-line nav edit. This fails that edit until PAGES is updated too.
    """
    login()
    page.goto(f"{live_server}/", wait_until="domcontentloaded")

    nav_links = page.locator("nav.nav a.nav-item")
    count = nav_links.count()
    assert count > 0, "No sidebar nav items found; the nav markup changed"

    nav_paths = {
        urlparse(nav_links.nth(i).get_attribute("href")).path for i in range(count)
    }
    covered = {path for path, _ in PAGES}
    uncovered = {p.rstrip("/") for p in nav_paths} - {p.rstrip("/") for p in covered}
    assert not uncovered, (
        f"Sidebar links with no reachability test: {sorted(uncovered)}. "
        "Add them to PAGES in tests/e2e/test_page_reachability.py."
    )
