"""The name filter on /tasks and /jobs must search every row, not just the page.

Regression tests for #414. Both listings paginate at 20 rows/page, but the
filter used to run client-side over the rendered rows only, so typing a name
that lived on a later page rendered "No tasks match that filter." even though
the record existed.

Each off-page test asserts its own precondition -- that the needle really is
absent from page 1 -- because without that the test would pass whether or not
the filter reaches the database.

Fixtures come from tests/unit/conftest.py (app, client). The login helper
mirrors tests/unit/test_rules_searches_notifications_branches.py.
"""

import re
from datetime import datetime

from hashview.models import Customers, Jobs, Tasks, Users, db

PER_PAGE = 20

# A needle that sorts after the filler names, so it lands on the last page.
LATE_NAME = "zzz-needle-on-a-later-page"


def _admin():
    u = Users(first_name="Ad", last_name="Min",
              email_address="admin@listfilter.test",
              password="x" * 60, admin=True)
    db.session.add(u)
    db.session.commit()
    return u


def _login(client, user):
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True


def _padding_names(count=PER_PAGE + 4, prefix="aaa-filler"):
    return [f"{prefix}-{i:03d}" for i in range(count)]


def _make_tasks(owner_id, names):
    for name in names:
        db.session.add(Tasks(name=name, hc_attackmode=0, owner_id=owner_id))
    db.session.commit()


def _make_jobs(owner_id, names):
    """Create one Jobs row per name, oldest first in list order.

    /jobs orders by created_at descending, so stamping created_at explicitly
    keeps the *first* name in ``names`` on the *last* page. Relying on
    insertion order instead would put the needle on page 1, and the off-page
    tests would pass without exercising anything.
    """
    customer = Customers(name="Filter Customer")
    db.session.add(customer)
    db.session.commit()
    for i, name in enumerate(names):
        db.session.add(Jobs(name=name, status="Ready",
                            customer_id=customer.id, owner_id=owner_id,
                            created_at=datetime(2026, 1, 1, 0, 0, i)))
    db.session.commit()


def _present(body, names):
    """Subset of ``names`` that appear in the rendered ``body``."""
    return [n for n in names if n in body]


# ---------------------------------------------------------------------------
# /tasks
# ---------------------------------------------------------------------------

def test_tasks_filter_finds_a_task_that_is_not_on_the_current_page(client, app):
    user = _admin()
    _login(client, user)
    _make_tasks(user.id, _padding_names() + [LATE_NAME])

    assert LATE_NAME not in client.get("/tasks").get_data(as_text=True), \
        "needle must be off page 1 for this test to mean anything"

    body = client.get("/tasks?q=needle").get_data(as_text=True)

    assert LATE_NAME in body


def test_tasks_filter_excludes_non_matching_tasks(client, app):
    user = _admin()
    _login(client, user)
    padding = _padding_names()
    _make_tasks(user.id, padding + [LATE_NAME])

    body = client.get("/tasks?q=needle").get_data(as_text=True)

    assert _present(body, padding) == []


def test_tasks_filter_is_case_insensitive(client, app):
    user = _admin()
    _login(client, user)
    _make_tasks(user.id, ["Best64-Mixed-Case"])

    body = client.get("/tasks?q=best64-MIXED").get_data(as_text=True)

    assert "Best64-Mixed-Case" in body


def test_tasks_filter_survives_a_sort_change(client, app):
    """Re-sorting a filtered listing keeps the filter applied."""
    user = _admin()
    _login(client, user)
    padding = _padding_names()
    _make_tasks(user.id, padding + [LATE_NAME])

    body = client.get(
        "/tasks?q=needle&sort_by=name&sort_order=desc").get_data(as_text=True)

    assert LATE_NAME in body
    assert _present(body, padding) == []


def test_tasks_filter_treats_like_wildcards_literally(client, app):
    """A literal % typed in the box must not match everything.

    Unescaped, '%' reaches SQL LIKE as "any sequence", so this would return
    the filler rows too.
    """
    user = _admin()
    _login(client, user)
    padding = _padding_names()
    _make_tasks(user.id, padding + ["100%-real-task"])

    body = client.get("/tasks?q=%25").get_data(as_text=True)

    assert "100%-real-task" in body
    assert _present(body, padding) == []


def test_tasks_empty_filter_is_a_no_op(client, app):
    """An empty q behaves like no filter at all (still a full first page)."""
    user = _admin()
    _login(client, user)
    names = _padding_names(25)
    _make_tasks(user.id, names)

    body = client.get("/tasks?q=").get_data(as_text=True)

    assert len(_present(body, names)) == PER_PAGE


# ---------------------------------------------------------------------------
# /jobs
# ---------------------------------------------------------------------------

def test_jobs_filter_finds_a_job_that_is_not_on_the_current_page(client, app):
    user = _admin()
    _login(client, user)
    _make_jobs(user.id, [LATE_NAME] + _padding_names())

    assert LATE_NAME not in client.get("/jobs").get_data(as_text=True), \
        "needle must be off page 1 for this test to mean anything"

    body = client.get("/jobs?q=needle").get_data(as_text=True)

    assert LATE_NAME in body


def test_jobs_filter_excludes_non_matching_jobs(client, app):
    user = _admin()
    _login(client, user)
    padding = _padding_names()
    _make_jobs(user.id, [LATE_NAME] + padding)

    body = client.get("/jobs?q=needle").get_data(as_text=True)

    assert _present(body, padding) == []


def test_tasks_clear_filter_link_drops_the_search_term(client, app):
    """The clear-filter affordance must not carry q, or it re-applies it."""
    user = _admin()
    _login(client, user)
    _make_tasks(user.id, ["needle-task"])

    body = client.get("/tasks?q=needle").get_data(as_text=True)

    clear_links = re.findall(r'href="([^"]*)"[^>]*title="Clear filter"', body)
    assert clear_links, "expected a clear-filter link while a filter is active"
    for href in clear_links:
        assert "q=needle" not in href


def test_jobs_clear_filter_link_drops_the_search_term(client, app):
    user = _admin()
    _login(client, user)
    _make_jobs(user.id, ["needle-job"])

    body = client.get("/jobs?q=needle").get_data(as_text=True)

    clear_links = re.findall(r'href="([^"]*)"[^>]*title="Clear filter"', body)
    assert clear_links, "expected a clear-filter link while a filter is active"
    for href in clear_links:
        assert "q=needle" not in href


def test_jobs_filter_composes_with_show_only_mine(client, app):
    """The filter and the owner toggle apply together, not one or the other."""
    mine = _admin()
    other = Users(first_name="Other", last_name="Owner",
                  email_address="other@listfilter.test",
                  password="x" * 60, admin=False)
    db.session.add(other)
    db.session.commit()
    _login(client, mine)

    customer = Customers(name="Compose Customer")
    db.session.add(customer)
    db.session.commit()
    db.session.add(Jobs(name="needle-mine", status="Ready",
                        customer_id=customer.id, owner_id=mine.id,
                        created_at=datetime(2026, 1, 1)))
    db.session.add(Jobs(name="needle-theirs", status="Ready",
                        customer_id=customer.id, owner_id=other.id,
                        created_at=datetime(2026, 1, 2)))
    db.session.commit()

    body = client.get(
        "/jobs?q=needle&show_only_mine=true").get_data(as_text=True)

    assert "needle-mine" in body
    assert "needle-theirs" not in body
