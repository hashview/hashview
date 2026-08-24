"""/rules pagination, sorting, and server-side filtering.

Tests for #413. The rules listing rendered every ruleset in one unpaginated
table with no sortable columns, unlike /tasks and /jobs. Adding pagination
means the filter has to run server-side in the same change, or /rules just
acquires the bug fixed for /tasks and /jobs in #414.

Fixtures come from tests/unit/conftest.py (app, client). The login helper
mirrors tests/unit/test_rules_searches_notifications_branches.py.
"""

import re
from datetime import datetime

from hashview.models import Rules, Tasks, Users, db

PER_PAGE = 20

# A needle that sorts after the filler names, so it lands on the last page.
LATE_NAME = "zzz-needle-on-a-later-page"


def _admin():
    u = Users(first_name="Ad", last_name="Min",
              email_address="admin@rulepage.test",
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


def _make_rules(owner_id, names, sizes=None):
    for i, name in enumerate(names):
        db.session.add(Rules(name=name, owner_id=owner_id,
                             path=f"/tmp/{name}.rule",
                             size=(sizes[i] if sizes else 1),
                             checksum=f"{i:064d}",
                             last_updated=datetime(2026, 1, 1 + (i % 27))))
    db.session.commit()


def _present(body, names):
    """Subset of ``names`` that appear in the rendered ``body``."""
    return [n for n in names if n in body]


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------

def test_rules_list_paginates_at_twenty_per_page(client, app):
    user = _admin()
    _login(client, user)
    names = _padding_names(25)
    _make_rules(user.id, names)

    body = client.get("/rules").get_data(as_text=True)

    assert len(_present(body, names)) == PER_PAGE


def test_rules_list_second_page_shows_the_remainder(client, app):
    user = _admin()
    _login(client, user)
    names = _padding_names(25)
    _make_rules(user.id, names)

    page1 = _present(client.get("/rules").get_data(as_text=True), names)
    page2 = _present(client.get("/rules?page=2").get_data(as_text=True), names)

    assert len(page2) == 5
    assert not set(page1) & set(page2)
    assert set(page1) | set(page2) == set(names)


def test_rules_page_out_of_range_does_not_error(client, app):
    """A page past the end renders an empty page rather than a 404/500."""
    user = _admin()
    _login(client, user)
    _make_rules(user.id, _padding_names(3))

    assert client.get("/rules?page=99").status_code == 200


def test_rules_non_numeric_page_falls_back_to_the_first_page(client, app):
    user = _admin()
    _login(client, user)
    names = _padding_names(25)
    _make_rules(user.id, names)

    body = client.get("/rules?page=notanumber").get_data(as_text=True)

    assert len(_present(body, names)) == PER_PAGE


# ---------------------------------------------------------------------------
# Server-side filtering
# ---------------------------------------------------------------------------

def test_rules_filter_finds_a_rule_that_is_not_on_the_current_page(client, app):
    user = _admin()
    _login(client, user)
    _make_rules(user.id, _padding_names() + [LATE_NAME])

    assert LATE_NAME not in client.get("/rules").get_data(as_text=True), \
        "needle must be off page 1 for this test to mean anything"

    body = client.get("/rules?q=needle").get_data(as_text=True)

    assert LATE_NAME in body


def test_rules_filter_excludes_non_matching_rules(client, app):
    user = _admin()
    _login(client, user)
    padding = _padding_names()
    _make_rules(user.id, padding + [LATE_NAME])

    body = client.get("/rules?q=needle").get_data(as_text=True)

    assert _present(body, padding) == []


def test_rules_filter_is_case_insensitive(client, app):
    user = _admin()
    _login(client, user)
    _make_rules(user.id, ["Best64-Mixed-Case"])

    body = client.get("/rules?q=best64-MIXED").get_data(as_text=True)

    assert "Best64-Mixed-Case" in body


def test_rules_filter_treats_like_wildcards_literally(client, app):
    user = _admin()
    _login(client, user)
    padding = _padding_names()
    _make_rules(user.id, padding + ["100%-real-rule"])

    body = client.get("/rules?q=%25").get_data(as_text=True)

    assert "100%-real-rule" in body
    assert _present(body, padding) == []


def test_rules_filter_is_preserved_across_pagination(client, app):
    """A filter matching more than one page keeps applying on page 2."""
    user = _admin()
    _login(client, user)
    matching = [f"needle-{i:03d}" for i in range(25)]
    _make_rules(user.id, matching + ["unrelated-rule"])

    body = client.get("/rules?q=needle&page=2").get_data(as_text=True)

    assert len(_present(body, matching)) == 5
    assert "unrelated-rule" not in body


# ---------------------------------------------------------------------------
# Sorting
# ---------------------------------------------------------------------------

def test_rules_sort_by_size_descending_puts_the_largest_first(client, app):
    user = _admin()
    _login(client, user)
    _make_rules(user.id, ["small-rule", "huge-rule"], sizes=[5, 9999])

    body = client.get("/rules?sort_by=size&sort_order=desc").get_data(as_text=True)

    assert body.index("huge-rule") < body.index("small-rule")


def test_rules_sort_by_name_descending_reverses_the_default_order(client, app):
    user = _admin()
    _login(client, user)
    _make_rules(user.id, ["aaa-rule", "zzz-rule"])

    asc = client.get("/rules?sort_by=name&sort_order=asc").get_data(as_text=True)
    desc = client.get("/rules?sort_by=name&sort_order=desc").get_data(as_text=True)

    assert asc.index("aaa-rule") < asc.index("zzz-rule")
    assert desc.index("zzz-rule") < desc.index("aaa-rule")


def test_rules_sort_by_owner_orders_by_owner_name(client, app):
    admin = _admin()
    zed = Users(first_name="Zed", last_name="Last",
                email_address="zed@rulepage.test",
                password="x" * 60, admin=False)
    db.session.add(zed)
    db.session.commit()
    _login(client, admin)
    _make_rules(admin.id, ["owned-by-ad"])
    _make_rules(zed.id, ["owned-by-zed"])

    body = client.get("/rules?sort_by=owner&sort_order=asc").get_data(as_text=True)

    assert body.index("owned-by-ad") < body.index("owned-by-zed")


def test_rules_unknown_sort_key_falls_back_to_name(client, app):
    """An unrecognised sort_by must not 500; it sorts by name."""
    user = _admin()
    _login(client, user)
    _make_rules(user.id, ["aaa-rule", "zzz-rule"])

    resp = client.get("/rules?sort_by=;DROP TABLE rules;--")
    body = resp.get_data(as_text=True)

    assert resp.status_code == 200
    assert body.index("aaa-rule") < body.index("zzz-rule")


# ---------------------------------------------------------------------------
# The info-modal data build must be scoped to the rendered page, not the
# whole table -- otherwise pagination bounds the DOM but not the query cost.
# ---------------------------------------------------------------------------

def test_rules_info_modal_data_is_built_only_for_the_current_page(client, app):
    user = _admin()
    _login(client, user)
    names = _padding_names(25)
    _make_rules(user.id, names)

    body = client.get("/rules").get_data(as_text=True)

    # One delete dialog is emitted per rule the template loops over; if that
    # loop still ran over the whole table there would be 25 of them.
    assert body.count('id="del-') == PER_PAGE


def test_rules_task_lookup_is_restricted_to_the_pages_rule_ids(client, app):
    """The tasks query must be narrowed, not just the rendering.

    Counting rendered dialogs cannot distinguish "loaded 20 rules' tasks" from
    "loaded every task and rendered 20", so this inspects the SQL actually
    issued: every SELECT against `tasks` must carry a rule_id restriction.
    """
    from sqlalchemy import event

    from hashview.models import db as _db

    user = _admin()
    _login(client, user)
    _make_rules(user.id, _padding_names(25))

    statements = []

    def record(conn, cursor, statement, parameters, context, executemany):
        statements.append(" ".join(statement.split()).lower())

    engine = _db.engine
    event.listen(engine, "before_cursor_execute", record)
    try:
        client.get("/rules")
    finally:
        event.remove(engine, "before_cursor_execute", record)

    # Aggregate counts are excluded: the sidebar nav badges issue a global
    # SELECT COUNT(*) FROM tasks on every authenticated page (see
    # inject_nav_counts in hashview/__init__.py). That is bounded work and
    # predates this route; what matters here is that no query *materialises*
    # task rows for rules outside the page.
    row_loads = [s for s in statements
                 if s.startswith("select") and " from tasks" in s
                 and "count(" not in s]

    # Deliberately not "every row-load must mention rule_id": asserting over
    # all captured statements makes the test hostage to any unrelated query
    # that happens to run inside the listener's window. Instead: the scoped
    # lookup must be present, and no row-load may be an unfiltered full scan.
    assert any("rule_id in" in s for s in row_loads), \
        f"no rule_id-scoped task lookup found; saw: {row_loads}"
    unfiltered = [s for s in row_loads if " where " not in s]
    assert not unfiltered, f"unrestricted scan of tasks: {unfiltered}"


def test_rules_info_modal_omits_tasks_belonging_to_off_page_rules(client, app):
    """A task attached to a rule on page 2 is not rendered into page 1."""
    user = _admin()
    _login(client, user)
    _make_rules(user.id, _padding_names(24) + ["zzz-last-page-rule"])
    off_page = Rules.query.filter_by(name="zzz-last-page-rule").first()
    db.session.add(Tasks(name="task-of-the-off-page-rule", hc_attackmode=0,
                         owner_id=user.id, rule_id=off_page.id))
    db.session.commit()

    page1 = client.get("/rules").get_data(as_text=True)
    page2 = client.get("/rules?page=2").get_data(as_text=True)

    assert "task-of-the-off-page-rule" not in page1
    assert "task-of-the-off-page-rule" in page2


def test_rules_clear_filter_link_drops_the_search_term(client, app):
    """The clear-filter affordance must not carry q, or it re-applies it."""
    user = _admin()
    _login(client, user)
    _make_rules(user.id, ["needle-rule"])

    body = client.get("/rules?q=needle").get_data(as_text=True)

    clear_links = re.findall(r'href="([^"]*)"[^>]*title="Clear filter"', body)
    assert clear_links, "expected a clear-filter link while a filter is active"
    for href in clear_links:
        assert "q=needle" not in href
