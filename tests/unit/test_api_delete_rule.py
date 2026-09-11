"""Unit tests for DELETE /v1/rules/<id> (issue #397).

The v1 API could create rules but never delete them, so an API-only scripting
mistake -- POST /v1/rules/add does not validate the name, so repeated calls make
duplicate rows -- was permanent without web-UI access.

The endpoint mirrors the web UI's rules_delete guard for guard, and the guard
that matters is the task check: `tasks.rule_id` has no foreign key, so deleting a
rule out from under a task would leave it building a hashcat command with no rule
file. Only `tasks.rule_id` counts -- `j_rule`/`k_rule` are hashcat's inline -j/-k
rule strings, not rows in this table, and a test pins that they do not block.

The issue's own acceptance spec lives in
tests/unit/test_issue_xfail_rules_delete.py (previously xfail, now a plain
regression guard); this file carries the fuller coverage.

Conventions follow tests/unit/test_api_task_groups.py: local fixtures (api_key is
required, which helpers.make_admin does not set), the security marker, and cookie
auth against domain="localhost.test".
"""

import json
from unittest import mock

import pytest

from hashview.api import routes as api_routes
from hashview.models import Agents, Rules, Tasks, Users
from hashview.models import db as _db


@pytest.fixture()
def admin_user(app):
    user = Users(first_name="Admin", last_name="User",
                 email_address="admin@example.test", password="hashed-pw",
                 admin=True, api_key="user-api-key-admin")
    _db.session.add(user)
    _db.session.commit()
    return user


@pytest.fixture()
def owner_user(app):
    user = Users(first_name="Owner", last_name="User",
                 email_address="owner@example.test", password="hashed-pw",
                 admin=False, api_key="user-api-key-owner")
    _db.session.add(user)
    _db.session.commit()
    return user


@pytest.fixture()
def other_user(app):
    user = Users(first_name="Other", last_name="User",
                 email_address="other@example.test", password="hashed-pw",
                 admin=False, api_key="user-api-key-other")
    _db.session.add(user)
    _db.session.commit()
    return user


@pytest.fixture()
def authorized_agent(app):
    agent = Agents(name="agent-1", src_ip="127.0.0.1", uuid="agent-uuid-ok",
                   status="Authorized")
    _db.session.add(agent)
    _db.session.commit()
    return agent


def _json_body(resp):
    return json.loads(resp.get_data(as_text=True))


def _rule(owner, name="rule-a", path="/tmp/does-not-matter.txt"):
    rule = Rules(name=name, owner_id=owner.id, path=path, size=1, checksum="c" * 64)
    _db.session.add(rule)
    _db.session.commit()
    return rule


def _task(owner, name="t", rule_id=None, j_rule=None, k_rule=None):
    task = Tasks(name=name, hc_attackmode=0, owner_id=owner.id, rule_id=rule_id,
                 j_rule=j_rule, k_rule=k_rule)
    _db.session.add(task)
    _db.session.commit()
    return task


#############################################
# Authorization
#############################################

@pytest.mark.security
def test_delete_no_cookie_redirects(client, owner_user):
    rule = _rule(owner_user)
    resp = client.delete(f"/v1/rules/{rule.id}")
    assert 300 <= resp.status_code < 400
    assert "/v1/not_authorized" in resp.headers.get("Location", "")
    assert Rules.query.get(rule.id) is not None


@pytest.mark.security
def test_delete_agent_cookie_rejected(client, owner_user, authorized_agent):
    """Agents only ever GET rules; deletion is a user action."""
    rule = _rule(owner_user)
    client.set_cookie("uuid", authorized_agent.uuid, domain="localhost.test")
    resp = client.delete(f"/v1/rules/{rule.id}")
    assert 300 <= resp.status_code < 400
    assert "/v1/not_authorized" in resp.headers.get("Location", "")
    assert Rules.query.get(rule.id) is not None


@pytest.mark.security
def test_delete_cookie_no_user_returns_403(client, owner_user):
    rule = _rule(owner_user)
    with mock.patch.object(api_routes, "is_authorized", return_value=True):
        client.set_cookie("uuid", "not-a-real-key", domain="localhost.test")
        resp = client.delete(f"/v1/rules/{rule.id}")
    # Real HTTP 403, unlike the sibling deletes which answer 200 with the code
    # only in the body -- see the comment on the endpoint for why.
    assert resp.status_code == 403
    assert _json_body(resp)["status"] == 403
    assert Rules.query.get(rule.id) is not None


@pytest.mark.security
def test_delete_by_a_different_non_admin_user_is_forbidden(client, owner_user, other_user):
    rule = _rule(owner_user)
    client.set_cookie("uuid", other_user.api_key, domain="localhost.test")
    resp = client.delete(f"/v1/rules/{rule.id}")
    body = _json_body(resp)
    assert resp.status_code == 403          # real status code, not just the envelope
    assert body["status"] == 403
    assert "do not have rights" in body["msg"]
    assert Rules.query.get(rule.id) is not None


@pytest.mark.security
def test_admin_may_delete_another_users_rule(client, owner_user, admin_user):
    rule = _rule(owner_user)
    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.delete(f"/v1/rules/{rule.id}")
    assert _json_body(resp)["status"] == 200
    assert Rules.query.get(rule.id) is None


#############################################
# The task guard -- the safeguard the web UI enforces
#############################################

def test_delete_is_refused_while_a_task_uses_the_rule(client, owner_user):
    """tasks.rule_id has no foreign key, so removing the rule would leave the
    task building a hashcat command against a rule that no longer exists."""
    rule = _rule(owner_user)
    _task(owner_user, name="uses-rule", rule_id=rule.id)

    client.set_cookie("uuid", owner_user.api_key, domain="localhost.test")
    resp = client.delete(f"/v1/rules/{rule.id}")

    assert resp.status_code == 409
    body = _json_body(resp)
    assert body["status"] == 409
    assert "currently used in a task" in body["msg"]
    assert Rules.query.get(rule.id) is not None


def test_delete_is_refused_even_for_an_admin(client, owner_user, admin_user):
    """The task guard is about data integrity, not permissions, so admin rights
    do not override it -- same as the web UI, which checks ownership first and
    the task association second."""
    rule = _rule(owner_user)
    _task(owner_user, rule_id=rule.id)

    client.set_cookie("uuid", admin_user.api_key, domain="localhost.test")
    resp = client.delete(f"/v1/rules/{rule.id}")

    assert resp.status_code == 409
    assert Rules.query.get(rule.id) is not None


def test_delete_is_refused_when_another_users_task_uses_the_rule(client, owner_user, other_user):
    rule = _rule(owner_user)
    _task(other_user, name="someone-elses", rule_id=rule.id)

    client.set_cookie("uuid", owner_user.api_key, domain="localhost.test")
    resp = client.delete(f"/v1/rules/{rule.id}")

    assert resp.status_code == 409
    assert Rules.query.get(rule.id) is not None


def test_a_task_using_a_different_rule_does_not_block(client, owner_user):
    """Guards against a check that looks for any task at all."""
    target = _rule(owner_user, name="target")
    other = _rule(owner_user, name="other")
    _task(owner_user, name="uses-other", rule_id=other.id)

    client.set_cookie("uuid", owner_user.api_key, domain="localhost.test")
    resp = client.delete(f"/v1/rules/{target.id}")

    assert _json_body(resp)["status"] == 200
    assert Rules.query.get(target.id) is None
    assert Rules.query.get(other.id) is not None


def test_inline_j_and_k_rules_do_not_block_deletion(client, owner_user):
    """j_rule/k_rule are hashcat's -j/-k inline rule STRINGS, not references to
    this table. A guard that treated them as references would make rules
    undeletable for unrelated reasons."""
    rule = _rule(owner_user)
    _task(owner_user, name="inline", rule_id=None, j_rule="$1", k_rule="^2")

    client.set_cookie("uuid", owner_user.api_key, domain="localhost.test")
    resp = client.delete(f"/v1/rules/{rule.id}")

    assert _json_body(resp)["status"] == 200
    assert Rules.query.get(rule.id) is None


def test_delete_succeeds_once_the_blocking_task_is_gone(client, owner_user):
    rule = _rule(owner_user)
    task = _task(owner_user, rule_id=rule.id)
    client.set_cookie("uuid", owner_user.api_key, domain="localhost.test")
    assert client.delete(f"/v1/rules/{rule.id}").status_code == 409

    _db.session.delete(task)
    _db.session.commit()

    resp = client.delete(f"/v1/rules/{rule.id}")
    assert _json_body(resp)["status"] == 200
    assert Rules.query.get(rule.id) is None


#############################################
# Happy path, 404, and the duplicate case from the issue
#############################################

def test_owner_deletes_own_rule(client, owner_user):
    rule = _rule(owner_user)
    rule_id = rule.id
    client.set_cookie("uuid", owner_user.api_key, domain="localhost.test")
    resp = client.delete(f"/v1/rules/{rule_id}")

    assert resp.status_code == 200
    body = _json_body(resp)
    assert body["status"] == 200
    assert body["type"] == "message"
    assert body["msg"] == "Rule deleted"
    assert body["rule_id"] == rule_id
    assert Rules.query.get(rule_id) is None


def test_delete_missing_rule_returns_real_404(client, owner_user):
    client.set_cookie("uuid", owner_user.api_key, domain="localhost.test")
    resp = client.delete("/v1/rules/999999")
    assert resp.status_code == 404
    assert _json_body(resp)["status"] == 404


def test_deleting_a_duplicate_leaves_its_twin(client, owner_user):
    """The reason the issue was filed: POST /v1/rules/add does not validate the
    name, so repeated calls create duplicate rows. Deleting one by id must
    remove exactly that row."""
    first = _rule(owner_user, name="dupe", path="/tmp/a.txt")
    second = _rule(owner_user, name="dupe", path="/tmp/b.txt")

    client.set_cookie("uuid", owner_user.api_key, domain="localhost.test")
    resp = client.delete(f"/v1/rules/{second.id}")

    assert _json_body(resp)["status"] == 200
    assert Rules.query.get(second.id) is None
    assert Rules.query.get(first.id) is not None
    assert Rules.query.filter_by(name="dupe").count() == 1


def test_delete_is_audited(client, owner_user):
    rule = _rule(owner_user, name="audited")
    client.set_cookie("uuid", owner_user.api_key, domain="localhost.test")
    with mock.patch.object(api_routes, "log_event") as logged:
        client.delete(f"/v1/rules/{rule.id}")

    assert logged.called
    event = logged.call_args
    assert event.args[0] == "rule.delete"
    assert "audited" in event.kwargs["target"]
    assert event.kwargs["actor"] == (owner_user.email_address, owner_user.id)


#############################################
# The file on disk
#############################################

@pytest.fixture()
def rules_dir(app, tmp_path, monkeypatch):
    """Point the app at a throwaway control/rules so no test writes to the real
    one (the conftest control_dirs fixture creates the package's actual
    directory)."""
    monkeypatch.setattr(app, "root_path", str(tmp_path))
    target = tmp_path / "control" / "rules"
    target.mkdir(parents=True)
    return target


def test_delete_removes_the_rule_file(client, owner_user, rules_dir):
    rule_file = rules_dir / "abc123.txt"
    rule_file.write_text(":\n")
    rule = _rule(owner_user, name="on-disk", path=str(rule_file))

    client.set_cookie("uuid", owner_user.api_key, domain="localhost.test")
    assert _json_body(client.delete(f"/v1/rules/{rule.id}"))["status"] == 200

    assert Rules.query.get(rule.id) is None
    assert not rule_file.exists()


def test_delete_resolves_a_relative_stored_path(client, owner_user, rules_dir):
    """The seeded 'Best64 Rule' row carries a path relative to the package
    (hashview/setup/__init__.py writes it that way), so the unlink has to resolve
    against control/rules rather than trusting the stored string."""
    rule_file = rules_dir / "best64.rule"
    rule_file.write_text(":\n")
    rule = _rule(owner_user, name="Best64 Rule",
                 path="hashview/control/rules/best64.rule")

    client.set_cookie("uuid", owner_user.api_key, domain="localhost.test")
    assert _json_body(client.delete(f"/v1/rules/{rule.id}"))["status"] == 200

    assert not rule_file.exists()


def test_delete_cannot_unlink_outside_the_rules_directory(client, owner_user,
                                                          rules_dir, tmp_path):
    """Resolution takes the basename, so a stored path pointing elsewhere can
    never make the delete reach outside control/rules."""
    outsider = tmp_path / "precious.rule"
    outsider.write_text("do not delete\n")
    rule = _rule(owner_user, name="escapee", path=str(outsider))

    client.set_cookie("uuid", owner_user.api_key, domain="localhost.test")
    assert _json_body(client.delete(f"/v1/rules/{rule.id}"))["status"] == 200

    assert Rules.query.get(rule.id) is None
    assert outsider.exists(), "unlink escaped control/rules"


def test_delete_keeps_a_file_another_rule_still_points_at(client, owner_user, rules_dir):
    """POST /v1/rules/add does not dedupe, so two rows can name one file.
    Removing one must not break the other."""
    shared = rules_dir / "shared.txt"
    shared.write_text(":\n")
    first = _rule(owner_user, name="dupe-a", path=str(shared))
    second = _rule(owner_user, name="dupe-b", path=str(shared))

    client.set_cookie("uuid", owner_user.api_key, domain="localhost.test")
    assert _json_body(client.delete(f"/v1/rules/{second.id}"))["status"] == 200

    assert Rules.query.get(second.id) is None
    assert Rules.query.get(first.id) is not None
    assert shared.exists(), "deleted a file the surviving rule still needs"


def test_delete_succeeds_quietly_when_the_file_is_already_gone(client, owner_user,
                                                               rules_dir, caplog):
    """A row whose file was removed out of band must still be deletable --
    otherwise the row is unremovable, which is the bug #397 is about.

    And it must not log an exception for it: a missing file is the normal case
    here, and letting os.remove raise into the handler would file a traceback in
    the operator's error log every time.
    """
    import logging

    rule = _rule(owner_user, name="ghost", path=str(rules_dir / "never-written.txt"))

    client.set_cookie("uuid", owner_user.api_key, domain="localhost.test")
    with caplog.at_level(logging.ERROR):
        assert _json_body(client.delete(f"/v1/rules/{rule.id}"))["status"] == 200

    assert Rules.query.get(rule.id) is None
    assert not [r for r in caplog.records if "Failed to remove rule file" in r.getMessage()], \
        "a missing rule file was logged as a failure"


def test_a_refused_delete_leaves_the_file(client, owner_user, rules_dir):
    """The task guard must stop the unlink too, not just the row removal."""
    rule_file = rules_dir / "inuse.txt"
    rule_file.write_text(":\n")
    rule = _rule(owner_user, name="in-use", path=str(rule_file))
    _task(owner_user, rule_id=rule.id)

    client.set_cookie("uuid", owner_user.api_key, domain="localhost.test")
    assert client.delete(f"/v1/rules/{rule.id}").status_code == 409

    assert Rules.query.get(rule.id) is not None
    assert rule_file.exists()
