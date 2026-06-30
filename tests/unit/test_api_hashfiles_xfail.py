"""xfail regression tests for the missing per-customer hashfile listing API.

There is currently no API endpoint that lists the hashfiles belonging to a
specific customer. The agent/user API only exposes per-id download
(``GET /v1/hashfiles/<id>``) and a by-hash-type listing
(``GET /v1/hashfiles/hash_type/<n>``); the per-customer view lives only in the
web UI (``hashview/customers/routes.py``).

These tests assert the *desired* post-implementation behavior of a new
``GET /v1/customers/<customer_id>/hashfiles`` endpoint and are marked
``@pytest.mark.xfail(strict=True)``. They therefore XFAIL today (the route
404s) and will turn into a hard failure (strict XPASS) the moment the endpoint
is implemented -- the signal to drop the marker and fold them into the normal
suite.

Design decisions captured here (see conversation 2026-06-18):
  * URL shape: ``/v1/customers/<int:customer_id>/hashfiles`` (RESTful nested,
    mirroring the existing ``/jobs/<id>/assigned_hashfile/`` nesting). A bare
    ``GET /v1/hashfiles`` list-all was deliberately rejected: no consumer, it
    crosses customer scope, and it is unbounded.
  * Auth: user-only, matching ``GET /v1/hashfiles/hash_type/<n>``. An agent
    cookie must be rejected with a redirect to ``/v1/not_authorized``.
  * Unknown customer: a valid empty result -- ``{status: 200, hashfiles: []}``
    -- not a 404, matching the by-hash-type endpoint's empty-list contract.

Auth/cookie model mirrors tests/unit/test_api_endpoints.py: the ``uuid`` cookie
is matched against ``Users.api_key`` (user routes) or ``Agents.uuid`` (agent
routes); the cookie domain must equal the test ``SERVER_NAME`` (localhost.test)
for Werkzeug 3.x to send it.
"""

import json

import pytest

from hashview.models import (
    Agents,
    Customers,
    Hashfiles,
    Users,
)
from hashview.models import db as _db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def admin_user(app):
    user = Users(
        first_name="Admin",
        last_name="User",
        email_address="admin@example.test",
        password="hashed-pw",
        admin=True,
        api_key="user-api-key-admin",
    )
    _db.session.add(user)
    _db.session.commit()
    return user


@pytest.fixture()
def authorized_agent(app):
    agent = Agents(
        name="agent-1",
        src_ip="127.0.0.1",
        uuid="agent-uuid-ok",
        status="Authorized",
    )
    _db.session.add(agent)
    _db.session.commit()
    return agent


def _json_body(resp):
    return json.loads(resp.get_data(as_text=True))


def _auth(client, value):
    client.set_cookie("uuid", value, domain="localhost.test")


def _seed_customer(name):
    cust = Customers(name=name)
    _db.session.add(cust)
    _db.session.commit()
    return cust


def _seed_hashfile(name, customer_id, owner_id):
    hf = Hashfiles(name=name, customer_id=customer_id, owner_id=owner_id)
    _db.session.add(hf)
    _db.session.commit()
    return hf


# ---------------------------------------------------------------------------
# GET /v1/customers/<customer_id>/hashfiles  (proposed)
# ---------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.xfail(strict=True, reason="endpoint not implemented: per-customer hashfile listing")
def test_customer_hashfiles_lists_only_that_customers_files(client, admin_user):
    """Returns exactly the requested customer's hashfiles, not another's."""
    cust_a = _seed_customer("Acme")
    cust_b = _seed_customer("Other")
    _seed_hashfile("acme-1.txt", cust_a.id, admin_user.id)
    _seed_hashfile("acme-2.txt", cust_a.id, admin_user.id)
    _seed_hashfile("other-1.txt", cust_b.id, admin_user.id)

    _auth(client, admin_user.api_key)
    resp = client.get(f"/v1/customers/{cust_a.id}/hashfiles")

    body = _json_body(resp)
    assert body["status"] == 200
    names = {entry["name"] for entry in body["hashfiles"]}
    assert names == {"acme-1.txt", "acme-2.txt"}
    for entry in body["hashfiles"]:
        assert entry["customer_id"] == cust_a.id
        assert "id" in entry
        assert "owner_id" in entry


@pytest.mark.security
@pytest.mark.xfail(strict=True, reason="endpoint not implemented: per-customer hashfile listing")
def test_customer_hashfiles_unknown_customer_returns_empty_list(client, admin_user):
    """An unknown customer id is a valid empty result, not a 404."""
    _auth(client, admin_user.api_key)
    resp = client.get("/v1/customers/99999/hashfiles")

    body = _json_body(resp)
    assert body["status"] == 200
    assert body["hashfiles"] == []


@pytest.mark.security
@pytest.mark.xfail(strict=True, reason="endpoint not implemented: per-customer hashfile listing")
def test_customer_hashfiles_existing_customer_no_files_returns_empty_list(client, admin_user):
    """A real customer with zero hashfiles returns an empty list at status 200."""
    cust = _seed_customer("Empty")

    _auth(client, admin_user.api_key)
    resp = client.get(f"/v1/customers/{cust.id}/hashfiles")

    body = _json_body(resp)
    assert body["status"] == 200
    assert body["hashfiles"] == []


@pytest.mark.security
@pytest.mark.xfail(strict=True, reason="endpoint not implemented: per-customer hashfile listing")
def test_customer_hashfiles_rejects_agent_cookie(client, authorized_agent, admin_user):
    """The endpoint is user-only; an agent credential is redirected away."""
    cust = _seed_customer("Acme")
    _seed_hashfile("acme-1.txt", cust.id, admin_user.id)

    _auth(client, authorized_agent.uuid)
    resp = client.get(f"/v1/customers/{cust.id}/hashfiles")

    assert 300 <= resp.status_code < 400
    assert "not_authorized" in resp.headers.get("Location", "")


@pytest.mark.security
@pytest.mark.xfail(strict=True, reason="endpoint not implemented: per-customer hashfile listing")
def test_customer_hashfiles_rejects_unauthenticated(client, admin_user):
    """No credential -> redirect to /v1/not_authorized, never a data leak."""
    cust = _seed_customer("Acme")
    _seed_hashfile("acme-1.txt", cust.id, admin_user.id)

    resp = client.get(f"/v1/customers/{cust.id}/hashfiles")

    assert 300 <= resp.status_code < 400
    assert "not_authorized" in resp.headers.get("Location", "")
