"""Additional branch-coverage tests for hashview/customers/routes.py.

Extends test_customers_routes_guards.py to cover the remaining missing lines:
- customers_edit: customer not found (lines 108-109)
- customers_delete: customer not found (lines 165-166)
- customers_delete: uncracked-hash inner loop with try_commit failure (lines 192-194)

Bug captured with xfail:
- hashview/customers/routes.py:185-186: `customer_cnt` is a SQLAlchemy Query
  object compared to an integer with `< 2`, which raises TypeError in Python 3.
  This makes the delete route crash (500) whenever the customer has an uncracked
  hash in their hashfiles. Fix: call `.count()` on the query first.
"""

from unittest.mock import patch

import pytest

from hashview.models import (
    Customers,
    HashfileHashes,
    Hashfiles,
    HashNotifications,
    Hashes,
    Jobs,
    Users,
    db,
)


# ------------------------------------------------------------------ helpers

def _admin():
    u = Users(
        first_name="Ad", last_name="Min",
        email_address="admin2@example.com",
        password="x" * 60, admin=True,
    )
    db.session.add(u)
    db.session.commit()
    return u


def _login(client, user):
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True


def _make_customer(name="BranchCo"):
    c = Customers(name=name)
    db.session.add(c)
    db.session.commit()
    return c


# ------------------------------------------ customers_edit: not-found branch

def test_customers_edit_not_found_redirects(app, client):
    """POST /customers/edit with a non-existent customer_id hits the 'not found'
    branch (lines 108-109) and redirects back to the list."""
    _login(client, _admin())
    resp = client.post(
        "/customers/edit",
        data={"customer_id": "999999", "name": "Whatever"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert b"Customer not found" in resp.data


def test_customers_edit_not_found_302(app, client):
    """Same branch, without following redirects, confirms a 302."""
    _login(client, _admin())
    resp = client.post(
        "/customers/edit",
        data={"customer_id": "999999", "name": "Whatever"},
        follow_redirects=False,
    )
    assert resp.status_code in (301, 302)


# --------------------------------------- customers_delete: not-found branch

def test_customers_delete_not_found_redirects(app, client):
    """POST /customers/delete/<id> for a non-existent id hits lines 165-166."""
    _login(client, _admin())
    resp = client.post("/customers/delete/999999", follow_redirects=True)
    assert resp.status_code == 200
    assert b"Customer not found" in resp.data


def test_customers_delete_not_found_302(app, client):
    _login(client, _admin())
    resp = client.post("/customers/delete/999999", follow_redirects=False)
    assert resp.status_code in (301, 302)


# ------------------------------------------ customers_delete: try_commit failure

def test_customers_delete_try_commit_failure_flashes(app, client):
    """If try_commit returns False (concurrent double-delete simulation),
    lines 193-194 are reached: a warning is flashed and we redirect back."""
    admin = _admin()
    _login(client, admin)
    customer = _make_customer("FailCo")

    with patch("hashview.customers.routes.try_commit", return_value=False):
        resp = client.post(f"/customers/delete/{customer.id}",
                           follow_redirects=True)

    assert resp.status_code == 200
    assert b"Customer could not be deleted" in resp.data


def test_customers_delete_try_commit_failure_302(app, client):
    """Same try_commit=False path, checking raw redirect status."""
    admin = _admin()
    _login(client, admin)
    customer = _make_customer("FailCo2")

    with patch("hashview.customers.routes.try_commit", return_value=False):
        resp = client.post(f"/customers/delete/{customer.id}",
                           follow_redirects=False)

    assert resp.status_code in (301, 302)


# --------------------- Bug: uncracked-hash inner loop crashes with TypeError

@pytest.mark.xfail(
    strict=True,
    reason=(
        "Bug at hashview/customers/routes.py:185-186: "
        "`customer_cnt` is assigned a SQLAlchemy Query object via "
        "`HashfileHashes.query.filter_by(hash_id=hash.id).distinct('customer_id')` "
        "but is then compared to an integer with `if customer_cnt < 2`. "
        "In Python 3, this raises TypeError: '<' not supported between instances "
        "of 'Query' and 'int', causing a 500 error whenever a customer with an "
        "uncracked hash is deleted. "
        "Fix: call `.count()` — "
        "`HashfileHashes.query.filter_by(hash_id=hash.id).distinct('customer_id').count()`"
    ),
)
def test_customers_delete_with_uncracked_hash_succeeds(app, client):
    """Deleting a customer whose hashfile has an uncracked hash should work.

    It currently raises TypeError at line 186 (Query < int comparison) and
    returns a 500, so this test is marked xfail(strict=True) to document the bug.
    """
    admin = _admin()
    _login(client, admin)
    customer = _make_customer("UncrackCo")

    hashfile = Hashfiles(name="uc.txt", customer_id=customer.id,
                         owner_id=admin.id)
    db.session.add(hashfile)
    db.session.commit()

    # Uncracked hash — triggers the inner loop at line 182
    h = Hashes(sub_ciphertext="u" * 32, ciphertext="v" * 32,
               hash_type=1000, cracked=False)
    db.session.add(h)
    db.session.commit()

    # Use matching ids to ensure the buggy filter_by(id=hashfile_hash.id) hits h.
    # In a fresh in-memory DB the first rows get id=1 in both tables, so
    # hashfile_hash.id == h.id == 1.
    hfh = HashfileHashes(hash_id=h.id, hashfile_id=hashfile.id)
    db.session.add(hfh)
    db.session.commit()

    hn = HashNotifications(owner_id=admin.id, hash_id=h.id, method="email")
    db.session.add(hn)
    db.session.commit()

    customer_id = customer.id
    resp = client.post(f"/customers/delete/{customer_id}",
                       follow_redirects=False)
    # With the bug this is a 500; after the fix it should be a redirect.
    assert resp.status_code in (301, 302), (
        f"Expected redirect, got {resp.status_code} — "
        "likely the TypeError at routes.py:186 fired"
    )
    assert Customers.query.get(customer_id) is None
