"""Additional branch-coverage tests for hashview/customers/routes.py.

Extends test_customers_routes_guards.py to cover the remaining missing lines:
- customers_edit: customer not found (lines 108-109)
- customers_delete: customer not found (lines 165-166)
- customers_delete: uncracked-hash inner loop with try_commit failure (lines 192-194)
- customers_delete: uncracked-hash inner loop regression (issue #208), see below
"""

from unittest.mock import patch

from hashview.models import (
    Customers,
    Hashes,
    HashfileHashes,
    Hashfiles,
    HashNotifications,
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


# --------------------- Regression: uncracked-hash inner loop (issue #208)

def test_customers_delete_with_uncracked_hash_succeeds(app, client):
    """Deleting a customer whose hashfile has an uncracked hash should work.

    Regression test for #208/#258/#259: the inner loop in customers_delete
    used to look the hash up by the association row's own id instead of its
    hash_id FK, and separately compared a SQLAlchemy Query object to an int
    (missing .count()), raising TypeError -> HTTP 500. Both were fixed in
    884bb62 (hash_id lookup + .count()); this test now pins the fixed
    behavior as a real assertion instead of an xfail.
    """
    admin = _admin()
    _login(client, admin)
    customer = _make_customer("UncrackCo")

    hashfile = Hashfiles(name="uc.txt", customer_id=customer.id,
                         owner_id=admin.id)
    db.session.add(hashfile)
    db.session.commit()

    # Uncracked hash — triggers the inner loop that prunes orphaned hashes
    h = Hashes(sub_ciphertext="u" * 32, ciphertext="v" * 32,
               hash_type=1000, cracked=False)
    db.session.add(h)
    db.session.commit()

    # Matching ids aren't load-bearing anymore (the loop now resolves the
    # hash via hash_id, not the association's own id), but kept so a fresh
    # in-memory DB deterministically has hashfile_hash.id == h.id == 1.
    hfh = HashfileHashes(hash_id=h.id, hashfile_id=hashfile.id)
    db.session.add(hfh)
    db.session.commit()

    hn = HashNotifications(owner_id=admin.id, hash_id=h.id, method="email")
    db.session.add(hn)
    db.session.commit()

    customer_id = customer.id
    resp = client.post(f"/customers/delete/{customer_id}",
                       follow_redirects=False)
    assert resp.status_code in (301, 302), (
        f"Expected redirect, got {resp.status_code}"
    )
    assert Customers.query.get(customer_id) is None
