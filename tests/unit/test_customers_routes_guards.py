"""Behavior-pinning tests for the customers routes guard branches.

Covers customers_add (create + duplicate-name rejection), customers_edit
(rename + duplicate-name rejection) and customers_delete (non-admin denied,
blocked while jobs exist, happy path including the hashfile cascade).
"""

from hashview.models import (
    Customers,
    Hashes,
    HashfileHashes,
    Hashfiles,
    Jobs,
    Users,
    db,
)


def _admin():
    u = Users(first_name="Ad", last_name="Min", email_address="admin@example.com",
              password="x" * 60, admin=True)
    db.session.add(u)
    db.session.commit()
    return u


def _nonadmin():
    u = Users(first_name="No", last_name="Body", email_address="user@example.com",
              password="x" * 60, admin=False)
    db.session.add(u)
    db.session.commit()
    return u


def _login(client, user):
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True


def _make_customer(name="Acme"):
    c = Customers(name=name)
    db.session.add(c)
    db.session.commit()
    return c


# -------------------------------------------------------------- customers_add

def test_customers_add_creates_row(app, client):
    _login(client, _admin())
    resp = client.post("/customers/add", data={"name": "NewCo"},
                       follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert Customers.query.filter_by(name="NewCo").count() == 1


def test_customers_add_duplicate_name_rejected(app, client):
    _login(client, _admin())
    _make_customer("DupeCo")
    resp = client.post("/customers/add", data={"name": "DupeCo"},
                       follow_redirects=True)
    assert b"That customer already exists" in resp.data
    assert Customers.query.filter_by(name="DupeCo").count() == 1  # no second row


# ------------------------------------------------------------- customers_edit

def test_customers_edit_renames(app, client):
    _login(client, _admin())
    customer = _make_customer("OldName")
    resp = client.post("/customers/edit",
                       data={"customer_id": str(customer.id), "name": "NewName"},
                       follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert Customers.query.get(customer.id).name == "NewName"


def test_customers_edit_duplicate_name_rejected(app, client):
    _login(client, _admin())
    _make_customer("TakenName")
    customer = _make_customer("MyName")
    resp = client.post("/customers/edit",
                       data={"customer_id": str(customer.id), "name": "TakenName"},
                       follow_redirects=True)
    assert b"That customer already exists" in resp.data
    assert Customers.query.get(customer.id).name == "MyName"  # unchanged


def test_customers_edit_blank_name_rejected(app, client):
    _login(client, _admin())
    customer = _make_customer("KeepMe")
    resp = client.post("/customers/edit",
                       data={"customer_id": str(customer.id), "name": "   "},
                       follow_redirects=True)
    assert b"Customer name is required" in resp.data
    assert Customers.query.get(customer.id).name == "KeepMe"  # unchanged


# ----------------------------------------------------------- customers_delete

def test_customers_delete_non_admin_denied(app, client):
    _admin()
    user = _nonadmin()
    customer = _make_customer("Protected")
    _login(client, user)

    resp = client.post(f"/customers/delete/{customer.id}", follow_redirects=True)
    assert b"Permission Denied" in resp.data
    assert Customers.query.get(customer.id) is not None  # NOT deleted


def test_customers_delete_blocked_when_job_exists(app, client):
    admin = _admin()
    _login(client, admin)
    customer = _make_customer("HasJob")
    db.session.add(Jobs(name="j1", status="Incomplete",
                        customer_id=customer.id, owner_id=admin.id))
    db.session.commit()

    resp = client.post(f"/customers/delete/{customer.id}", follow_redirects=True)
    assert b"Customer has active job" in resp.data
    assert Customers.query.get(customer.id) is not None  # NOT deleted


def test_customers_delete_happy_path_cascades_hashfiles(app, client):
    admin = _admin()
    _login(client, admin)
    customer = _make_customer("GoneSoon")
    hashfile = Hashfiles(name="hf1", customer_id=customer.id, owner_id=admin.id)
    db.session.add(hashfile)
    db.session.commit()
    # a cracked hash linked through the hashfile (cracked rows are kept by design)
    h = Hashes(sub_ciphertext="a" * 32, ciphertext="b" * 32, hash_type=1000,
               cracked=True)
    db.session.add(h)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hashfile.id))
    db.session.commit()
    hashfile_id, customer_id = hashfile.id, customer.id

    resp = client.post(f"/customers/delete/{customer_id}", follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert Customers.query.get(customer_id) is None
    assert Hashfiles.query.get(hashfile_id) is None
    assert HashfileHashes.query.filter_by(hashfile_id=hashfile_id).count() == 0


# --------------------------------------------- customers_list / customers_info

def _customer_with_hashfile(owner_id, cracked=True, name="StatsCo"):
    customer = _make_customer(name)
    hashfile = Hashfiles(name=f"{name}.txt", customer_id=customer.id,
                         owner_id=owner_id)
    db.session.add(hashfile)
    db.session.commit()
    h = Hashes(sub_ciphertext="c" * 32, ciphertext="d" * 32, hash_type=1000,
               cracked=cracked, plaintext="hunter2" if cracked else None)
    db.session.add(h)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hashfile.id))
    db.session.commit()
    return customer, hashfile


def test_customers_list_renders_per_customer_stats(app, client):
    admin = _admin()
    _login(client, admin)
    customer, _ = _customer_with_hashfile(admin.id, cracked=True)
    db.session.add(Jobs(name="job-stats", status="Incomplete",
                        customer_id=customer.id, owner_id=admin.id))
    db.session.commit()

    resp = client.get("/customers")
    assert resp.status_code == 200
    assert b"StatsCo" in resp.data


def test_customers_info_modal_renders_stats(app, client):
    admin = _admin()
    _login(client, admin)
    customer, hashfile = _customer_with_hashfile(admin.id, cracked=True)
    db.session.add(Jobs(name="info-job", status="Incomplete",
                        customer_id=customer.id, owner_id=admin.id))
    db.session.commit()

    resp = client.get(f"/customers/{customer.id}/info")
    assert resp.status_code == 200
    assert b"StatsCo.txt" in resp.data   # the hashfile is listed
    assert b"NTLM" in resp.data          # mode 1000 reverse-mapped to a name


def test_customers_info_missing_customer_404s(app, client):
    _login(client, _admin())
    resp = client.get("/customers/999999/info")
    assert resp.status_code == 404
