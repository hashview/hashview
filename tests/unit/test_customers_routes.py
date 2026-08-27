"""Regression tests for customers routes/helpers (function-coverage batch)."""

from hashview.models import (
    Hashes,
    HashfileHashes,
    Hashfiles,
    db,
)
from tests.unit.helpers import login, make_admin, make_customer


def test_hash_type_names_maps_modes(app):
    from hashview.customers.routes import _hash_type_names
    names = _hash_type_names()
    assert isinstance(names, dict)
    # 1000 is NTLM in the form choices
    assert "1000" in names


def test_customers_list_renders(app, client):
    admin = make_admin()
    login(client, admin)
    make_customer(name="AcmeCorp")
    resp = client.get("/customers")
    assert resp.status_code == 200
    assert b"AcmeCorp" in resp.data


def test_customers_info_renders_with_stats(app, client):
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    hf = Hashfiles(name="hf", customer_id=cust.id, owner_id=admin.id)
    db.session.add(hf)
    db.session.commit()
    h = Hashes(sub_ciphertext="0" * 8, ciphertext="abc", hash_type=1000, cracked=True,
               plaintext="pw")
    db.session.add(h)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id))
    db.session.commit()
    resp = client.get(f"/customers/{cust.id}/info")
    assert resp.status_code == 200


def test_customers_info_missing_returns_404(app, client):
    admin = make_admin()
    login(client, admin)
    resp = client.get("/customers/999999/info")
    assert resp.status_code == 404
