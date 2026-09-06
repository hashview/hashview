"""Cascade semantics for deleting a customer.

customers_delete removes the customer's hashfiles, their hash links, and any
uncracked hash left unreferenced by them. It used to do that with a triple
nested loop plus a per-hash reference count, so these are the rules the
set-based replacement has to keep -- and one bug it fixes.

The old count was ``HashfileHashes.query.filter_by(hash_id=...)
.distinct('customer_id').count()``. ``Query.distinct(<expr>)`` is DISTINCT ON,
which SQLAlchemy silently ignores outside PostgreSQL, and hashfile_hashes has
no customer_id column at all -- so it counted junction rows, not customers. It
still reached the right answer, but only by accident: the loop deleted each
link as it went, so by the last hashfile holding a given hash the count had
fallen to 1. These tests pin the outcomes rather than that mechanism, so the
set-based replacement is held to the same results without inheriting the
reasoning.

Every helper here returns an *id*, never a live ORM instance: the cascade
issues bulk deletes with synchronize_session=False and then commits, which
expires the session, so touching a stale instance afterwards tries to refresh
a row that is gone. The pre-existing cascade test in
test_customers_routes_guards.py captures ids up front for the same reason.
"""

from sqlalchemy import event

from hashview.models import (
    Customers,
    Hashes,
    HashfileHashes,
    Hashfiles,
    HashNotifications,
    db,
)
from tests.unit.helpers import login, make_admin, make_customer


def _customer(name):
    return make_customer(name=name).id


def _hashfile(customer_id, owner, name):
    hf = Hashfiles(name=name, customer_id=customer_id, owner_id=owner.id)
    db.session.add(hf)
    db.session.commit()
    return hf.id


def _hash(sub, cracked=False):
    h = Hashes(sub_ciphertext=sub, ciphertext="c" + sub, hash_type=1000,
               cracked=cracked, plaintext="pw" if cracked else None)
    db.session.add(h)
    db.session.commit()
    return h.id


def _link(hash_id, hashfile_id):
    db.session.add(HashfileHashes(hash_id=hash_id, hashfile_id=hashfile_id))
    db.session.commit()


def _delete(client, customer_id):
    resp = client.post(f"/customers/delete/{customer_id}", follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert Customers.query.get(customer_id) is None


def test_uncracked_hash_unique_to_the_customer_is_deleted(app, client):
    admin = make_admin()
    login(client, admin)
    cid = _customer("Solo")
    hf = _hashfile(cid, admin, "hf")
    h = _hash("only")
    _link(h, hf)

    _delete(client, cid)
    assert Hashes.query.get(h) is None
    assert HashfileHashes.query.count() == 0
    assert Hashfiles.query.count() == 0


def test_hash_shared_with_another_customer_survives_with_its_link(app, client):
    # The hash belongs to someone else too: it must stay, and the other
    # customer's link must not be left pointing at a deleted row.
    admin = make_admin()
    login(client, admin)
    doomed, keeper = _customer("Doomed"), _customer("Keeper")
    hf_d, hf_k = _hashfile(doomed, admin, "d"), _hashfile(keeper, admin, "k")
    shared = _hash("shared")
    _link(shared, hf_d)
    _link(shared, hf_k)

    _delete(client, doomed)
    assert Hashes.query.get(shared) is not None
    assert HashfileHashes.query.filter_by(hashfile_id=hf_k).count() == 1
    assert Hashfiles.query.get(hf_k) is not None


def test_hash_in_two_of_the_same_customers_hashfiles_is_deleted(app, client):
    # The case the old junction-row count only got right because it deleted
    # links as it went: the hash is skipped for the first hashfile (count 2)
    # and deleted at the second (count 1). The rule is simply "no links left".
    admin = make_admin()
    login(client, admin)
    cid = _customer("TwoFiles")
    hf1, hf2 = _hashfile(cid, admin, "one"), _hashfile(cid, admin, "two")
    h = _hash("dupe")
    _link(h, hf1)
    _link(h, hf2)

    _delete(client, cid)
    assert Hashes.query.get(h) is None, "hash left orphaned with no remaining links"


def test_cracked_hashes_survive_the_cascade(app, client):
    # Recovered plaintext outlives the hashfile it arrived in -- existing,
    # deliberate behaviour shared with the hashfile cascade.
    admin = make_admin()
    login(client, admin)
    cid = _customer("Cracked")
    hf = _hashfile(cid, admin, "hf")
    cracked, plain = _hash("crk", cracked=True), _hash("unc")
    _link(cracked, hf)
    _link(plain, hf)

    _delete(client, cid)
    assert Hashes.query.get(cracked) is not None
    assert Hashes.query.get(plain) is None


def test_notifications_follow_their_hash(app, client):
    admin = make_admin()
    login(client, admin)
    doomed, keeper = _customer("D"), _customer("K")
    hf_d, hf_k = _hashfile(doomed, admin, "d"), _hashfile(keeper, admin, "k")
    going, staying = _hash("going"), _hash("staying")
    _link(going, hf_d)
    _link(staying, hf_k)
    db.session.add(HashNotifications(owner_id=admin.id, hash_id=going, method="email"))
    db.session.add(HashNotifications(owner_id=admin.id, hash_id=staying, method="email"))
    db.session.commit()

    _delete(client, doomed)
    assert HashNotifications.query.filter_by(hash_id=going).count() == 0
    assert HashNotifications.query.filter_by(hash_id=staying).count() == 1


def test_cascade_leaves_no_dangling_links(app, client):
    admin = make_admin()
    login(client, admin)
    doomed, keeper = _customer("D2"), _customer("K2")
    hf_d, hf_k = _hashfile(doomed, admin, "d"), _hashfile(keeper, admin, "k")
    for i in range(5):
        _link(_hash(f"d{i}"), hf_d)
    for i in range(3):
        _link(_hash(f"k{i}"), hf_k)

    _delete(client, doomed)
    live_hash_ids = {h.id for h in Hashes.query.all()}
    live_hf_ids = {hf.id for hf in Hashfiles.query.all()}
    for link in HashfileHashes.query.all():
        assert link.hash_id in live_hash_ids, "link points at a deleted hash"
        assert link.hashfile_id in live_hf_ids, "link points at a deleted hashfile"


def test_delete_query_count_does_not_grow_with_hash_count(app, client):
    """The N+1 guard: this path issued roughly one query per hash.

    Two customers of identical shape but different hash counts must cost the
    same number of statements to delete.
    """
    admin = make_admin()
    login(client, admin)

    def build(name, n_hashes):
        cid = _customer(name)
        hf = _hashfile(cid, admin, f"hf-{name}")
        for i in range(n_hashes):
            _link(_hash(f"{name}{i}"), hf)
        return cid

    small, large = build("small", 2), build("large", 25)

    def count_delete_statements(customer_id):
        seen = []

        def record(conn, cursor, statement, parameters, context, executemany):
            seen.append(" ".join(statement.split()).lower())

        event.listen(db.engine, "before_cursor_execute", record)
        try:
            _delete(client, customer_id)
        finally:
            event.remove(db.engine, "before_cursor_execute", record)
        # Only statements against the hash tables: Flask-Login's user lookup is
        # session-cache dependent and shows up once per run regardless of the
        # cascade, so counting every statement makes this flap by one.
        return len([s for s in seen if "hashfile_hashes" in s or "from hashes" in s])

    with_two = count_delete_statements(small)
    with_twentyfive = count_delete_statements(large)
    assert with_twentyfive == with_two, (
        f"deleting 2 hashes took {with_two} statements but 25 took {with_twentyfive} -- "
        "the per-hash loop is back"
    )


def test_delete_contract_all_three_rules_in_one_scenario(app, client):
    """The whole contract, stated as one scenario.

    1. cracked hashes are kept, always;
    2. uncracked hashes are removed only when no other hashfile still links
       to them;
    3. the hashfile_hashes links and the hashfiles themselves are removed.
    """
    admin = make_admin()
    login(client, admin)
    doomed, other = _customer("Doomed"), _customer("Other")
    hf1 = _hashfile(doomed, admin, "doomed-1")
    hf2 = _hashfile(doomed, admin, "doomed-2")
    hf_other = _hashfile(other, admin, "other-1")

    only_here_uncracked = _hash("a-uncracked-solo")            # -> deleted   (rule 2)
    shared_uncracked = _hash("b-uncracked-shared")             # -> kept      (rule 2)
    only_here_cracked = _hash("c-cracked-solo", cracked=True)  # -> kept      (rule 1)
    two_doomed_files = _hash("d-uncracked-twofiles")           # -> deleted   (rule 2)
    shared_cracked = _hash("e-cracked-shared", cracked=True)   # -> kept      (rule 1)

    _link(only_here_uncracked, hf1)
    _link(shared_uncracked, hf1)
    _link(shared_uncracked, hf_other)          # the other customer keeps it alive
    _link(only_here_cracked, hf1)
    _link(two_doomed_files, hf1)
    _link(two_doomed_files, hf2)               # both files belong to the doomed customer
    _link(shared_cracked, hf1)
    _link(shared_cracked, hf_other)

    _delete(client, doomed)

    # (1) cracked hashes survive whether or not anything still links to them
    assert Hashes.query.get(only_here_cracked) is not None
    assert Hashes.query.get(shared_cracked) is not None

    # (2) uncracked hashes go only when no hashfile links to them any more
    assert Hashes.query.get(only_here_uncracked) is None
    assert Hashes.query.get(two_doomed_files) is None
    assert Hashes.query.get(shared_uncracked) is not None

    # (3) the links and the hashfiles themselves are gone
    assert Hashfiles.query.get(hf1) is None
    assert Hashfiles.query.get(hf2) is None
    assert HashfileHashes.query.filter(
        HashfileHashes.hashfile_id.in_([hf1, hf2])).count() == 0

    # ...and the untouched customer is entirely intact
    assert Hashfiles.query.get(hf_other) is not None
    # shared_uncracked + shared_cracked
    assert HashfileHashes.query.filter_by(hashfile_id=hf_other).count() == 2
