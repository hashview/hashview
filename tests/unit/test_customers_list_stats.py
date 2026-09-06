"""Correctness + query-shape guards for the /customers listing stats.

The per-customer numbers on this page (jobs, hashfiles, total, cracked, pct)
were previously computed by one aggregate query per customer. Nothing in the
suite pinned any of those numbers, so the loop could be rewritten into
something silently wrong. These tests pin the values, and pin that the query
count does not grow with the number of customers.

Stats are captured from the template context via Flask's ``template_rendered``
signal rather than scraped out of the HTML: ``total`` and ``cracked`` feed the
percentage but are not both rendered as text, and asserting on markup would
make these hostage to styling changes.
"""

from flask import template_rendered
from sqlalchemy import event

from hashview.models import Hashes, HashfileHashes, Hashfiles, Jobs, db
from tests.unit.helpers import login, make_admin, make_customer


def _stats(client):
    """GET /customers and return the customer_stats dict the template received."""
    captured = {}

    def record(sender, template, context, **extra):
        if 'customer_stats' in context:
            captured.update(context['customer_stats'])

    template_rendered.connect(record)
    try:
        resp = client.get("/customers")
    finally:
        template_rendered.disconnect(record)
    assert resp.status_code == 200
    return captured, resp


def _hashfile(customer, owner, name="hf"):
    hf = Hashfiles(name=name, customer_id=customer.id, owner_id=owner.id)
    db.session.add(hf)
    db.session.commit()
    return hf


def _hash(sub, cracked, hash_type=1000):
    h = Hashes(sub_ciphertext=sub, ciphertext="c" + sub, hash_type=hash_type,
               cracked=cracked, plaintext="pw" if cracked else None)
    db.session.add(h)
    db.session.commit()
    return h


def _link(h, hf, username=None):
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id, username=username))
    db.session.commit()


def test_stats_are_scoped_per_customer(app, client):
    admin = make_admin()
    login(client, admin)
    a = make_customer(name="Alpha")
    b = make_customer(name="Bravo")
    hf_a, hf_b = _hashfile(a, admin, "a-hf"), _hashfile(b, admin, "b-hf")
    _link(_hash("a1", True), hf_a)
    _link(_hash("a2", False), hf_a)
    _link(_hash("b1", False), hf_b)

    stats, _ = _stats(client)
    assert stats[a.id]['total'] == 2 and stats[a.id]['cracked'] == 1
    assert stats[a.id]['hashfiles'] == 1 and stats[a.id]['pct'] == 50
    # Bravo's single uncracked hash must not pick up Alpha's crack.
    assert stats[b.id]['total'] == 1 and stats[b.id]['cracked'] == 0
    assert stats[b.id]['pct'] == 0


def test_customer_with_no_hashfiles_still_renders(app, client):
    # A customer absent from every aggregate must keep its row and read zero,
    # not vanish from the listing and not raise ZeroDivisionError on pct.
    admin = make_admin()
    login(client, admin)
    lonely = make_customer(name="NoFiles")

    stats, resp = _stats(client)
    assert stats[lonely.id] == {'jobs': 0, 'hashfiles': 0, 'total': 0, 'cracked': 0, 'pct': 0}
    assert b"NoFiles" in resp.data


def test_customer_with_no_cracked_hashes_renders_zero(app, client):
    # The cracked aggregate returns NO ROW for this customer; indexing instead
    # of .get(id, 0) would raise KeyError here — and on a fresh instance that
    # is every customer.
    admin = make_admin()
    login(client, admin)
    c = make_customer(name="Uncracked")
    hf = _hashfile(c, admin)
    _link(_hash("u1", False), hf)
    _link(_hash("u2", False), hf)

    stats, _ = _stats(client)
    assert stats[c.id]['total'] == 2
    assert stats[c.id]['cracked'] == 0
    assert stats[c.id]['pct'] == 0


def test_hashfile_with_no_hashes_counts_as_zero(app, client):
    admin = make_admin()
    login(client, admin)
    c = make_customer(name="EmptyFile")
    _hashfile(c, admin)

    stats, _ = _stats(client)
    assert stats[c.id]['hashfiles'] == 1
    assert stats[c.id]['total'] == 0
    assert stats[c.id]['pct'] == 0


def test_percentage_rounds_like_the_original(app, client):
    admin = make_admin()
    login(client, admin)
    c = make_customer(name="Third")
    hf = _hashfile(c, admin)
    _link(_hash("t1", True), hf)
    _link(_hash("t2", False), hf)
    _link(_hash("t3", False), hf)

    stats, resp = _stats(client)
    assert stats[c.id]['pct'] == 33          # round(1/3*100)
    assert b"33%" in resp.data               # and it reaches the page


def test_hash_shared_between_two_customers_counts_for_both(app, client):
    # Hashes are globally deduplicated, so one row can belong to two customers'
    # hashfiles. Each customer counts it.
    admin = make_admin()
    login(client, admin)
    a, b = make_customer(name="ShareA"), make_customer(name="ShareB")
    hf_a, hf_b = _hashfile(a, admin, "sa"), _hashfile(b, admin, "sb")
    shared = _hash("s1", True)
    _link(shared, hf_a)
    _link(shared, hf_b)

    stats, _ = _stats(client)
    assert stats[a.id]['total'] == 1 and stats[a.id]['cracked'] == 1
    assert stats[b.id]['total'] == 1 and stats[b.id]['cracked'] == 1


def test_jobs_are_counted_per_customer(app, client):
    admin = make_admin()
    login(client, admin)
    a, b = make_customer(name="JobsA"), make_customer(name="JobsB")
    for name in ("j1", "j2"):
        db.session.add(Jobs(name=name, customer_id=a.id, owner_id=admin.id, status='Queued'))
    db.session.add(Jobs(name="j3", customer_id=b.id, owner_id=admin.id, status='Queued'))
    db.session.commit()

    stats, _ = _stats(client)
    assert stats[a.id]['jobs'] == 2
    assert stats[b.id]['jobs'] == 1


def test_query_count_does_not_grow_with_customer_count(app, client):
    """The regression guard that matters.

    Deliberately NOT phrased as "the loop is gone" or "there is one grouped
    query": a single grouped COUNT+SUM(CASE) measured *slower* than the
    per-customer loop it replaced, and a test phrased that way would wave it
    through. What must hold is that the statement count is flat in the number
    of customers.
    """
    admin = make_admin()
    login(client, admin)

    def seed(i):
        # Every seeded customer needs a hashfile holding a hash: the old loop
        # skipped its per-customer aggregate when a customer had none, so
        # seeding bare customers would leave this guard unable to fire.
        c = make_customer(name=f"seed-{i:03d}")
        hf = _hashfile(c, admin, f"seed-hf-{i:03d}")
        _link(_hash(f"sd{i:03d}", i % 2 == 0), hf)

    for i in range(3):
        seed(i)

    def count_statements():
        seen = []

        def record(conn, cursor, statement, parameters, context, executemany):
            seen.append(" ".join(statement.split()).lower())

        event.listen(db.engine, "before_cursor_execute", record)
        try:
            assert client.get("/customers").status_code == 200
        finally:
            event.remove(db.engine, "before_cursor_execute", record)
        return len([s for s in seen if s.startswith("select")])

    with_three = count_statements()
    for i in range(3, 12):
        seed(i)
    with_twelve = count_statements()

    assert with_twelve == with_three, (
        f"/customers issued {with_three} SELECTs for 3 customers but {with_twelve} for 12 — "
        "the per-customer aggregate loop is back"
    )
