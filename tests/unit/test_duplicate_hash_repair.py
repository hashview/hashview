"""Repairing duplicate (sub_ciphertext, hash_type) rows so the constraint can land.

Migration f3b8c1a7d942 adds uq_hashes_sub_ciphertext_hash_type. It used to RAISE
when the table already held duplicates, and that was worse than the defect it
guarded: a raise aborts the whole upgrade loop, so two later revisions were held
hostage to a data problem that has nothing to do with them -- and because the app
applies migrations inside create_app() under a broad `except Exception` that only
logs, the operator's symptom was a web server quietly serving traffic on a schema
its own models no longer matched.

So the migration now warns, skips the constraint, and lets the chain finish; these
tests pin that, the repair that follows, and the constraint finally landing.

The tests build a real SQLite database, stamp it at head and DOWNGRADE to the
revision below f3b8c1a7d942 -- which is the only way to get a table that lacks
the constraint, since hashview/models.py declares it and create_all() would
enforce it. That also means the real migration is what runs here, not a copy.
"""

from flask_migrate import downgrade, stamp, upgrade
from sqlalchemy import inspect as sa_inspect
from sqlalchemy import text

from hashview.models import Hashes, db
from hashview.utils.dedupe import (
    classify_group,
    delete_orphaned_alerts,
    duplicate_summary,
    find_duplicate_groups,
    group_hashfiles,
    group_rows,
    merge_group,
    orphan_summary,
    orphaned_links,
    recommend_keeper,
)

MIGRATIONS = "migrations"
BELOW = "a8c4d2e1f5b3"          # the revision immediately under f3b8c1a7d942


def head():
    """The chain's single head, read from the scripts rather than hardcoded.

    This was `HEAD = "a4c9e7b21f60"`, and merging v0.8.3-dev in moved the head
    three revisions past it -- so the test failed with
    `assert 'd8b3e5c02a71' == 'a4c9e7b21f60'` for a reason that has nothing to do
    with what it asserts: that a database carrying duplicates still reaches head,
    whatever head is. Pinning it means every unrelated migration breaks this test.
    test_migration_smoke.py already guarantees there is exactly one head, and
    test_migration_drift_idempotency.py derives it the same way for the same
    reason.
    """
    from alembic.config import Config as AlembicConfig
    from alembic.script import ScriptDirectory

    cfg = AlembicConfig()
    cfg.set_main_option("script_location", MIGRATIONS)
    heads = ScriptDirectory.from_config(cfg).get_heads()
    assert len(heads) == 1, f"Expected exactly one migration head; found {heads}"
    return heads[0]
OLD_INDEX = "ix_hashes_sub_ciphertext"
UNIQUE = "uq_hashes_sub_ciphertext_hash_type"


def _app_below_constraint(tmp_path):
    """A database whose hashes table has no unique constraint yet."""
    from hashview import create_app

    app = create_app(testing=True, config_overrides={
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path}/dupes.db",
        "SECRET_KEY": "dupe-repair-test",
        "HASHVIEW_SKIP_SETUP": True,
        "HASHVIEW_SKIP_GUI_SETUP": True,
        "HASHVIEW_DISABLE_SCHEDULER": True,
    })
    with app.app_context():
        db.create_all()
        stamp(directory=MIGRATIONS, revision="head")
        downgrade(directory=MIGRATIONS, revision=BELOW)
    return app


def _hash(hid, sub, hash_type, cracked=0, plaintext=None, ciphertext=None):
    db.session.execute(text(
        "INSERT INTO hashes (id, sub_ciphertext, ciphertext, hash_type, cracked, plaintext)"
        " VALUES (:i,:s,:c,:t,:k,:p)"),
        {"i": hid, "s": sub, "c": ciphertext or ("CIPHER-" + sub), "t": hash_type,
         "k": cracked, "p": plaintext})


def _link(lid, hash_id, hashfile_id, username=None):
    db.session.execute(text(
        "INSERT INTO hashfile_hashes (id, hash_id, hashfile_id, username)"
        " VALUES (:i,:h,:f,:u)"),
        {"i": lid, "h": hash_id, "f": hashfile_id, "u": username})


def _alert(nid, hash_id):
    db.session.execute(text(
        "INSERT INTO hash_notifications (id, owner_id, hash_id, method)"
        " VALUES (:i,1,:h,'email')"), {"i": nid, "h": hash_id})


def _orphans():
    links = db.session.execute(text(
        "SELECT COUNT(*) FROM hashfile_hashes f"
        " WHERE NOT EXISTS (SELECT 1 FROM hashes h WHERE h.id = f.hash_id)")).scalar()
    alerts = db.session.execute(text(
        "SELECT COUNT(*) FROM hash_notifications n"
        " WHERE NOT EXISTS (SELECT 1 FROM hashes h WHERE h.id = n.hash_id)")).scalar()
    return links, alerts


# --- the migration must not hold the rest of the chain hostage -----------------

def test_duplicates_no_longer_block_the_rest_of_the_migration_chain(tmp_path):
    app = _app_below_constraint(tmp_path)
    with app.app_context():
        _hash(1, "a" * 32, 1000)
        _hash(2, "a" * 32, 1000)
        db.session.commit()

        upgrade(directory=MIGRATIONS)          # must not raise

        insp = sa_inspect(db.engine)
        assert db.session.execute(
            text("SELECT version_num FROM alembic_version")).scalar() == head()
        assert not [c for c in insp.get_unique_constraints("hashes")
                    if c["name"] == UNIQUE], "constraint must be skipped, not forced"
        # The later revisions landed -- that is the whole point of not raising.
        assert any(c["name"] == "file_missing_notified"
                   for c in insp.get_columns("rules"))


def test_skipping_the_constraint_keeps_the_index_it_would_have_replaced(tmp_path):
    """The drop_index sits OUTSIDE the branch that creates the constraint, so a
    bare `pass` instead of a `return` would leave the table with no index on
    sub_ciphertext at all -- turning the import's dedup lookup into a full scan."""
    app = _app_below_constraint(tmp_path)
    with app.app_context():
        _hash(1, "a" * 32, 1000)
        _hash(2, "a" * 32, 1000)
        db.session.commit()

        upgrade(directory=MIGRATIONS)

        indexes = {i["name"] for i in sa_inspect(db.engine).get_indexes("hashes")}
        assert OLD_INDEX in indexes


def test_a_clean_database_still_gets_the_constraint(tmp_path):
    """The no-duplicates path must be untouched by any of this."""
    app = _app_below_constraint(tmp_path)
    with app.app_context():
        _hash(1, "a" * 32, 1000)
        _hash(2, "b" * 32, 1000)
        db.session.commit()

        upgrade(directory=MIGRATIONS)

        insp = sa_inspect(db.engine)
        assert [c for c in insp.get_unique_constraints("hashes") if c["name"] == UNIQUE]
        assert OLD_INDEX not in {i["name"] for i in insp.get_indexes("hashes")}


# --- what counts as a duplicate ------------------------------------------------

def test_the_same_ciphertext_under_two_hash_types_is_not_a_duplicate(tmp_path):
    """A 32-hex string uploaded once as MD5 and once as NTLM shares a
    sub_ciphertext but not a hash_type. The constraint is on the PAIR precisely
    so that stays legal, and the repair must never touch it."""
    app = _app_below_constraint(tmp_path)
    with app.app_context():
        _hash(1, "a" * 32, 0)          # MD5
        _hash(2, "a" * 32, 1000)       # NTLM
        db.session.commit()

        assert duplicate_summary(db.session.connection()) == (0, 0)
        upgrade(directory=MIGRATIONS)
        assert [c for c in sa_inspect(db.engine).get_unique_constraints("hashes")
                if c["name"] == UNIQUE], "this was never a duplicate; constraint applies"


def test_summary_counts_excess_rows_not_just_groups(tmp_path):
    app = _app_below_constraint(tmp_path)
    with app.app_context():
        _hash(1, "a" * 32, 1000)
        _hash(2, "a" * 32, 1000)
        _hash(3, "a" * 32, 1000)
        _hash(4, "b" * 32, 1000)
        _hash(5, "b" * 32, 1000)
        db.session.commit()

        # 2 groups, but 3 rows would go away -- the number an operator cares about.
        assert duplicate_summary(db.session.connection()) == (2, 3)


# --- which row to keep ---------------------------------------------------------

def test_a_cracked_row_is_kept_over_an_uncracked_one():
    rows = [{"id": 1, "cracked": False, "plaintext": None, "recovered_at": None,
             "ciphertext": "x"},
            {"id": 2, "cracked": True, "plaintext": "hunter2", "recovered_at": None,
             "ciphertext": "x"}]
    assert recommend_keeper(rows) == 2, "a recovered password is the only thing here that cannot be recomputed"


def test_the_lowest_id_wins_when_nothing_else_separates_them():
    rows = [{"id": 7, "cracked": False, "plaintext": None, "recovered_at": None, "ciphertext": "x"},
            {"id": 3, "cracked": False, "plaintext": None, "recovered_at": None, "ciphertext": "x"}]
    assert recommend_keeper(rows) == 3


def test_differing_ciphertexts_are_never_merged_automatically():
    """Same sub_ciphertext is supposed to mean same ciphertext -- it is its md5.
    If it doesn't, these are not interchangeable rows and merging would destroy a
    real hash. This gate is what keeps an automatic merge from ever being wrong."""
    rows = [{"id": 1, "cracked": False, "plaintext": None, "recovered_at": None,
             "ciphertext": "ONE"},
            {"id": 2, "cracked": False, "plaintext": None, "recovered_at": None,
             "ciphertext": "TWO"}]
    kind, keeper, reason = classify_group(rows)
    assert kind == "conflict" and keeper is None
    assert "ciphertext" in reason


def test_two_different_plaintexts_need_a_human():
    rows = [{"id": 1, "cracked": True, "plaintext": "alpha", "recovered_at": None, "ciphertext": "x"},
            {"id": 2, "cracked": True, "plaintext": "beta", "recovered_at": None, "ciphertext": "x"}]
    kind, keeper, reason = classify_group(rows)
    assert kind == "conflict" and keeper is None
    assert "alpha" in reason and "beta" in reason


def test_the_same_plaintext_twice_is_not_a_conflict():
    rows = [{"id": 1, "cracked": True, "plaintext": "letmein", "recovered_at": None, "ciphertext": "x"},
            {"id": 2, "cracked": True, "plaintext": "letmein", "recovered_at": None, "ciphertext": "x"}]
    assert classify_group(rows)[0] == "auto"


# --- merging -------------------------------------------------------------------

def test_merge_promotes_a_recovered_password_onto_the_survivor(tmp_path):
    app = _app_below_constraint(tmp_path)
    with app.app_context():
        _hash(1, "a" * 32, 1000)
        _hash(2, "a" * 32, 1000, cracked=1, plaintext="hunter2")
        db.session.commit()
        conn = db.session.connection()

        rows = group_rows(conn, 1000, "a" * 32)
        keeper = recommend_keeper(rows)
        merge_group(conn, keeper, [r["id"] for r in rows if r["id"] != keeper])
        db.session.commit()

        kept = db.session.execute(text(
            "SELECT id, cracked, plaintext FROM hashes")).fetchall()
        assert len(kept) == 1
        assert kept[0][1] and kept[0][2] == "hunter2", "the crack must survive the merge"


def test_merge_repoints_links_instead_of_orphaning_them(tmp_path):
    """hashes.id has no foreign key, so a link left pointing at a deleted hash is
    silent -- and lethal: build_hashcat_command raises on it (the job becomes
    undispatchable) and _hashfile_has_uncracked reads it as "nothing left to
    crack", which cancels the job's remaining tasks."""
    app = _app_below_constraint(tmp_path)
    with app.app_context():
        _hash(1, "a" * 32, 1000)
        _hash(2, "a" * 32, 1000)
        _link(1, 1, 100, "alice")
        _link(2, 2, 200, "bob")
        _alert(1, 2)
        db.session.commit()
        conn = db.session.connection()

        merge_group(conn, 1, [2])
        db.session.commit()

        assert _orphans() == (0, 0)
        links = db.session.execute(text(
            "SELECT hash_id, hashfile_id FROM hashfile_hashes ORDER BY hashfile_id")).fetchall()
        assert links == [(1, 100), (1, 200)], "both files keep their account"
        assert db.session.execute(text(
            "SELECT hash_id FROM hash_notifications")).scalar() == 1


def test_merge_collapses_links_that_repointing_made_identical(tmp_path):
    """Two copies of one hash in the SAME hashfile under the same username become
    one link row. Neither child table has a unique constraint to do this for us."""
    app = _app_below_constraint(tmp_path)
    with app.app_context():
        _hash(1, "a" * 32, 1000)
        _hash(2, "a" * 32, 1000)
        _link(1, 1, 300, "carol")
        _link(2, 2, 300, "carol")
        db.session.commit()
        conn = db.session.connection()

        merge_group(conn, 1, [2])
        db.session.commit()

        assert db.session.execute(text(
            "SELECT COUNT(*) FROM hashfile_hashes WHERE hashfile_id = 300")).scalar() == 1
        assert _orphans() == (0, 0)


def test_merge_handles_a_group_of_three(tmp_path):
    app = _app_below_constraint(tmp_path)
    with app.app_context():
        _hash(1, "c" * 32, 0)
        _hash(2, "c" * 32, 0, cracked=1, plaintext="letmein")
        _hash(3, "c" * 32, 0, cracked=1, plaintext="letmein")
        _link(1, 1, 10)
        _link(2, 2, 20)
        _link(3, 3, 30)
        db.session.commit()
        conn = db.session.connection()

        rows = group_rows(conn, 0, "c" * 32)
        keeper = recommend_keeper(rows)
        merge_group(conn, keeper, [r["id"] for r in rows if r["id"] != keeper])
        db.session.commit()

        assert db.session.execute(text("SELECT COUNT(*) FROM hashes")).scalar() == 1
        assert db.session.execute(text(
            "SELECT COUNT(*) FROM hashfile_hashes")).scalar() == 3, "three files, three links"
        assert _orphans() == (0, 0)


# --- the whole operator journey -------------------------------------------------

def test_after_repairing_every_group_the_constraint_finally_lands(tmp_path):
    app = _app_below_constraint(tmp_path)
    with app.app_context():
        _hash(1, "a" * 32, 1000)
        _hash(2, "a" * 32, 1000, cracked=1, plaintext="hunter2")
        _hash(3, "b" * 32, 1000)
        _hash(4, "b" * 32, 1000)
        _link(1, 2, 100, "alice")
        db.session.commit()

        upgrade(directory=MIGRATIONS)           # warns, skips, reaches head
        conn = db.session.connection()
        for group in find_duplicate_groups(conn):
            rows = group_rows(conn, group["hash_type"], group["sub_ciphertext"])
            kind, keeper, _reason = classify_group(rows)
            assert kind == "auto"
            merge_group(conn, keeper, [r["id"] for r in rows if r["id"] != keeper])
        db.session.commit()

        assert duplicate_summary(db.session.connection()) == (0, 0)
        assert _orphans() == (0, 0)

        # Re-running the upgrade now creates what it skipped.
        db.session.execute(text(
            "UPDATE alembic_version SET version_num = :r"), {"r": BELOW})
        db.session.commit()
        upgrade(directory=MIGRATIONS)

        insp = sa_inspect(db.engine)
        assert [c for c in insp.get_unique_constraints("hashes") if c["name"] == UNIQUE]
        assert OLD_INDEX not in {i["name"] for i in insp.get_indexes("hashes")}


# --- the Settings page ----------------------------------------------------------
#
# The web flow exists for operators who will not run a script. It uses the same
# dedupe helpers, so these tests cover the routing, the admin gate and the
# stale-form guard rather than re-testing the merge itself.

def _admin_user(admin=True):
    from hashview.models import Users

    user = Users(first_name="A", last_name="D",
                 email_address=f"{'adm' if admin else 'usr'}@dupes.test",
                 password="x" * 60, admin=admin, api_key=f"dupekey-{admin}")
    db.session.add(user)
    db.session.commit()
    return user


def _login(client, user):
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True


def test_duplicate_page_is_admin_only(app, client):
    _login(client, _admin_user(admin=False))
    assert client.get("/settings/duplicate_hashes").status_code == 403
    assert client.post("/settings/duplicate_hashes/merge").status_code == 403


def test_duplicate_page_lists_groups_and_flags_conflicts(app, client):
    _login(client, _admin_user())
    # The in-memory unit DB has the constraint (it comes from the models), so
    # exercise the page against rows that differ only by hash_type -- which the
    # page must NOT list -- plus a real conflict inserted around the constraint.
    db.session.add(Hashes(sub_ciphertext="a" * 32, ciphertext="SAME", hash_type=0,
                          cracked=False))
    db.session.add(Hashes(sub_ciphertext="a" * 32, ciphertext="SAME", hash_type=1000,
                          cracked=False))
    db.session.commit()

    body = client.get("/settings/duplicate_hashes").get_data(as_text=True)
    assert "No duplicate hashes" in body, (
        "the same ciphertext under two hash types is not a duplicate")


def test_merge_ignores_a_keeper_id_that_no_longer_exists(app, client):
    """The page can be minutes stale. A merge is driven by re-reading the group
    from the keeper, so a vanished row is skipped rather than acted on."""
    _login(client, _admin_user())
    resp = client.post("/settings/duplicate_hashes/merge",
                       data={"keep_1000_" + "a" * 32: "999999"},
                       follow_redirects=True)
    assert resp.status_code == 200
    assert Hashes.query.count() == 0


# --- orphaned child rows --------------------------------------------------------
#
# Not caused by merging -- merge_group repoints rather than deletes -- but the
# same absent foreign key lets anything else that removed a hash leave these
# behind, and almost nothing cleans them up.

def test_merging_never_creates_an_orphan_and_never_touches_an_existing_one(tmp_path):
    app = _app_below_constraint(tmp_path)
    with app.app_context():
        _hash(1, "a" * 32, 1000)
        _hash(2, "a" * 32, 1000)
        _link(1, 2, 100, "alice")
        _alert(1, 2)
        _link(99, 424242, 900, "ghost")      # already dangling, unrelated
        _alert(99, 424242)
        db.session.commit()
        conn = db.session.connection()

        merge_group(conn, 1, [2])
        db.session.commit()

        # The merge's own children were repointed, not orphaned...
        assert db.session.execute(text(
            "SELECT hash_id FROM hashfile_hashes WHERE id = 1")).scalar() == 1
        assert db.session.execute(text(
            "SELECT hash_id FROM hash_notifications WHERE id = 1")).scalar() == 1
        # ...and the pre-existing orphans are still exactly as they were.
        assert _orphans() == (1, 1)


def test_orphan_summary_counts_both_kinds(tmp_path):
    app = _app_below_constraint(tmp_path)
    with app.app_context():
        _hash(1, "a" * 32, 1000)
        _link(1, 1, 100)                     # fine
        _link(2, 424242, 900, "ghost")       # dangling
        _alert(1, 424242)                    # dangling
        db.session.commit()

        assert orphan_summary(db.session.connection()) == (1, 1)


def test_orphaned_alerts_are_deleted(tmp_path):
    """One can never fire: process_recovered_hash_notifications looks its hash up,
    `continue`s when it is missing, and so never reaches the delete that would
    retire it -- while still being re-read on every crack upload, forever."""
    app = _app_below_constraint(tmp_path)
    with app.app_context():
        _hash(1, "a" * 32, 1000)
        _alert(1, 1)                         # live, must survive
        _alert(2, 424242)                    # dangling, must go
        db.session.commit()
        conn = db.session.connection()

        assert delete_orphaned_alerts(conn) == 1
        db.session.commit()

        assert [r[0] for r in db.session.execute(text(
            "SELECT id FROM hash_notifications ORDER BY id")).fetchall()] == [1]


def test_orphaned_links_are_reported_not_deleted(tmp_path):
    """The row is the record that an account existed in a hashfile, and that is
    not recoverable without re-importing the file -- so removing it is the
    operator's call, even though it is the harmful kind."""
    app = _app_below_constraint(tmp_path)
    with app.app_context():
        _link(1, 424242, 900, "ghost")
        db.session.commit()
        conn = db.session.connection()

        delete_orphaned_alerts(conn)
        db.session.commit()

        assert _orphans()[0] == 1, "links survive"
        reported = orphaned_links(db.session.connection())
        assert len(reported) == 1
        assert reported[0]["hash_id"] == 424242
        assert reported[0]["username"] == "ghost"
        assert reported[0]["hashfile_id"] == 900


def test_group_hashfiles_reports_every_file_an_account_appears_in(tmp_path):
    """group_hashfiles is the operator-facing context for a duplicate group.

    Exercised here because the expanding bindparam replaced a hand-built
    ':h0, :h1' placeholder list: if SQLAlchemy is not expanding the parameter the
    query returns nothing rather than erroring, so a silent empty result is
    exactly the failure mode this has to rule out. Two hashes across three links
    prove the rows are grouped by hash_id rather than flattened.
    """
    app = _app_below_constraint(tmp_path)
    with app.app_context():
        _hash(1, "a" * 32, 1000)
        _hash(2, "a" * 32, 1000)
        _link(1, 1, 100, "alice")
        _link(2, 1, 200, "alice")
        _link(3, 2, 300, "bob")
        db.session.commit()
        conn = db.session.connection()

        out = group_hashfiles(conn, [1, 2])

        assert set(out) == {1, 2}
        assert [(f, u) for f, _name, u in out[1]] == [(100, "alice"), (200, "alice")]
        assert [(f, u) for f, _name, u in out[2]] == [(300, "bob")]


def test_group_hashfiles_short_circuits_on_an_empty_id_list(tmp_path):
    """The early return is load-bearing: an expanding bindparam rejects []."""
    app = _app_below_constraint(tmp_path)
    with app.app_context():
        conn = db.session.connection()
        assert group_hashfiles(conn, []) == {}


def test_group_hashfiles_omits_a_hash_with_no_links(tmp_path):
    """A hash nobody references contributes no key, rather than an empty list."""
    app = _app_below_constraint(tmp_path)
    with app.app_context():
        _hash(1, "a" * 32, 1000)
        _hash(2, "a" * 32, 1000)
        _link(1, 1, 100, "alice")
        db.session.commit()
        conn = db.session.connection()

        out = group_hashfiles(conn, [1, 2])

        assert set(out) == {1}
