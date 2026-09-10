"""Unit tests for the redesigned /analytics page.

Exercises the three scopes the page supports via the customer_id / hashfile_id
query args (all data / per-customer / per-hashfile), the server-side aggregation
(top passwords, shared passwords, username==password, complexity histogram), and
that the template renders without error in each scope. Uses the in-memory SQLite
app from tests/unit/conftest.py.
"""

from datetime import datetime, timedelta

from hashview.models import (
    Customers,
    Hashes,
    HashfileHashes,
    Hashfiles,
    Tasks,
    Users,
    db,
)
from hashview.utils.utils import get_md5_hash


def _admin():
    user = Users(first_name="A", last_name="D", email_address="a@e.com",
                 password="x" * 60, admin=True, api_key="an-key")
    db.session.add(user)
    db.session.commit()
    return user


def _login(client, user):
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True


def _hash(ciphertext, plaintext, cracked):
    h = Hashes(sub_ciphertext=get_md5_hash(ciphertext), ciphertext=ciphertext, hash_type=1000,
               cracked=cracked, plaintext=plaintext,
               recovered_at=datetime(2024, 1, 2) if cracked else None)
    db.session.add(h)
    db.session.commit()
    return h


def _seed():
    """One customer, one hashfile, 3 cracked + 1 uncracked accounts.

    'Password1' is shared by alice & bob; 'admin' uses its name as password.
    Returns (customer_id, hashfile_id).
    """
    cust = Customers(name="Acme Corp")
    db.session.add(cust)
    db.session.commit()
    hf = Hashfiles(name="corp_dump", customer_id=cust.id, owner_id=1, runtime=7200)
    db.session.add(hf)
    db.session.commit()
    rows = [
        ("aaa", "Password1", True, "alice"),
        ("bbb", "Password1", True, "bob"),
        ("ccc", "admin", True, "admin"),
        ("ddd", None, False, "carol"),
    ]
    for ct, pt, cracked, user in rows:
        h = _hash(ct, pt, cracked)
        db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id, username=user))
    db.session.commit()
    return cust.id, hf.id


def test_analytics_all_scope(app, client):
    user = _admin()
    _login(client, user)
    _seed()
    resp = client.get("/analytics")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "Analytics" in html
    assert "Hashes Recovered" in html and "Accounts Recovered" in html
    assert "All Data" in html                       # summary title for the all scope
    assert "rollup" not in html                     # no customer rollup when unscoped
    assert "Password1" in html                       # top recovered password
    assert "Password Complexity Compliance" in html
    assert "admin" in html                           # username == password row


def test_analytics_customer_scope(app, client):
    user = _admin()
    _login(client, user)
    customer_id, _hf = _seed()
    resp = client.get(f"/analytics?customer_id={customer_id}")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "Customer Summary" in html
    assert "rollup" in html                          # rollup shown when a customer is selected
    assert "Acme Corp" in html
    # hashfile select is enabled (has the per-file option) in customer scope
    assert "hashfile_id" in html


def test_analytics_hashfile_scope(app, client):
    user = _admin()
    _login(client, user)
    customer_id, hashfile_id = _seed()
    resp = client.get(f"/analytics?customer_id={customer_id}&hashfile_id={hashfile_id}")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "Hashfile Summary" in html
    assert "Password1" in html


def test_analytics_empty_scope_renders(app, client):
    """A customer/hashfile with no cracked hashes must still render (placeholders)."""
    user = _admin()
    _login(client, user)
    cust = Customers(name="Empty Co")
    db.session.add(cust)
    db.session.commit()
    hf = Hashfiles(name="nada", customer_id=cust.id, owner_id=1, runtime=0)
    db.session.add(hf)
    db.session.commit()
    h = _hash("eee", None, False)
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id, username="nobody"))
    db.session.commit()
    resp = client.get(f"/analytics?customer_id={cust.id}&hashfile_id={hf.id}")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "no recovered passwords" in html          # empty-state placeholder


def test_analytics_pattern_intelligence(app, client):
    """The Pattern Intelligence section: base words, themes, years, and endings."""
    user = _admin()
    _login(client, user)
    cust = Customers(name="Acme Corp")
    db.session.add(cust)
    db.session.commit()
    hf = Hashfiles(name="corp_dump", customer_id=cust.id, owner_id=1, runtime=3600)
    db.session.add(hf)
    db.session.commit()
    # a real wordlist task to attribute one crack to (the rest stay task_id=None)
    task = Tasks(name="RockYou", hc_attackmode=0, owner_id=1)
    db.session.add(task)
    db.session.commit()

    rows = [
        ("h1", "Summer2024!", "alice", task.id),   # base 'summer', season, year, ends '!'
        ("h2", "Welcome1", "bob", None),            # base 'welcome', ends '1'
        ("h3", "Acme2023!", "carol", None),         # company token 'acme', year 2023
        ("h4", "qwerty123", "dave", None),          # keyboard walk, ends '123'
        ("h5", "admin", "admin", None),             # username == password
    ]
    for ct, pt, un, task_id in rows:
        h = _hash(ct, pt, True)
        h.task_id = task_id
        db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id, username=un))
    db.session.commit()

    html = client.get(f"/analytics?customer_id={cust.id}").get_data(as_text=True)
    assert "pattern intelligence" in html
    assert "Top Base Words" in html and "summer" in html and "welcome" in html
    assert "Common Themes" in html and "Keyboard walk" in html
    assert "Year in Password" in html and "2024" in html and "2023" in html
    assert "Password Endings" in html
    assert "How They Fell" not in html          # figure removed in favor of Recovery by Task
    # structure / strength additions
    assert "brighter = more passwords" in html          # length x complexity heatmap
    assert "Password Strength" in html and "Very weak" in html
    assert "Password Rotation" in html                   # Summer2024!/Summer2023! share stem 'summer'
    # Export report prints the page to PDF in the browser (no server download)
    assert "window.print()" in html and "no-print" in html


def test_analytics_download_recovered_scoped(app, client):
    """The summary's download buttons hit the existing scoped download endpoint."""
    user = _admin()
    _login(client, user)
    customer_id, hashfile_id = _seed()
    resp = client.get(f"/analytics/download?type=found&customer_id={customer_id}&hashfile_id={hashfile_id}")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "Password1" in body                       # cracked export contains plaintext


def test_analytics_download_unknown_type_redirects_without_serving_a_file(app, client):
    """Issue #389: an unknown ?type must bail out before any query runs, not
    fall through and serve an empty attachment. This bug was fixed as a side
    effect of #421's streaming rewrite (the redirect that used to be built
    and discarded is now returned early). The docker-integration suite
    (tests/integration/test_analytics_docker_bugs.py) used to carry the same
    assertion as a strict xfail against #389, removed in this same change,
    but that suite is opt-in and skips without a live docker stack -- this is
    the only coverage that runs in a plain `pytest tests/`.
    """
    user = _admin()
    _login(client, user)
    customer_id, hashfile_id = _seed()
    resp = client.get(
        f"/analytics/download?type=bogus&customer_id={customer_id}&hashfile_id={hashfile_id}",
        follow_redirects=False,
    )
    assert resp.status_code in (301, 302, 303)
    assert resp.headers["Location"].endswith("/analytics")


def test_analytics_summary_above_donuts(app, client):
    """The scope summary card (with its download buttons) sits above the donuts."""
    user = _admin()
    _login(client, user)
    customer_id, _hf = _seed()
    html = client.get(f"/analytics?customer_id={customer_id}").get_data(as_text=True)
    assert html.index("Customer Summary") < html.index("Hashes Recovered")
    assert "Download recovered" in html and "Download uncracked" in html
    # complexity compliance shows one decimal place (e.g. 99.9%)
    assert ".toFixed(1)" in html
    # whole-page print: the shell's 100vh/overflow is unpinned for print
    assert "height: auto !important" in html


def test_recovery_over_time_hourly_toggle_and_48h_cap(app, client):
    """Recovery Over Time buckets by hour, offers a Cumulative/Per-hour toggle,
    and caps the visible window to 48 hours (older recoveries fold into the
    cumulative baseline rather than widening the x-axis)."""
    user = _admin()
    _login(client, user)
    cust = Customers(name="Tempo Inc")
    db.session.add(cust)
    db.session.commit()
    hf = Hashfiles(name="dump", customer_id=cust.id, owner_id=1, runtime=0)
    db.session.add(hf)
    db.session.commit()

    base = datetime(2026, 3, 2, 10, 0, 0)
    # recent cluster (2 @ 10:00, 1 @ 11:00) + one recovery 5 days earlier
    stamps = [base, base, base + timedelta(hours=1), base - timedelta(days=5)]
    for i, ts in enumerate(stamps):
        h = Hashes(sub_ciphertext=get_md5_hash(f"c{i}"), ciphertext=f"c{i}", hash_type=1000,
                   cracked=True, plaintext=f"p{i}", recovered_at=ts)
        db.session.add(h)
        db.session.commit()
        db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id, username=f"u{i}"))
    db.session.commit()

    html = client.get(f"/analytics?customer_id={cust.id}&hashfile_id={hf.id}").get_data(as_text=True)

    # toggle controls + both chart containers + handler
    assert ">Cumulative<" in html and ">Per hour<" in html
    assert 'id="rot-cum"' in html and 'id="rot-hour"' in html
    assert "hvRotMode(" in html
    # hourly x-axis labels (the last bucket is the most recent recovery hour)
    assert "03/02 11:00" in html
    # the 5-day-old recovery is outside the 48h window -> not an x-axis bucket
    assert "02/25 10:00" not in html


def test_shared_password_row_download(app, client):
    """Clicking a shared-password row POSTs the plaintext and downloads its users."""
    user = _admin()
    _login(client, user)
    customer_id, _hf = _seed()
    resp = client.post("/analytics/download/shared",
                       data={"plaintext": "Password1", "customer_id": str(customer_id), "hashfile_id": ""})
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert body.startswith("The following users were found to share the same password: Password1")
    assert "alice" in body and "bob" in body
    assert resp.headers["Content-Disposition"].startswith("attachment")


def test_shared_password_zip_download(app, client):
    """The card's download button zips one txt per shared-password group."""
    import io
    import zipfile
    user = _admin()
    _login(client, user)
    customer_id, _hf = _seed()
    resp = client.get(f"/analytics/download/shared_zip?customer_id={customer_id}")
    assert resp.status_code == 200
    assert resp.mimetype == "application/zip"
    archive = zipfile.ZipFile(io.BytesIO(resp.data))
    names = archive.namelist()
    assert len(names) >= 1                            # at least the Password1 group
    content = "\n".join(archive.read(n).decode("utf-8") for n in names)
    assert "Password1" in content and "alice" in content and "bob" in content


def test_download_fig9_shared_password_accounts(app, client):
    """fig9 download serves the shared-password usernames as a .txt attachment."""
    user = _admin()
    _login(client, user)
    customer_id, hashfile_id = _seed()
    resp = client.get(f"/analytics/download/fig9?customer_id={customer_id}&hashfile_id={hashfile_id}")
    assert resp.status_code == 200
    assert resp.headers["Content-Disposition"].startswith("attachment")


def test_download_fig8_same_user_pass(app, client):
    """fig8 download serves a .txt attachment (empty result is still valid)."""
    user = _admin()
    _login(client, user)
    customer_id, hashfile_id = _seed()
    resp = client.get(f"/analytics/download/fig8?customer_id={customer_id}&hashfile_id={hashfile_id}")
    assert resp.status_code == 200
    assert resp.headers["Content-Disposition"].startswith("attachment")


# ---------------------------------------------------------------------------
# $HEX[...] cracked passwords — length/strength analytics (issue #291)
#
# hashcat stores non-UTF-8 plaintexts as the lossless `$HEX[<hex>]` marker.
# Analytics must decode that before measuring length, the way Wrapped already
# does (tests/unit/test_wrapped_view.py). These are xfail until #291 lands.
# ---------------------------------------------------------------------------

# "pässwörd": 8 real characters, but the $HEX[...] wrapper is 26 chars wide.
_HEX_PW = "$HEX[" + "pässwörd".encode().hex() + "]"


def _seed_single_hex_password():
    """A scope whose only cracked hash is a $HEX[...] (non-UTF-8) password."""
    cust = Customers(name="Hex Corp")
    db.session.add(cust)
    db.session.commit()
    hf = Hashfiles(name="hex_dump", customer_id=cust.id, owner_id=1, runtime=60)
    db.session.add(hf)
    db.session.commit()
    h = _hash("hexct", _HEX_PW, True)
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id, username="bob"))
    db.session.commit()
    return cust.id, hf.id


def test_analytics_hex_length_uses_decoded_length(app, client):
    """The length-distribution chart must bucket the decoded password length
    (8 for 'pässwörd'), not the 26-char $HEX[...] wrapper."""
    user = _admin()
    _login(client, user)
    customer_id, hashfile_id = _seed_single_hex_password()
    html = client.get(
        f"/analytics?customer_id={customer_id}&hashfile_id={hashfile_id}"
    ).get_data(as_text=True)
    # length_dist renders title="{len} chars: {n}" and a {len} label per bar.
    assert "8 chars" in html          # decoded length
    assert "26 chars" not in html     # the $HEX[...] wrapper length


def test_analytics_hex_not_overscored_as_long_strong(app, client):
    """An 8-char password must not be rated as if it were 26 chars: the
    raw $HEX[...] string should never leak into the rendered page."""
    user = _admin()
    _login(client, user)
    customer_id, hashfile_id = _seed_single_hex_password()
    html = client.get(
        f"/analytics?customer_id={customer_id}&hashfile_id={hashfile_id}"
    ).get_data(as_text=True)
    assert _HEX_PW not in html        # wrapper must not appear in top passwords/masks


# --- Recovery by Task figure -----------------------------------------------

def _task(owner_id, name, attackmode=0, rule_id=None):
    t = Tasks(name=name, hc_attackmode=attackmode, owner_id=owner_id, rule_id=rule_id)
    db.session.add(t)
    db.session.commit()
    return t


def _cracked_for_task(hashfile_id, task_id, n, prefix):
    """n cracked hashes attributed to task_id, linked to the hashfile."""
    for i in range(n):
        h = Hashes(sub_ciphertext=get_md5_hash("%s%d" % (prefix, i)), ciphertext="%s%d" % (prefix, i), hash_type=1000,
                   cracked=True, plaintext="pw-%s-%d" % (prefix, i),
                   recovered_at=datetime(2024, 1, 2), task_id=task_id)
        db.session.add(h)
        db.session.commit()
        db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hashfile_id,
                                      username="u%s%d" % (prefix, i)))
    db.session.commit()


def test_recovery_by_task_groups_counts_shares_and_scopes(app, client):
    from hashview.analytics.routes import _recovery_by_task

    admin = _admin()
    cust = Customers(name="RBT Corp")
    db.session.add(cust)
    db.session.commit()
    hf = Hashfiles(name="rbt_dump", customer_id=cust.id, owner_id=admin.id, runtime=0)
    db.session.add(hf)
    db.session.commit()

    t_dict = _task(admin.id, "rockyou.txt", attackmode=0)
    t_rule = _task(admin.id, "rockyou + best64", attackmode=0, rule_id=1)
    t_mask = _task(admin.id, "8-char brute", attackmode=3)
    _cracked_for_task(hf.id, t_dict.id, 3, "d")     # 3 recovered
    _cracked_for_task(hf.id, t_rule.id, 6, "r")     # 6 recovered
    _cracked_for_task(hf.id, t_mask.id, 1, "m")     # 1 recovered
    # a cracked hash with no task_id is unattributable and must be excluded
    orphan = Hashes(sub_ciphertext=get_md5_hash("orphan"), ciphertext="orphan", hash_type=1000,
                    cracked=True, plaintext="orphan", recovered_at=datetime(2024, 1, 2),
                    task_id=None)
    db.session.add(orphan)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=orphan.id, hashfile_id=hf.id, username="orphan"))
    db.session.commit()

    rows, total = _recovery_by_task(cust.id, hf.id)
    assert total == 10                                        # 6 + 3 + 1 (orphan excluded)
    assert [r["name"] for r in rows] == ["rockyou + best64", "rockyou.txt", "8-char brute"]
    assert (rows[0]["n"], rows[0]["mode"], rows[0]["share"], rows[0]["bar"]) == (6, "Dict + Rule", 60.0, 100.0)
    assert (rows[1]["n"], rows[1]["mode"], rows[1]["share"]) == (3, "Dictionary", 30.0)
    assert (rows[2]["n"], rows[2]["mode"], rows[2]["share"], rows[2]["bar"]) == (1, "Mask", 10.0, round(100.0 / 6, 1))

    # scope isolation: a different customer sees nothing; all-scope sees everything
    other = Customers(name="Other Corp")
    db.session.add(other)
    db.session.commit()
    assert _recovery_by_task(other.id, None) == ([], 0)
    assert _recovery_by_task(None, None)[1] == 10

    # the figure renders on the page (and the retired "How They Fell" figure does not)
    _login(client, admin)
    html = client.get("/analytics?customer_id=%d&hashfile_id=%d" % (cust.id, hf.id)).get_data(as_text=True)
    assert "Recovery by Task" in html
    assert "rockyou + best64" in html
    assert "Dict + Rule" in html                              # mode badge text (CSS uppercases it)
    assert "How They Fell" not in html


def test_recovery_by_task_deleted_task_labelled(app, client):
    """A task that no longer exists is labelled '(Task Deleted)', not by id."""
    from hashview.analytics.routes import _recovery_by_task

    admin = _admin()
    cust = Customers(name="Ghost Corp")
    db.session.add(cust)
    db.session.commit()
    hf = Hashfiles(name="ghost_dump", customer_id=cust.id, owner_id=admin.id, runtime=0)
    db.session.add(hf)
    db.session.commit()
    # attribute cracks to a task_id with no surviving Tasks row (task was deleted)
    _cracked_for_task(hf.id, 4242, 2, "g")

    rows, total = _recovery_by_task(cust.id, hf.id)
    assert total == 2
    assert len(rows) == 1
    assert rows[0]["name"] == "(Task Deleted)"
    assert rows[0]["mode"] == "Unknown"

    _login(client, admin)
    html = client.get("/analytics?customer_id=%d&hashfile_id=%d" % (cust.id, hf.id)).get_data(as_text=True)
    assert "(Task Deleted)" in html


# --- payload bounding: the page must not render one DOM node per group ------
# A production hashfile yields tens of thousands of shared-password groups and
# username==password accounts. Rendering all of them produced a ~50MB response
# that locked up the browser; the card now shows a capped preview and defers the
# full set to the existing download endpoints.

def _seed_many(n_shared=300, n_userpass=300):
    """A customer whose scope has n_shared shared-password groups (2 accounts
    each) and n_userpass accounts whose password equals their username."""
    cust = Customers(name="Bulk Corp")
    db.session.add(cust)
    db.session.commit()
    hf = Hashfiles(name="bulk_dump", customer_id=cust.id, owner_id=1, runtime=1)
    db.session.add(hf)
    db.session.commit()
    for i in range(n_shared):
        h = _hash(f"share{i}", f"Shared{i}!", True)
        db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id, username=f"u{i}a"))
        db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id, username=f"u{i}b"))
    for i in range(n_userpass):
        h = _hash(f"same{i}", f"selfuser{i}", True)
        db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id, username=f"selfuser{i}"))
    db.session.commit()
    return cust.id, hf.id


def test_shared_and_userpass_cards_cap_rendered_rows(app, client):
    """Only SHARED_PREVIEW_LIMIT rows reach the HTML, however many groups exist."""
    from hashview.analytics.routes import PREVIEW_LIMIT

    user = _admin()
    _login(client, user)
    customer_id, _hf = _seed_many()
    resp = client.get(f"/analytics?customer_id={customer_id}")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)

    # one <form> per rendered shared-password group
    assert html.count('action="/analytics/download/shared"') == PREVIEW_LIMIT
    # one <tr> per rendered username==password account
    assert html.count('class="userpass-row"') == PREVIEW_LIMIT


def test_capped_cards_report_the_full_totals(app, client):
    """The capped cards still tell the operator the true totals, so the numbers
    stay trustworthy and match what the download endpoints return."""
    user = _admin()
    _login(client, user)
    customer_id, _hf = _seed_many()
    html = client.get(f"/analytics?customer_id={customer_id}").get_data(as_text=True)
    assert "300 groups" in html          # all shared groups counted, not just rendered
    assert "300 accounts" in html        # all username==password accounts counted


def test_analytics_response_stays_small_on_bulk_data(app, client):
    """Regression guard on the hang itself: the rendered page must stay far
    below the multi-megabyte payload that locked up the browser."""
    user = _admin()
    _login(client, user)
    customer_id, _hf = _seed_many(n_shared=1500, n_userpass=1500)
    resp = client.get(f"/analytics?customer_id={customer_id}")
    assert resp.status_code == 200
    assert len(resp.data) < 1_000_000, f"analytics page is {len(resp.data)} bytes"


def test_shared_groups_need_two_distinct_named_accounts(app, client):
    """A hash that appears in several hashfiles is still ONE account: it must not
    register as a shared password, and rows with no username can't form a group.

    This is the miscount that made every plaintext in a real dataset look
    'shared' -- the group size counted join rows, not distinct usernames.
    """
    user = _admin()
    _login(client, user)
    cust = Customers(name="Dup Corp")
    db.session.add(cust)
    db.session.commit()
    hf1 = Hashfiles(name="f1", customer_id=cust.id, owner_id=1, runtime=1)
    hf2 = Hashfiles(name="f2", customer_id=cust.id, owner_id=1, runtime=1)
    db.session.add_all([hf1, hf2])
    db.session.commit()

    # same account, same hash, present in both hashfiles -> not shared
    dup = _hash("dup", "DupPass1", True)
    db.session.add(HashfileHashes(hash_id=dup.id, hashfile_id=hf1.id, username="dave"))
    db.session.add(HashfileHashes(hash_id=dup.id, hashfile_id=hf2.id, username="dave"))
    # two rows with no username at all -> not shared
    anon = _hash("anon", "AnonPass1", True)
    db.session.add(HashfileHashes(hash_id=anon.id, hashfile_id=hf1.id, username=None))
    db.session.add(HashfileHashes(hash_id=anon.id, hashfile_id=hf2.id, username=None))
    # genuinely shared by two different people -> counted
    for ct, uname in (("realA", "erin"), ("realB", "frank")):
        h = _hash(ct, "RealShared1", True)
        db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf1.id, username=uname))
    db.session.commit()

    html = client.get(f"/analytics?customer_id={cust.id}").get_data(as_text=True)
    assert "1 groups" in html
    # Assert against the shared card's own POST forms -- the plaintexts also
    # appear in Top Passwords, which is a different (and correct) figure.
    assert 'name="plaintext" value="RealShared1"' in html
    assert 'name="plaintext" value="DupPass1"' not in html
    assert 'name="plaintext" value="AnonPass1"' not in html


# ---------------------------------------------------------------------------
# account unit, not join rows (#385)
# ---------------------------------------------------------------------------


def _ctx(client, qs=""):
    """GET /analytics and return the context the template received."""
    from flask import template_rendered

    captured = {}

    def record(sender, template, context, **extra):
        if "total_cracked" in context:
            captured.update(context)

    template_rendered.connect(record)
    try:
        resp = client.get("/analytics" + qs)
    finally:
        template_rendered.disconnect(record)
    assert resp.status_code == 200
    return captured


def _customer_with_hashfiles(admin, name, n_files):
    cust = Customers(name=name)
    db.session.add(cust)
    db.session.commit()
    files = []
    for i in range(n_files):
        hf = Hashfiles(name=f"{name}-{i}", customer_id=cust.id, owner_id=admin.id)
        db.session.add(hf)
        files.append(hf)
    db.session.commit()
    return cust, files


def test_one_account_in_two_hashfiles_is_not_password_reuse(app, client):
    """The regression the issue was filed for.

    One account whose hash sits in two hashfiles used to be counted twice, so it
    "shared" a password with its own duplicate row and the donut read 100%
    reused on a scope where every password is distinct.
    """
    admin = _admin()
    _login(client, admin)
    cust, (hf_a, hf_b) = _customer_with_hashfiles(admin, "TwoFiles", 2)
    for name, pw in (("alice", "Alpha1"), ("bob", "Bravo2")):
        h = _hash(f"ct-{name}", pw, True)
        db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf_a.id, username=name))
        db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf_b.id, username=name))
    db.session.commit()

    ctx = _ctx(client, f"?customer_id={cust.id}")
    assert ctx["total_cracked"] == 2, "two accounts, not four join rows"
    assert ctx["reused_pct"] == 0.0
    assert ctx["unique_pct"] == 100.0
    assert ctx["top_reuse_count"] == 1
    assert [p["n"] for p in ctx["top_passwords"]] == [1, 1]


def test_duplicate_rows_in_one_hashfile_are_counted_once(app, client):
    """hashfile_hashes has no unique constraint on (hashfile, hash, username).

    Repeated lines in a source file therefore produce identical rows -- 89,475
    such groups on the instance this was measured against -- which inflated a
    single-hashfile scope too. Selecting one hashfile was not a workaround.
    """
    admin = _admin()
    _login(client, admin)
    cust, (hf,) = _customer_with_hashfiles(admin, "Dupes", 1)
    h = _hash("ct-dup", "Solo1", True)
    for _ in range(3):
        db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id, username="carol"))
    db.session.commit()

    ctx = _ctx(client, f"?hashfile_id={hf.id}")
    assert ctx["total_cracked"] == 1
    assert ctx["reused_pct"] == 0.0
    assert ctx["top_reuse_count"] == 1


def test_genuine_cross_account_reuse_is_still_reported(app, client):
    """The fix must not become a per-hash count.

    Imports dedupe hashes globally on (hash_type, sub_ciphertext), so two
    accounts with the same password share ONE hashes row. Deduping the corpus on
    Hashes.id -- the fix the issue suggested -- would make that invisible and
    report 0% reuse no matter how widely a password is shared.
    """
    admin = _admin()
    _login(client, admin)
    cust, (hf,) = _customer_with_hashfiles(admin, "RealReuse", 1)
    shared = _hash("ct-shared", "Summer2025", True)
    for name in ("dave", "erin", "frank"):
        db.session.add(HashfileHashes(hash_id=shared.id, hashfile_id=hf.id, username=name))
    solo = _hash("ct-solo", "Unique99", True)
    db.session.add(HashfileHashes(hash_id=solo.id, hashfile_id=hf.id, username="gina"))
    db.session.commit()

    ctx = _ctx(client, f"?hashfile_id={hf.id}")
    assert ctx["total_cracked"] == 4                 # 4 accounts, 2 hashes
    assert ctx["top_reuse_count"] == 3               # not 1
    assert ctx["reused_pct"] == 75.0                 # 3 of 4 accounts share
    assert ctx["unique_pct"] == 25.0


def test_password_property_charts_stay_weighted_by_account(app, client):
    """Length/mask/charset are per account, so a widely shared password counts
    once per account holding it -- otherwise a password used by a thousand
    people would weigh the same as one used by nobody else."""
    admin = _admin()
    _login(client, admin)
    cust, (hf,) = _customer_with_hashfiles(admin, "Weighted", 1)
    shared = _hash("ct-w", "aaaaaa", True)           # length 6, one class
    for name in ("h1", "h2", "h3"):
        db.session.add(HashfileHashes(hash_id=shared.id, hashfile_id=hf.id, username=name))
    db.session.commit()

    ctx = _ctx(client, f"?hashfile_id={hf.id}")
    assert ctx["total_cracked"] == 3
    # length_dist is [{'len': n, 'n': count}] -- the six-character password must
    # weigh 3, one per account, not 1 (per hash) and not 3-with-duplicates.
    lengths = {row["len"]: row["n"] for row in ctx["length_dist"]}
    assert lengths == {6: 3}, lengths
    assert ctx["masks"][0]["n"] == 3


def test_accounts_tile_and_cracked_corpus_agree(app, client):
    """The page used to quote two different "cracked" numbers -- a join-row
    count in the ACCOUNTS donut and another in the chart denominators."""
    admin = _admin()
    _login(client, admin)
    cust, (hf_a, hf_b) = _customer_with_hashfiles(admin, "Agree", 2)
    h1 = _hash("ct-1", "One11", True)
    h2 = _hash("ct-2", None, False)
    db.session.add(HashfileHashes(hash_id=h1.id, hashfile_id=hf_a.id, username="ida"))
    db.session.add(HashfileHashes(hash_id=h1.id, hashfile_id=hf_b.id, username="ida"))
    db.session.add(HashfileHashes(hash_id=h2.id, hashfile_id=hf_a.id, username="jack"))
    db.session.commit()

    ctx = _ctx(client, f"?customer_id={cust.id}")
    assert ctx["accounts_cracked"] == ctx["total_cracked"] == 1
    assert ctx["accounts"] == 2                      # ida + jack, not 3 join rows


def test_rows_without_a_username_count_once_per_hash(app, client):
    """hash_only imports carry no usernames, so those rows have no account
    identity -- they must still contribute one entry per hash rather than
    vanishing (COUNT(DISTINCT a, b) would drop them) or inflating."""
    admin = _admin()
    _login(client, admin)
    cust, (hf_a, hf_b) = _customer_with_hashfiles(admin, "NoNames", 2)
    h = _hash("ct-anon", "Anon1", True)
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf_a.id, username=None))
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf_b.id, username=None))
    db.session.commit()

    ctx = _ctx(client, f"?customer_id={cust.id}")
    assert ctx["total_cracked"] == 1
    assert ctx["accounts"] == 1
    assert ctx["reused_pct"] == 0.0
