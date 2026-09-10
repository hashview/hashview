"""Unit tests for Settings -> Data management: the hashes-table rollup + exports.

The card shows one row per hash_type straight off the `hashes` table, and every
figure in it links to a .txt of exactly the rows it counts:

    type=all   -> ciphertext per line
    type=found -> ciphertext:plaintext (recovered only)
    type=left  -> ciphertext (uncracked only)

Uses the in-memory SQLite app from tests/unit/conftest.py.
"""

from hashview.models import Hashes, HashfileHashes, Hashfiles, Settings, Users, db
from hashview.utils.utils import get_md5_hash


def _admin(admin=True):
    user = Users(first_name="A", last_name="D", email_address=f"{'adm' if admin else 'usr'}@e.com",
                 password="x" * 60, admin=admin, api_key=f"key-{admin}")
    db.session.add(user)
    db.session.commit()
    return user


def _login(client, user):
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True


def _hash(ciphertext, hash_type=1000, plaintext=None):
    row = Hashes(sub_ciphertext=get_md5_hash(ciphertext), ciphertext=ciphertext,
                 hash_type=hash_type, cracked=plaintext is not None, plaintext=plaintext)
    db.session.add(row)
    db.session.commit()
    return row


def _raw(ciphertext, cracked, plaintext, hash_type=1000):
    """A row with an arbitrary cracked/plaintext combination, so a test can tell
    which of the two the export actually filters on."""
    row = Hashes(sub_ciphertext=get_md5_hash(ciphertext), ciphertext=ciphertext,
                 hash_type=hash_type, cracked=cracked, plaintext=plaintext)
    db.session.add(row)
    db.session.commit()
    return row


def _settings_row():
    db.session.add(Settings(retention_period=30, max_runtime_jobs=0, max_runtime_tasks=0))
    db.session.commit()


def _lines(resp):
    return [ln for ln in resp.get_data(as_text=True).split("\n") if ln]


#############################################
# The rollup
#############################################

def test_rollup_groups_by_hash_type_and_sorts_by_size(app):
    from hashview.settings.routes import _hashes_rollup

    for i in range(3):
        _hash(f"ntlm{i}", 1000, plaintext="pw" if i < 2 else None)
    _hash("krb", 13100)

    rows, total, cracked = _hashes_rollup()

    assert total == 4 and cracked == 2
    assert [r["mode"] for r in rows] == ["1000", "13100"]     # biggest first
    assert rows[0] == {"mode": "1000", "name": "NTLM", "total": 3, "cracked": 2, "uncracked": 1}
    assert rows[1]["total"] == 1 and rows[1]["cracked"] == 0 and rows[1]["uncracked"] == 1


def test_rollup_uses_full_mode_names_so_families_stay_distinct(app):
    """The badge-sized names truncate at the first comma, which collapses every
    Kerberos mode to 'Kerberos 5'. A table listing them side by side needs the
    full hashcat description."""
    from hashview.settings.routes import _hashes_rollup

    _hash("tgs", 13100)
    _hash("asrep", 18200)

    names = {r["mode"]: r["name"] for r in _hashes_rollup()[0]}
    assert names["13100"] == "Kerberos 5, etype 23, TGS-REP"
    assert names["18200"] == "Kerberos 5, etype 23, AS-REP"
    assert names["13100"] != names["18200"]


def test_rollup_falls_back_to_the_mode_number_for_unlisted_modes(app):
    """LM (3000) is deliberately absent from the mode tables, and /v1 will accept
    any mode, so an unmapped hash_type must still get a row."""
    from hashview.settings.routes import _hashes_rollup

    _hash("lm", 3000)
    assert _hashes_rollup()[0][0]["name"] == "mode 3000"


def test_rollup_counts_each_hash_once_regardless_of_hashfiles(app):
    """`hashes` holds one row per unique (sub_ciphertext, hash_type); the same
    hash reached through two hashfiles must not double-count."""
    from hashview.settings.routes import _hashes_rollup

    row = _hash("shared", 1000, plaintext="pw")
    for hf_id in (1, 2):
        db.session.add(Hashfiles(id=hf_id, name=f"f{hf_id}", customer_id=1, owner_id=1))
    db.session.commit()
    for hf_id in (1, 2):
        db.session.add(HashfileHashes(hash_id=row.id, hashfile_id=hf_id, username=f"u{hf_id}"))
    db.session.commit()

    rows, total, cracked = _hashes_rollup()
    assert total == 1 and cracked == 1
    assert rows[0]["total"] == 1


def test_rollup_is_empty_on_a_fresh_instance(app):
    from hashview.settings.routes import _hashes_rollup

    assert _hashes_rollup() == ([], 0, 0)


#############################################
# The exports
#############################################

def test_export_all_serves_every_hash_of_that_mode(app, client):
    _login(client, _admin())
    _hash("aaa", 1000, plaintext="pw1")
    _hash("bbb", 1000)
    _hash("ccc", 13100)

    resp = client.get("/settings/hashes/download?mode=1000&type=all")
    assert resp.status_code == 200
    assert sorted(_lines(resp)) == ["aaa", "bbb"]            # cracked and uncracked, no plaintext


def test_export_found_serves_hash_colon_plaintext(app, client):
    _login(client, _admin())
    _hash("aaa", 1000, plaintext="Summer2024!")
    _hash("bbb", 1000)

    resp = client.get("/settings/hashes/download?mode=1000&type=found")
    assert _lines(resp) == ["aaa:Summer2024!"]


def test_export_left_serves_only_uncracked_ciphertexts(app, client):
    _login(client, _admin())
    _hash("aaa", 1000, plaintext="pw")
    _hash("bbb", 1000)

    resp = client.get("/settings/hashes/download?mode=1000&type=left")
    assert _lines(resp) == ["bbb"]


def test_export_partitions_on_the_cracked_flag_not_on_plaintext(app, client):
    """`cracked` is what the Recovered/Unrecovered columns count, so it has to be
    what the exports filter on. An inconsistent row (a plaintext left on an
    uncracked hash, or a cracked hash with none) must follow the flag -- otherwise
    a NULL check alone would look like it was doing the job."""
    _login(client, _admin())
    _raw("aaa", cracked=True, plaintext="pw")
    _raw("bbb", cracked=False, plaintext="stale")     # not recovered, despite the plaintext
    _raw("ccc", cracked=True, plaintext=None)         # recovered, but nothing to print

    assert _lines(client.get("/settings/hashes/download?mode=1000&type=found")) == ["aaa:pw"]
    assert sorted(_lines(client.get("/settings/hashes/download?mode=1000&type=left"))) == ["bbb"]


def test_export_without_a_mode_covers_every_mode(app, client):
    _login(client, _admin())
    _hash("aaa", 1000, plaintext="pw")
    _hash("ccc", 13100, plaintext="pw2")

    assert sorted(_lines(client.get("/settings/hashes/download?type=all"))) == ["aaa", "ccc"]
    assert sorted(_lines(client.get("/settings/hashes/download?type=found"))) == ["aaa:pw", "ccc:pw2"]


def test_export_line_count_matches_the_figure_that_linked_to_it(app, client):
    """The point of the links: the file holds exactly as many lines as the cell."""
    from hashview.settings.routes import _hashes_rollup

    _login(client, _admin())
    for i in range(25):
        _hash(f"h{i:03d}", 1000, plaintext="pw" if i % 5 else None)

    row = _hashes_rollup()[0][0]
    for export_type, expected in (("all", row["total"]), ("found", row["cracked"]),
                                  ("left", row["uncracked"])):
        resp = client.get(f"/settings/hashes/download?mode=1000&type={export_type}")
        assert len(_lines(resp)) == expected, export_type


def test_export_pages_through_every_row_exactly_once(app, client, monkeypatch):
    """Exports are keyset-paged on the primary key (the driver can't do
    server-side cursors), so the batch boundary has to be exercised: a lost or
    repeated cursor advance would duplicate or drop rows."""
    from hashview.settings import routes

    _login(client, _admin())
    monkeypatch.setattr(routes, "_HASH_EXPORT_BATCH", 3)
    expected = [f"h{i:02d}" for i in range(10)]
    for i, ciphertext in enumerate(expected):
        # every third row is uncracked, so a page can also end on a skipped row
        _hash(ciphertext, 1000, plaintext=None if i % 3 == 0 else "pw")

    assert _lines(client.get("/settings/hashes/download?mode=1000&type=all")) == expected
    assert _lines(client.get("/settings/hashes/download?mode=1000&type=found")) == [
        f"{c}:pw" for i, c in enumerate(expected) if i % 3]


def test_export_pages_are_ordered_and_bounded_in_sql(app, client, monkeypatch):
    """Keyset paging is only correct if each page is ORDER BY id LIMIT n -- without
    the ordering, MySQL may return any n matching rows and the cursor then skips
    or repeats whole blocks. SQLite hands back insert order regardless, so this
    invariant can only be pinned on the SQL the route actually emits."""
    from sqlalchemy import event

    from hashview.settings import routes

    _login(client, _admin())
    monkeypatch.setattr(routes, "_HASH_EXPORT_BATCH", 3)
    for i in range(7):
        _hash(f"h{i:02d}", 1000, plaintext="pw")

    statements = []

    def record(conn, cursor, statement, parameters, context, executemany):
        statements.append(" ".join(statement.split()).upper())

    event.listen(db.engine, "before_cursor_execute", record)
    try:
        assert len(_lines(client.get("/settings/hashes/download?mode=1000&type=all"))) == 7
    finally:
        event.remove(db.engine, "before_cursor_execute", record)

    pages = [s for s in statements if s.startswith("SELECT") and " FROM HASHES" in s]
    assert len(pages) >= 3                                   # it really paged
    for statement in pages:
        assert "ORDER BY HASHES.ID" in statement, statement
        assert "LIMIT" in statement, statement


def test_export_stops_cleanly_on_an_exact_multiple_of_the_batch(app, client, monkeypatch):
    """The generator returns early on a short page; a full final page has to fall
    through to the next (empty) one instead of looping forever."""
    from hashview.settings import routes

    _login(client, _admin())
    monkeypatch.setattr(routes, "_HASH_EXPORT_BATCH", 5)
    for i in range(10):
        _hash(f"h{i:02d}", 1000, plaintext="pw")

    assert len(_lines(client.get("/settings/hashes/download?mode=1000&type=all"))) == 10


def test_export_keeps_an_empty_plaintext(app, client):
    """An empty password is a legitimate recovered value -- only a NULL is skipped,
    so the export can't be shorter than the Recovered count."""
    _login(client, _admin())
    _hash("aaa", 1000, plaintext="")

    resp = client.get("/settings/hashes/download?mode=1000&type=found")
    assert resp.get_data(as_text=True) == "aaa:\n"


def test_export_sends_a_named_txt_attachment(app, client):
    _login(client, _admin())
    _hash("aaa", 1000, plaintext="pw")

    resp = client.get("/settings/hashes/download?mode=1000&type=found")
    assert resp.mimetype == "text/plain"
    assert 'filename="hashes_1000_found.txt"' in resp.headers["Content-Disposition"]

    resp = client.get("/settings/hashes/download?type=left")
    assert 'filename="hashes_all_left.txt"' in resp.headers["Content-Disposition"]


def test_export_rejects_a_bad_type_or_mode(app, client):
    _login(client, _admin())
    assert client.get("/settings/hashes/download?type=everything").status_code == 400
    assert client.get("/settings/hashes/download?mode=1000%27&type=all").status_code == 400
    assert client.get("/settings/hashes/download?mode=../../etc/passwd&type=all").status_code == 400


def test_export_rejects_a_mode_that_is_digits_but_not_an_int(app, client):
    """str.isdigit() is a wider set than int() accepts, and the mode reaches both a
    Content-Disposition filename and an Integer column. Anything that slips past the
    guard raises while the body is already streaming, which cannot become a 400: it
    degrades to a bare 500, and a non-latin-1 filename hangs werkzeug's send_header
    outright."""
    _login(client, _admin())
    _hash("aaa", 1000, plaintext="pw")

    # U+00B2 SUPERSCRIPT TWO: isdigit() is True, int() raises ValueError
    assert client.get("/settings/hashes/download?mode=\u00b2&type=all").status_code == 400
    # U+0662 ARABIC-INDIC TWO: isdigit() is True and int() reads it as 2, so without
    # the ASCII check this exported hash_type 2 under a non-latin-1 filename
    assert client.get("/settings/hashes/download?mode=\u0662&type=all").status_code == 400
    # ASCII digits, but past MySQL's signed INT ceiling -- DataError at the driver
    assert client.get("/settings/hashes/download?mode=" + "9" * 25 + "&type=all").status_code == 400
    assert client.get("/settings/hashes/download?mode=2147483648&type=all").status_code == 400

    # a real mode still streams, and mode 0 (MD5) is not mistaken for "no mode"
    assert client.get("/settings/hashes/download?mode=1000&type=all").status_code == 200
    resp = client.get("/settings/hashes/download?mode=0&type=all")
    assert resp.status_code == 200 and _lines(resp) == []
    assert 'filename="hashes_0_all.txt"' in resp.headers["Content-Disposition"]


def test_export_defaults_to_all_when_type_is_omitted(app, client):
    _login(client, _admin())
    _hash("aaa", 1000, plaintext="pw")
    assert _lines(client.get("/settings/hashes/download")) == ["aaa"]


def test_export_is_admin_only(app, client):
    _login(client, _admin(admin=False))
    _hash("aaa", 1000, plaintext="pw")
    assert client.get("/settings/hashes/download?type=found").status_code == 403


def test_export_requires_login(app, client):
    _hash("aaa", 1000, plaintext="pw")
    resp = client.get("/settings/hashes/download?type=found")
    assert resp.status_code in (301, 302, 401)
    assert "aaa" not in resp.get_data(as_text=True)


#############################################
# The rendered card
#############################################

def test_settings_page_renders_the_hashes_table_with_download_links(app, client):
    _login(client, _admin())
    _settings_row()
    for i in range(1200):
        _hash(f"h{i:04d}", 1000, plaintext="pw" if i < 400 else None)
    _hash("krb", 13100)

    html = client.get("/settings").get_data(as_text=True)

    assert "Hashes table" in html
    assert "2 hash types" in html
    assert "1,201 rows" in html                              # commafied, per the UI convention
    assert "Kerberos 5, etype 23, TGS-REP" in html
    # every figure is a link to its own export
    assert 'href="/settings/hashes/download?mode=1000&amp;type=all"' in html
    assert 'href="/settings/hashes/download?mode=1000&amp;type=found"' in html
    assert 'href="/settings/hashes/download?mode=1000&amp;type=left"' in html
    assert 'href="/settings/hashes/download?type=found"' in html   # the summary tile
    assert "1,200" in html and "800" in html                 # total / uncracked for mode 1000
    # The card is rendered in the phosphor amber by rules scoped to these hooks
    # (phosphor-app.css .hv-hashes-card ...), so losing them silently reverts the
    # whole rollup to the default body ink.
    for hook in ("hv-hashes-card", "hv-hash-mode", "hv-hash-name",
                 "hv-hash-found", "hv-hash-left", "hv-kpi-dim", "hv-hashes-meta"):
        assert hook in html, hook


def test_settings_page_renders_zero_counts_as_plain_text(app, client):
    """A zero has nothing to download, so it must not be a link."""
    _login(client, _admin())
    _settings_row()
    _hash("aaa", 13100)

    html = client.get("/settings").get_data(as_text=True)
    assert 'href="/settings/hashes/download?mode=13100&amp;type=all"' in html
    assert 'href="/settings/hashes/download?mode=13100&amp;type=found"' not in html
    # ...but the figure is still rendered, in the muted span the CSS styles, so an
    # empty Recovered cell can't be misread as missing data. Asserting only the
    # absence of the link would pass if the zero branch emitted nothing at all.
    assert '<td class="center num hv-hash-found"><span class=" hv-count-zero">0</span></td>' in html


def test_settings_page_handles_an_empty_hashes_table(app, client):
    _login(client, _admin())
    _settings_row()

    html = client.get("/settings").get_data(as_text=True)
    assert "no hashes imported yet" in html
    assert "0 hash types" in html
