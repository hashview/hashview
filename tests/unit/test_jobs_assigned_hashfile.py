"""Characterization tests for the hashfile-upload block of
``jobs_assigned_hashfile`` (POST /jobs/<id>/assigned_hashfile/).

Focus: the pasted-hashes happy path (write temp file -> validate -> import ->
``finally:`` removes the temp file), the AJAX JSON 400 error branches, the
existing-hashfile assignment path, and the running-job guard. All assertions
pin ACTUAL behavior against the in-memory app; app source is never modified.
"""

import os
import re

import pytest
from sqlalchemy import event

from hashview.models import Hashes, HashfileHashes, Hashfiles, Jobs, db
from tests.unit.helpers import login, make_admin, make_customer

# A valid hash_only line for hash_type '1000' (NTLM): 32 hex characters.
VALID_NTLM = "8846f7eaee8fb117ad06bdd830b7586c"
AJAX = {"X-Requested-With": "fetch"}

# The real form renders five Hash-Type SelectFields; only the one matching the
# chosen file_type carries a value, but the browser submits all of them. Each
# non-active SelectField must receive its empty-string choice ('') or WTForms
# rejects the POST with "Not a valid choice." Mirror that here.
EMPTY_SUBTYPES = {
    "shadow_hash_type": "",
    "pwdump_hash_type": "",
    "netntlm_hash_type": "",
    "kerberos_hash_type": "",
}


def _paste_data(name, hashes=VALID_NTLM, hash_type="1000", file_type="hash_only",
                 custom_hash_type=None):
    data = {
        "name": name,
        "file_type": file_type,
        "hash_type": hash_type,
        "hashfilehashes": hashes,
        **EMPTY_SUBTYPES,
    }
    if custom_hash_type is not None:
        data["custom_hash_type"] = str(custom_hash_type)
    return data


def _job(owner, customer, status="Ready", name="j1"):
    job = Jobs(name=name, status=status, owner_id=owner.id,
               customer_id=customer.id)
    db.session.add(job)
    db.session.commit()
    return job


def _tmp_dir(app):
    return os.path.join(app.root_path, "control", "tmp")


@pytest.fixture
def tmp_snapshot(app):
    """Yield the control/tmp dir and clean up any NEW files left behind after
    the test (mirrors the _clean_backups pattern in test_db_backup.py)."""
    tmp_dir = _tmp_dir(app)

    def snap():
        return set(os.listdir(tmp_dir)) if os.path.isdir(tmp_dir) else set()

    before = snap()
    yield tmp_dir, before
    for n in snap() - before:
        try:
            os.remove(os.path.join(tmp_dir, n))
        except OSError:
            pass


def _new_files(tmp_dir, before):
    after = set(os.listdir(tmp_dir)) if os.path.isdir(tmp_dir) else set()
    return after - before


def test_paste_hashes_happy_path_imports_and_cleans_tmp(app, client, tmp_snapshot):
    tmp_dir, before = tmp_snapshot
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    job = _job(admin, cust)

    resp = client.post(
        f"/jobs/{job.id}/assigned_hashfile/",
        data=_paste_data("PastedHF"),
        headers=AJAX,
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["status"] == "ok"
    assert "imported" in body["msg"]

    hf = Hashfiles.query.filter_by(name="PastedHF").first()
    assert hf is not None
    assert HashfileHashes.query.filter_by(hashfile_id=hf.id).count() >= 1
    assert Jobs.query.get(job.id).hashfile_id == hf.id

    # The finally: removes the random-hex temp file on success.
    assert _new_files(tmp_dir, before) == set()


def test_paste_hashes_invalid_hash_ajax_returns_400_and_cleans_tmp(app, client, tmp_snapshot):
    tmp_dir, before = tmp_snapshot
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    job = _job(admin, cust)

    # hash_type '1000' has a curated rule requiring 32 hex chars -> rejected.
    resp = client.post(
        f"/jobs/{job.id}/assigned_hashfile/",
        data=_paste_data("BadHF", hashes="not-a-hash"),
        headers=AJAX,
    )
    assert resp.status_code == 400
    body = resp.get_json()
    assert body["status"] == "error"

    # No hashfile created, job unchanged.
    assert Hashfiles.query.filter_by(name="BadHF").first() is None
    assert Jobs.query.get(job.id).hashfile_id is None

    # finally: runs on the validation-error return path too.
    assert _new_files(tmp_dir, before) == set()


def test_paste_hashes_missing_name_ajax_400(app, client, tmp_snapshot):
    tmp_dir, before = tmp_snapshot
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    job = _job(admin, cust)

    resp = client.post(
        f"/jobs/{job.id}/assigned_hashfile/",
        data=_paste_data(""),
        headers=AJAX,
    )
    assert resp.status_code == 400
    body = resp.get_json()
    assert body["status"] == "error"
    assert "must assign a name" in body["msg"]

    # This branch returns BEFORE any temp file is written.
    assert _new_files(tmp_dir, before) == set()


def test_validation_failed_ajax_returns_errors_400(app, client):
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    job = _job(admin, cust)

    # Omit file_type (DataRequired fails) and provide no hashfile/hashes.
    resp = client.post(
        f"/jobs/{job.id}/assigned_hashfile/",
        data={"name": "x"},
        headers=AJAX,
    )
    assert resp.status_code == 400
    body = resp.get_json()
    assert body["status"] == "error"


def test_assign_existing_hashfile_id_redirects(app, client):
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    job = _job(admin, cust)
    hf = Hashfiles(name="existing", customer_id=cust.id, owner_id=admin.id)
    db.session.add(hf)
    db.session.commit()

    resp = client.post(
        f"/jobs/{job.id}/assigned_hashfile/",
        data={"hashfile_id": str(hf.id)},
        follow_redirects=False,
    )
    assert resp.status_code in (301, 302)
    assert Jobs.query.get(job.id).hashfile_id == hf.id


def test_running_job_cannot_edit(app, client, tmp_snapshot):
    tmp_dir, before = tmp_snapshot
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    job = _job(admin, cust, status="Running")

    resp = client.post(
        f"/jobs/{job.id}/assigned_hashfile/",
        data=_paste_data("ShouldNotImport"),
        headers=AJAX,
        follow_redirects=False,
    )
    assert resp.status_code in (301, 302)
    assert Hashfiles.query.filter_by(name="ShouldNotImport").first() is None
    assert _new_files(tmp_dir, before) == set()


def test_page_renders_the_import_progress_modal(app, client):
    """The upload page ships the import progress indicator from issue #176.

    #176 was delivered as a client-side modal (the ``hf-import-modal``
    dialog in jobs_assigned_hashfiles.html.j2), not a persisted model
    field, so this markup is the whole feature — nothing server-side
    records import progress. Guard the three pieces the upload JS drives
    by id so a template refactor can't silently drop the indicator.

    Note this only covers imports that finish inside the upload request.
    Reporting on an import that outlives the response needs a persisted
    status column, tracked in #364.
    """
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    job = _job(admin, cust)

    resp = client.get(f"/jobs/{job.id}/assigned_hashfile/")

    assert resp.status_code == 200
    body = resp.data
    assert b'id="hf-import-modal"' in body
    assert b'id="hf-step-upload"' in body
    assert b'id="hf-step-import"' in body


def test_custom_hash_type_hash_only_imports_with_typed_mode(app, client, tmp_snapshot):
    """A hash_only upload with hash_type='custom' + custom_hash_type=31337
    imports successfully and stores the typed mode number, never the literal
    string 'custom' (#447)."""
    tmp_dir, before = tmp_snapshot
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    job = _job(admin, cust)

    resp = client.post(
        f"/jobs/{job.id}/assigned_hashfile/",
        data=_paste_data("CustomModeHF", hashes="deadbeef", hash_type="custom",
                          custom_hash_type=31337),
        headers=AJAX,
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["status"] == "ok"

    hf = Hashfiles.query.filter_by(name="CustomModeHF").first()
    assert hf is not None
    hfh = HashfileHashes.query.filter_by(hashfile_id=hf.id).first()
    assert hfh is not None
    stored_hash = Hashes.query.get(hfh.hash_id)
    assert stored_hash is not None
    assert stored_hash.hash_type == 31337
    assert stored_hash.hash_type != "custom"


def test_custom_hash_type_user_hash_imports_with_typed_mode(app, client, tmp_snapshot):
    tmp_dir, before = tmp_snapshot
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    job = _job(admin, cust)

    resp = client.post(
        f"/jobs/{job.id}/assigned_hashfile/",
        data=_paste_data("CustomModeUserHashHF", hashes="someuser:deadbeef",
                          hash_type="custom", file_type="user_hash",
                          custom_hash_type=31337),
        headers=AJAX,
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["status"] == "ok"

    hf = Hashfiles.query.filter_by(name="CustomModeUserHashHF").first()
    assert hf is not None
    hfh = HashfileHashes.query.filter_by(hashfile_id=hf.id).first()
    assert hfh is not None
    stored_hash = Hashes.query.get(hfh.hash_id)
    assert stored_hash is not None
    assert stored_hash.hash_type == 31337


def test_custom_hash_type_missing_number_fails_validation(app, client, tmp_snapshot):
    """hash_type='custom' without a custom_hash_type fails clean-message
    validation, and (for the AJAX path) that message reaches the JSON error
    response the import modal reads."""
    tmp_dir, before = tmp_snapshot
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    job = _job(admin, cust)

    resp = client.post(
        f"/jobs/{job.id}/assigned_hashfile/",
        data=_paste_data("NoCustomModeHF", hashes="deadbeef", hash_type="custom"),
        headers=AJAX,
    )
    assert resp.status_code == 400
    body = resp.get_json()
    assert body["status"] == "error"
    assert "Enter a hashcat mode number" in body["msg"]

    assert Hashfiles.query.filter_by(name="NoCustomModeHF").first() is None
    assert _new_files(tmp_dir, before) == set()


def test_hashfile_picker_n_plus_one_fixed(app, client):
    """Verify that the GET hashfile-picker route (jobs_assigned_hashfile) uses
    ONE grouped query to fetch hashfile stats (total, cracked, mode) instead of
    one query per hashfile. Issue #422, defect 2.

    Seeds multiple hashfiles with varying cracked/total counts, fetches the
    hashfile-picker page, and inspects SQL statements to prove the aggregate
    query runs once per set of hashfiles, grouped by hashfile_id, not once per
    hashfile in the loop.
    """
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    job = _job(admin, cust)

    # Seed 3 hashfiles with varying stats
    hf1 = Hashfiles(name="hf1", customer_id=cust.id, owner_id=admin.id)
    hf2 = Hashfiles(name="hf2", customer_id=cust.id, owner_id=admin.id)
    hf3 = Hashfiles(name="hf3", customer_id=cust.id, owner_id=admin.id)
    db.session.add_all([hf1, hf2, hf3])
    db.session.commit()

    # Populate hf1 with 10 hashes, 3 cracked
    for i in range(10):
        h = Hashes(
            sub_ciphertext=f"sub_{hf1.id}_{i}",
            ciphertext=f"hash_{hf1.id}_{i}",
            cracked=(i < 3),
            hash_type=1000,
        )
        db.session.add(h)
        db.session.flush()
        db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf1.id, username=f"user{i}"))

    # Populate hf2 with 5 hashes, all cracked
    for i in range(5):
        h = Hashes(
            sub_ciphertext=f"sub_{hf2.id}_{i}",
            ciphertext=f"hash_{hf2.id}_{i}",
            cracked=True,
            hash_type=100,
        )
        db.session.add(h)
        db.session.flush()
        db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf2.id, username=f"user{i}"))

    # Populate hf3 with 8 hashes, none cracked
    for i in range(8):
        h = Hashes(
            sub_ciphertext=f"sub_{hf3.id}_{i}",
            ciphertext=f"hash_{hf3.id}_{i}",
            cracked=False,
            hash_type=500,
        )
        db.session.add(h)
        db.session.flush()
        db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf3.id, username=f"user{i}"))

    db.session.commit()

    # Capture all SQL statements during the GET request
    statements = []

    def record(conn, cursor, statement, parameters, context, executemany):
        statements.append(" ".join(statement.split()).lower())

    engine = db.engine
    event.listen(engine, "before_cursor_execute", record)
    try:
        resp = client.get(f"/jobs/{job.id}/assigned_hashfile/")
    finally:
        event.remove(engine, "before_cursor_execute", record)

    # Verify the response is successful
    assert resp.status_code == 200
    body = resp.data

    # The route should render hashfile stats in the template.
    # Check that the stats appear in the page (confirms data is populated).
    assert b"hf1" in body or b"hf2" in body or b"hf3" in body

    # Find the grouped query that fetches hashfile stats.
    # It should:
    # 1. Join HashfileHashes and Hashes
    # 2. Filter by hashfile_id IN (list of ids)
    # 3. Group by HashfileHashes.hashfile_id
    # 4. Select count, sum (for cracked), and min (for mode)
    grouped_agg_queries = [
        s for s in statements
        if s.startswith("select")
        and "from hashfile_hashes" in s
        and "join hashes" in s
        and "group by" in s
        and "count(" in s
    ]

    # There should be exactly ONE such grouped query (not one per hashfile).
    assert len(grouped_agg_queries) == 1, (
        f"Expected exactly 1 grouped aggregate query, got {len(grouped_agg_queries)}. "
        f"This suggests the N+1 pattern (one query per hashfile) is still present. "
        f"Queries found:\n" + "\n".join(grouped_agg_queries)
    )

    # Verify the query shape: it should select the hashfile_id, so we can
    # correlate results back.
    agg_query = grouped_agg_queries[0]
    assert "hashfile_id" in agg_query, (
        f"Grouped query should select hashfile_id for result mapping. "
        f"Query: {agg_query}"
    )


def test_combine_two_hashfiles_creates_combined_file(app, client):
    """POST with two hashfile_id values creates a combined file, assigns it,
    and redirects to /jobs/<id>/notifications."""
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    job = _job(admin, cust)

    # Create two source hashfiles with different hashes
    hf1 = Hashfiles(name="source1", customer_id=cust.id, owner_id=admin.id)
    hf2 = Hashfiles(name="source2", customer_id=cust.id, owner_id=admin.id)
    db.session.add_all([hf1, hf2])
    db.session.commit()

    # Add hashes to both
    h1 = Hashes(
        sub_ciphertext="sub1",
        ciphertext="hash1",
        cracked=False,
        hash_type=1000,
    )
    h2 = Hashes(
        sub_ciphertext="sub2",
        ciphertext="hash2",
        cracked=False,
        hash_type=1000,
    )
    db.session.add_all([h1, h2])
    db.session.flush()
    db.session.add(HashfileHashes(hash_id=h1.id, hashfile_id=hf1.id, username="user1"))
    db.session.add(HashfileHashes(hash_id=h2.id, hashfile_id=hf2.id, username="user2"))
    db.session.commit()

    # Count existing hashfiles
    existing_count = Hashfiles.query.count()

    # POST with two hashfile_id values
    resp = client.post(
        f"/jobs/{job.id}/assigned_hashfile/",
        data={"hashfile_id": [str(hf1.id), str(hf2.id)]},
        follow_redirects=False,
    )

    # Should redirect
    assert resp.status_code in (301, 302)
    assert "/notifications" in resp.location

    # Should have created a new hashfile
    assert Hashfiles.query.count() == existing_count + 1

    # Job should reference the new hashfile
    job_after = Jobs.query.get(job.id)
    assert job_after.hashfile_id is not None
    assert job_after.hashfile_id != hf1.id
    assert job_after.hashfile_id != hf2.id

    # The combined file should have a name like combined-YYYYMMDD-HHMMSS
    combined = Hashfiles.query.get(job_after.hashfile_id)
    assert combined is not None
    assert combined.name.startswith("combined-")
    assert re.match(r"combined-\d{8}-\d{6}$", combined.name)

    # The combined file should have exactly the union of source hashes
    combined_hash_ids = {
        r.hash_id
        for r in HashfileHashes.query.filter_by(hashfile_id=combined.id).all()
    }
    assert combined_hash_ids == {h1.id, h2.id}


def test_combine_one_hashfile_assigns_existing(app, client):
    """POST with one hashfile_id assigns that exact id, creates no new
    Hashfiles row, and redirects to /jobs/<id>/notifications."""
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    job = _job(admin, cust)

    hf = Hashfiles(name="single", customer_id=cust.id, owner_id=admin.id)
    db.session.add(hf)
    db.session.commit()

    existing_count = Hashfiles.query.count()

    resp = client.post(
        f"/jobs/{job.id}/assigned_hashfile/",
        data={"hashfile_id": str(hf.id)},
        follow_redirects=False,
    )

    # Should redirect to notifications
    assert resp.status_code in (301, 302)
    assert "/notifications" in resp.location

    # Should NOT create a new Hashfiles row
    assert Hashfiles.query.count() == existing_count

    # Job should reference the original file
    job_after = Jobs.query.get(job.id)
    assert job_after.hashfile_id == hf.id


def test_combine_differing_hash_types_rejected(app, client):
    """POST with two hashfiles of different hash types is rejected with no
    new Hashfiles row."""
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    job = _job(admin, cust)

    # Create two source hashfiles with different hash types
    hf1 = Hashfiles(name="source1", customer_id=cust.id, owner_id=admin.id)
    hf2 = Hashfiles(name="source2", customer_id=cust.id, owner_id=admin.id)
    db.session.add_all([hf1, hf2])
    db.session.commit()

    # Add hash type 1000 (NTLM) to hf1
    h1 = Hashes(
        sub_ciphertext="sub1",
        ciphertext="hash1",
        cracked=False,
        hash_type=1000,
    )
    # Add hash type 100 (MD5) to hf2
    h2 = Hashes(
        sub_ciphertext="sub2",
        ciphertext="hash2",
        cracked=False,
        hash_type=100,
    )
    db.session.add_all([h1, h2])
    db.session.flush()
    db.session.add(HashfileHashes(hash_id=h1.id, hashfile_id=hf1.id))
    db.session.add(HashfileHashes(hash_id=h2.id, hashfile_id=hf2.id))
    db.session.commit()

    existing_count = Hashfiles.query.count()
    original_job_hf = job.hashfile_id

    resp = client.post(
        f"/jobs/{job.id}/assigned_hashfile/",
        data={"hashfile_id": [str(hf1.id), str(hf2.id)]},
        follow_redirects=False,
    )

    # Should redirect BACK to the picker, not on to /notifications (the
    # success path is also a 302, so the status code alone proves nothing).
    assert resp.status_code in (301, 302)
    assert f"/jobs/{job.id}/assigned_hashfile/" in resp.location
    assert "/notifications" not in resp.location

    # Should NOT create a new Hashfiles row
    assert Hashfiles.query.count() == existing_count

    # Job's hashfile should be unchanged
    job_after = Jobs.query.get(job.id)
    assert job_after.hashfile_id == original_job_hf


def test_combine_other_customer_hashfile_rejected(app, client):
    """POST with a hashfile belonging to another customer is rejected
    (D3 customer-ownership check)."""
    admin = make_admin()
    login(client, admin)
    cust1 = make_customer()
    cust2 = make_customer()
    job = _job(admin, cust1)

    # Create a hashfile for a different customer
    hf_other = Hashfiles(name="other_customer", customer_id=cust2.id, owner_id=admin.id)
    db.session.add(hf_other)
    db.session.commit()

    existing_count = Hashfiles.query.count()
    original_job_hf = job.hashfile_id

    resp = client.post(
        f"/jobs/{job.id}/assigned_hashfile/",
        data={"hashfile_id": str(hf_other.id)},
        follow_redirects=False,
    )

    # Should redirect BACK to the picker, not on to /notifications (the
    # success path is also a 302, so the status code alone proves nothing).
    assert resp.status_code in (301, 302)
    assert f"/jobs/{job.id}/assigned_hashfile/" in resp.location
    assert "/notifications" not in resp.location

    # Should NOT create a new Hashfiles row
    assert Hashfiles.query.count() == existing_count

    # Job's hashfile should be unchanged
    job_after = Jobs.query.get(job.id)
    assert job_after.hashfile_id == original_job_hf


def test_existing_form_with_no_selection_flashes_and_redirects(app, client):
    """POST from existing form with no selection flashes error and redirects
    back (D5 empty selection behavior)."""
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    job = _job(admin, cust)

    # POST with hf_source=existing (form marker) but no checkboxes selected
    resp = client.post(
        f"/jobs/{job.id}/assigned_hashfile/",
        data={"hf_source": "existing"},
        follow_redirects=False,
    )

    # Should redirect (302)
    assert resp.status_code == 302

    # Should redirect back to the assigned_hashfile page
    assert f"/jobs/{job.id}/assigned_hashfile/" in resp.location

    # Following the redirect should show the flash message
    resp_redirect = client.get(resp.location)
    assert b'Select at least one hashfile.' in resp_redirect.data

    # Job's hashfile should be unchanged
    job_after = Jobs.query.get(job.id)
    assert job_after.hashfile_id is None


def test_existing_form_with_invalid_hashfile_id_rejects(app, client):
    """POST from existing form with empty string hashfile_id flashes error
    and redirects (validates int parsing)."""
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    job = _job(admin, cust)

    # POST with hf_source=existing and empty string hashfile_id (invalid)
    resp = client.post(
        f"/jobs/{job.id}/assigned_hashfile/",
        data={"hf_source": "existing", "hashfile_id": ""},
        follow_redirects=False,
    )

    # Should redirect (302)
    assert resp.status_code == 302

    # Following the redirect should show the flash message
    resp_redirect = client.get(resp.location)
    assert b'Invalid hashfile selection.' in resp_redirect.data

    # Job's hashfile should be unchanged
    job_after = Jobs.query.get(job.id)
    assert job_after.hashfile_id is None


def test_assigned_hashfile_page_renders_checkboxes(app, client):
    """GET /jobs/<id>/assigned_hashfile/ renders checkbox inputs (not
    radio) for the hashfile picker."""
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    job = _job(admin, cust)

    # Create a hashfile so the table is rendered
    hf = Hashfiles(name="test", customer_id=cust.id, owner_id=admin.id)
    db.session.add(hf)
    db.session.commit()

    resp = client.get(f"/jobs/{job.id}/assigned_hashfile/")

    assert resp.status_code == 200
    body = resp.data

    # Should have checkboxes
    assert b'type="checkbox" name="hashfile_id"' in body

    # Should NOT have radio buttons
    assert b'type="radio" name="hashfile_id"' not in body

    # Should have the form marker (hf_source) so the route can identify
    # the existing form submission (D5 empty-selection path depends on this)
    assert b'name="hf_source"' in body
    assert b'value="existing"' in body


HASHFILE_CHECKBOX_RE = re.compile(r'<input[^>]*name="hashfile_id"[^>]*>')


def test_picker_renders_no_pre_checked_hashfile(app, client):
    """With a toggle-per-row checkbox, a pre-checked row would turn a single
    click on another file into a silent two-file combine (and, on the edit
    path, combine the current file with the clicked one instead of switching
    to it). Nothing may be checked on load; the job's current hashfile is
    only marked with a non-interactive ``current`` badge."""
    admin = make_admin()
    login(client, admin)
    cust = make_customer()
    job = _job(admin, cust)

    hfs = [Hashfiles(name=f"pick{i}", customer_id=cust.id, owner_id=admin.id)
           for i in range(3)]
    db.session.add_all(hfs)
    db.session.commit()
    # Edit path: the job already uses the middle file.
    job.hashfile_id = hfs[1].id
    db.session.commit()

    resp = client.get(f"/jobs/{job.id}/assigned_hashfile/")
    assert resp.status_code == 200
    html = resp.data.decode()

    inputs = HASHFILE_CHECKBOX_RE.findall(html)
    assert len(inputs) == 3, inputs
    assert all('type="checkbox"' in tag for tag in inputs), inputs
    checked = [tag for tag in inputs if "checked" in tag]
    assert checked == [], f"pre-checked hashfile inputs rendered: {checked}"

    # No row starts out visually selected either, so the look matches the
    # (empty) checkbox state.
    assert 'class="sel-box on"' not in html
    assert 'class="selected"' not in html

    # The current hashfile is still identifiable, via a badge in its name cell.
    assert html.count(">current</span>") == 1
    assert re.search(r"pick1\s*<span class=\"badge dim\"[^>]*>current</span>", html)
    assert not re.search(r"pick0\s*<span class=\"badge", html)
    assert not re.search(r"pick2\s*<span class=\"badge", html)
