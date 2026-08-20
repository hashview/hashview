"""Characterization tests for the hashfile-upload block of
``jobs_assigned_hashfile`` (POST /jobs/<id>/assigned_hashfile/).

Focus: the pasted-hashes happy path (write temp file -> validate -> import ->
``finally:`` removes the temp file), the AJAX JSON 400 error branches, the
existing-hashfile assignment path, and the running-job guard. All assertions
pin ACTUAL behavior against the in-memory app; app source is never modified.
"""

import os

import pytest

from hashview.models import HashfileHashes, Hashfiles, Jobs, db
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


def _paste_data(name, hashes=VALID_NTLM, hash_type="1000"):
    return {
        "name": name,
        "file_type": "hash_only",
        "hash_type": hash_type,
        "hashfilehashes": hashes,
        **EMPTY_SUBTYPES,
    }


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
