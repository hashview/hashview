"""Tests for server-side source file conversion (pcap + NTDS.dit)."""
import os
import subprocess
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest
from hashview.models import Customers, Hashfiles, HashfileConversions, Users, db


def _make_owner():
    u = Users(first_name="T", last_name="U", email_address="t@example.com",
               password="x" * 60, admin=True)
    db.session.add(u)
    db.session.commit()
    return u


def _make_hashfile(owner_id):
    hf = Hashfiles(name="capture.pcapng", customer_id=1, owner_id=owner_id)
    db.session.add(hf)
    db.session.commit()
    return hf


def test_hashfile_conversions_model_creates_and_queries(app):
    """HashfileConversions record can be saved and loaded with all fields."""
    owner = _make_owner()
    hf = _make_hashfile(owner.id)

    conv = HashfileConversions(
        hashfile_id=hf.id,
        source_type="wpa_pcap",
        status="pending",
        source_path="/tmp/capture.pcapng",
        system_path=None,
    )
    db.session.add(conv)
    db.session.commit()

    loaded = HashfileConversions.query.filter_by(hashfile_id=hf.id).first()
    assert loaded is not None
    assert loaded.source_type == "wpa_pcap"
    assert loaded.status == "pending"
    assert loaded.source_path == "/tmp/capture.pcapng"
    assert loaded.system_path is None
    assert loaded.conversion_error is None


def test_hashfile_backref_gives_conversion(app):
    """hashfile.conversion returns the HashfileConversions record or None."""
    owner = _make_owner()
    hf = _make_hashfile(owner.id)

    assert hf.conversion is None  # no conversion record yet

    conv = HashfileConversions(
        hashfile_id=hf.id,
        source_type="wpa_pcap",
        status="pending",
        source_path="/tmp/cap.pcapng",
    )
    db.session.add(conv)
    db.session.commit()
    db.session.refresh(hf)

    assert hf.conversion is not None
    assert hf.conversion.status == "pending"


def _login(client, user):
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True


def _make_job(app, owner_id, customer_id):
    from hashview.models import Jobs
    job = Jobs(
        name="test-job",
        status="Incomplete",
        customer_id=customer_id,
        owner_id=owner_id,
    )
    db.session.add(job)
    db.session.commit()
    return job


def _make_customer(name="Acme"):
    from hashview.models import Customers, Settings
    cust = Customers(name=name)
    db.session.add(cust)
    if not Settings.query.first():
        from hashview.models import Settings
        db.session.add(Settings(retention_period=30, max_runtime_jobs=0, max_runtime_tasks=0))
    db.session.commit()
    return cust


def test_scheduler_resets_stuck_converting_records(app, tmp_path, monkeypatch):
    """Records stuck in 'converting' for >10 min are reset to 'pending'."""
    monkeypatch.chdir(tmp_path)
    os.makedirs(tmp_path / 'hashview' / 'control' / 'tmp')

    owner = _make_owner()
    hf = _make_hashfile(owner.id)

    stuck_time = datetime.utcnow() - timedelta(minutes=15)
    conv = HashfileConversions(
        hashfile_id=hf.id,
        source_type="wpa_pcap",
        status="converting",
        source_path="/tmp/cap.pcapng",
        started_at=stuck_time,
    )
    db.session.add(conv)
    db.session.commit()

    from hashview.scheduler import process_pending_conversions
    process_pending_conversions(app)

    db.session.refresh(conv)
    assert conv.status == "pending"


def test_scheduler_fails_unknown_source_type(app, tmp_path, monkeypatch):
    """A HashfileConversions record with an unrecognised source_type is marked failed."""
    monkeypatch.chdir(tmp_path)
    os.makedirs(tmp_path / 'hashview' / 'control' / 'tmp')

    owner = _make_owner()
    hf = _make_hashfile(owner.id)

    conv = HashfileConversions(
        hashfile_id=hf.id,
        source_type="unknown_format",
        status="pending",
        source_path="/tmp/whatever",
    )
    db.session.add(conv)
    db.session.commit()

    from hashview.scheduler import process_pending_conversions
    process_pending_conversions(app)

    db.session.refresh(conv)
    assert conv.status == "failed"
    assert "unknown_format" in conv.conversion_error


def test_convert_pcap_raises_when_tool_not_installed(tmp_path):
    """ConversionError is raised with an install hint when hcxpcapngtool is absent."""
    from hashview.utils.convert import ConversionError, convert_pcap

    src = tmp_path / "cap.pcapng"
    src.write_bytes(b"fake pcap content")

    with patch("hashview.utils.convert.subprocess.run",
               side_effect=FileNotFoundError("hcxpcapngtool")):
        with pytest.raises(ConversionError, match="hcxpcapngtool"):
            convert_pcap(str(src))


def test_convert_pcap_raises_when_tool_exits_nonzero(tmp_path):
    """ConversionError carries the tool's stderr when it exits non-zero."""
    from hashview.utils.convert import ConversionError, convert_pcap

    src = tmp_path / "cap.pcapng"
    src.write_bytes(b"fake pcap content")

    failed_result = subprocess.CompletedProcess(
        args=[], returncode=1,
        stdout=b"", stderr=b"error: invalid pcap file",
    )
    with patch("hashview.utils.convert.subprocess.run", return_value=failed_result):
        with pytest.raises(ConversionError, match="invalid pcap file"):
            convert_pcap(str(src))


def test_convert_pcap_raises_when_output_is_empty(tmp_path):
    """ConversionError is raised when the tool succeeds but produces no hashes."""
    from hashview.utils.convert import ConversionError, convert_pcap

    src = tmp_path / "cap.pcapng"
    src.write_bytes(b"fake pcap content")

    def _fake_run(cmd, **kwargs):
        out_path = cmd[cmd.index('-o') + 1]
        open(out_path, 'w').close()
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=b"", stderr=b"")

    with patch("hashview.utils.convert.subprocess.run", side_effect=_fake_run):
        with pytest.raises(ConversionError, match="No valid WPA"):
            convert_pcap(str(src))


def test_convert_pcap_raises_on_timeout(tmp_path):
    """ConversionError is raised with a clean message when hcxpcapngtool times out."""
    from hashview.utils.convert import ConversionError, convert_pcap

    src = tmp_path / "cap.pcapng"
    src.write_bytes(b"fake pcap content")

    with patch("hashview.utils.convert.subprocess.run",
               side_effect=subprocess.TimeoutExpired(cmd=['hcxpcapngtool'], timeout=300)):
        with pytest.raises(ConversionError, match="timed out"):
            convert_pcap(str(src))


def test_convert_pcap_returns_output_path_on_success(tmp_path):
    """convert_pcap returns the path to the converted file when the tool succeeds."""
    from hashview.utils.convert import convert_pcap

    src = tmp_path / "cap.pcapng"
    src.write_bytes(b"fake pcap content")

    wpa_line = b"WPA*02*aabbcc*001122334455*aabbccddeeff*targetssid*abc123*01*\n"

    def _fake_run(cmd, **kwargs):
        out_path = cmd[cmd.index('-o') + 1]
        with open(out_path, 'wb') as f:
            f.write(wpa_line)
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=b"", stderr=b"")

    with patch("hashview.utils.convert.subprocess.run", side_effect=_fake_run):
        result = convert_pcap(str(src))

    assert result.endswith('.hc22000')
    assert os.path.exists(result)
    with open(result, 'rb') as f:
        assert f.read() == wpa_line


def test_wpa_pcap_upload_creates_pending_conversion_record(app, client, tmp_path):
    """POSTing a pcap file with file_type=wpa_pcap creates a HashfileConversions
    record with status='pending' and does NOT immediately import hashes."""
    import io as _io
    from hashview.models import Customers, HashfileHashes

    cust = Customers(name="TestCorp")
    db.session.add(cust)
    db.session.commit()

    owner = _make_owner()
    _login(client, owner)
    job = _make_job(app, owner.id, cust.id)

    pcap_bytes = b"\xd4\xc3\xb2\xa1fake pcap"
    data = {
        "file_type": "wpa_pcap",
        "name": "pwnagotchi-capture",
        "hash_type": "",
        "shadow_hash_type": "",
        "pwdump_hash_type": "",
        "netntlm_hash_type": "",
        "kerberos_hash_type": "",
        "hashfile": (
            _io.BytesIO(pcap_bytes),
            "capture.pcapng",
        ),
    }
    resp = client.post(
        f"/jobs/{job.id}/assigned_hashfile/",
        data=data,
        content_type="multipart/form-data",
        follow_redirects=False,
    )

    assert resp.status_code in (302, 303)

    hf = Hashfiles.query.filter_by(name="capture.pcapng").first()
    assert hf is not None

    conv = HashfileConversions.query.filter_by(hashfile_id=hf.id).first()
    assert conv is not None
    assert conv.status == "pending"
    assert conv.source_type == "wpa_pcap"

    assert HashfileHashes.query.filter_by(hashfile_id=hf.id).count() == 0


def test_scheduler_processes_wpa_pcap_conversion_successfully(app, tmp_path, monkeypatch):
    """Scheduler converts a pending wpa_pcap record and imports hashes."""
    monkeypatch.chdir(tmp_path)
    os.makedirs(tmp_path / 'hashview' / 'control' / 'tmp')

    owner = _make_owner()
    hf = _make_hashfile(owner.id)

    src = tmp_path / "cap.pcapng"
    src.write_bytes(b"fake pcap")
    out = str(src) + '.hc22000'

    conv = HashfileConversions(
        hashfile_id=hf.id,
        source_type='wpa_pcap',
        status='pending',
        source_path=str(src),
    )
    db.session.add(conv)
    db.session.commit()

    wpa_line = "WPA*02*aabbcc*001122334455*aabbccddeeff*targetssid*abc123*01*\n"

    def _fake_convert_pcap(src_path):
        with open(out, 'w') as f:
            f.write(wpa_line)
        return out

    with patch("hashview.scheduler.convert_pcap", _fake_convert_pcap):
        from hashview.scheduler import process_pending_conversions
        process_pending_conversions(app)

    db.session.refresh(conv)
    assert conv.status == 'ready'

    from hashview.models import Hashes, HashfileHashes
    imported = (
        Hashes.query
        .join(HashfileHashes, Hashes.id == HashfileHashes.hash_id)
        .filter(HashfileHashes.hashfile_id == hf.id)
        .all()
    )
    assert len(imported) == 1
    assert str(imported[0].hash_type) == '22000'


def test_scheduler_marks_failed_on_conversion_error(app, tmp_path, monkeypatch):
    """When ConversionError is raised, the record status becomes 'failed'."""
    monkeypatch.chdir(tmp_path)
    os.makedirs(tmp_path / 'hashview' / 'control' / 'tmp')

    owner = _make_owner()
    hf = _make_hashfile(owner.id)

    conv = HashfileConversions(
        hashfile_id=hf.id,
        source_type='wpa_pcap',
        status='pending',
        source_path='/tmp/nonexistent.pcapng',
    )
    db.session.add(conv)
    db.session.commit()

    from hashview.utils.convert import ConversionError

    with patch("hashview.scheduler.convert_pcap",
               side_effect=ConversionError("hcxpcapngtool is not installed")):
        from hashview.scheduler import process_pending_conversions
        process_pending_conversions(app)

    db.session.refresh(conv)
    assert conv.status == 'failed'
    assert 'hcxpcapngtool' in conv.conversion_error


# ---------------------------------------------------------------------------
# Test 1: FK cascade — deleting a Hashfiles record deletes its HashfileConversions
# ---------------------------------------------------------------------------

def test_hashfile_deletion_cascades_to_conversion(app):
    """Deleting a Hashfiles record also deletes its HashfileConversions record (FK cascade)."""
    owner = _make_owner()
    hf = _make_hashfile(owner.id)

    conv = HashfileConversions(
        hashfile_id=hf.id,
        source_type='wpa_pcap',
        status='pending',
        source_path='/tmp/cap.pcapng',
    )
    db.session.add(conv)
    db.session.commit()
    conv_id = conv.id

    db.session.delete(hf)
    db.session.commit()

    assert HashfileConversions.query.filter_by(id=conv_id).first() is None


# ---------------------------------------------------------------------------
# Test 2: Source pcap file deleted from disk after successful wpa_pcap conversion
# ---------------------------------------------------------------------------

def test_scheduler_removes_source_file_after_wpa_pcap_success(app, tmp_path, monkeypatch):
    """Source pcap and converted .hc22000 are removed from disk after successful wpa_pcap conversion."""
    monkeypatch.chdir(tmp_path)
    os.makedirs(tmp_path / 'hashview' / 'control' / 'tmp')

    owner = _make_owner()
    hf = _make_hashfile(owner.id)

    src = tmp_path / "cap.pcapng"
    src.write_bytes(b"fake pcap")
    out = str(src) + '.hc22000'

    conv = HashfileConversions(
        hashfile_id=hf.id,
        source_type='wpa_pcap',
        status='pending',
        source_path=str(src),
    )
    db.session.add(conv)
    db.session.commit()

    wpa_line = "WPA*02*aabbcc*001122334455*aabbccddeeff*targetssid*abc123*01*\n"

    def _fake_convert_pcap(src_path):
        with open(out, 'w') as f:
            f.write(wpa_line)
        return out

    with patch("hashview.scheduler.convert_pcap", _fake_convert_pcap):
        from hashview.scheduler import process_pending_conversions
        process_pending_conversions(app)

    assert not os.path.exists(str(src)), "source pcap should be deleted after conversion"
    assert not os.path.exists(out), ".hc22000 output should be deleted after import"


# ---------------------------------------------------------------------------
# Test 5: convert_pcap fallback message when tool exits nonzero with no stderr
# ---------------------------------------------------------------------------

def test_convert_pcap_raises_fallback_when_no_stderr(tmp_path):
    """ConversionError has a generic message when hcxpcapngtool exits non-zero with no stderr."""
    from hashview.utils.convert import ConversionError, convert_pcap

    src = tmp_path / "cap.pcapng"
    src.write_bytes(b"fake pcap content")

    silent_failure = subprocess.CompletedProcess(
        args=[], returncode=1, stdout=b"", stderr=b"",
    )
    with patch("hashview.utils.convert.subprocess.run", return_value=silent_failure):
        with pytest.raises(ConversionError, match="exited with an error"):
            convert_pcap(str(src))


# ---------------------------------------------------------------------------
# Test 7: Non-ConversionError exceptions also mark record failed
# ---------------------------------------------------------------------------

def test_scheduler_marks_failed_on_unexpected_exception(app, tmp_path, monkeypatch):
    """Non-ConversionError exceptions (e.g. RuntimeError) also mark the record as failed."""
    monkeypatch.chdir(tmp_path)
    os.makedirs(tmp_path / 'hashview' / 'control' / 'tmp')

    owner = _make_owner()
    hf = _make_hashfile(owner.id)

    conv = HashfileConversions(
        hashfile_id=hf.id,
        source_type='wpa_pcap',
        status='pending',
        source_path='/tmp/nonexistent.pcapng',
    )
    db.session.add(conv)
    db.session.commit()

    with patch("hashview.scheduler.convert_pcap",
               side_effect=RuntimeError("disk full")):
        from hashview.scheduler import process_pending_conversions
        process_pending_conversions(app)

    db.session.refresh(conv)
    assert conv.status == 'failed'
    assert 'disk full' in conv.conversion_error


# ---------------------------------------------------------------------------
# Test 8: Hashfiles list view includes conversion status badge
# ---------------------------------------------------------------------------

def test_hashfiles_list_shows_converting_badge_for_pending_conversion(app, client):
    """The hashfiles list page renders a status badge for hashfiles with pending conversions."""
    from hashview.models import Customers

    owner = _make_owner()
    _login(client, owner)

    cust = Customers(name="BadgeCorp")
    db.session.add(cust)
    db.session.commit()

    hf = Hashfiles(name="badge-test-capture", customer_id=cust.id, owner_id=owner.id)
    db.session.add(hf)
    db.session.commit()

    conv = HashfileConversions(
        hashfile_id=hf.id,
        source_type='wpa_pcap',
        status='pending',
        source_path='/tmp/cap.pcapng',
    )
    db.session.add(conv)
    db.session.commit()

    resp = client.get('/hashfiles')
    assert resp.status_code == 200
    # The template renders "Converting…" for pending/converting status
    assert 'Converting' in resp.get_data(as_text=True)


# ---------------------------------------------------------------------------
# Test 9: Two pending records both processed in a single scheduler cycle
# ---------------------------------------------------------------------------

def test_scheduler_processes_multiple_pending_records(app, tmp_path, monkeypatch):
    """A single scheduler run processes all pending records, not just the first."""
    monkeypatch.chdir(tmp_path)
    os.makedirs(tmp_path / 'hashview' / 'control' / 'tmp')

    owner = _make_owner()

    hf1 = Hashfiles(name="cap1.pcapng", customer_id=1, owner_id=owner.id)
    hf2 = Hashfiles(name="cap2.pcapng", customer_id=1, owner_id=owner.id)
    db.session.add_all([hf1, hf2])
    db.session.commit()

    src1 = tmp_path / "cap1.pcapng"
    src2 = tmp_path / "cap2.pcapng"
    src1.write_bytes(b"fake pcap 1")
    src2.write_bytes(b"fake pcap 2")

    conv1 = HashfileConversions(hashfile_id=hf1.id, source_type='wpa_pcap',
                                 status='pending', source_path=str(src1))
    conv2 = HashfileConversions(hashfile_id=hf2.id, source_type='wpa_pcap',
                                 status='pending', source_path=str(src2))
    db.session.add_all([conv1, conv2])
    db.session.commit()

    wpa_line = "WPA*02*aabbcc*001122334455*aabbccddeeff*targetssid*abc123*01*\n"

    def _fake_convert_pcap(src_path):
        out = src_path + '.hc22000'
        with open(out, 'w') as f:
            f.write(wpa_line)
        return out

    with patch("hashview.scheduler.convert_pcap", _fake_convert_pcap):
        from hashview.scheduler import process_pending_conversions
        process_pending_conversions(app)

    db.session.refresh(conv1)
    db.session.refresh(conv2)
    assert conv1.status == 'ready'
    assert conv2.status == 'ready'
