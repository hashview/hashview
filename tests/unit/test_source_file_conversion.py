"""Tests for server-side source file conversion (pcap + NTDS.dit)."""
import os
from datetime import datetime, timedelta

from hashview.models import Hashfiles, HashfileConversions, Users, db


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
