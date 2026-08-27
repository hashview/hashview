"""Unit tests for Settings -> Data management actions.

- purge_cracked: admin-only POST that resets every cracked hash to uncracked
  (wipes plaintext + recovery metadata, keeps the hash rows) and flashes a
  success message.
- clear_temp_folder: now flashes a success message after clearing.

Uses the in-memory SQLite app from tests/unit/conftest.py. Flash messages are
read from the session (avoids rendering the whole settings page).
"""

from datetime import datetime

from hashview.models import Hashes, Settings, Users, db


def _admin(admin=True):
    u = Users(first_name="A", last_name="D", email_address=f"{'adm' if admin else 'usr'}@e.com",
              password="x" * 60, admin=admin, api_key=f"key-{admin}")
    db.session.add(u)
    db.session.commit()
    return u


def _login(client, user):
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True


def _cracked(ciphertext):
    h = Hashes(sub_ciphertext="0" * 8, ciphertext=ciphertext, hash_type=1000, cracked=True,
               plaintext="secret", recovered_at=datetime(2024, 1, 1), task_id=5, recovered_by=1)
    db.session.add(h)
    db.session.commit()
    return h


def test_purge_cracked_resets_hashes(app, client):
    user = _admin()
    _login(client, user)
    _cracked("aaa")
    _cracked("bbb")
    uncracked = Hashes(sub_ciphertext="0" * 8, ciphertext="ccc", hash_type=1000, cracked=False)
    db.session.add(uncracked)
    db.session.commit()

    resp = client.post("/settings/purge_cracked")
    assert resp.status_code == 302                       # redirect back to settings

    assert Hashes.query.filter_by(cracked=True).count() == 0
    for h in Hashes.query.all():                         # plaintext + metadata wiped, rows kept
        assert h.plaintext is None
        assert h.recovered_at is None and h.task_id is None and h.recovered_by is None
    assert Hashes.query.count() == 3                     # the hashes themselves are NOT deleted

    with client.session_transaction() as sess:
        flashes = sess.get("_flashes", [])
    assert any(cat == "success" and "Purged" in msg for cat, msg in flashes)


def test_purge_cracked_requires_admin(app, client):
    user = _admin(admin=False)
    _login(client, user)
    _cracked("aaa")
    resp = client.post("/settings/purge_cracked")
    assert resp.status_code == 403
    assert Hashes.query.filter_by(cracked=True).count() == 1   # untouched


def test_clear_temp_flashes_success(app, client, monkeypatch):
    user = _admin()
    _login(client, user)
    # Don't touch the real control/tmp dir — pretend it's already empty.
    monkeypatch.setattr("hashview.settings.routes.os.scandir", lambda path: iter([]))
    resp = client.get("/settings/clear_temp")
    assert resp.status_code == 302
    with client.session_transaction() as sess:
        flashes = sess.get("_flashes", [])
    assert any(cat == "success" and "Temp folder cleared" in msg for cat, msg in flashes)


# --- send_test_admin_slack (administrative Slack room test button) ---------

def _settings_row(channel=None):
    s = Settings(retention_period=1, max_runtime_jobs=0, max_runtime_tasks=0,
                 slack_enabled=True, slack_bot_token="xoxb-x", slack_admin_channel=channel)
    db.session.add(s)
    db.session.commit()
    return s


def test_send_test_admin_slack_forbidden_for_non_admin(app, client):
    user = _admin(admin=False)
    _login(client, user)
    resp = client.get("/settings/send_test_admin_slack")
    assert resp.status_code == 403


def test_send_test_admin_slack_no_room_flashes(app, client, monkeypatch):
    user = _admin()
    _login(client, user)
    _settings_row(channel=None)
    calls = []
    monkeypatch.setattr("hashview.settings.routes.send_slack_channel",
                        lambda *a, **k: calls.append(a))
    resp = client.get("/settings/send_test_admin_slack", follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert calls == []          # no room configured -> nothing sent
    with client.session_transaction() as sess:
        flashes = sess.get("_flashes", [])
    assert any(cat == "danger" for cat, _ in flashes)


def test_send_test_admin_slack_posts_to_room(app, client, monkeypatch):
    user = _admin()
    _login(client, user)
    _settings_row(channel="C0ADMIN")
    calls = []
    monkeypatch.setattr("hashview.settings.routes.send_slack_channel",
                        lambda ch, sub, msg: calls.append(ch))
    resp = client.get("/settings/send_test_admin_slack", follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert calls == ["C0ADMIN"]
