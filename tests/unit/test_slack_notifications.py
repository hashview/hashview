"""Unit tests for the Slack notification channel.

Covers the new sender (send_slack), the channel dispatcher
(deliver_user_notification), the de-duplicated hash-recovery helper
(process_recovered_hash_notifications), and the job-wizard writing a
method='slack' JobNotifications row. Uses the in-memory SQLite app from
tests/unit/conftest.py (CSRF disabled, mail suppressed).
"""
import pytest

from hashview.models import (
    Customers,
    Hashes,
    HashfileHashes,
    Hashfiles,
    HashNotifications,
    JobNotifications,
    Jobs,
    Settings,
    Users,
)
from hashview.models import db as _db
from hashview.utils import utils as utils_mod


class _FakeResp:
    def __init__(self, ok=True, error=None):
        self._ok = ok
        self._error = error

    def json(self):
        return {'ok': self._ok} if self._ok else {'ok': False, 'error': self._error}


def _user(slack_id='U123ABC', **kw):
    u = Users(first_name='A', last_name='D', email_address=kw.pop('email', 'u@e.test'),
              password='x' * 60, admin=True, slack_id=slack_id, **kw)
    _db.session.add(u)
    _db.session.commit()
    return u


def _settings(enabled=True, token='xoxb-test'):
    s = Settings(retention_period=1, max_runtime_jobs=0, max_runtime_tasks=0,
                 slack_enabled=enabled, slack_bot_token=token)
    _db.session.add(s)
    _db.session.commit()
    return s


# --------------------------------------------------------------------------
# send_slack
# --------------------------------------------------------------------------

@pytest.mark.security
def test_send_slack_posts_chat_postmessage(app, monkeypatch):
    _settings(enabled=True, token='xoxb-secret')
    user = _user(slack_id='U999')
    calls = {}

    def fake_post(url, json=None, headers=None, timeout=None, **kw):
        calls.update(url=url, json=json, headers=headers)
        return _FakeResp(ok=True)

    monkeypatch.setattr(utils_mod.requests, 'post', fake_post)
    utils_mod.send_slack(user, 'Subj', 'Body text')

    assert calls['url'] == 'https://slack.com/api/chat.postMessage'
    assert calls['headers']['Authorization'] == 'Bearer xoxb-secret'
    assert calls['json']['channel'] == 'U999'
    assert 'Subj' in calls['json']['text'] and 'Body text' in calls['json']['text']


@pytest.mark.security
def test_send_slack_noop_when_disabled(app, monkeypatch):
    _settings(enabled=False, token='xoxb-secret')
    user = _user(slack_id='U999')
    called = {'n': 0}
    monkeypatch.setattr(utils_mod.requests, 'post',
                        lambda *a, **k: called.__setitem__('n', called['n'] + 1) or _FakeResp())
    utils_mod.send_slack(user, 'S', 'M')
    assert called['n'] == 0   # disabled -> never hits the network


@pytest.mark.security
def test_send_slack_noop_when_user_has_no_slack_id(app, monkeypatch):
    _settings(enabled=True, token='xoxb-secret')
    user = _user(slack_id=None)
    called = {'n': 0}
    monkeypatch.setattr(utils_mod.requests, 'post',
                        lambda *a, **k: called.__setitem__('n', called['n'] + 1) or _FakeResp())
    utils_mod.send_slack(user, 'S', 'M')
    assert called['n'] == 0


# --------------------------------------------------------------------------
# deliver_user_notification (dispatcher)
# --------------------------------------------------------------------------

@pytest.mark.security
def test_dispatcher_routes_slack_when_configured(app, monkeypatch):
    _settings(enabled=True, token='xoxb-x')
    user = _user(slack_id='U1')
    sent = {}
    monkeypatch.setattr(utils_mod, 'send_slack', lambda u, s, m: sent.update(slack=(u, s, m)))
    monkeypatch.setattr(utils_mod, 'send_email', lambda *a, **k: sent.update(email=a))
    utils_mod.deliver_user_notification(user, 'slack', 'Subj', 'Msg')
    assert 'slack' in sent and 'email' not in sent


@pytest.mark.security
def test_dispatcher_skips_disabled_channel(app, monkeypatch):
    """A channel disabled instance-wide is skipped silently (no send, no fallback)."""
    _settings(enabled=False, token=None)          # Slack globally off
    user = _user(slack_id='U1')
    sent = {}
    monkeypatch.setattr(utils_mod, 'send_slack', lambda *a, **k: sent.update(slack=True))
    monkeypatch.setattr(utils_mod, 'send_email', lambda *a, **k: sent.update(email=True))
    utils_mod.deliver_user_notification(user, 'slack', 'Subj', 'Msg')
    assert sent == {}            # disabled -> nothing sent, no email fallback


@pytest.mark.security
def test_dispatcher_enabled_slack_missing_user_id_emails_fallback(app, monkeypatch):
    """Slack enabled but the user has no Slack Member ID -> email them to fix it."""
    _settings(enabled=True, token='xoxb-x')       # Slack on (email defaults on)
    user = _user(slack_id=None)
    sent = {}
    monkeypatch.setattr(utils_mod, 'send_slack', lambda *a, **k: sent.update(slack=True))
    monkeypatch.setattr(utils_mod, 'send_email', lambda u, s, m: sent.update(email=(s, m)))
    utils_mod.deliver_user_notification(user, 'slack', 'Subj', 'Msg')
    assert 'slack' not in sent
    assert 'email' in sent and 'Slack' in sent['email'][0]   # "Missing Slack configuration"


# --------------------------------------------------------------------------
# notify_admins (administrative alerts) + send_slack_channel
# --------------------------------------------------------------------------

@pytest.mark.security
def test_notify_admins_respects_channel_flags(app, monkeypatch):
    """An opted-in admin gets only their selected channels, gated by the global
    Email/Pushover switches."""
    settings = _settings(enabled=False)            # slack off; email/pushover default ON
    admin = _user(email='admin@x.test', slack_id=None,
                  admin_notifications_enabled=True,
                  admin_notify_email=True, admin_notify_pushover=True)
    admin.pushover_app_id = 'a'
    admin.pushover_user_key = 'u'
    _db.session.commit()
    sent = {'email': 0, 'push': 0}
    monkeypatch.setattr(utils_mod, 'send_email', lambda *a, **k: sent.__setitem__('email', sent['email'] + 1))
    monkeypatch.setattr(utils_mod, 'send_pushover', lambda *a, **k: sent.__setitem__('push', sent['push'] + 1))

    utils_mod.notify_admins('S', 'M')
    assert sent['email'] > 0 and sent['push'] > 0          # both selected + on

    settings.email_enabled = False
    _db.session.commit()
    sent['email'] = sent['push'] = 0
    utils_mod.notify_admins('S', 'M')
    assert sent['email'] == 0 and sent['push'] > 0          # email off -> only pushover

    settings.pushover_enabled = False
    _db.session.commit()
    sent['email'] = sent['push'] = 0
    utils_mod.notify_admins('S', 'M')
    assert sent == {'email': 0, 'push': 0}                  # both off -> nothing


@pytest.mark.security
def test_notify_admins_requires_optin(app, monkeypatch):
    """An admin who hasn't opted in (or selected no channels) gets nothing."""
    _settings(enabled=True)
    # opted out entirely (channels on, but master off)
    _user(email='a1@x.test', slack_id=None, admin_notifications_enabled=False,
          admin_notify_email=True, admin_notify_pushover=True)
    # opted in but every channel explicitly off
    _user(email='a2@x.test', slack_id=None, admin_notifications_enabled=True,
          admin_notify_email=False, admin_notify_pushover=False, admin_notify_slack=False)
    sent = {'email': 0, 'push': 0}
    monkeypatch.setattr(utils_mod, 'send_email', lambda *a, **k: sent.__setitem__('email', sent['email'] + 1))
    monkeypatch.setattr(utils_mod, 'send_pushover', lambda *a, **k: sent.__setitem__('push', sent['push'] + 1))
    utils_mod.notify_admins('S', 'M')
    assert sent == {'email': 0, 'push': 0}


@pytest.mark.security
def test_notify_admins_slack_posts_to_room_once(app, monkeypatch):
    """When >=1 opted-in admin selects Slack and a room is set, the alert posts to
    the shared room exactly ONCE (not per admin); no room -> no slack post."""
    settings = _settings(enabled=True, token='xoxb-x')
    settings.slack_admin_channel = 'C0ADMIN'
    _db.session.commit()
    _user(email='s1@x.test', slack_id='U1', admin_notifications_enabled=True, admin_notify_slack=True)
    _user(email='s2@x.test', slack_id='U2', admin_notifications_enabled=True, admin_notify_slack=True)
    posts = []
    monkeypatch.setattr(utils_mod, 'send_slack_channel', lambda ch, s, m: posts.append((ch, s, m)))
    monkeypatch.setattr(utils_mod, 'send_email', lambda *a, **k: None)

    utils_mod.notify_admins('Agent down', 'Boom')
    assert len(posts) == 1 and posts[0][0] == 'C0ADMIN'

    settings.slack_admin_channel = None
    _db.session.commit()
    posts.clear()
    utils_mod.notify_admins('Agent down', 'Boom')
    assert posts == []


@pytest.mark.security
def test_send_slack_channel_posts_to_channel(app, monkeypatch):
    """send_slack_channel posts chat.postMessage with channel set to the room."""
    _settings(enabled=True, token='xoxb-room')
    calls = {}
    monkeypatch.setattr(utils_mod.requests, 'post',
                        lambda url, json=None, headers=None, timeout=None, **kw:
                        calls.update(url=url, json=json, headers=headers) or _FakeResp(ok=True))
    utils_mod.send_slack_channel('C0ROOM', 'Subj', 'Body')
    assert calls['json']['channel'] == 'C0ROOM'
    assert calls['headers']['Authorization'] == 'Bearer xoxb-room'
    assert 'Subj' in calls['json']['text']


@pytest.mark.security
def test_process_recovered_only_notifies_cracked_and_deletes(app, monkeypatch):
    user = _user()
    cracked = Hashes(sub_ciphertext='0' * 8, ciphertext='aa', hash_type=0, cracked=True, plaintext='70')
    uncracked = Hashes(sub_ciphertext='1' * 8, ciphertext='bb', hash_type=0, cracked=False)
    _db.session.add_all([cracked, uncracked])
    _db.session.commit()
    _db.session.add_all([
        HashNotifications(owner_id=user.id, hash_id=cracked.id, method='slack'),
        HashNotifications(owner_id=user.id, hash_id=uncracked.id, method='email'),
    ])
    _db.session.commit()

    delivered = []
    monkeypatch.setattr(utils_mod, 'deliver_user_notification',
                        lambda u, method, subj, msg, html_message=None: delivered.append(method))

    utils_mod.process_recovered_hash_notifications()

    # the cracked-hash notification fired (slack) and was deleted; the uncracked one is kept
    assert delivered == ['slack']
    remaining = {hn.hash_id for hn in HashNotifications.query.all()}
    assert remaining == {uncracked.id}


# --------------------------------------------------------------------------
# job wizard writes a method='slack' JobNotifications row
# --------------------------------------------------------------------------

@pytest.mark.security
def test_wizard_job_completion_slack_creates_row(app, client):
    _settings(enabled=True, token='xoxb-x')
    user = _user()
    cust = Customers(name='C')
    _db.session.add(cust)
    _db.session.commit()
    job = Jobs(name='J', status='Ready', customer_id=cust.id, owner_id=user.id)
    _db.session.add(job)
    _db.session.commit()

    with client.session_transaction() as sess:
        sess['_user_id'] = str(user.id)
        sess['_fresh'] = True

    resp = client.post('/jobs/%d/notifications' % job.id, data={'job_completion_slack': 'y'})
    assert resp.status_code in (301, 302, 303, 307, 308)   # redirect to /tasks
    row = JobNotifications.query.filter_by(job_id=job.id, owner_id=user.id, method='slack').first()
    assert row is not None


@pytest.mark.security
def test_wizard_hashes_route_splits_comma_methods(app, client):
    """POST /notifications/email,push,slack/hashes creates one row per method."""
    _settings(enabled=True, token='xoxb-x')
    user = _user()
    cust = Customers(name='C2')
    _db.session.add(cust)
    _db.session.commit()
    hf = Hashfiles(name='hf', customer_id=cust.id, owner_id=user.id)
    _db.session.add(hf)
    _db.session.commit()
    job = Jobs(name='J2', status='Ready', customer_id=cust.id, owner_id=user.id, hashfile_id=hf.id)
    h = Hashes(sub_ciphertext='2' * 8, ciphertext='cc', hash_type=0, cracked=False)
    _db.session.add_all([job, h])
    _db.session.commit()
    _db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id, username='6162'))
    _db.session.commit()

    with client.session_transaction() as sess:
        sess['_user_id'] = str(user.id)
        sess['_fresh'] = True

    resp = client.post('/jobs/%d/notifications/email,push,slack/hashes' % job.id,
                       data={'selected': str(h.id)})
    assert resp.status_code in (301, 302, 303, 307, 308)
    methods = sorted(hn.method for hn in HashNotifications.query.filter_by(hash_id=h.id).all())
    assert methods == ['email', 'push', 'slack']


@pytest.mark.security
def test_wizard_gates_channels_by_settings(app, client):
    """The wizard shows each channel's toggles only when that channel is enabled
    instance-wide; with none enabled it shows the empty-state note (end-to-end:
    route + context processor + template)."""
    settings = _settings(enabled=False, token=None)   # slack off; email/pushover default on
    user = _user()
    cust = Customers(name='C3')
    _db.session.add(cust)
    _db.session.commit()
    job = Jobs(name='J3', status='Ready', customer_id=cust.id, owner_id=user.id)
    _db.session.add(job)
    _db.session.commit()

    with client.session_transaction() as sess:
        sess['_user_id'] = str(user.id)
        sess['_fresh'] = True

    url = '/jobs/%d/notifications' % job.id

    # email + pushover on, slack off
    html = client.get(url).get_data(as_text=True)
    assert 'job_completion_email' in html
    assert 'job_completion_pushover' in html
    assert 'job_completion_slack' not in html

    # flip: only slack on
    settings.email_enabled = False
    settings.pushover_enabled = False
    settings.slack_enabled = True
    _db.session.commit()
    html = client.get(url).get_data(as_text=True)
    assert 'job_completion_email' not in html
    assert 'job_completion_pushover' not in html
    assert 'job_completion_slack' in html and 'hash_completion_slack' in html

    # all off -> empty-state note, no switches
    settings.slack_enabled = False
    _db.session.commit()
    html = client.get(url).get_data(as_text=True)
    assert 'No notification channels are enabled' in html
    assert 'job_completion_email' not in html and 'job_completion_slack' not in html
