"""Over-long input is refused by the app, not by the database.

tests/unit/test_form_db_length_parity.py proves each form field *declares* the
right bound. This module proves the bound is actually enforced on the way in:
every route that persists one of those fields is POSTed a value one character
longer than its column and must leave the database untouched.

That distinction matters because the unit suite runs on SQLite, which stores an
over-long string happily. A test that only asserted "the row came back wrong"
would pass on SQLite and still 500 in production, where MySQL in strict mode
raises DataError. So every assertion here is "nothing was written" -- the one
outcome that means the app stopped the value before the INSERT, on either
database.

Three of these routes never see a form validator at all and carry their own
check: customers_edit and users_edit read request.form directly, and the
hashfile upload takes its name from the browser-supplied filename.

The contract asserted here is "the app refuses the value", not "the db_length
validator is what refused it" -- in three cases something else gets there
first, noted at each. There is deliberately no /rules/edit case: that route
edits a rule's file content and cannot rename it, and no route anywhere can
(RulesEditForm is unreferenced), so `Rules.name` is only ever written by
/rules/add.
"""

import io

import pytest

from hashview.models import (
    Agents,
    Customers,
    Hashfiles,
    Jobs,
    Rules,
    Settings,
    TaskGroups,
    Tasks,
    Users,
    Wordlists,
    db,
)
from hashview.utils.form_limits import column_length
from tests.unit.helpers import (
    login,
    make_admin,
    make_customer,
    make_wordlist_with_file,
)


def _too_long(model, column):
    """One character more than the column holds."""
    return 'x' * (column_length(model, column) + 1)


def _long_email(limit):
    """An over-limit, email-shaped value.

    On the forms that carry Email(), that validator is what rejects this (RFC
    caps a local part at 64 characters, so no address it accepts can overflow
    the 255-char column anyway -- the db_length there is belt-and-braces).
    users_edit has no Email() validator at all, so there the explicit length
    check in the route is the only thing standing between this and MySQL.
    """
    return 'x' * (limit + 1 - len('@example.com')) + '@example.com'


@pytest.fixture()
def admin(app, client):
    with app.app_context():
        user = make_admin()
        login(client, user)
        yield user


# --- customers ---------------------------------------------------------------

def test_customers_add_rejects_an_over_long_name(app, client, admin):
    client.post('/customers/add', data={'name': _too_long(Customers, 'name')},
                follow_redirects=True)
    assert Customers.query.count() == 0


def test_customers_edit_rejects_an_over_long_name(app, client, admin):
    """customers_edit reads request.form directly, bypassing CustomersForm."""
    customer = make_customer(name='Acme')
    client.post('/customers/edit',
                data={'customer_id': customer.id, 'name': _too_long(Customers, 'name')},
                follow_redirects=True)
    assert Customers.query.get(customer.id).name == 'Acme'


# --- jobs --------------------------------------------------------------------

def test_jobs_add_rejects_an_over_long_job_name(app, client, admin):
    customer = make_customer()
    client.post('/jobs/add', data={'name': _too_long(Jobs, 'name'),
                                   'priority': '3',
                                   'customer_id': str(customer.id)},
                follow_redirects=True)
    assert Jobs.query.count() == 0


def test_jobs_add_rejects_an_over_long_new_customer_name(app, client, admin):
    """'+ Add new customer' on the wizard writes straight to Customers.name."""
    client.post('/jobs/add', data={'name': 'a job', 'priority': '3',
                                   'customer_id': 'add_new',
                                   'customer_name': _too_long(Customers, 'name')},
                follow_redirects=True)
    assert Customers.query.count() == 0
    assert Jobs.query.count() == 0


def _job_for_upload(admin_user):
    customer = make_customer()
    job = Jobs(name='upload-job', status='Incomplete', customer_id=customer.id,
               owner_id=admin_user.id, priority=3)
    db.session.add(job)
    db.session.commit()
    return job


# Every hash-type <select> on this form is submitted by the real page, and an
# omitted SelectField fails its own choice check before anything else runs --
# which would make these tests pass for a reason that has nothing to do with
# length. The happy-path case below is what proves the payload is otherwise good.
_HASHFILE_FORM = {'file_type': 'hash_only', 'hash_type': '0',
                  'shadow_hash_type': '500', 'netntlm_hash_type': '5500',
                  'kerberos_hash_type': '7500', 'pwdump_hash_type': '1000'}
_ONE_MD5 = '5f4dcc3b5aa765d61d8327deb882cf99'


def test_hashfile_upload_accepts_a_normal_filename(app, client, admin):
    """The control for the two tests below: this payload really does insert."""
    job = _job_for_upload(admin)
    client.post(f'/jobs/{job.id}/assigned_hashfile/',
                data={**_HASHFILE_FORM,
                      'hashfile': (io.BytesIO(_ONE_MD5.encode() + b'\n'), 'short.txt')},
                content_type='multipart/form-data', follow_redirects=True)
    assert Hashfiles.query.count() == 1


def test_hashfile_upload_rejects_an_over_long_filename(app, client, admin):
    """The upload branch names the hashfile after the FILE, not the name field.

    No validator ever sees a filename, so this route checks the column itself.
    """
    job = _job_for_upload(admin)
    overlong = _too_long(Hashfiles, 'name') + '.txt'
    client.post(f'/jobs/{job.id}/assigned_hashfile/',
                data={**_HASHFILE_FORM,
                      'hashfile': (io.BytesIO(_ONE_MD5.encode() + b'\n'), overlong)},
                content_type='multipart/form-data', follow_redirects=True)
    assert Hashfiles.query.count() == 0


def test_hashfile_paste_rejects_an_over_long_name(app, client, admin):
    job = _job_for_upload(admin)
    client.post(f'/jobs/{job.id}/assigned_hashfile/',
                data={**_HASHFILE_FORM,
                      'name': _too_long(Hashfiles, 'name'),
                      'hashfilehashes': _ONE_MD5},
                follow_redirects=True)
    assert Hashfiles.query.count() == 0


# --- tasks -------------------------------------------------------------------

@pytest.mark.parametrize('field,column', [('name', 'name'),
                                          ('mask', 'hc_mask'),
                                          ('j_rule', 'j_rule'),
                                          ('k_rule', 'k_rule')])
def test_tasks_add_rejects_an_over_long_value(app, client, admin, field, column):
    wordlist = make_wordlist_with_file(admin.id)
    payload = {'name': 'a task', 'hc_attackmode': '3', 'mask': '?d?d?d?d',
               'wl_id': str(wordlist.id), 'wl_id_2': str(wordlist.id),
               'rule_id': 'None', 'submit': 'Create'}
    payload[field] = _too_long(Tasks, column)
    client.post('/tasks/add', data=payload, follow_redirects=True)
    assert Tasks.query.count() == 0


def test_tasks_edit_rejects_an_over_long_name(app, client, admin):
    wordlist = make_wordlist_with_file(admin.id)
    task = Tasks(name='keep-me', owner_id=admin.id, hc_attackmode=3,
                 hc_mask='?d?d?d?d')
    db.session.add(task)
    db.session.commit()
    client.post(f'/tasks/edit/{task.id}',
                data={'name': _too_long(Tasks, 'name'), 'hc_attackmode': '3',
                      'mask': '?d?d?d?d', 'wl_id': str(wordlist.id),
                      'wl_id_2': str(wordlist.id), 'rule_id': 'None'},
                follow_redirects=True)
    assert Tasks.query.get(task.id).name == 'keep-me'


# --- task groups -------------------------------------------------------------

def test_task_groups_add_rejects_an_over_long_name(app, client, admin):
    client.post('/task_groups/add',
                data={'name': _too_long(TaskGroups, 'name'), 'task_ids': ''},
                follow_redirects=True)
    assert TaskGroups.query.count() == 0


def test_task_groups_edit_rejects_an_over_long_name(app, client, admin):
    group = TaskGroups(name='keep-me', owner_id=admin.id, tasks='[]')
    db.session.add(group)
    db.session.commit()
    client.post('/task_groups/edit',
                data={'group_id': group.id, 'name': _too_long(TaskGroups, 'name'),
                      'task_ids': ''},
                follow_redirects=True)
    assert TaskGroups.query.get(group.id).name == 'keep-me'


# --- rules / wordlists -------------------------------------------------------

# The rule and wordlist upload modals hide the name box and fill it from the
# chosen file's name, so there is no field for the user to shorten. Those two
# are trimmed to fit instead of refused -- refusing would be a dead end only
# escapable by renaming the file on disk (Rules.name is 50 characters, which an
# ordinary .rule filename passes easily). The value still never exceeds the
# column, which is what this module is about.

def test_rules_add_trims_an_over_long_name_to_the_column(app, client, admin):
    client.post('/rules/add',
                data={'name': _too_long(Rules, 'name'),
                      'rules': (io.BytesIO(b'$1\n'), 'r.rule')},
                content_type='multipart/form-data', follow_redirects=True)
    rule = Rules.query.one()
    assert len(rule.name) == column_length(Rules, 'name')


def test_wordlists_add_trims_an_over_long_name_to_the_column(app, client, admin):
    client.post('/wordlists/add',
                data={'name': _too_long(Wordlists, 'name'),
                      'wordlist': (io.BytesIO(b'alpha\nbravo\n'), 'wl.txt')},
                content_type='multipart/form-data', follow_redirects=True)
    wordlist = Wordlists.query.one()
    assert len(wordlist.name) == column_length(Wordlists, 'name')


# --- agents ------------------------------------------------------------------

def test_agents_edit_rejects_an_over_long_name(app, client, admin):
    agent = Agents(name='keep-me', src_ip='127.0.0.1', uuid='u' * 32,
                   status='Authorized')
    db.session.add(agent)
    db.session.commit()
    client.post(f'/agents/edit/{agent.id}',
                data={'name': _too_long(Agents, 'name'), 'id': str(agent.id)},
                follow_redirects=True)
    assert Agents.query.get(agent.id).name == 'keep-me'


# --- users -------------------------------------------------------------------

@pytest.mark.parametrize('field,column', [('first_name', 'first_name'),
                                          ('last_name', 'last_name'),
                                          ('email', 'email_address')])
def test_users_add_rejects_an_over_long_value(app, client, admin, field, column):
    password = 'correct horse battery staple'
    payload = {'first_name': 'New', 'last_name': 'User',
               'email': 'new@example.com',
               'password': password, 'confirm_password': password}
    limit = column_length(Users, column)
    payload[field] = _long_email(limit) if field == 'email' else 'x' * (limit + 1)
    client.post('/users/add', data=payload, follow_redirects=True)
    assert Users.query.filter(Users.id != admin.id).count() == 0


@pytest.mark.parametrize('field,column', [('first_name', 'first_name'),
                                          ('last_name', 'last_name'),
                                          ('email', 'email_address')])
def test_users_edit_rejects_an_over_long_value(app, client, admin, field, column):
    """users_edit reads request.form directly, bypassing UsersForm."""
    target = make_admin(email='victim@example.com')
    before = getattr(target, column)
    payload = {'first_name': target.first_name, 'last_name': target.last_name,
               'email': target.email_address}
    limit = column_length(Users, column)
    payload[field] = _long_email(limit) if field == 'email' else 'x' * (limit + 1)
    client.post(f'/users/edit/{target.id}', data=payload, follow_redirects=True)
    assert getattr(Users.query.get(target.id), column) == before


@pytest.mark.parametrize('field,column', [('first_name', 'first_name'),
                                          ('last_name', 'last_name'),
                                          ('email', 'email_address'),
                                          ('pushover_user_key', 'pushover_user_key'),
                                          ('pushover_app_id', 'pushover_app_id'),
                                          ('slack_id', 'slack_id')])
def test_profile_rejects_an_over_long_value(app, client, admin, field, column):
    before = getattr(Users.query.get(admin.id), column)
    payload = {'first_name': admin.first_name, 'last_name': admin.last_name,
               'email': admin.email_address}
    limit = column_length(Users, column)
    payload[field] = _long_email(limit) if field == 'email' else 'x' * (limit + 1)
    client.post('/profile', data=payload, follow_redirects=True)
    assert getattr(Users.query.get(admin.id), column) == before


def test_set_theme_rejects_an_over_long_value(app, client, admin):
    """Here the route's allowed-value set is what rejects it, not the length.

    Kept because the outcome is what matters -- nothing over-long reaches the
    column -- and because a future free-text theme would land on db_length.
    """
    before = Users.query.get(admin.id).theme
    client.post('/profile/set_theme', data={'theme': _too_long(Users, 'theme')})
    assert Users.query.get(admin.id).theme == before


# --- settings ----------------------------------------------------------------

SETTINGS_FIELDS = ['slack_bot_token', 'slack_admin_channel', 'azure_tenant_id',
                   'azure_client_id', 'azure_client_secret', 'azure_redirect_uri',
                   'azure_allowed_groups']


@pytest.mark.parametrize('field', SETTINGS_FIELDS)
def test_settings_rejects_an_over_long_value(app, client, admin, field):
    settings = Settings(retention_period=30, max_runtime_jobs=0,
                        max_runtime_tasks=0)
    db.session.add(settings)
    db.session.commit()
    before = getattr(settings, field)
    payload = {'retention_period': '30', 'max_runtime_jobs': '0',
               'max_runtime_tasks': '0', 'agent_timeout_minutes': '60',
               'chunk_target_duration': '600', 'auth_method': 'local',
               field: _too_long(Settings, field)}
    resp = client.post('/settings', data=payload, follow_redirects=True)
    assert getattr(Settings.query.get(settings.id), field) == before
    # A rejected save must say so. These five Entra ID inputs rendered no error
    # and the route flashed nothing, so an over-long value silently discarded
    # every other setting on the page at the same time.
    body = resp.get_data(as_text=True)
    assert 'Settings not saved' in body
    assert 'cannot be longer than' in body
