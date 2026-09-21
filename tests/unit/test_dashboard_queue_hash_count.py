"""The queue table says how many hashes each pending job is aimed at.

The queue showed job, customer, attack count, priority and owner -- nothing
about size, so two queued jobs looked identical whether one targeted 40 hashes
and the other 4 million. The new column carries the same figure the Recovered
column of the running tables reads X/Y against, so the two agree.

That unit matters: it counts ACCOUNTS (HashfileHashes rows), not distinct
hashes. They differ whenever one hash is listed against several usernames, and
putting two different totals for one hashfile on the same screen would be worse
than either.
"""

import re

import pytest

from hashview.models import (
    Customers,
    Hashes,
    HashfileHashes,
    Hashfiles,
    Jobs,
    Settings,
)
from hashview.models import db as _db
from tests.unit.helpers import login, make_admin

pytestmark = pytest.mark.security


def _hashfile(owner, customer, name, accounts, shared_hash=False):
    """A hashfile with `accounts` HashfileHashes rows.

    shared_hash puts every account on ONE hash, which is what makes the
    accounts-vs-hashes distinction observable.
    """
    hashfile = Hashfiles(name=name, customer_id=customer.id, owner_id=owner.id)
    _db.session.add(hashfile)
    _db.session.commit()
    single = None
    for i in range(accounts):
        if shared_hash and single is not None:
            hash_row = single
        else:
            hash_row = Hashes(ciphertext=f'{name}{i}',
                              sub_ciphertext=f'{abs(hash(name)) % 1000:03d}{i:029d}',
                              hash_type=1000, cracked=False)
            _db.session.add(hash_row)
            _db.session.commit()
            single = hash_row
        _db.session.add(HashfileHashes(hashfile_id=hashfile.id,
                                       hash_id=hash_row.id, username=f'u{i}'))
    _db.session.commit()
    return hashfile


@pytest.fixture()
def dash(app, client):
    with app.app_context():
        admin = make_admin()
        login(client, admin)
        _db.session.add(Settings(retention_period=30, max_runtime_jobs=0,
                                 max_runtime_tasks=0))
        customer = Customers(name='Acme')
        _db.session.add(customer)
        _db.session.commit()
        yield admin, customer


def _queue_row(body, job_name):
    """The <tr> for one queued job."""
    start = body.index(job_name)
    return body[body.rfind('<tr>', 0, start):body.index('</tr>', start)]


def _hash_cell(body, job_name):
    """Just the Hashes cell of one queued row.

    Targeted by class rather than by position: asserting against the whole row
    matched the Tasks cell instead and let a wrong value pass.
    """
    row = _queue_row(body, job_name)
    cell = re.search(r'<td[^>]*qcol-hashes[^>]*>(.*?)</td>', row, re.S)
    assert cell, f'no Hashes cell in the row for {job_name}: {row}'
    return cell.group(1)


def _headers(body):
    head = re.search(r'<table class="tbl queue-tbl">.*?<thead>(.*?)</thead>',
                     body, re.S)
    assert head, 'no queue table rendered'
    return re.findall(r'<th[^>]*>(.*?)</th>', head.group(1), re.S)


def test_the_column_sits_between_tasks_and_priority(dash, client):
    admin, customer = dash
    hashfile = _hashfile(admin, customer, 'corp.txt', 5)
    _db.session.add(Jobs(name='queued-job', status='Queued', priority=3,
                         customer_id=customer.id, owner_id=admin.id,
                         hashfile_id=hashfile.id))
    _db.session.commit()

    headers = [h.strip() for h in _headers(
        client.get('/', follow_redirects=True).get_data(as_text=True))]

    assert 'Hashes' in headers, f'no Hashes column; headers are {headers}'
    assert headers.index('Tasks') + 1 == headers.index('Hashes'), (
        f'Hashes is not immediately right of Tasks: {headers}')
    assert headers.index('Hashes') + 1 == headers.index('Priority'), (
        f'Hashes is not immediately left of Priority: {headers}')


def test_the_count_is_the_hashfiles_account_total(dash, client):
    admin, customer = dash
    hashfile = _hashfile(admin, customer, 'corp.txt', 1234)
    _db.session.add(Jobs(name='big-queued-job', status='Queued', priority=3,
                         customer_id=customer.id, owner_id=admin.id,
                         hashfile_id=hashfile.id))
    _db.session.commit()

    cell = _hash_cell(client.get('/', follow_redirects=True).get_data(as_text=True),
                      'big-queued-job')
    assert cell.strip() == '1,234', f'Hashes cell reads {cell.strip()!r}'


def test_it_counts_accounts_not_distinct_hashes(dash, client):
    """Ten accounts sharing one hash is ten, matching Recovered's denominator.

    Counting distinct hashes would read 1 here and disagree with every other
    figure on the page for the same hashfile.
    """
    admin, customer = dash
    hashfile = _hashfile(admin, customer, 'shared.txt', 10, shared_hash=True)
    _db.session.add(Jobs(name='shared-hash-job', status='Queued', priority=3,
                         customer_id=customer.id, owner_id=admin.id,
                         hashfile_id=hashfile.id))
    _db.session.commit()

    cell = _hash_cell(client.get('/', follow_redirects=True).get_data(as_text=True),
                      'shared-hash-job')
    assert cell.strip() == '10', (
        f'Hashes cell reads {cell.strip()!r}; 10 accounts share 1 hash, and the '
        'column must agree with the Recovered denominator, which counts accounts')


def test_a_queued_job_with_no_hashfile_shows_a_dash(dash, client):
    """A job can be queued before a hashfile is attached; 0 would be a lie."""
    admin, customer = dash
    _db.session.add(Jobs(name='no-hashfile-job', status='Queued', priority=3,
                         customer_id=customer.id, owner_id=admin.id))
    _db.session.commit()

    cell = _hash_cell(client.get('/', follow_redirects=True).get_data(as_text=True),
                      'no-hashfile-job')
    assert 'dash' in cell, f'no empty-cell dash in the Hashes cell: {cell}'
    assert '0' not in cell, f'rendered 0 rather than "no hashfile": {cell}'


def test_the_queue_figure_matches_the_running_tables_denominator(dash, client):
    """One hashfile, two tables, one number.

    The running card's Recovered column reads X/Y for the same hashfile. If the
    queue used a different aggregate the two would disagree on screen, which is
    the whole reason both are fed from hashfile_account_totals.
    """
    from hashview.main.routes import hashfile_account_totals

    admin, customer = dash
    hashfile = _hashfile(admin, customer, 'corp.txt', 77)
    _db.session.add(Jobs(name='queued-job', status='Queued', priority=3,
                         customer_id=customer.id, owner_id=admin.id,
                         hashfile_id=hashfile.id))
    _db.session.commit()

    totals = hashfile_account_totals([hashfile.id])
    assert totals[hashfile.id] == 77

    cell = _hash_cell(client.get('/', follow_redirects=True).get_data(as_text=True),
                      'queued-job')
    assert cell.strip() == '77'


def test_the_count_costs_one_query_however_many_jobs_are_queued(dash, client):
    """The dashboard polls, so a per-job lookup here would be a per-poll N+1."""
    from sqlalchemy import event

    admin, customer = dash
    hashfile = _hashfile(admin, customer, 'corp.txt', 3)
    for i in range(6):
        _db.session.add(Jobs(name=f'q{i}', status='Queued', priority=3,
                             customer_id=customer.id, owner_id=admin.id,
                             hashfile_id=hashfile.id))
    _db.session.commit()

    counted = []
    engine = _db.engine

    @event.listens_for(engine, 'before_cursor_execute')
    def _record(conn, cursor, statement, parameters, context, executemany):
        if 'hashfile_hashes' in statement.lower() and 'count' in statement.lower():
            counted.append(statement)

    try:
        client.get('/', follow_redirects=True)
    finally:
        event.remove(engine, 'before_cursor_execute', _record)

    assert len(counted) <= 2, (
        f'{len(counted)} account-count queries for 6 queued jobs -- the shared '
        'aggregate has become a per-job lookup')
