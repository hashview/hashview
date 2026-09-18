"""An Incomplete job gets the same Info and Analytics actions as any other.

Both were hidden behind `{% if job.status != 'Incomplete' %}`, which is exactly
backwards: an incomplete job is the one an operator most needs to look into --
it either never finished being built, or it ran and ended with work outstanding.
The info modal was already rendered for every job, so only the button was
missing.

Analytics is gated on the hashfile instead of on the status. A job abandoned at
step one of the creation wizard exists with status Incomplete and no hashfile at
all (jobs_add commits the row before the hashfile step), and url_for drops a
None parameter -- so the link would quietly become "every hashfile this customer
owns" rather than this job's.
"""

import re

import pytest

from hashview.models import Hashfiles, Jobs
from hashview.models import db as _db
from tests.unit.helpers import login, make_admin, make_customer

pytestmark = pytest.mark.security


def _job(owner, customer, status, hashfile_id=None, name=None):
    job = Jobs(name=name or f'job-{status.lower()}', status=status,
               customer_id=customer.id, owner_id=owner.id, priority=3,
               hashfile_id=hashfile_id)
    _db.session.add(job)
    _db.session.commit()
    return job


def _actions(body, job):
    """Just this job's action cell.

    Anchored on the row's own Info onclick and its own delete button, so a
    sibling job's markup can never satisfy an assertion made about this one --
    which matters because these tests render several jobs at once.
    """
    end = body.index(f"getElementById('info-{job.id}')")
    start = body.rfind('<td', 0, end)
    return body[start:body.index(f"del-{job.id}", end) + 40]


@pytest.fixture()
def listing(app, client):
    with app.app_context():
        admin = make_admin()
        login(client, admin)
        customer = make_customer(name='Acme')
        hashfile = Hashfiles(name='hf.txt', customer_id=customer.id,
                             owner_id=admin.id)
        _db.session.add(hashfile)
        _db.session.commit()
        yield admin, customer, hashfile


def _body(client):
    resp = client.get('/jobs', follow_redirects=True)
    assert resp.status_code == 200
    return resp.get_data(as_text=True)


def test_an_incomplete_job_has_an_info_button(listing, client):
    admin, customer, hashfile = listing
    job = _job(admin, customer, 'Incomplete', hashfile_id=hashfile.id)

    body = _body(client)
    assert f"getElementById('info-{job.id}')" in body, (
        'an Incomplete job has no Info button, though its modal is rendered')


def test_an_incomplete_job_has_an_analytics_link(listing, client):
    admin, customer, hashfile = listing
    job = _job(admin, customer, 'Incomplete', hashfile_id=hashfile.id)

    body = _body(client)
    assert f'hashfile_id={hashfile.id}' in _actions(body, job), (
        'an Incomplete job has no Analytics link')


@pytest.mark.parametrize('status', ['Queued', 'Running', 'Completed',
                                    'Canceled', 'Incomplete'])
def test_every_status_gets_info_and_analytics(listing, client, status):
    """The point is parity: no status is special here."""
    admin, customer, hashfile = listing
    job = _job(admin, customer, status, hashfile_id=hashfile.id,
               name=f'job-{status}')

    body = _body(client)
    actions = _actions(body, job)
    assert f"getElementById('info-{job.id}')" in body, f'{status}: no Info button'
    assert f'hashfile_id={hashfile.id}' in actions, f'{status}: no Analytics link'


def test_a_job_with_no_hashfile_gets_no_live_analytics_link(listing, client):
    """A job abandoned at step one of the wizard has no hashfile.

    url_for drops a None parameter, so a link built anyway would resolve to the
    customer-wide analytics view -- every hashfile they own, presented under
    this job's row. Show the control disabled instead of pointing somewhere
    broader than the operator asked for.
    """
    admin, customer, _hashfile = listing
    job = _job(admin, customer, 'Incomplete', hashfile_id=None,
               name='abandoned-at-step-one')

    body = _body(client)
    actions = _actions(body, job)
    assert 'No hashfile assigned yet' in actions, (
        'no disabled-analytics affordance for a job without a hashfile')
    assert not re.search(r'get_analytics|/analytics', actions), (
        'a job with no hashfile still links to analytics, which would widen the '
        'view to every hashfile the customer owns')
    # The Info button does not depend on a hashfile.
    assert f"getElementById('info-{job.id}')" in body


def test_the_info_modal_exists_for_an_incomplete_job(listing, client):
    """The button is useless if the dialog it opens was never rendered."""
    admin, customer, hashfile = listing
    job = _job(admin, customer, 'Incomplete', hashfile_id=hashfile.id)

    body = _body(client)
    assert f'id="info-{job.id}"' in body, (
        'the Info button would call showModal() on a missing element')
