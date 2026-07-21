"""Unit tests for provider-backed dynamic wordlists.

Covers the ``update_dynamic_wordlist`` provider branch, backward-compat with the
internal (name-substring) generators, the job-wizard detection helper, and that a
provider's secret is never serialized by the API encoder.
"""
import json
from unittest import mock

import pytest

from hashview.models import (
    Customers,
    Hashes,
    Jobs,
    JobTasks,
    Tasks,
    Users,
    WordlistProviders,
    Wordlists,
    db,
)
from hashview.utils.utils import update_dynamic_wordlist


def _user():
    u = Users(first_name="t", last_name="u", email_address="t@example.com",
              password="x" * 60, admin=True)
    db.session.add(u)
    db.session.commit()
    return u


def _provider(**over):
    base = dict(name="Weakpass", base_url="https://api.example.com/hv",
                auth_type="bearer", provider_secret="s3cr3t", verify_tls=True,
                enabled=True, owner_id=1)
    base.update(over)
    p = WordlistProviders(**base)
    db.session.add(p)
    db.session.commit()
    return p


def _wordlist(tmp_path, name, provider_id=None):
    path = str(tmp_path / f"{name.replace(' ', '_')}.txt")
    open(path, "w").close()
    wl = Wordlists(name=name, owner_id=1, type="dynamic", path=path,
                   checksum="", size=0, provider_id=provider_id)
    db.session.add(wl)
    db.session.commit()
    return wl


def _job(provider_input=None):
    db.session.add(Customers(name="c"))
    db.session.commit()
    job = Jobs(name="j", status="Ready", customer_id=1, owner_id=1,
               provider_input=provider_input)
    db.session.add(job)
    db.session.commit()
    return job


@pytest.mark.security
def test_provider_branch_calls_generate_with_job_input(app, tmp_path):
    _user()
    provider = _provider()
    wl = _wordlist(tmp_path, "(DYNAMIC) Weakpass", provider_id=provider.id)
    job = _job(provider_input="example.com")

    with mock.patch("hashview.utils.wordlist_providers.generate_wordlist") as gen:
        update_dynamic_wordlist(wl.id, job.id)

    gen.assert_called_once()
    called_provider, called_input, called_path = gen.call_args[0]
    assert called_provider.id == provider.id
    assert called_input == "example.com"
    assert called_path == wl.path


@pytest.mark.security
def test_provider_branch_no_input_noops(app, tmp_path):
    _user()
    provider = _provider()
    wl = _wordlist(tmp_path, "(DYNAMIC) Weakpass", provider_id=provider.id)
    job = _job(provider_input=None)

    with mock.patch("hashview.utils.wordlist_providers.generate_wordlist") as gen:
        update_dynamic_wordlist(wl.id, job.id)

    gen.assert_not_called()


@pytest.mark.security
def test_provider_branch_no_job_noops(app, tmp_path):
    _user()
    provider = _provider()
    wl = _wordlist(tmp_path, "(DYNAMIC) Weakpass", provider_id=provider.id)

    with mock.patch("hashview.utils.wordlist_providers.generate_wordlist") as gen:
        update_dynamic_wordlist(wl.id, None)  # e.g. manual UI refresh, no running job

    gen.assert_not_called()


@pytest.mark.security
def test_backward_compat_internal_generator_still_runs(app, tmp_path):
    """A dynamic wordlist with provider_id=None must still route by name."""
    _user()
    wl = _wordlist(tmp_path, "(DYNAMIC) All Recovered Passwords", provider_id=None)
    h = Hashes(sub_ciphertext="0" * 32, ciphertext="a" * 32, hash_type=1000,
               cracked=True, plaintext="hunter2")
    db.session.add(h)
    db.session.commit()

    # The provider client must NOT be consulted for a non-provider wordlist.
    with mock.patch("hashview.utils.wordlist_providers.generate_wordlist") as gen:
        update_dynamic_wordlist(wl.id)

    gen.assert_not_called()
    assert "hunter2" in open(wl.path).read().splitlines()


@pytest.mark.security
def test_job_uses_provider_wordlist_helper(app, tmp_path):
    from hashview.jobs.routes import _job_uses_provider_wordlist

    _user()
    provider = _provider()
    wl = _wordlist(tmp_path, "(DYNAMIC) Weakpass", provider_id=provider.id)
    job = _job()
    task = Tasks(name="t", hc_attackmode=0, owner_id=1, wl_id=wl.id)
    db.session.add(task)
    db.session.commit()
    db.session.add(JobTasks(job_id=job.id, task_id=task.id, status="Not Started"))
    db.session.commit()

    assert _job_uses_provider_wordlist(job.id) is True

    other = _job()
    assert _job_uses_provider_wordlist(other.id) is False


@pytest.mark.security
def test_provider_secret_is_never_serialized(app):
    from hashview.api.routes import AlchemyEncoder

    _user()
    provider = _provider(provider_secret="TOP-SECRET-TOKEN")
    blob = json.dumps(provider, cls=AlchemyEncoder)

    assert "provider_secret" not in blob
    assert "TOP-SECRET-TOKEN" not in blob
    # a non-sensitive field still serializes
    assert "base_url" in blob
