"""Route tests for the wordlist-provider settings CRUD.

Verifies admin gating, that adding a provider also creates its backing (DYNAMIC)
wordlist, edit's write-only secret handling, and the in-use delete guard.
"""
import pytest

from hashview.models import Tasks, WordlistProviders, Wordlists, db
from tests.unit.helpers import login, make_admin, make_user


def _add_payload(**over):
    data = dict(name="Weakpass", description="", base_url="https://api.example.com/hv",
                auth_type="bearer", username="", provider_secret="tok",
                verify_tls="y", enabled="y")
    data.update(over)
    return data


@pytest.mark.security
def test_add_provider_creates_provider_and_wordlist(app, client):
    login(client, make_admin())
    resp = client.post("/settings/providers/add", data=_add_payload(), follow_redirects=False)
    assert resp.status_code == 302

    provider = WordlistProviders.query.filter_by(name="Weakpass").first()
    assert provider is not None
    assert provider.provider_secret == "tok"
    wl = Wordlists.query.filter_by(provider_id=provider.id).first()
    assert wl is not None
    assert wl.type == "dynamic"
    assert wl.name == "(DYNAMIC) Weakpass"


@pytest.mark.security
def test_add_provider_rejects_non_http_base_url(app, client):
    login(client, make_admin())
    client.post("/settings/providers/add",
                data=_add_payload(base_url="ftp://host/x"), follow_redirects=False)
    assert WordlistProviders.query.count() == 0


@pytest.mark.security
def test_add_provider_rejects_duplicate_name(app, client):
    login(client, make_admin())
    client.post("/settings/providers/add", data=_add_payload(), follow_redirects=False)
    client.post("/settings/providers/add",
                data=_add_payload(base_url="https://other.example/x"), follow_redirects=False)
    assert WordlistProviders.query.filter_by(name="Weakpass").count() == 1


@pytest.mark.security
def test_edit_blank_secret_keeps_existing(app, client):
    login(client, make_admin())
    client.post("/settings/providers/add", data=_add_payload(), follow_redirects=False)
    provider = WordlistProviders.query.filter_by(name="Weakpass").first()

    client.post(f"/settings/providers/{provider.id}/edit",
                data=_add_payload(name="Weakpass", description="renamed", provider_secret=""),
                follow_redirects=False)
    refreshed = WordlistProviders.query.get(provider.id)
    assert refreshed.provider_secret == "tok"           # unchanged
    assert refreshed.description == "renamed"
    # backing wordlist name stays in sync when the provider name is unchanged
    assert Wordlists.query.filter_by(provider_id=provider.id).first().name == "(DYNAMIC) Weakpass"


@pytest.mark.security
def test_delete_blocked_when_wordlist_in_use(app, client):
    login(client, make_admin())
    client.post("/settings/providers/add", data=_add_payload(), follow_redirects=False)
    provider = WordlistProviders.query.filter_by(name="Weakpass").first()
    wl = Wordlists.query.filter_by(provider_id=provider.id).first()
    db.session.add(Tasks(name="t", hc_attackmode=0, owner_id=1, wl_id=wl.id))
    db.session.commit()

    client.post(f"/settings/providers/{provider.id}/delete", follow_redirects=False)
    assert WordlistProviders.query.get(provider.id) is not None   # still there


@pytest.mark.security
def test_delete_removes_provider_and_wordlist_when_unused(app, client):
    login(client, make_admin())
    client.post("/settings/providers/add", data=_add_payload(), follow_redirects=False)
    provider = WordlistProviders.query.filter_by(name="Weakpass").first()
    pid = provider.id

    client.post(f"/settings/providers/{pid}/delete", follow_redirects=False)
    assert WordlistProviders.query.get(pid) is None
    assert Wordlists.query.filter_by(provider_id=pid).first() is None


@pytest.mark.security
def test_non_admin_forbidden_on_all_provider_routes(app, client):
    login(client, make_user())
    for path in ("/settings/providers/add",
                 "/settings/providers/1/edit",
                 "/settings/providers/1/delete",
                 "/settings/providers/1/test"):
        resp = client.post(path, data=_add_payload(), follow_redirects=False)
        assert resp.status_code == 403, path
