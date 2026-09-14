"""Settings.catalog_prune_orphans — the switch that arms the orphan prune (#494).

Automatic row deletion has to be turnable off without rebuilding the image, so
the switch lives in the database rather than config.conf (which is baked at
build time). These cover the default, the round-trip through the settings form,
and the fact that an unchecked box actually disarms it — a BooleanField that is
never read back would leave the sweep pruning forever.
"""

from hashview.models import Settings, Users, db


def _settings():
    """The unit app seeds no Settings row; the model defaults are what ship."""
    settings = Settings.query.first()
    if settings is None:
        settings = Settings(retention_period=30, max_runtime_jobs=0, max_runtime_tasks=0)
        db.session.add(settings)
        db.session.commit()
    return settings


def _admin():
    u = Users(first_name="A", last_name="D", email_address="prune-adm@e.com",
              password="x" * 60, admin=True, api_key="key-prune")
    db.session.add(u)
    db.session.commit()
    return u


def _login(client, user):
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True


def _settings_post(settings, **overrides):
    """The whole settings form — a partial POST fails validation and saves nothing."""
    data = {
        "retention_period": settings.retention_period or 30,
        "max_runtime_jobs": settings.max_runtime_jobs or 0,
        "max_runtime_tasks": settings.max_runtime_tasks or 0,
        "agent_timeout_minutes": settings.agent_timeout_minutes or 60,
        "chunk_target_duration": settings.chunk_target_duration or 3600,
        "auth_method": "local",
        "submit": "Update",
    }
    data.update(overrides)
    return data


def test_default_is_on(app):
    """A fresh install prunes: the debris it removes is unusable by construction."""
    assert _settings().catalog_prune_orphans is True


def test_toggle_off_round_trips_through_the_form(app, client):
    _login(client, _admin())
    settings = _settings()

    # unchecked box == the key is absent from the POST, not "false"
    resp = client.post("/settings", data=_settings_post(settings), follow_redirects=False)
    assert resp.status_code == 302
    assert Settings.query.first().catalog_prune_orphans is False

    resp = client.post("/settings",
                       data=_settings_post(settings, catalog_prune_orphans="y"),
                       follow_redirects=False)
    assert resp.status_code == 302
    assert Settings.query.first().catalog_prune_orphans is True


def test_the_switch_renders_on_the_settings_page(app, client):
    _settings()
    _login(client, _admin())
    resp = client.get("/settings")
    assert resp.status_code == 200
    assert b'name="catalog_prune_orphans"' in resp.data
