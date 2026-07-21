import pytest

from hashview.models import Users, db
from tests.unit.helpers import login, make_admin


@pytest.mark.parametrize("value", ["dark", "light-paper", "light-invert", "light-clean"])
def test_explicit_theme_is_baked_into_html(app, client, value):
    admin = make_admin()
    admin.theme = value
    db.session.commit()
    login(client, admin)
    html = client.get("/users").data.decode()
    assert f'data-theme="{value}"' in html
    assert f'data-theme-pref="{value}"' in html


def test_auto_theme_defers_to_script(app, client):
    admin = make_admin()
    admin.theme = "auto"
    db.session.commit()
    login(client, admin)
    html = client.get("/users").data.decode()
    assert 'data-theme-pref="auto"' in html
    # server bakes the safe dark default for auto; the script resolves the rest
    assert 'data-theme="dark"' in html
    assert "prefers-color-scheme: light" in html


def test_login_page_has_theme_script_and_no_pref(app, client):
    html = client.get("/login").data.decode()
    assert "prefers-color-scheme: light" in html
    assert 'data-theme-pref=""' in html
