import pytest

from hashview.models import Users
from hashview.users.routes import EXPLICIT_THEMES, VALID_THEMES
from tests.unit.helpers import login, make_user


@pytest.mark.parametrize("value", sorted(VALID_THEMES))
def test_set_theme_accepts_valid_values(app, client, value):
    user = make_user()
    login(client, user)
    resp = client.post("/profile/set_theme", data={"theme": value})
    assert resp.status_code == 200
    assert resp.is_json and resp.get_json()["ok"] is True
    assert Users.query.get(user.id).theme == value


def test_set_theme_rejects_invalid_value(app, client):
    user = make_user()
    login(client, user)
    before = Users.query.get(user.id).theme  # server default 'auto'
    resp = client.post("/profile/set_theme", data={"theme": "rainbow"})
    assert resp.status_code == 400
    assert Users.query.get(user.id).theme == before


def test_set_theme_rejects_missing_field(app, client):
    user = make_user()
    login(client, user)
    before = Users.query.get(user.id).theme  # server default 'auto'
    resp = client.post("/profile/set_theme", data={})
    assert resp.status_code == 400
    assert Users.query.get(user.id).theme == before


def test_set_theme_requires_login(app, client):
    resp = client.post("/profile/set_theme", data={"theme": "dark"},
                       follow_redirects=False)
    assert resp.status_code in (302, 401)


def test_valid_themes_membership():
    assert "auto" in VALID_THEMES
    assert "auto" not in EXPLICIT_THEMES
    assert EXPLICIT_THEMES == VALID_THEMES - {"auto"}
