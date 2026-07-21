# Light/Dark Theme Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add user-selectable themes (dark + three light skins) with an OS-aware default, persisted per user, applied without a flash of the wrong theme.

**Architecture:** A `theme` column on `Users` (`auto`/`dark`/`light-paper`/`light-invert`/`light-clean`). The server bakes `data-theme` onto `<html>` and a pre-paint inline script resolves `auto` against the OS. Light skins are token-override blocks in `phosphor.css`. A segmented control in the account modal applies the theme live and POSTs it to a CSRF-protected route.

**Tech Stack:** Flask + SQLAlchemy + Alembic (Flask-Migrate), Jinja2 templates, vanilla JS, CSS custom properties, pytest + Playwright (python) for e2e.

---

## File Structure

- `hashview/models.py` — add `Users.theme` column.
- `migrations/versions/d4e7a1c9f2b8_add_users_theme.py` — **new** migration.
- `hashview/static/css/phosphor.css` — append three `[data-theme="light-*"]` blocks.
- `hashview/templates/layout.html.j2` — `<html>` attrs + pre-paint script + theme control in modal + JS.
- `hashview/templates/setup_base.html.j2` — `<html>` attrs + pre-paint script.
- `hashview/users/routes.py` — new `set_theme` route.
- `tests/unit/test_users_set_theme.py` — **new** unit tests.
- `tests/unit/test_layout_theme_render.py` — **new** template render tests.
- `tests/e2e/test_theme.py` — **new** e2e tests.

**Allowed theme constant:** define once in `hashview/users/routes.py` as
`VALID_THEMES = {'auto', 'dark', 'light-paper', 'light-invert', 'light-clean'}`
and `EXPLICIT_THEMES = VALID_THEMES - {'auto'}`. Import into tests; do not
re-declare the literal set elsewhere.

---

## Task 1: Add `theme` column to the Users model

**Files:**
- Modify: `hashview/models.py:20-48` (the `Users` class column block)

- [ ] **Step 1: Add the column**

In `hashview/models.py`, inside `class Users`, add after the `azure_oid` line (around line 48):

```python
    theme             = db.Column(db.String(16), nullable=False, default='auto')
```

- [ ] **Step 2: Sanity import**

Run: `python -c "from hashview.models import Users; print(Users.theme)"`
Expected: prints a column reference, no ImportError.

- [ ] **Step 3: Commit**

```bash
git add hashview/models.py
git commit -m "feat(models): add per-user theme column"
```

---

## Task 2: Alembic migration for the theme column

**Files:**
- Create: `migrations/versions/d4e7a1c9f2b8_add_users_theme.py`

- [ ] **Step 1: Confirm current head**

Run: `grep -rl "down_revision = None\|Revises:" migrations/versions/ | head` then
Run: `python -c "import os;print([f for f in os.listdir('migrations/versions') if f.endswith('.py')])"`
Confirm the current head revision id is `c8b3f0a14d27` (the squash delta). If it
differs, use the actual head as `down_revision` in Step 2.

- [ ] **Step 2: Write the migration**

Create `migrations/versions/d4e7a1c9f2b8_add_users_theme.py`:

```python
"""add users.theme column

Revision ID: d4e7a1c9f2b8
Revises: c8b3f0a14d27
Create Date: 2026-07-21 00:00:00.000000

Adds a per-user theme preference. Additive DDL only; existing rows backfill to
the server-default 'auto' (follow the OS color-scheme).
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'd4e7a1c9f2b8'
down_revision = 'c8b3f0a14d27'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        'users',
        sa.Column('theme', sa.String(length=16), nullable=False,
                  server_default='auto'),
    )


def downgrade():
    op.drop_column('users', 'theme')
```

- [ ] **Step 3: Apply and verify**

Run: `flask db upgrade` (from repo root with the app env configured)
Expected: upgrades to `d4e7a1c9f2b8` with no error.
Run: `flask db current`
Expected: shows `d4e7a1c9f2b8 (head)`.

- [ ] **Step 4: Commit**

```bash
git add migrations/versions/d4e7a1c9f2b8_add_users_theme.py
git commit -m "feat(migration): add users.theme column"
```

---

## Task 3: `set_theme` route (TDD)

**Files:**
- Modify: `hashview/users/routes.py` (add constant near top after imports; add route after `generate_api_key`, ~line 371)
- Create: `tests/unit/test_users_set_theme.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_users_set_theme.py`. Use the project's existing unit
test fixtures (look at another file in `tests/unit/` for the `client` /
logged-in-user fixture names and reuse them — do not invent new ones). The tests:

```python
import pytest

from hashview.users.routes import EXPLICIT_THEMES, VALID_THEMES


@pytest.mark.parametrize("value", sorted(VALID_THEMES))
def test_set_theme_accepts_valid_values(logged_in_client, db_session, value):
    resp = logged_in_client.post(
        "/profile/set_theme",
        data={"theme": value, "csrf_token": logged_in_client.csrf_token()},
    )
    assert resp.status_code == 200
    assert resp.is_json and resp.get_json()["ok"] is True
    from hashview.models import Users
    assert Users.query.first().theme == value


def test_set_theme_rejects_invalid_value(logged_in_client, db_session):
    from hashview.models import Users
    before = Users.query.first().theme
    resp = logged_in_client.post(
        "/profile/set_theme",
        data={"theme": "rainbow", "csrf_token": logged_in_client.csrf_token()},
    )
    assert resp.status_code == 400
    assert Users.query.first().theme == before


def test_set_theme_requires_login(client):
    resp = client.post("/profile/set_theme", data={"theme": "dark"})
    assert resp.status_code in (302, 401)


def test_valid_themes_membership():
    assert "auto" in VALID_THEMES
    assert "auto" not in EXPLICIT_THEMES
    assert EXPLICIT_THEMES == VALID_THEMES - {"auto"}
```

> If `tests/unit/` has no `logged_in_client` / `csrf_token` helper, adapt these
> to the actual fixtures used by an existing route test (e.g. copy the login +
> CSRF-extraction pattern from the nearest `tests/unit/test_*routes*.py`).
> Keep the assertions identical.

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/test_users_set_theme.py -v`
Expected: FAIL — `ImportError: cannot import name 'EXPLICIT_THEMES'` / 404 on route.

- [ ] **Step 3: Add the constant**

In `hashview/users/routes.py`, after the `users = Blueprint('users', __name__)`
line (~line 70), add:

```python
VALID_THEMES = {'auto', 'dark', 'light-paper', 'light-invert', 'light-clean'}
EXPLICIT_THEMES = VALID_THEMES - {'auto'}
```

- [ ] **Step 4: Add the route**

In `hashview/users/routes.py`, after the `generate_api_key` function (~line 371):

```python
@users.route("/profile/set_theme", methods=['POST'])
@login_required
def set_theme():
    """Persist the account theme preference chosen from the account-settings
    modal. CSRF-protected (Flask-WTF validates the csrf_token field on POST).
    Returns JSON so the segmented control can save without a page reload."""
    value = (request.form.get('theme') or '').strip()
    if value not in VALID_THEMES:
        return jsonify(ok=False, error='invalid theme'), 400
    current_user.theme = value
    db.session.commit()
    return jsonify(ok=True, theme=value)
```

Ensure `jsonify` and `request` are imported from `flask` at the top of the file
(the `from flask import (...)` block near line 6). Add `jsonify` to that import
list if missing.

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/unit/test_users_set_theme.py -v`
Expected: PASS (all parametrized cases + rejects + login + membership).

- [ ] **Step 6: Commit**

```bash
git add hashview/users/routes.py tests/unit/test_users_set_theme.py
git commit -m "feat(users): CSRF-protected set_theme route"
```

---

## Task 4: Server-side `data-theme` + pre-paint script in the layout (TDD)

**Files:**
- Modify: `hashview/templates/layout.html.j2:1-5` (the `<html>` tag + first script)
- Create: `tests/unit/test_layout_theme_render.py`

- [ ] **Step 1: Write the failing render tests**

Create `tests/unit/test_layout_theme_render.py` (reuse the same fixtures as
Task 3; `logged_in_client` renders an authenticated page, `client` an anon one):

```python
import pytest

from hashview.models import Users


@pytest.mark.parametrize("value", ["dark", "light-paper", "light-invert", "light-clean"])
def test_explicit_theme_is_baked_into_html(logged_in_client, db_session, value):
    Users.query.first().theme = value
    from hashview.models import db
    db.session.commit()
    html = logged_in_client.get("/").data.decode()
    assert f'data-theme="{value}"' in html
    assert 'data-theme-pref="%s"' % value in html


def test_auto_theme_defers_to_script(logged_in_client, db_session):
    Users.query.first().theme = "auto"
    from hashview.models import db
    db.session.commit()
    html = logged_in_client.get("/").data.decode()
    # server picks a safe default but marks the pref so the pre-paint script
    # resolves against the OS
    assert 'data-theme-pref="auto"' in html
    assert "prefers-color-scheme: light" in html


def test_login_page_has_theme_script_and_no_pref(client):
    html = client.get("/login").data.decode()
    assert "prefers-color-scheme: light" in html
    assert 'data-theme-pref=""' in html
```

- [ ] **Step 2: Run to verify failure**

Run: `pytest tests/unit/test_layout_theme_render.py -v`
Expected: FAIL — attributes/script not present yet.

- [ ] **Step 3: Update the `<html>` tag and add the pre-paint script**

In `hashview/templates/layout.html.j2`, replace line 2 (the `<html ...>` tag):

```jinja
<html lang="en" data-glow="subtle" data-scanlines="{% block scanlines %}on{% endblock %}" data-density="comfortable"
      data-theme="{% if current_user.is_authenticated and current_user.theme in ['dark','light-paper','light-invert','light-clean'] %}{{ current_user.theme }}{% else %}dark{% endif %}"
      data-theme-pref="{% if current_user.is_authenticated %}{{ current_user.theme }}{% else %}{% endif %}">
```

Then, immediately after the existing sidebar-collapse `<script>` (line 5),
add a second pre-paint script:

```html
    <script>/* theme — applied before paint to avoid a flash of the wrong theme */(function(){try{var el=document.documentElement;var pref=el.getAttribute('data-theme-pref');if(!pref){pref=localStorage.getItem('hv_theme')||'auto';}var resolved=pref;if(pref==='auto'){resolved=(window.matchMedia&&window.matchMedia('(prefers-color-scheme: light)').matches)?'light-paper':'dark';}el.setAttribute('data-theme',resolved);}catch(e){}})();</script>
```

- [ ] **Step 4: Run to verify pass**

Run: `pytest tests/unit/test_layout_theme_render.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add hashview/templates/layout.html.j2 tests/unit/test_layout_theme_render.py
git commit -m "feat(ui): server-baked data-theme + no-flash pre-paint script"
```

---

## Task 5: Apply the same theme handling to the setup pages

**Files:**
- Modify: `hashview/templates/setup_base.html.j2` (its `<html>` tag + head)

- [ ] **Step 1: Inspect the setup base head**

Run: `sed -n '1,15p' hashview/templates/setup_base.html.j2`
Identify the `<html ...>` tag line and the first line inside `<head>`.

- [ ] **Step 2: Add theme attributes + script**

On the `<html>` tag add (setup runs pre-login, so no user record):

```jinja
data-theme="dark" data-theme-pref=""
```

As the first element inside `<head>`, add the identical pre-paint script from
Task 4 Step 3 (copy it verbatim):

```html
    <script>/* theme — applied before paint to avoid a flash of the wrong theme */(function(){try{var el=document.documentElement;var pref=el.getAttribute('data-theme-pref');if(!pref){pref=localStorage.getItem('hv_theme')||'auto';}var resolved=pref;if(pref==='auto'){resolved=(window.matchMedia&&window.matchMedia('(prefers-color-scheme: light)').matches)?'light-paper':'dark';}el.setAttribute('data-theme',resolved);}catch(e){}})();</script>
```

- [ ] **Step 3: Smoke test the setup page renders**

Run: `pytest tests/unit -k setup -q` (if setup route tests exist) OR
Run: `python -c "from hashview import create_app; app=create_app(); c=app.test_client(); print(c.get('/setup').status_code)"`
Expected: a 2xx/3xx status, no template error. (Adjust the setup URL if needed.)

- [ ] **Step 4: Commit**

```bash
git add hashview/templates/setup_base.html.j2
git commit -m "feat(ui): theme handling on setup pages"
```

---

## Task 6: Light theme CSS palettes

**Files:**
- Modify: `hashview/static/css/phosphor.css` (append after the `html[data-density="dense"]` block, ~line 82)

- [ ] **Step 1: Append the three light-theme blocks**

Add to `hashview/static/css/phosphor.css` after the density block:

```css
/* =========================================================================
   LIGHT THEMES — token overrides on <html data-theme>. Dark is the default
   :root above and is intentionally left untouched.
   ========================================================================= */

/* --- Paper Terminal: warm paper, dark ink, amber accent, no glow/scanlines. */
html[data-theme="light-paper"] {
  --bg:          #efeadc;
  --bg-grad:     #e9e3d2;
  --surface:     #f6f2e6;
  --surface-2:   #f0ebdb;
  --surface-3:   #e7e0cd;
  --inset:       #e2dcc9;

  --border:        #cfc7b0;
  --border-soft:   #ddd6c1;
  --border-bright: #b8ad8f;

  --text:        #1c1b16;
  --text-dim:    #5c5647;
  --text-faint:  #8a806690;
  --text-mute:   #7a6f57;

  --green:       #2fae5b;
  --green-deep:  #1f7d40;
  --green-dim:   #cfe6d5;
  --amber:       #b8901f;
  --amber-deep:  #8a6c15;
  --amber-dim:   #efe2c0;
  --red:         #c4362f;
  --red-dim:     #f0d6d3;
  --cyan:        #1f8f99;

  --primary:      var(--amber);
  --primary-deep: var(--amber-deep);
  --primary-dim:  var(--amber-dim);
  --primary-rgb:  184, 144, 31;

  --glow-sm: none;
  --glow:    none;
  --glow-text: none;
}
html[data-theme="light-paper"] .scanlines { display: none; }

/* --- Minimal Invert: light bg, phosphor green/amber accents, faint glow. */
html[data-theme="light-invert"] {
  --bg:          #f3f4ef;
  --bg-grad:     #eceee7;
  --surface:     #fbfbf6;
  --surface-2:   #f4f5ef;
  --surface-3:   #eaece4;
  --inset:       #e6e8df;

  --border:        #c9ccbf;
  --border-soft:   #d8dace;
  --border-bright: #aab09c;

  --text:        #14231a;
  --text-dim:    #4a5a4e;
  --text-faint:  #7c8a7690;
  --text-mute:   #5f6d5c;

  --green:       #2fae5b;
  --green-deep:  #1f7d40;
  --green-dim:   #cfe6d5;
  --amber:       #b8901f;
  --amber-deep:  #8a6c15;
  --amber-dim:   #efe2c0;
  --red:         #c4362f;
  --red-dim:     #f0d6d3;
  --cyan:        #1f8f99;

  --primary:      var(--green);
  --primary-deep: var(--green-deep);
  --primary-dim:  var(--green-dim);
  --primary-rgb:  47, 174, 91;

  --glow-sm:   0 0 3px rgba(var(--primary-rgb), 0.25);
  --glow:      0 0 6px rgba(var(--primary-rgb), 0.20);
  --glow-text: 0 0 4px rgba(var(--primary-rgb), 0.18);
}
html[data-theme="light-invert"] .scanlines { display: none; }

/* --- Clean Light UI: conventional dashboard. Sans body, soft shadows, neutral
   accent, no CRT effects. This is the only theme that changes typography. */
html[data-theme="light-clean"] {
  --bg:          #f5f6f8;
  --bg-grad:     #eef0f3;
  --surface:     #ffffff;
  --surface-2:   #f9fafb;
  --surface-3:   #f1f3f5;
  --inset:       #eef0f2;

  --border:        #e2e5e9;
  --border-soft:   #edeff2;
  --border-bright: #cdd2d8;

  --text:        #111827;
  --text-dim:    #4b5563;
  --text-faint:  #9ca3af90;
  --text-mute:   #6b7280;

  --green:       #16a34a;
  --green-deep:  #15803d;
  --green-dim:   #dcfce7;
  --amber:       #d97706;
  --amber-deep:  #b45309;
  --amber-dim:   #fef3c7;
  --red:         #dc2626;
  --red-dim:     #fee2e2;
  --cyan:        #0891b2;

  --primary:      #2563eb;
  --primary-deep: #1d4ed8;
  --primary-dim:  #dbeafe;
  --primary-rgb:  37, 99, 235;

  --glow-sm: none;
  --glow:    none;
  --glow-text: none;

  /* conventional dashboard: sans body instead of the console mono */
  --mono: "IBM Plex Sans", system-ui, -apple-system, sans-serif;
}
html[data-theme="light-clean"] .scanlines { display: none; }
html[data-theme="light-clean"] body { font-family: var(--sans); }
```

- [ ] **Step 2: Lint the CSS loads**

Run: `python -c "import pathlib;s=pathlib.Path('hashview/static/css/phosphor.css').read_text();print('light-paper' in s, 'light-invert' in s, 'light-clean' in s, s.count('{')==s.count('}'))"`
Expected: `True True True True` (all three present, braces balanced).

- [ ] **Step 3: Commit**

```bash
git add hashview/static/css/phosphor.css
git commit -m "feat(ui): Paper/Invert/Clean light theme palettes"
```

---

## Task 7: Theme segmented control in the account modal

**Files:**
- Modify: `hashview/templates/layout.html.j2` — add a section inside the modal body (after the `API access` field block, before the form's closing/next section) and a JS helper near the modal-reopen script (~line 262).

- [ ] **Step 1: Add the theme control markup**

In `hashview/templates/layout.html.j2`, inside the account-settings modal body,
after the API-access `<div class="field">...</div>` block, insert:

```html
                {# APPEARANCE #}
                <div class="as-sec">Appearance</div>
                <div class="field" style="margin-bottom:0;">
                    <label class="field-label">Theme</label>
                    <div class="hv-theme-seg" role="group" aria-label="Theme"
                         data-current="{{ current_user.theme }}"
                         style="display:flex; gap:6px; flex-wrap:wrap;">
                        {% for val, lbl in [('auto','System'),('light-paper','Paper'),('light-invert','Invert'),('light-clean','Clean'),('dark','Dark')] %}
                        <button type="button" class="btn hv-theme-opt{{ ' active' if current_user.theme == val else '' }}"
                                data-theme-value="{{ val }}" onclick="hvSetTheme('{{ val }}', this)">{{ lbl }}</button>
                        {% endfor %}
                    </div>
                    <span class="field-hint" style="margin-top:8px; display:block;">System follows your operating system's light/dark setting. Your choice is saved to your account.</span>
                </div>
```

Note: this control lives inside the existing `<form>` but its buttons are
`type="button"`, so they never submit the profile form.

- [ ] **Step 2: Add the JS helper**

Near the other modal helpers in `layout.html.j2` (around line 262, in the same
`<script>` region that handles the modal), add:

```javascript
function hvSetTheme(value, btn) {
    // apply live
    var resolved = value;
    if (value === 'auto') {
        resolved = (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) ? 'light-paper' : 'dark';
    }
    document.documentElement.setAttribute('data-theme', resolved);
    document.documentElement.setAttribute('data-theme-pref', value);
    try { localStorage.setItem('hv_theme', value); } catch (e) {}
    // reflect active state on the segmented control
    if (btn && btn.parentNode) {
        btn.parentNode.querySelectorAll('.hv-theme-opt').forEach(function (b) { b.classList.remove('active'); });
        btn.classList.add('active');
    }
    // persist to the account
    var token = document.querySelector('#account-settings-modal input[name="csrf_token"]');
    var body = new URLSearchParams();
    body.set('theme', value);
    if (token) { body.set('csrf_token', token.value); }
    fetch("{{ url_for('users.set_theme') }}", {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: body.toString(),
        credentials: 'same-origin'
    }).catch(function () {});
}
```

- [ ] **Step 3: Add minimal active-state CSS**

In `hashview/static/css/phosphor.css`, append:

```css
.hv-theme-opt.active { border-color: var(--primary); color: var(--primary); box-shadow: var(--glow-sm); }
```

- [ ] **Step 4: Manual smoke check**

Run the app locally (`flask run` or the project's run script), log in, open the
account modal, click each theme button.
Expected: page recolors instantly; the active button highlights; a network POST
to `/profile/set_theme` returns `{"ok": true}`; reload keeps the theme.

- [ ] **Step 5: Commit**

```bash
git add hashview/templates/layout.html.j2 hashview/static/css/phosphor.css
git commit -m "feat(ui): theme segmented control in account modal"
```

---

## Task 8: End-to-end Playwright tests (full coverage)

**Files:**
- Create: `tests/e2e/test_theme.py`

Fixtures available (from `tests/conftest.py` / existing e2e tests): `page`,
`live_server`, `login`, `test_user_credentials`. Follow the skip-on-external-
login-failure pattern used in `tests/e2e/test_navigation.py`.

- [ ] **Step 1: Write the e2e tests**

Create `tests/e2e/test_theme.py`:

```python
import re

import pytest
from playwright.sync_api import expect


def _open_account_modal(page):
    # the modal is opened from the sidebar name/avatar
    page.evaluate("document.getElementById('account-settings-modal').showModal()")
    expect(page.locator("#account-settings-modal")).to_be_visible()


def _theme_attr(page):
    return page.evaluate("document.documentElement.getAttribute('data-theme')")


@pytest.mark.e2e
def test_toggle_applies_live(page, live_server, login):
    login()
    if not page.get_by_role("link", name="Jobs").is_visible():
        pytest.skip("Login failed against external server; set HASHVIEW_E2E_EMAIL/PASSWORD.")
    _open_account_modal(page)
    for value in ["light-paper", "light-invert", "light-clean", "dark"]:
        page.locator(f'.hv-theme-opt[data-theme-value="{value}"]').click()
        expect(page).to_have_url(re.compile(r".*"))  # settle
        assert _theme_attr(page) == value


@pytest.mark.e2e
def test_persistence_across_reload_no_flash(page, live_server, login):
    login()
    if not page.get_by_role("link", name="Jobs").is_visible():
        pytest.skip("Login failed against external server; set HASHVIEW_E2E_EMAIL/PASSWORD.")
    _open_account_modal(page)
    page.locator('.hv-theme-opt[data-theme-value="light-paper"]').click()
    # wait for the persist POST to land, then reload
    page.wait_for_timeout(500)
    resp = page.goto(f"{live_server}/", wait_until="domcontentloaded")
    # no-flash guard: the initial server HTML already carries the light theme
    assert 'data-theme="light-paper"' in resp.text()
    assert _theme_attr(page) == "light-paper"


@pytest.mark.e2e
def test_persistence_across_sessions(page, live_server, login):
    login()
    if not page.get_by_role("link", name="Jobs").is_visible():
        pytest.skip("Login failed against external server; set HASHVIEW_E2E_EMAIL/PASSWORD.")
    _open_account_modal(page)
    page.locator('.hv-theme-opt[data-theme-value="light-invert"]').click()
    page.wait_for_timeout(500)
    # clear client state so only the DB-backed pref can restore the theme
    page.goto(f"{live_server}/logout", wait_until="domcontentloaded")
    page.evaluate("try{localStorage.removeItem('hv_theme')}catch(e){}")
    login()
    resp = page.goto(f"{live_server}/", wait_until="domcontentloaded")
    assert 'data-theme="light-invert"' in resp.text()


@pytest.mark.e2e
def test_auto_follows_os(page, live_server, login):
    login()
    if not page.get_by_role("link", name="Jobs").is_visible():
        pytest.skip("Login failed against external server; set HASHVIEW_E2E_EMAIL/PASSWORD.")
    _open_account_modal(page)
    page.locator('.hv-theme-opt[data-theme-value="auto"]').click()
    page.wait_for_timeout(500)
    page.emulate_media(color_scheme="light")
    page.goto(f"{live_server}/", wait_until="domcontentloaded")
    assert _theme_attr(page) == "light-paper"
    page.emulate_media(color_scheme="dark")
    page.goto(f"{live_server}/", wait_until="domcontentloaded")
    assert _theme_attr(page) == "dark"


@pytest.mark.e2e
def test_unauthenticated_login_page_honors_localstorage(page, live_server):
    page.goto(f"{live_server}/login", wait_until="domcontentloaded")
    page.evaluate("try{localStorage.setItem('hv_theme','light-paper')}catch(e){}")
    page.goto(f"{live_server}/login", wait_until="domcontentloaded")
    assert _theme_attr(page) == "light-paper"
```

- [ ] **Step 2: Run the e2e suite**

Run: `pytest tests/e2e/test_theme.py -m e2e -v` (with the e2e harness/live
server up — see `tests/e2e/run_e2e_compose.sh` for how CI brings it up).
Expected: all pass, or cleanly SKIP if the external login isn't configured
(never silent-pass on a failed login).

- [ ] **Step 3: Commit**

```bash
git add tests/e2e/test_theme.py
git commit -m "test(e2e): full theme coverage (live toggle, persistence, auto, anon)"
```

---

## Task 9: Full regression + docs

- [ ] **Step 1: Run the unit + security suites**

Run: `pytest tests/unit tests/security -q`
Expected: PASS, coverage gate satisfied (the CI floor is enforced — see project
`TESTING.md`). If coverage dips, the new route/template lines are covered by
Tasks 3–4; add assertions rather than lowering the floor.

- [ ] **Step 2: Run ruff + bandit (pre-push gates)**

Run: `ruff check hashview tests && bandit -q -r hashview -x hashview/tests`
Expected: clean (matches the pre-push hook gates).

- [ ] **Step 3: Update the changelog / version if the project requires it**

Run: `grep -rn "0.8.3" CHANGELOG* docs/ 2>/dev/null | head`
If a changelog entry is expected for features (follow the pre-push-checklist
skill), add a "Light/dark theme support" line under the current dev version.

- [ ] **Step 4: Commit any docs**

```bash
git add -A
git commit -m "docs: note light/dark theme support"
```

---

## Self-Review (completed by plan author)

**Spec coverage:**
- Theme model (auto + 3 lights + dark) → Task 1, 3 (constant).
- Migration → Task 2.
- No-flash (server bake + pre-paint script) → Task 4 (layout), Task 5 (setup).
- Three palettes incl. Clean's typography change → Task 6.
- Toggle in account modal + CSRF POST route → Task 3 (route), Task 7 (UI).
- Error handling (invalid value 400, auth required, auto fallback) → Task 3 tests, script fallback in Task 4.
- Unit/integration + migration tests → Tasks 3, 4 (migration verified in Task 2 Step 3; DB e2e proves the column).
- Full e2e (6 scenarios) → Task 8 covers live toggle, reload no-flash, cross-session DB persistence, auto-follows-OS, unauthenticated page. The explicit no-flash assertion is folded into `test_persistence_across_reload_no_flash`.

**Placeholder scan:** none — every code step has concrete code; fixture-name
adaptation notes point to specific existing files to copy from.

**Type/name consistency:** `VALID_THEMES`/`EXPLICIT_THEMES`, `data-theme`,
`data-theme-pref`, `hv_theme` (localStorage key), `hvSetTheme`, `set_theme`
route, theme values (`auto`/`dark`/`light-paper`/`light-invert`/`light-clean`)
are used identically across model, route, templates, CSS, and tests.
