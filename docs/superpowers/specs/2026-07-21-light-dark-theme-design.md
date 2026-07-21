# Light/Dark Theme (Paper Terminal) — Design

**Date:** 2026-07-21
**Branch:** `feature/light-dark-mode`
**Status:** Approved design, ready for implementation plan

## Summary

Add a light theme and a per-user theme preference to Hashview. The current UI *is*
the dark theme — a "Phosphor Console" CRT aesthetic (green/amber text on near-black,
glow + scanlines) whose colors all flow through CSS variables in
`hashview/static/css/phosphor.css`. This feature adds a **light** variant in the
"Paper Terminal" direction (warm paper background, dark ink, amber accent, no
glow/scanlines) plus a three-way user preference (System / Light / Dark) exposed in
the account-settings modal and persisted in the database.

## Goals

- A light theme that keeps Hashview's monospace console identity (Paper Terminal).
- A per-user preference stored in the DB so it follows the user across browsers/devices.
- Default to the OS setting (`prefers-color-scheme`) until the user makes an explicit choice.
- No flash of the wrong theme on page load.
- Full test coverage: unit, template-render, migration, and end-to-end (Playwright).

## Non-Goals

- No redesign of components or layout. This is a token swap plus a preference control.
- No additional themes beyond light/dark. No per-page or scheduled theming.
- No changes to the dark theme's appearance (it stays the untouched default).

## Decisions (locked during brainstorming)

| Decision | Choice |
|---|---|
| Light-theme direction | **Paper Terminal** — keep monospace console identity, warm paper + dark ink + amber, drop glow/scanlines |
| Preference values | **Three-way**: `auto` (default), `light`, `dark`. `auto` = follow OS |
| Toggle placement | Inside the existing **account-settings modal** (rendered in `layout.html.j2`) |
| Default for new users | **Follow OS** via `prefers-color-scheme`, then remember explicit choice |
| Persistence | **Per-user in the database** (`users.theme` column) |

## Architecture

### 1. Data model

Add a column to `Users` (`hashview/models.py`):

```python
theme = db.Column(db.String(10), nullable=False, default='auto')  # 'auto' | 'light' | 'dark'
```

Valid values are constrained in application code (not a DB enum), matching the
existing `auth_source` string-column pattern.

### 2. Migration

One new Alembic revision under `migrations/versions/`, `down_revision` = current head
(`c8b3f0a14d27_squash_v0_8_3_dev_schema_delta` or whatever HEAD is at implementation
time — verify with `alembic heads`). Adds:

```
users.theme VARCHAR(10) NOT NULL DEFAULT 'auto'
```

`upgrade()` adds the column with a server default so existing rows backfill to `auto`;
`downgrade()` drops it.

### 3. Theme resolution & no-flash strategy

Theme is expressed as `data-theme="light|dark"` on the `<html>` element. Two paths,
both applied **before first paint**:

- **Server-side bake (authenticated, explicit choice):** when `current_user` is
  authenticated and `theme` is `light` or `dark`, the template renders
  `<html ... data-theme="{{ current_user.theme }}">`. Zero flash, no JS required for
  the initial paint.
- **Client pre-paint (auto, or any unauthenticated page):** when the resolved server
  value is `auto` — or the visitor is on login/reset/setup with no user record — an
  inline `<head>` script (mirroring the existing sidebar-collapse pre-paint script)
  sets `data-theme` from, in priority order: `localStorage['hv_theme']` if it is
  `light`/`dark`, else `matchMedia('(prefers-color-scheme: light)')`.

Both `layout.html.j2` and `setup_base.html.j2` carry the `<html>` tag, so **both** get
the inline pre-paint script and the server-bake expression. All app pages
(including login/reset) extend `layout.html.j2`; setup pages extend `setup_base.html.j2`.

The dark default is the base `:root`; when `data-theme` is absent the app renders dark,
so a script failure degrades gracefully to the current look.

### 4. Light palette (Paper Terminal)

Add a single override block to `hashview/static/css/phosphor.css`:

```css
[data-theme="light"] {
  /* warm paper surfaces */
  --bg: #efeadc; --bg-grad: #f2eee1; --surface: #f6f2e6; --inset: #e7e1cf;
  /* borders */
  --border: #cfc7b0; --border-soft: #ddd6c2; --border-bright: #b8ad8e;
  /* ink */
  --text: #1c1b16; --text-dim: #5b5647; --text-faint: #9a927b; --text-mute: #7a7360;
  /* status colors retuned for contrast on paper */
  --green: #2f8f4e; --green-deep: #1f6e3a; --green-dim: #cfe3d3;
  --amber: #b8901f; --amber-deep: #8a6a15; --amber-dim: #efe4c4;
  --red: #c23b33; --red-dim: #f2d5d3; --cyan: #1f8fa0;
  --primary: var(--amber); --primary-deep: var(--amber-deep);
  --primary-dim: var(--amber-dim); --primary-rgb: 184, 144, 31;
  /* CRT effects off in daylight */
  --glow-sm: none; --glow: none; --glow-text: none;
}
[data-theme="light"] .scanlines { display: none; }
```

Exact hex values are tuned during implementation for WCAG AA text contrast; the table
above is the starting point. **No component CSS changes** — every component already
consumes these variables. Verify by grepping for hard-coded colors introduced outside
variables (e.g. inline `style=` in templates such as the topbar's
`var(--primary)`/`var(--amber)` usage already uses variables — confirm none are literal).

### 5. Toggle UI + save endpoint

- **Control:** a three-segment control (System / Light / Dark) added to the
  account-settings modal markup in `layout.html.j2`, reflecting `current_user.theme`.
- **Live apply:** on change, JS sets `document.documentElement.setAttribute('data-theme', …)`
  (or removes it for `auto` and re-runs the resolver), and writes `localStorage['hv_theme']`.
- **Persist:** the same change POSTs to a new route `users.set_theme`
  (`POST /profile/theme`) with the CSRF token (Flask-WTF CSRF is enforced on form
  routes — follow the existing POST+CSRF pattern used by `generate_api_key`/`profile`).
  The route validates the value against `{'auto','light','dark'}`, rejects anything else
  with 400, requires `@login_required`, saves to the DB, and returns a small JSON
  `{"ok": true, "theme": …}` for the AJAX caller.

A dedicated lightweight route is used (rather than folding into the existing `profile()`
POST) so the theme saves instantly without submitting the whole account modal.

## Error handling

- Invalid `set_theme` value → HTTP 400, no DB write.
- Unauthenticated `set_theme` → redirected/401 by `@login_required`.
- Missing CSRF token → rejected by Flask-WTF (existing behavior).
- Pre-paint script wrapped in `try/catch` (like the sidebar script); any failure
  falls through to the dark default.

## Testing

### Unit (`tests/unit/`)
- `set_theme` persists `light`/`dark`/`auto` to the DB for the current user.
- `set_theme` rejects invalid values with 400 and no write.
- `set_theme` requires authentication.
- `set_theme` requires a valid CSRF token.

### Template render (`tests/unit/`)
- Authenticated render with `theme='light'`/`'dark'` bakes `data-theme` on `<html>`.
- Authenticated render with `theme='auto'` leaves `data-theme` off the server output
  (delegated to the pre-paint script).
- The account modal reflects the user's current `theme` selection.

### Migration (`tests/integration/` / `tests/migration/`)
- After `upgrade`, `users.theme` exists, is `NOT NULL`, and existing rows read `auto`.
- `downgrade` removes the column. Include the new column in the main→dev migration
  parity checks if applicable.

### End-to-end (`tests/e2e/`, Playwright) — **required**
New `tests/e2e/test_theme.py` using the existing `login` fixture (`tests/conftest.py`)
and live-server harness:
1. **Default is dark** for a fresh user (`theme='auto'`, dark OS emulation) — assert
   `<html>` has no `data-theme` or resolves to dark; assert a known dark token
   (e.g. computed `--bg`) is the dark value.
2. **OS light emulation** — with Playwright `color_scheme='light'` and `theme='auto'`,
   the page resolves to light before paint (assert computed background is the paper value).
3. **Explicit toggle → Light** in the account modal updates the page live (assert
   `data-theme="light"` and paper background) without a full reload.
4. **Persistence across reload/navigation** — after choosing Light and reloading (and
   navigating to another page), the theme is still light, proving the DB round-trip and
   server-side bake (assert `data-theme="light"` present in server HTML, independent of
   OS emulation).
5. **Explicit choice overrides OS** — user set to `light`, OS emulated dark → page is light.

E2e must run under the real harness (not skipped) and pass in CI, consistent with the
project's strict e2e gate.

## Files touched

- `hashview/models.py` — add `theme` column.
- `migrations/versions/<new>_add_users_theme.py` — new revision.
- `hashview/static/css/phosphor.css` — `[data-theme="light"]` override block.
- `hashview/templates/layout.html.j2` — pre-paint script, `<html>` bake expression,
  account-modal segmented control + JS.
- `hashview/templates/setup_base.html.j2` — pre-paint script + `<html>` bake.
- `hashview/users/routes.py` — new `set_theme` route.
- `tests/unit/…`, `tests/e2e/test_theme.py`, migration test additions.

## Rollout / safety

- Additive migration with a server default; no data loss, safe downgrade.
- Dark remains the fallback default, so any JS/CSS regression degrades to today's look.
- No agent/API surface changes; no security-sensitive routes beyond a validated,
  auth+CSRF-protected preference write.
