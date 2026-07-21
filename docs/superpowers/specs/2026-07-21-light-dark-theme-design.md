# Light/Dark Theme Support — Design

**Date:** 2026-07-21
**Branch:** `feature/light-dark-mode`
**Status:** Approved design, pending implementation plan

## Summary

Hashview currently ships a single dark "Phosphor Console" aesthetic (green/amber
CRT text on near-black, with glow and scanlines). All colors already route
through CSS custom properties defined in one `:root` block in
`hashview/static/css/phosphor.css`.

This feature adds selectable themes plus a per-user, OS-aware default:

- **Dark** — the existing phosphor console (unchanged default `:root`).
- **Paper Terminal** (`light-paper`) — warm paper background, dark ink, amber
  accent; keeps the monospace console identity; no glow/scanlines. **Default
  light theme.**
- **Minimal Invert** (`light-invert`) — light background retaining phosphor
  green/amber accents with faint glow; token-only swap.
- **Clean Light UI** (`light-clean`) — conventional light dashboard: sans-serif
  body, soft shadows, neutral accent; drops the CRT personality.

Users pick a theme (or "System") in the account-settings modal; the choice is
stored on their user record and applied without a flash of the wrong theme.

## Theme Model

A single `theme` string column on `Users` with these allowed values:

| Value          | Meaning                                              |
|----------------|------------------------------------------------------|
| `auto`         | Follow the OS `prefers-color-scheme` (**default**)   |
| `dark`         | Phosphor console (dark)                              |
| `light-paper`  | Paper Terminal                                       |
| `light-invert` | Minimal Invert                                       |
| `light-clean`  | Clean Light UI                                       |

**`auto` resolution:** the OS only reports light vs. dark. When `auto` resolves
to light, the designated **default light theme is `light-paper`**. When it
resolves to dark, it uses `dark`.

The rendered `<html>` element carries the resolved concrete theme via a
`data-theme` attribute whose value is one of `dark`, `light-paper`,
`light-invert`, `light-clean` (never `auto` — `auto` is resolved to a concrete
value before it reaches the DOM).

## Components & Data Flow

### 1. Data model + migration

- Add `theme = db.Column(db.String(16), nullable=False, default='auto')` to
  `Users` in `hashview/models.py`.
- One new Alembic revision (on top of the flattened v0.8.3 delta) adding the
  column: `theme VARCHAR(16) NOT NULL DEFAULT 'auto'`. Existing rows backfill to
  `'auto'`.

### 2. No-flash theme resolution

Two `<html>`-owning templates need handling: `layout.html.j2` (all app pages,
including the unauthenticated login/reset pages) and `setup_base.html.j2` (setup
pages).

- **Authenticated + explicit choice** (`theme` is `dark`/`light-*`): the server
  bakes `data-theme="<value>"` onto `<html>` at render time. Zero flash, no JS
  needed for first paint.
- **`auto`, or any unauthenticated page** (login/reset/setup — no user record):
  the server emits `data-theme="dark"` as a safe default, then a tiny inline
  pre-paint script (mirroring the existing sidebar-collapse script already in
  `layout.html.j2`) runs before first paint and, if resolution is `auto`, sets
  `data-theme` from `matchMedia('(prefers-color-scheme: light)')` →
  `light-paper`. A `localStorage` mirror (`hv_theme`) lets pre-login pages honor
  a returning user's last explicit choice instantly.

The server passes the current user's stored theme to the template (via context
or `current_user.theme`); the inline script receives the resolved intent so it
knows whether to defer to the OS.

### 3. Light palettes — CSS

All in `hashview/static/css/phosphor.css`, appended after the existing `:root`:

- `[data-theme="light-paper"] { … }` — override the ~25 color tokens (`--bg`,
  `--bg-grad`, `--surface`, `--inset`, `--border*`, `--text*`, greens, ambers,
  `--red*`, `--cyan`, `--primary*`, `--primary-rgb`) with Paper Terminal values;
  set `--glow*: none`; hide `.scanlines`.
- `[data-theme="light-invert"] { … }` — token-only invert keeping phosphor
  green/amber accents and a faint `--glow*`.
- `[data-theme="light-clean"] { … }` — token overrides **plus** switch the body
  typography to sans by overriding the font tokens (`--mono`/`--sans` usage),
  soften/replace shadows, and disable glow + scanlines. This is the only theme
  that touches beyond pure color tokens; any component that hard-codes the
  console font must be routed through a variable first.

Dark remains the untouched `:root` default.

### 4. Toggle UI + save endpoint

- A segmented control (**System · Paper · Invert · Clean · Dark**) added to the
  existing account-settings modal in `layout.html.j2`.
- On change it (a) applies `data-theme` live via JS, (b) writes `localStorage`
  `hv_theme`, and (c) POSTs the chosen value to a new route
  `users.set_theme` including the CSRF token (matching the existing POST+CSRF
  pattern used elsewhere).
- `users.set_theme`: login-required, CSRF-protected, validates the value against
  the allowed set (rejects anything else with 400), persists to the user record,
  returns JSON `{ok: true}`.

## Error Handling

- Invalid theme value at the endpoint → 400, no DB write.
- Unauthenticated POST to `set_theme` → redirected/401 per existing auth guard.
- Missing/blank `theme` on an existing row (pre-migration edge) → treated as
  `auto` by the resolver.
- JS/localStorage unavailable → server-baked `data-theme` still yields a correct
  non-`auto` render; `auto` falls back to `dark`.

## Testing

### Unit / integration (pytest)

- `set_theme` rejects invalid values (400, no write); accepts each valid value
  and persists it.
- `set_theme` requires authentication and a valid CSRF token.
- Template render: for a user with `theme` in {`dark`,`light-paper`,
  `light-invert`,`light-clean`}, `<html>` carries the matching `data-theme`;
  for `auto`, the server default + pre-paint script path is present.
- Migration test: after upgrade, `users.theme` exists as `VARCHAR(16)`,
  `NOT NULL`, default `'auto'`; existing rows read back as `'auto'`.

### End-to-end (Playwright) — **required, full coverage**

Add an e2e spec exercising the real running app:

1. **Toggle applies live:** log in, open the account modal, select each theme in
   turn, assert `<html data-theme>` updates to the expected concrete value and
   the computed background color changes accordingly.
2. **Persistence across reload:** select `light-paper`, reload, assert the page
   renders with `data-theme="light-paper"` server-side (no flash — attribute
   present in initial HTML, not applied post-load).
3. **Persistence across sessions/devices proxy:** select a theme, log out, log
   back in, assert the stored theme is reapplied (DB-backed, not just
   localStorage).
4. **`auto` follows OS:** with `theme=auto`, emulate `prefers-color-scheme:
   light` and assert resolution to `light-paper`; emulate `dark` and assert
   `dark`.
5. **Unauthenticated pages:** on the login page with `hv_theme` set, assert the
   chosen theme (or OS default) is applied.
6. **No flash-of-wrong-theme:** for an explicit light choice, assert the initial
   server HTML already contains the correct `data-theme` (guards against a
   dark→light paint jump).

E2e runs under the existing dockerized Playwright harness and CI gate.

## Out of Scope

- Per-theme logo/favicon variants.
- Animated theme transitions.
- Admin-level default-theme policy for the whole install.

## Key Decisions (rationale)

- **Three-way+ `auto` model, not a boolean:** required to honor "follow OS by
  default, remember an explicit choice."
- **`light-paper` as the default light:** preserves hashview's distinctive
  console identity when `auto` resolves to light.
- **Server-baked `data-theme` for explicit choices:** eliminates the
  flash-of-wrong-theme that a JS-only approach would cause on DB-backed prefs.
- **All-token-swap for Paper/Invert; Clean is the only component-level theme:**
  contains risk to a single theme.
