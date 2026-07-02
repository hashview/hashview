# End-to-End Migration Test: `main` → dev branch

**Date:** 2026-07-02
**Status:** Approved design (pre-implementation)
**Branch:** `work/off-dev` (based on `v0.8.3-dev`)

## Problem

The dev branch (`v0.8.3-dev`) adds **14 migrations** on top of `main`'s 43
(`main`: 43 migration files; dev: 57). Those migrations must apply cleanly to a
**live, populated** database created by the *current* `main` code — not just to
an empty schema. Critically, one of the changes is a **data-transforming**
step that does **not** live in the Alembic chain:

- Migration `a1f7c4e9d2b3_unicode_text_storage` only adds
  `settings.passwords_decoded` (`NOT NULL server_default 0`, so existing rows
  are flagged) and widens two text columns to `utf8mb4`.
- The actual legacy **hex → text** rewrite of `hashfile_hashes.username` and
  `hashes.plaintext` happens at **dev app startup** in
  `decode_legacy_hex_if_needed` (`hashview/setup/__init__.py:204`), gated by
  `settings.passwords_decoded`.

An Alembic-only migration test would therefore miss the most consequential data
change. We need a test that runs the **actual app images** end to end.

## Goal

Prove that a database created and populated by the current `main` app image
upgrades correctly when the dev app image boots against the same database:

1. Alembic reaches the dev head revision.
2. Pre-existing (main-era) seeded rows survive intact.
3. The legacy hex → text/`$HEX[...]` backfill converts data exactly as
   specified.
4. DDL-added columns backfill sane server-defaults on pre-existing rows.
5. The migrated schema is identical to a dev schema built fresh from empty
   (no drift).

## Non-Goals

- Testing downgrade paths.
- Testing the agent, cracking, or browser (e2e Playwright) flows.
- Comparing against a fixed `v0.8.2` git tag or a captured SQL dump — the
  starting database is produced by **whatever is on `main` right now**.

## Architecture

A dedicated compose stack with **one persistent MySQL volume** and **two app
images built from two codebases**, plus a throwaway MySQL that serves as a
schema-parity oracle.

```
docker-compose.migration.yml
  db        MySQL 8, persistent named volume  (the DB under test)
  db-fresh  MySQL 8, ephemeral                 (parity oracle)
  app-main  image hashview:main  (built from origin/main, 43 migrations)
  app-dev   image hashview:dev   (built from this worktree, 57 migrations)
```

- `hashview:main` boots against the fresh `db`, runs its own
  `alembic upgrade head` on startup, creating the **main-era** schema, and
  seeds its defaults (this creates the `settings` row).
- We load a legacy-format seed into `db`.
- `hashview:dev` boots against the **same** `db` volume, runs
  `alembic upgrade head` (applying the 14 new migrations) and then, during
  startup, runs `decode_legacy_hex_if_needed` (because the migration set
  `passwords_decoded = 0` on the existing settings row).
- `db-fresh` gets the dev schema built **from empty** via
  `scripts/run_migrations.py`, to compare against.

### Why the app image, not just Alembic

The hex → text backfill is app-startup code gated by a flag the migration sets.
Only booting the dev **app** exercises it. This is the core reason the test
drives real images end to end.

## Flow (orchestrated by `tests/run_migration_e2e.sh`)

1. Build `hashview:dev` from this worktree's `Dockerfile`.
2. `git worktree add` a temp checkout of `origin/main`; build `hashview:main`
   from its `Dockerfile`; the worktree is removed on teardown.
3. `docker compose -f docker-compose.migration.yml up -d db`; wait healthy
   (TCP + query healthcheck, same pattern as the main compose file).
4. Start `app-main`; wait until it reports healthy (schema migrated to main
   head, defaults seeded).
5. Load `tests/migration/seed_main.sql` into `db` via `mysql <`.
6. Stop `app-main`.
7. Start `app-dev`; wait until healthy **and** confirm the backfill finished
   (poll health endpoint and confirm `settings.passwords_decoded = 1`).
8. Start `db-fresh`; run `scripts/run_migrations.py` against it to build the
   dev schema from empty.
9. Run the `@pytest.mark.mysql` verifier against `db` (and `db-fresh` for the
   parity comparison).
10. Tear down containers, volumes, and the temp `main` worktree.

## Seed (`tests/migration/seed_main.sql`)

Pure SQL, loaded **after** `app-main` migrates, so it inserts using only
columns that exist in main's 43-migration schema (decoupled from any Python /
ORM version — the starting state is explicit and code-independent).

### Legacy hex rows (exercise every branch of `_decode_hex_column`)

`hashfile_hashes.username` and `hashes.plaintext` are stored on main as
latin-1 / raw-bytes **hex strings**.

| Seeded value (hex, main format) | Expected after dev boot | Branch covered |
|---|---|---|
| `41646d696e` | `Admin` | plain ASCII → UTF-8 text |
| `c3a9` (UTF-8 `é`) | `é` | valid multibyte UTF-8 → text |
| `ff01` (non-UTF-8 bytes) | `$HEX[ff01]` | invalid UTF-8 → `$HEX[...]` marker |
| an already-plain-text value (not valid hex) | unchanged | not-hex guard / idempotent re-run |
| (optional) hex whose decoded form exceeds the column width | left hex-encoded | overflow guard |

### DDL-affected rows

Representative rows so we can assert the DDL migrations backfilled sane
server-defaults on pre-existing data:

- `hashfiles` (→ `hex_salt` defaults `0`)
- `agents` (→ benchmark / GPU-telemetry / timeout+offline columns)
- `settings` (→ slack / email+pushover / azure-sso columns; and
  `passwords_decoded`)
- `wordlists` (→ `byte_size`)
- `hashes` (→ `ciphertext` widened to `TEXT`; a long ciphertext value present)
- `tasks` (→ loopback column)

## Verifier (`tests/integration/test_migration_e2e.py`, `@pytest.mark.mysql`)

Asserts against the migrated `db`:

- `alembic_version` == dev head revision.
- `settings.passwords_decoded` flipped `0 → 1`.
- Each legacy hex row converted exactly as the seed table specifies.
- DDL-added columns present with expected server-defaults on the pre-existing
  rows.
- **Schema parity:** the migrated `db` schema equals the `db-fresh`
  (dev-from-empty) schema — compare `information_schema` for tables, columns,
  types, nullability, defaults, indexes, and foreign keys.

## Files to add

- `docker-compose.migration.yml` — `db`, `db-fresh`, `app-main`, `app-dev`.
- `tests/migration/seed_main.sql` — legacy-format seed.
- `tests/integration/test_migration_e2e.py` — the verifier.
- `tests/run_migration_e2e.sh` — the orchestrator (modeled on
  `tests/run_e2e_crack_compose.sh`).
- `.github/workflows/migration-e2e.yml` — push/PR trigger, full-history
  checkout (needs `origin/main`), calls the runner (modeled on
  `e2e-crack.yml`).
- `pytest.ini` — register a `migration` marker (verifier also carries
  `mysql`).

## Robustness notes

- Wait on the **dev app's health**, not just container-up: the hex backfill
  runs during startup, so the orchestrator confirms it finished (health
  endpoint + `passwords_decoded = 1`) before the verifier runs.
- Reuse the TCP-with-query MySQL healthcheck from `docker-compose.yml` (a
  Unix-socket healthcheck reports ready during MySQL's temporary init server,
  before the real server accepts connections, and silently breaks migrations).
- Tracking "whatever is on `main` right now" is intentional: the test rebuilds
  `hashview:main` from `origin/main` on each run.

## Existing patterns leveraged

- Migration runner: `scripts/run_migrations.py` (used by `db-parity.yml`).
- Programmatic upgrade at boot: `alembic.command.upgrade(config, 'head')` in
  `hashview/__init__.py`.
- MySQL integration fixtures + SAVEPOINT isolation: `tests/integration/conftest.py`.
- Compose e2e harness + shell runner: `docker-compose.e2e.yml` /
  `tests/run_e2e_crack_compose.sh`.
