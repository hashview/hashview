# End-to-End Migration Test (`main` → dev) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove that a MySQL database created and populated by the *current* `main` app image upgrades correctly — schema **and** data — when the dev app image boots against the same database.

**Architecture:** A dedicated docker-compose stack runs two app images (`hashview:main` built from `origin/main`, `hashview:dev` built from this worktree) against one persistent MySQL volume, plus a throwaway MySQL that holds a dev-from-empty schema as a parity oracle. A shell runner orchestrates the sequence; a `@pytest.mark.mysql` verifier asserts alembic head, data survival, the legacy-hex→text backfill, DDL-column backfills, and full schema parity. A GitHub Actions workflow runs it on push/PR.

**Tech Stack:** Docker + docker compose, MySQL 8, Flask/Flask-Migrate/Alembic, pytest, `mysql-connector-python`, bash, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-07-02-migration-e2e-test-design.md`

**Key facts (verified against the code):**
- Dev head revision: **`c8b3f0a14d27`** (`c8b3f0a14d27_add_agent_timeout_and_offline_flag.py`). Main head differs (14 fewer migrations).
- The app runs `alembic upgrade head`, then `decode_legacy_hex_if_needed`, inside `setup_defaults_if_needed()`, which is called during `create_app` **before** `flask run` serves (hashview/__init__.py:438-440). So HTTP-ready ⇒ migrations + backfill already ran. The runner still gates on `settings.passwords_decoded = 1` for certainty.
- The legacy backfill converts `hashfile_hashes.username` and `hashes.plaintext` from hex to text/`$HEX[...]` (hashview/setup/__init__.py:165-226). It skips values that aren't valid hex, and leaves a value hex-encoded if its decoded form exceeds the column's `max_len` (256).
- Config is read from `hashview/config.conf`, baked into each image at build time (see `tests/run_e2e_crack_compose.sh` for the write-then-build pattern). DB host is `db`, creds `hashview`/`hashview`.
- MySQL healthcheck MUST use TCP + a query (not the unix socket) — copy the block from `docker-compose.yml`.
- Migration-touched model columns and their defaults (hashview/models.py): `settings.passwords_decoded` (Bool, default True; migration server_default 0), `settings.pushover_enabled`/`slack_enabled`/`slack_bot_token`/`slack_admin_channel`, `settings.azure_*`, `settings.agent_timeout_minutes` (Int default 60), `hashfiles.hex_salt` (Bool server_default 0), `agents.offline_notified` (Bool default False), `agents.benchmark`/`gpu_count`/`gpu_model`/`gpu_temps`, `wordlists.byte_size` (BigInteger nullable), `tasks.loopback` (Bool default False), `hashes.ciphertext` (Text NOT NULL), `hashes.plaintext` (String(256)), `hashfile_hashes.username` (String(256)).

---

## File Structure

- **Create** `docker-compose.migration.yml` — services `db` (persistent), `db-fresh` (ephemeral oracle), `app-main` (`hashview:main`), `app-dev` (`hashview:dev`).
- **Create** `tests/migration/seed_main.sql` — legacy-format seed, main-era columns only.
- **Create** `tests/migration/expected_hex.py` — shared table of hex-seed inputs → expected decoded outputs (imported by both the seed-generator check and the verifier so they can't drift). *(Small pure-data module.)*
- **Create** `tests/integration/test_migration_e2e.py` — the `@pytest.mark.mysql`, `@pytest.mark.migration` verifier.
- **Create** `tests/run_migration_e2e.sh` — orchestrator.
- **Create** `.github/workflows/migration-e2e.yml` — CI trigger.
- **Modify** `pytest.ini` — register the `migration` marker.

---

## Task 1: Register the `migration` pytest marker

**Files:**
- Modify: `pytest.ini`

- [ ] **Step 1: Add the marker**

In `pytest.ini`, under `markers =`, after the `mysql:` line, add:

```
    migration: end-to-end main->dev database migration test (needs docker + built images)
```

- [ ] **Step 2: Verify pytest accepts it**

Run: `python -m pytest --markers | grep migration`
Expected: the new marker description prints, no "unknown marker" warnings.

- [ ] **Step 3: Commit**

```bash
git add pytest.ini
git commit -m "test: register migration pytest marker"
```

---

## Task 2: Capture main's schema for the affected tables (authoring aid — no commit)

This is a throwaway investigation step so the seed in Task 4 uses columns/NOT-NULL/FK
constraints that actually exist on `main`. Do NOT guess column lists.

**Files:** none created.

- [ ] **Step 1: Build the main image from `origin/main`**

```bash
ROOT=$(git rev-parse --show-toplevel)
git worktree add /tmp/hv-main-schema origin/main
cd /tmp/hv-main-schema
cat > hashview/config.conf <<'EOF'
[SERVER]
SERVER_NAME = app:5000
SECRET_KEY = migration-e2e
[database]
host = db
username = hashview
password = hashview
[SMTP]
server = smtp.example.com
port = 25
use_tls = False
username =
password =
default_sender =
EOF
DOCKER_PLATFORM=${DOCKER_PLATFORM:-linux/amd64} docker build --platform ${DOCKER_PLATFORM:-linux/amd64} -t hashview:main .
cd "$ROOT"
```

Expected: image `hashview:main` builds successfully.

- [ ] **Step 2: Bring up a scratch db + app-main and dump the schema**

```bash
docker network create hvscratch || true
docker run -d --name hvdb --network hvscratch -e MYSQL_DATABASE=hashview \
  -e MYSQL_USER=hashview -e MYSQL_PASSWORD=hashview -e MYSQL_RANDOM_ROOT_PASSWORD=yes mysql:8
# wait for TCP readiness
until docker exec hvdb mysql -h127.0.0.1 -uhashview -phashview -e 'SELECT 1' hashview >/dev/null 2>&1; do sleep 2; done
docker run -d --name hvapp --network hvscratch --link hvdb:db hashview:main
# app-main runs migrations on boot; wait until users table exists
until docker exec hvdb mysql -h127.0.0.1 -uhashview -phashview -e 'SHOW TABLES' hashview 2>/dev/null | grep -q alembic_version; do sleep 2; done
for t in settings hashfiles hashfile_hashes hashes agents wordlists tasks customers; do
  echo "==== $t ===="; docker exec hvdb mysql -h127.0.0.1 -uhashview -phashview -e "SHOW CREATE TABLE $t\G" hashview
done
docker exec hvdb mysql -h127.0.0.1 -uhashview -phashview -e "SELECT id FROM settings" hashview
```

Expected: `SHOW CREATE TABLE` output for each table. **Record the NOT-NULL columns and FK relationships** — they drive the seed. Note that `app-main` already created a `settings` row (id present).

- [ ] **Step 3: Tear down the scratch env**

```bash
docker rm -f hvapp hvdb; docker network rm hvscratch; git worktree remove /tmp/hv-main-schema --force
```

No commit (investigation only). Keep the recorded schema notes for Task 4.

---

## Task 3: Shared expected-conversion table

**Files:**
- Create: `tests/migration/__init__.py` (empty)
- Create: `tests/migration/expected_hex.py`

- [ ] **Step 1: Create the package marker**

Create empty file `tests/migration/__init__.py`.

- [ ] **Step 2: Write the expected-conversion module**

Create `tests/migration/expected_hex.py`:

```python
"""Single source of truth for the legacy-hex seed cases.

Each entry maps the value AS SEEDED on main (a hex string, the legacy storage
format for usernames/plaintext) to the value EXPECTED after the dev app's
``decode_legacy_hex_if_needed`` backfill runs. The seed SQL (seed_main.sql) and
the verifier (test_migration_e2e.py) both consume this so they cannot drift.

``marker`` is a stable ASCII tag stored alongside the value (in a sibling column
the verifier queries on) so each row is individually addressable regardless of
how the hex/text sorts.
"""

# marker -> (seeded_hex_value, expected_after_backfill)
USERNAME_CASES = {
    "u_ascii":     ("41646d696e", "Admin"),          # ASCII hex -> text
    "u_utf8":      ("c3a9",       "é"),          # 'é' UTF-8 -> text
    "u_nonutf8":   ("ff01",       "$HEX[ff01]"),      # invalid UTF-8 -> $HEX[...]
    "u_plaintext": ("already-text", "already-text"),  # not valid hex -> untouched
}

# For the overflow guard: a hex string whose decoded UTF-8 form is > 256 chars
# stays hex-encoded (column is VARCHAR(256)). 260 'A's = 520 hex chars.
_OVERFLOW_HEX = "41" * 260
PLAINTEXT_CASES = {
    "p_ascii":    ("70617373", "pass"),               # 'pass'
    "p_utf8":     ("f09f9880", "\U0001f600"),          # 😀 emoji (4-byte) -> text
    "p_nonutf8":  ("ff",       "$HEX[ff]"),            # invalid UTF-8 -> $HEX[...]
    "p_overflow": (_OVERFLOW_HEX, _OVERFLOW_HEX),      # decoded > 256 -> left hex
}
```

- [ ] **Step 3: Verify it imports**

Run: `python -c "from tests.migration.expected_hex import USERNAME_CASES, PLAINTEXT_CASES; print(len(USERNAME_CASES), len(PLAINTEXT_CASES))"`
Expected: `4 4`

- [ ] **Step 4: Commit**

```bash
git add tests/migration/__init__.py tests/migration/expected_hex.py
git commit -m "test(migration): shared legacy-hex expected-conversion table"
```

---

## Task 4: The main-era seed SQL

**Files:**
- Create: `tests/migration/seed_main.sql`

Use the schema recorded in Task 2 to satisfy every NOT-NULL column and FK. The
example below assumes the common main columns; **adjust column lists to match
the Task 2 dump** (e.g. required `owner_id`, `created_at`, `sub_ciphertext`,
`salt`, `hash_type`). The `marker` values MUST match `expected_hex.py`.

- [ ] **Step 1: Write the seed**

Create `tests/migration/seed_main.sql`. Insert parent rows first (customers,
hashfiles, agents, wordlists, tasks) then child rows. Store each hex case using
the marker as a second addressable column: for usernames use the row's
`hashes_id`/`hashfile_id` linkage as recorded; the verifier locates rows by a
distinctive sentinel. Concretely, seed:

```sql
-- Representative main-era data. Columns match `SHOW CREATE TABLE` from Task 2.
-- (Placeholders like <FKCOL> must be replaced with the real column names.)

-- customer (FK parent for hashfiles/jobs)
INSERT INTO customers (id, name) VALUES (900, 'MigrationTestCo');

-- a hashfile (exercises hex_salt backfill -> expect 0 after migrate)
INSERT INTO hashfiles (id, customer_id, name) VALUES (900, 900, 'mig-hashfile');

-- hashfile_hashes.username legacy-hex cases (markers align with expected_hex.USERNAME_CASES)
-- Each row carries a unique id so the verifier can address it; we encode the
-- marker into the id range 9001..9004 and assert by id.
INSERT INTO hashfile_hashes (id, hashfile_id, hash_id, username) VALUES
  (9001, 900, 1, '41646d696e'),
  (9002, 900, 1, 'c3a9'),
  (9003, 900, 1, 'ff01'),
  (9004, 900, 1, 'already-text');

-- hashes.plaintext legacy-hex cases (markers align with expected_hex.PLAINTEXT_CASES)
-- ciphertext is set to a long value to prove the widen-to-TEXT migration.
INSERT INTO hashes (id, sub_ciphertext, ciphertext, plaintext) VALUES
  (9001, 'mig1', REPEAT('a', 600), '70617373'),
  (9002, 'mig2', REPEAT('b', 600), 'f09f9880'),
  (9003, 'mig3', REPEAT('c', 600), 'ff'),
  (9004, 'mig4', REPEAT('d', 600), REPEAT('41', 260));

-- an agent (exercises benchmark/gpu/offline/timeout columns added on dev)
INSERT INTO agents (id, name) VALUES (900, 'mig-agent');

-- a wordlist (exercises byte_size backfill -> expect NULL, nullable)
INSERT INTO wordlists (id, name, type, path) VALUES (900, 'mig-wl', 'static', '/tmp/mig-wl');

-- a task (exercises loopback backfill -> expect 0)
INSERT INTO tasks (id, name) VALUES (900, 'mig-task');
```

> NOTE: `ciphertext` is `VARCHAR(500)` NOT NULL on main; `REPEAT('a',600)` will
> be rejected there. Seed a ≤500-char value on main and instead assert the
> **column type** widened to TEXT (Task 6). If Task 2 shows main already TEXT,
> use 600. Reconcile against the Task 2 dump before finalizing.

- [ ] **Step 2: Syntax-check the SQL offline**

Run: `python -c "open('tests/migration/seed_main.sql').read(); print('readable')"` and eyeball for balanced statements. (Full validation happens in Task 7 against the live main schema.)
Expected: `readable`

- [ ] **Step 3: Commit**

```bash
git add tests/migration/seed_main.sql
git commit -m "test(migration): main-era seed with legacy-hex + DDL-affected rows"
```

---

## Task 5: The docker-compose migration stack

**Files:**
- Create: `docker-compose.migration.yml`

- [ ] **Step 1: Write the compose file**

Create `docker-compose.migration.yml`:

```yaml
# End-to-end main->dev migration stack. Orchestrated by
# tests/run_migration_e2e.sh. `db` is the DB under test (persistent within a
# run); `db-fresh` is the dev-from-empty parity oracle. app-main and app-dev
# are built by the runner and tagged hashview:main / hashview:dev.
services:
  db:
    image: "mysql:8"
    platform: ${DOCKER_PLATFORM:-linux/amd64}
    environment:
      MYSQL_DATABASE: hashview
      MYSQL_USER: hashview
      MYSQL_PASSWORD: hashview
      MYSQL_RANDOM_ROOT_PASSWORD: yes
    ports:
      - '3306:3306'
    healthcheck:
      test: ["CMD-SHELL", "mysql -h 127.0.0.1 -u hashview -phashview -e 'SELECT 1' hashview || exit 1"]
      interval: 5s
      timeout: 5s
      retries: 20
      start_period: 30s

  db-fresh:
    image: "mysql:8"
    platform: ${DOCKER_PLATFORM:-linux/amd64}
    environment:
      MYSQL_DATABASE: hashview
      MYSQL_USER: hashview
      MYSQL_PASSWORD: hashview
      MYSQL_RANDOM_ROOT_PASSWORD: yes
    ports:
      - '3307:3306'
    healthcheck:
      test: ["CMD-SHELL", "mysql -h 127.0.0.1 -u hashview -phashview -e 'SELECT 1' hashview || exit 1"]
      interval: 5s
      timeout: 5s
      retries: 20
      start_period: 30s

  app-main:
    image: hashview:main
    platform: ${DOCKER_PLATFORM:-linux/amd64}
    links:
      - db
    ports:
      - "5000:5000"
    depends_on:
      db:
        condition: service_healthy

  app-dev:
    image: hashview:dev
    platform: ${DOCKER_PLATFORM:-linux/amd64}
    links:
      - db
    ports:
      - "5001:5000"
    depends_on:
      db:
        condition: service_healthy
```

- [ ] **Step 2: Validate compose parses**

Run: `docker compose -f docker-compose.migration.yml config >/dev/null && echo OK`
Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add docker-compose.migration.yml
git commit -m "test(migration): compose stack (db, db-fresh, app-main, app-dev)"
```

---

## Task 6: The verifier (pytest)

**Files:**
- Create: `tests/integration/test_migration_e2e.py`

The verifier connects to two databases via env vars set by the runner:
`HASHVIEW_MIGRATED_DB_URI` (the migrated `db`) and `HASHVIEW_FRESH_DB_URI`
(`db-fresh`). It uses raw `mysql.connector`/SQLAlchemy engine reads (no ORM, so
it is version-agnostic).

- [ ] **Step 1: Write the failing test module**

Create `tests/integration/test_migration_e2e.py`:

```python
"""End-to-end main->dev migration verifier.

Run by tests/run_migration_e2e.sh AFTER the dev app has migrated + backfilled
the DB. Reads two live MySQL databases:
  HASHVIEW_MIGRATED_DB_URI  - the db that went main -> seed -> dev
  HASHVIEW_FRESH_DB_URI     - dev schema built from empty (parity oracle)
"""
import os
import pytest
from sqlalchemy import create_engine, text

from tests.migration.expected_hex import USERNAME_CASES, PLAINTEXT_CASES

DEV_HEAD = "c8b3f0a14d27"

pytestmark = [pytest.mark.mysql, pytest.mark.migration]


def _engine(env):
    uri = os.environ.get(env)
    if not uri:
        pytest.skip(f"{env} not set (run via tests/run_migration_e2e.sh)")
    return create_engine(uri)


@pytest.fixture(scope="module")
def migrated():
    return _engine("HASHVIEW_MIGRATED_DB_URI")


@pytest.fixture(scope="module")
def fresh():
    return _engine("HASHVIEW_FRESH_DB_URI")


def _scalar(engine, sql, **params):
    with engine.connect() as c:
        return c.execute(text(sql), params).scalar()


def test_alembic_at_dev_head(migrated):
    assert _scalar(migrated, "SELECT version_num FROM alembic_version") == DEV_HEAD


def test_passwords_decoded_flag_flipped(migrated):
    assert _scalar(migrated, "SELECT passwords_decoded FROM settings LIMIT 1") == 1


@pytest.mark.parametrize("row_id,marker", [(9001, "u_ascii"), (9002, "u_utf8"),
                                           (9003, "u_nonutf8"), (9004, "u_plaintext")])
def test_username_hex_backfill(migrated, row_id, marker):
    _seeded, expected = USERNAME_CASES[marker]
    got = _scalar(migrated, "SELECT username FROM hashfile_hashes WHERE id=:i", i=row_id)
    assert got == expected


@pytest.mark.parametrize("row_id,marker", [(9001, "p_ascii"), (9002, "p_utf8"),
                                           (9003, "p_nonutf8"), (9004, "p_overflow")])
def test_plaintext_hex_backfill(migrated, row_id, marker):
    _seeded, expected = PLAINTEXT_CASES[marker]
    got = _scalar(migrated, "SELECT plaintext FROM hashes WHERE id=:i", i=row_id)
    assert got == expected


def test_ddl_backfills_on_preexisting_rows(migrated):
    assert _scalar(migrated, "SELECT hex_salt FROM hashfiles WHERE id=900") == 0
    assert _scalar(migrated, "SELECT loopback FROM tasks WHERE id=900") == 0
    # settings columns added on dev exist and carry upgrade-safe defaults
    assert _scalar(migrated, "SELECT pushover_enabled FROM settings LIMIT 1") == 1
    assert _scalar(migrated, "SELECT slack_enabled FROM settings LIMIT 1") == 0
    assert _scalar(migrated, "SELECT agent_timeout_minutes FROM settings LIMIT 1") == 60


def _col(engine, table, col):
    row = engine.connect().execute(text(
        "SELECT data_type, character_set_name, is_nullable, column_default "
        "FROM information_schema.columns "
        "WHERE table_schema=DATABASE() AND table_name=:t AND column_name=:c"),
        {"t": table, "c": col}).fetchone()
    return row


def test_explicit_type_assertions(migrated):
    dt, cs, _null, _def = _col(migrated, "hashes", "ciphertext")
    assert dt == "text"
    assert cs == "utf8mb4"
    assert _col(migrated, "hashes", "plaintext").character_set_name == "utf8mb4"
    assert _col(migrated, "hashfile_hashes", "username").character_set_name == "utf8mb4"


def _schema_snapshot(engine):
    """Comparable dict of the schema from information_schema."""
    snap = {}
    with engine.connect() as c:
        cols = c.execute(text(
            "SELECT table_name, column_name, ordinal_position, data_type, "
            "character_maximum_length, numeric_precision, numeric_scale, "
            "is_nullable, column_default, character_set_name, collation_name, extra "
            "FROM information_schema.columns WHERE table_schema=DATABASE() "
            "ORDER BY table_name, ordinal_position")).fetchall()
        snap["columns"] = [tuple(r) for r in cols]
        idx = c.execute(text(
            "SELECT table_name, index_name, non_unique, seq_in_index, column_name "
            "FROM information_schema.statistics WHERE table_schema=DATABASE() "
            "ORDER BY table_name, index_name, seq_in_index")).fetchall()
        snap["indexes"] = [tuple(r) for r in idx]
        fks = c.execute(text(
            "SELECT table_name, column_name, referenced_table_name, referenced_column_name "
            "FROM information_schema.key_column_usage WHERE table_schema=DATABASE() "
            "AND referenced_table_name IS NOT NULL "
            "ORDER BY table_name, column_name, referenced_table_name")).fetchall()
        snap["fks"] = [tuple(r) for r in fks]
    return snap


def test_schema_parity_with_fresh_build(migrated, fresh):
    m = _schema_snapshot(migrated)
    f = _schema_snapshot(fresh)
    assert m["columns"] == f["columns"], "column definitions differ (type/charset/collation/default/order)"
    assert m["indexes"] == f["indexes"], "index definitions differ"
    assert m["fks"] == f["fks"], "foreign key definitions differ"
```

- [ ] **Step 2: Verify it collects and skips cleanly without env**

Run: `python -m pytest tests/integration/test_migration_e2e.py -m migration -v`
Expected: tests SKIP (env vars unset) — proves the module imports and collects. No import errors.

- [ ] **Step 3: Commit**

```bash
git add tests/integration/test_migration_e2e.py
git commit -m "test(migration): verifier for head, hex backfill, DDL defaults, schema parity"
```

---

## Task 7: The orchestrator shell runner

**Files:**
- Create: `tests/run_migration_e2e.sh` (chmod +x)

- [ ] **Step 1: Write the runner**

Create `tests/run_migration_e2e.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export DOCKER_PLATFORM="${DOCKER_PLATFORM:-linux/amd64}"
COMPOSE="${COMPOSE_BIN:-docker compose} -f docker-compose.migration.yml"
KEEP="${HASHVIEW_MIGRATION_KEEP:-0}"
MAIN_REF="${HASHVIEW_MAIN_REF:-origin/main}"
MAIN_WT="$(mktemp -d)/hv-main"

CONFIG_CONF=$'[SERVER]\nSERVER_NAME = app:5000\nSECRET_KEY = migration-e2e\n[database]\nhost = db\nusername = hashview\npassword = hashview\n[SMTP]\nserver = smtp.example.com\nport = 25\nuse_tls = False\nusername =\npassword =\ndefault_sender =\n'

cleanup() {
  if [ "$KEEP" != "1" ]; then
    $COMPOSE down -v --remove-orphans || true
    git worktree remove "$MAIN_WT" --force 2>/dev/null || true
  fi
}
trap cleanup EXIT

db_exec() { $COMPOSE exec -T "$1" mysql -h127.0.0.1 -uhashview -phashview hashview -N -e "$2"; }
wait_healthy() {  # $1 = service
  echo "Waiting for $1 healthy..."
  for _ in $(seq 1 60); do
    cid="$($COMPOSE ps -q "$1")"
    [ -n "$cid" ] && [ "$(docker inspect -f '{{.State.Health.Status}}' "$cid" 2>/dev/null)" = "healthy" ] && return 0
    sleep 3
  done
  echo "$1 never became healthy"; $COMPOSE logs --tail 100 "$1"; return 1
}

echo "== Build dev image =="
printf '%s' "$CONFIG_CONF" > hashview/config.conf
docker build --platform "$DOCKER_PLATFORM" -t hashview:dev .

echo "== Build main image from $MAIN_REF =="
git worktree add "$MAIN_WT" "$MAIN_REF"
printf '%s' "$CONFIG_CONF" > "$MAIN_WT/hashview/config.conf"
( cd "$MAIN_WT" && docker build --platform "$DOCKER_PLATFORM" -t hashview:main . )

echo "== Start db + db-fresh =="
$COMPOSE up -d db db-fresh
wait_healthy db
wait_healthy db-fresh

echo "== app-main: create + migrate main schema =="
$COMPOSE up -d app-main
# app-main runs migrations at boot; wait until alembic_version populated
for _ in $(seq 1 60); do
  db_exec db "SELECT 1 FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='alembic_version'" | grep -q 1 && break
  sleep 3
done
for _ in $(seq 1 60); do
  [ -n "$(db_exec db 'SELECT version_num FROM alembic_version')" ] && break; sleep 2
done
echo "main head: $(db_exec db 'SELECT version_num FROM alembic_version')"

echo "== Load seed =="
$COMPOSE cp tests/migration/seed_main.sql db:/tmp/seed_main.sql
$COMPOSE exec -T db sh -c "mysql -h127.0.0.1 -uhashview -phashview hashview < /tmp/seed_main.sql"

echo "== Stop app-main, start app-dev (migrate + hex backfill) =="
$COMPOSE stop app-main
$COMPOSE up -d app-dev
# wait until dev head reached AND backfill flag flipped
for _ in $(seq 1 60); do
  hv="$(db_exec db 'SELECT version_num FROM alembic_version' || true)"
  pd="$(db_exec db 'SELECT passwords_decoded FROM settings LIMIT 1' || true)"
  [ "$hv" = "c8b3f0a14d27" ] && [ "$pd" = "1" ] && break
  sleep 3
done
echo "migrated head: $(db_exec db 'SELECT version_num FROM alembic_version'), passwords_decoded: $(db_exec db 'SELECT passwords_decoded FROM settings LIMIT 1')"

echo "== Build fresh dev schema from empty in db-fresh =="
python -m venv .mig-venv >/dev/null 2>&1 || true
. .mig-venv/bin/activate 2>/dev/null || true
pip install -q -r requirements.txt
HASHVIEW_TEST_DATABASE_URI="mysql+mysqlconnector://hashview:hashview@127.0.0.1:3307/hashview?charset=utf8mb4" \
  python scripts/run_migrations.py

echo "== Run verifier =="
export HASHVIEW_MIGRATED_DB_URI="mysql+mysqlconnector://hashview:hashview@127.0.0.1:3306/hashview?charset=utf8mb4"
export HASHVIEW_FRESH_DB_URI="mysql+mysqlconnector://hashview:hashview@127.0.0.1:3307/hashview?charset=utf8mb4"
python -m pytest tests/integration/test_migration_e2e.py -m migration -v
```

- [ ] **Step 2: Make executable**

Run: `chmod +x tests/run_migration_e2e.sh`

- [ ] **Step 3: Full local run (the real integration test)**

Run: `./tests/run_migration_e2e.sh`
Expected: builds both images, brings up the stack, seeds, migrates on dev, builds the fresh oracle, and the pytest verifier reports **all PASS**. If the seed fails to load (main NOT-NULL/FK mismatch), fix `tests/migration/seed_main.sql` per the error and re-run — iterate here until green.

- [ ] **Step 4: Commit**

```bash
git add tests/run_migration_e2e.sh
git commit -m "test(migration): orchestrator runner for main->dev e2e migration"
```

---

## Task 8: CI workflow

**Files:**
- Create: `.github/workflows/migration-e2e.yml`

- [ ] **Step 1: Write the workflow**

Create `.github/workflows/migration-e2e.yml`:

```yaml
name: migration-e2e
on:
  push:
  pull_request:

jobs:
  migration-e2e:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # need origin/main to build the main image

      - name: Ensure origin/main is available
        run: git fetch origin main:refs/remotes/origin/main

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Run end-to-end migration test
        run: ./tests/run_migration_e2e.sh
        env:
          DOCKER_PLATFORM: linux/amd64
```

- [ ] **Step 2: Validate YAML**

Run: `python -c "import yaml; yaml.safe_load(open('.github/workflows/migration-e2e.yml')); print('valid')"`
Expected: `valid`

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/migration-e2e.yml
git commit -m "ci: run end-to-end main->dev migration test on push/PR"
```

---

## Task 9: Finalize — PR

- [ ] **Step 1: Confirm the full suite is green locally**

Run: `./tests/run_migration_e2e.sh`
Expected: all verifier tests PASS.

- [ ] **Step 2: Push and open the PR into `v0.8.3-dev`**

```bash
git push -u origin work/off-dev
gh pr create --base v0.8.3-dev --head work/off-dev \
  --title "test: end-to-end main->dev database migration test" \
  --body "Implements docs/superpowers/specs/2026-07-02-migration-e2e-test-design.md. Builds hashview:main from origin/main and hashview:dev from this branch, migrates a populated main DB to dev, and verifies alembic head, legacy-hex->text backfill, DDL-column defaults, and full schema parity vs a dev-from-empty build. 🤖 Generated with [Claude Code](https://claude.com/claude-code)"
```

Expected: PR created against `v0.8.3-dev`.

---

## Notes for the implementer

- **DRY:** the hex cases live only in `tests/migration/expected_hex.py`; the seed and verifier reference the same values. If you change a case, change it there and mirror the hex literal in `seed_main.sql`.
- **The seed is the risky part.** Task 2 exists specifically so the seed matches main's real NOT-NULL/FK constraints. Do not skip it. If `ciphertext` is `VARCHAR(500)` on main, seed a ≤500-char value and rely on the type-parity assertion for the widening; do not seed a 600-char value into main.
- **Idempotency of the not-hex case:** `already-text` is not valid hex, so the backfill leaves it untouched — that verifies the guard and the re-run safety in one row.
- **Cleanup:** the runner tears down containers, volumes, and the temp main worktree on exit. Set `HASHVIEW_MIGRATION_KEEP=1` to keep them for debugging.
