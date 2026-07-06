#!/usr/bin/env bash
# End-to-end main->dev database migration test.
#
# Builds hashview:main (from origin/main) and hashview:dev (from this worktree),
# lets app-main create + seed a MySQL db, loads legacy-format rows, then boots
# app-dev against the SAME db so it applies the 14 dev migrations AND runs the
# startup hex->text backfill. A dev-from-empty schema is built in db-fresh as a
# parity oracle, and a pytest verifier asserts head/data/schema.
#
# Env knobs:
#   PYTHON                 python with project deps (default: build a temp venv)
#   HASHVIEW_MAIN_REF      ref to build the "old" image from (default origin/main)
#   HASHVIEW_MIGRATION_KEEP=1  keep containers/volumes/worktree for debugging
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export DOCKER_PLATFORM="${DOCKER_PLATFORM:-linux/amd64}"
COMPOSE="${COMPOSE_BIN:-docker compose} -f docker-compose.migration.yml"
KEEP="${HASHVIEW_MIGRATION_KEEP:-0}"
MAIN_REF="${HASHVIEW_MAIN_REF:-origin/main}"
DEV_HEAD="c8b3f0a14d27"

TMP_ROOT="$(mktemp -d)"
MAIN_WT="$TMP_ROOT/hv-main"
VENV_DIR="$TMP_ROOT/venv"

CONFIG_CONF=$'[SERVER]\nSERVER_NAME = app:5000\nSECRET_KEY = migration-e2e\n[database]\nhost = db\nusername = hashview\npassword = hashview\n[SMTP]\nserver = smtp.example.com\nport = 25\nuse_tls = False\nusername =\npassword =\ndefault_sender =\n'

cleanup() {
  if [ "$KEEP" != "1" ]; then
    $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
    git worktree remove "$MAIN_WT" --force >/dev/null 2>&1 || true
    rm -rf "$TMP_ROOT" || true
  else
    echo "HASHVIEW_MIGRATION_KEEP=1 -> leaving stack up. Temp dir: $TMP_ROOT"
  fi
}
trap cleanup EXIT

db_exec() {  # $1 = service, $2 = SQL ; prints scalar/rows (-N no headers)
  $COMPOSE exec -T "$1" mysql -h127.0.0.1 -uhashview -phashview hashview -N -e "$2"
}

wait_healthy() {  # $1 = service
  echo "Waiting for $1 to be healthy..."
  for _ in $(seq 1 60); do
    cid="$($COMPOSE ps -q "$1" 2>/dev/null || true)"
    if [ -n "$cid" ] && [ "$(docker inspect -f '{{.State.Health.Status}}' "$cid" 2>/dev/null)" = "healthy" ]; then
      return 0
    fi
    sleep 3
  done
  echo "ERROR: $1 never became healthy"; $COMPOSE logs --tail 100 "$1" || true; return 1
}

poll() {  # $1 = description, $2 = SQL, $3 = expected value
  echo "Waiting for: $1 ..."
  for _ in $(seq 1 80); do
    got="$(db_exec db "$2" 2>/dev/null | tr -d '[:space:]' || true)"
    [ "$got" = "$3" ] && { echo "  -> $1 satisfied ($got)"; return 0; }
    sleep 3
  done
  echo "ERROR: timed out waiting for $1 (last value: '${got:-}')"
  $COMPOSE logs --tail 120 app-dev app-main || true
  return 1
}

echo "== Build hashview:dev from this worktree =="
printf '%s' "$CONFIG_CONF" > hashview/config.conf
docker build --platform "$DOCKER_PLATFORM" -t hashview:dev .

echo "== Build hashview:main from $MAIN_REF =="
git worktree add "$MAIN_WT" "$MAIN_REF"
printf '%s' "$CONFIG_CONF" > "$MAIN_WT/hashview/config.conf"
( cd "$MAIN_WT" && docker build --platform "$DOCKER_PLATFORM" -t hashview:main . )

echo "== Start db + db-fresh =="
$COMPOSE up -d db db-fresh
wait_healthy db
wait_healthy db-fresh

echo "== app-main: create + migrate the main-era schema =="
$COMPOSE up -d app-main
# app-main runs its migrations during create_app (before serving); wait until the
# alembic bookkeeping table has a revision recorded.
rev=""
for _ in $(seq 1 80); do
  rev="$(db_exec db "SELECT version_num FROM alembic_version" 2>/dev/null | tr -d '[:space:]' || true)"
  [ -n "$rev" ] && break
  sleep 3
done
[ -n "$rev" ] || { echo "ERROR: app-main never recorded an alembic revision"; $COMPOSE logs --tail 120 app-main; exit 1; }
echo "  main schema at revision: $rev"

echo "== Load main-era seed =="
$COMPOSE exec -T db mysql -h127.0.0.1 -uhashview -phashview hashview < tests/migration/seed_main.sql
echo "  seeded rows: hashfile_hashes=$(db_exec db 'SELECT COUNT(*) FROM hashfile_hashes'), hashes=$(db_exec db 'SELECT COUNT(*) FROM hashes'), settings=$(db_exec db 'SELECT COUNT(*) FROM settings')"

echo "== Stop app-main; boot app-dev to migrate + backfill the same db =="
$COMPOSE stop app-main
$COMPOSE up -d app-dev
# app-dev applies the 14 dev migrations, then decode_legacy_hex_if_needed flips
# settings.passwords_decoded 0 -> 1. Gate on BOTH so the backfill definitely ran.
poll "alembic at dev head ($DEV_HEAD)" "SELECT version_num FROM alembic_version" "$DEV_HEAD"
poll "settings.passwords_decoded = 1" "SELECT passwords_decoded FROM settings LIMIT 1" "1"

echo "== Build dev-from-empty schema in db-fresh (parity oracle) =="
if [ -z "${PYTHON:-}" ]; then
  echo "  creating temp venv (set PYTHON=... to reuse an existing env)"
  python3 -m venv "$VENV_DIR"
  "$VENV_DIR/bin/pip" install -q -r requirements.txt -r requirements-dev.txt
  PYTHON="$VENV_DIR/bin/python"
fi
HASHVIEW_TEST_DATABASE_URI="mysql+mysqlconnector://hashview:hashview@127.0.0.1:3307/hashview?charset=utf8mb4" \
  "$PYTHON" scripts/run_migrations.py

echo "== Run verifier =="
export HASHVIEW_MIGRATED_DB_URI="mysql+mysqlconnector://hashview:hashview@127.0.0.1:3306/hashview?charset=utf8mb4"
export HASHVIEW_FRESH_DB_URI="mysql+mysqlconnector://hashview:hashview@127.0.0.1:3307/hashview?charset=utf8mb4"
"$PYTHON" -m pytest tests/integration/test_migration_e2e.py -m migration -v

echo "== Migration e2e PASSED =="
