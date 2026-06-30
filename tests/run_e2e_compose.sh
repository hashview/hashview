#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# Load .env.test so the seed step below sees the same HASHVIEW_E2E_* vars the
# pytest conftest reads (set -a exports each assignment).
if [ -f .env.test ]; then
  echo "Loading e2e environment from .env.test..."
  set -a
  # shellcheck disable=SC1091
  . ./.env.test
  set +a
fi

export DOCKER_PLATFORM="linux/amd64"

COMPOSE_BIN="${COMPOSE_BIN:-docker compose}"
BASE_URL="${HASHVIEW_E2E_BASE_URL:-http://127.0.0.1:5000}"
KEEP_CONTAINERS="${HASHVIEW_E2E_KEEP_CONTAINERS:-0}"

if [ ! -f hashview/config.conf ]; then
  echo "Writing hashview/config.conf for e2e (matches docker-compose.yml db credentials)..."
  cat > hashview/config.conf <<'EOF'
[SERVER]
SERVER_NAME = 127.0.0.1:5000
SECRET_KEY = e2e-test-secret-key

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
fi

if [ ! -x .venv/bin/python ]; then
  echo "Creating .venv and installing test deps from requirements-dev.txt..."
  python3 -m venv .venv
  ./.venv/bin/pip install -r requirements-dev.txt
fi
./.venv/bin/python -m playwright install

echo "Starting docker compose services..."
$COMPOSE_BIN up -d --build

cleanup() {
  if [ "$KEEP_CONTAINERS" = "1" ]; then
    echo "Keeping containers running (HASHVIEW_E2E_KEEP_CONTAINERS=1)."
  else
    echo "Stopping docker compose services..."
    # Include the test override + profile so the agent-test sim is torn down too.
    $COMPOSE_BIN -f docker-compose.yml -f docker-compose.test.yml --profile test \
      down -v
  fi
}
trap cleanup EXIT

echo "Waiting for app to respond at $BASE_URL ..."
for _ in {1..60}; do
  if curl -fsS "$BASE_URL/login" >/dev/null 2>&1; then
    echo "App is up."
    break
  fi
  sleep 2
done

if ! curl -fsS "$BASE_URL/login" >/dev/null 2>&1; then
  echo "App did not become ready in time."
  # Surface startup/migration errors first — a long readiness poll floods the
  # log with per-request tracebacks that bury the real boot failure under a
  # plain --tail.
  echo "--- startup-relevant app log lines ---"
  # `|| true`: under `set -euo pipefail`, a no-match grep exits 1 and would
  # abort the script here, skipping the tail dump and the explicit exit below.
  $COMPOSE_BIN logs app 2>&1 | grep -iE \
    "Upgrading Database|Setting up defaults|Adding Default|Traceback|Error|Exception|Connection refused|doesn't exist|Multiple head|alembic" \
    | head -60 || true
  echo "--- recent docker logs (tail) ---"
  $COMPOSE_BIN logs --tail 200
  exit 1
fi

export HASHVIEW_E2E_BASE_URL="$BASE_URL"

# Bring up the heartbeat-only agent simulator (docker-compose.test.yml, `test`
# profile) now that the app is healthy. It's fire-and-forget: the sim polls
# /v1/agents/heartbeat for HASHVIEW_AGENT_MAX_SECONDS then exits, so we start it
# detached and never block the suite on it. `|| true` keeps a sim launch hiccup
# from aborting the harness under `set -e` — the dedicated test_agent_sim.py
# still exercises the heartbeat path directly.
echo "Starting agent simulator (test profile, fire-and-forget)..."
$COMPOSE_BIN -f docker-compose.yml -f docker-compose.test.yml --profile test \
  up -d --no-deps agent-test || true

# Seed the database to the state the suite pins via env vars: the admin user
# (id=1) gets the e2e email/password/api_key, a Settings row exists, and the
# Customer/Hashfile/Job rows are created at the expected IDs. Idempotent. Runs
# INSIDE the app container (PYTHONPATH=/ — the package lives at /hashview in the
# image). SETUP_EMAIL/SETUP_PASSWORD default to the login email/password.
#
# Only seed when the e2e env is actually configured (e.g. a local .env.test).
# CI has no .env.test, so these are unset — skip seeding (the seeder exits
# non-zero on missing required vars, which under `set -e` would abort the whole
# harness) and let the individual tests skip on missing data, exactly as they
# did before seeding existed.
if [ -n "${HASHVIEW_E2E_API_KEY:-}" ] && [ -n "${HASHVIEW_E2E_CUSTOMER_ID:-}" ] \
   && [ -n "${HASHVIEW_E2E_HASHFILE_ID:-}" ] && [ -n "${HASHVIEW_E2E_JOB_ID:-}" ] \
   && [ -n "${HASHVIEW_E2E_TASK_ID:-}" ] \
   && { [ -n "${HASHVIEW_E2E_SETUP_EMAIL:-}" ] || [ -n "${HASHVIEW_E2E_EMAIL:-}" ]; }; then
  echo "Seeding e2e database (customer/hashfile/job + admin)..."
  $COMPOSE_BIN cp tests/seed_e2e_db.py app:/tmp/seed_e2e_db.py
  $COMPOSE_BIN exec -T \
    -e PYTHONPATH=/ \
    -e HASHVIEW_E2E_SETUP_EMAIL="${HASHVIEW_E2E_SETUP_EMAIL:-${HASHVIEW_E2E_EMAIL:-}}" \
    -e HASHVIEW_E2E_SETUP_PASSWORD="${HASHVIEW_E2E_SETUP_PASSWORD:-${HASHVIEW_E2E_PASSWORD:-}}" \
    -e HASHVIEW_E2E_API_KEY="${HASHVIEW_E2E_API_KEY:-}" \
    -e HASHVIEW_E2E_SECOND_EMAIL="${HASHVIEW_E2E_SECOND_EMAIL:-}" \
    -e HASHVIEW_E2E_SECOND_PASSWORD="${HASHVIEW_E2E_SECOND_PASSWORD:-}" \
    -e HASHVIEW_E2E_CUSTOMER_ID="${HASHVIEW_E2E_CUSTOMER_ID:-}" \
    -e HASHVIEW_E2E_HASHFILE_ID="${HASHVIEW_E2E_HASHFILE_ID:-}" \
    -e HASHVIEW_E2E_JOB_ID="${HASHVIEW_E2E_JOB_ID:-}" \
    -e HASHVIEW_E2E_TASK_ID="${HASHVIEW_E2E_TASK_ID:-}" \
    -w / app python /tmp/seed_e2e_db.py
else
  echo "Skipping DB seed: e2e env vars not set (no .env.test?). Data-dependent tests will skip."
fi

echo "Running pytest against $BASE_URL"
set +e
./.venv/bin/python -m pytest -m e2e \
    --ignore=tests/security \
    --ignore=tests/unit \
    -vv -s --maxfail=1
TEST_EXIT=$?
set -e

if [ "$TEST_EXIT" -ne 0 ]; then
  echo "Pytest failed; printing recent docker logs..."
  $COMPOSE_BIN logs --tail 200
fi

exit "$TEST_EXIT"
