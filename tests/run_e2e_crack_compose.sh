#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export DOCKER_PLATFORM="${DOCKER_PLATFORM:-linux/amd64}"
COMPOSE="${COMPOSE_BIN:-docker compose} -f docker-compose.yml -f docker-compose.e2e.yml"
BASE_URL="${HASHVIEW_E2E_BASE_URL:-http://127.0.0.1:5000}"
KEEP="${HASHVIEW_E2E_KEEP_CONTAINERS:-0}"
ARTIFACTS="$ROOT_DIR/tests/e2e/crack/.artifacts"

if [ -z "${ROCKYOU_PATH:-}" ] || [ ! -f "${ROCKYOU_PATH:-}" ]; then
  echo "ROCKYOU_PATH not set or file missing; set it to a rockyou wordlist to run this test." >&2
  exit 2
fi

# Server config (matches docker-compose.yml db credentials).
if [ ! -f hashview/config.conf ]; then
  cat > hashview/config.conf <<'EOF'
[SERVER]
SERVER_NAME = 127.0.0.1:5000
SECRET_KEY = e2e-crack-secret-key

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
  python3 -m venv .venv
  ./.venv/bin/pip install -r requirements-dev.txt
fi

echo "Generating rockyou slices + manifest..."
rm -rf "$ARTIFACTS"
CRACK_ARTIFACT_DIR="$ARTIFACTS" ./.venv/bin/python tests/e2e/crack/gen_slices.py
MANIFEST="$ARTIFACTS/manifest.json"

echo "Building + starting db and app..."
$COMPOSE up -d --build app

cleanup() {
  if [ "$KEEP" = "1" ]; then
    echo "Keeping containers (HASHVIEW_E2E_KEEP_CONTAINERS=1)."
  else
    $COMPOSE down -v
  fi
}
trap cleanup EXIT

echo "Waiting for app at $BASE_URL ..."
for _ in {1..60}; do
  curl -fsS "$BASE_URL/login" >/dev/null 2>&1 && { echo "App up."; break; }
  sleep 2
done
if ! curl -fsS "$BASE_URL/login" >/dev/null 2>&1; then
  echo "App did not become ready."; $COMPOSE logs --tail 200 app; exit 1
fi

echo "Seeding crack job + authorizing agents..."
$COMPOSE cp tests/e2e/crack/seed_crack_db.py app:/tmp/seed_crack_db.py
$COMPOSE cp tests/e2e/crack/verify_crack.py app:/tmp/verify_crack.py
$COMPOSE exec -T app mkdir -p /tmp/crack
$COMPOSE cp "$ARTIFACTS/sliceA.txt" app:/tmp/crack/sliceA.txt
$COMPOSE cp "$ARTIFACTS/sliceB.txt" app:/tmp/crack/sliceB.txt
$COMPOSE cp "$MANIFEST" app:/tmp/crack/manifest.json
$COMPOSE exec -T -e PYTHONPATH=/ -w / app python /tmp/seed_crack_db.py /tmp/crack/manifest.json

echo "Starting agents..."
$COMPOSE up -d --build agent1 agent2

echo "Running pytest -m e2e_crack ..."
set +e
HASHVIEW_E2E_CRACK_MANIFEST="$MANIFEST" \
HASHVIEW_E2E_CRACK_COMPOSE="$COMPOSE" \
  ./.venv/bin/python -m pytest -m e2e_crack tests/e2e/test_multiagent_ntlm_crack.py -vv -s
EXIT=$?
set -e

if [ "$EXIT" -ne 0 ]; then
  echo "--- app logs ---";    $COMPOSE logs --tail 100 app
  echo "--- agent1 logs ---"; $COMPOSE logs --tail 100 agent1
  echo "--- agent2 logs ---"; $COMPOSE logs --tail 100 agent2
fi
exit "$EXIT"
