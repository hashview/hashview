#!/usr/bin/env bash
#
# preflight.sh — run every CI gate locally before pushing.
#
# Mirrors the GitHub Actions workflows so failures are caught on your machine
# instead of after a push:
#   .github/workflows/lint.yml    -> ruff, bandit (vs baseline), pip-audit, openapi
#   .github/workflows/pylint.yml  -> pylint (rules + fail-under from .pylintrc)
#   .github/workflows/e2e.yml     -> docker-compose Playwright harness  (opt-in: --e2e)
# Plus the unit-test suite (tests/unit/), which has no CI job but is meant to be
# run locally (see CLAUDE.md / tests/unit/conftest.py — in-memory SQLite, no DB).
#
# Tool versions are pinned in requirements-dev.txt; install once with:
#   pip install -r requirements.txt -r requirements-dev.txt
#
# Usage:
#   scripts/preflight.sh              # all static gates + unit tests
#   scripts/preflight.sh --fast       # skip the slow gates (pip-audit, unit tests)
#   scripts/preflight.sh --no-audit   # skip pip-audit only (e.g. offline)
#   scripts/preflight.sh --e2e        # also run the docker e2e harness (slow, needs docker)
#   scripts/preflight.sh -h|--help
#
# Wire it as a pre-push hook (optional):
#   ln -s ../../scripts/preflight.sh .git/hooks/pre-push
# The per-commit framework (.pre-commit-config.yaml) stays as-is for fast,
# auto-fixing commit-time checks; this script is the heavier pre-push mirror.

set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# --- options ---------------------------------------------------------------
RUN_AUDIT=1
RUN_UNIT=1
RUN_E2E=0
for arg in "$@"; do
  case "$arg" in
    --fast)     RUN_AUDIT=0; RUN_UNIT=0 ;;
    --no-audit) RUN_AUDIT=0 ;;
    --e2e)      RUN_E2E=1 ;;
    -h|--help)
      sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "Unknown option: $arg (try --help)" >&2; exit 2 ;;
  esac
done

# Prefer an explicit $PYTHON, then a local .venv, then python3 on PATH.
if [ -n "${PYTHON:-}" ]; then
  PY="$PYTHON"
elif [ -x .venv/bin/python ]; then
  PY=".venv/bin/python"
else
  PY="python3"
fi

# --- pretty output ---------------------------------------------------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  BOLD=$'\033[1m'; RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; DIM=$'\033[2m'; RESET=$'\033[0m'
else
  BOLD=""; RED=""; GREEN=""; YELLOW=""; DIM=""; RESET=""
fi

declare -a RESULTS=()
FAILED=0

have() { command -v "$1" >/dev/null 2>&1; }

# run_gate <name> <missing-tool-hint> <command...>
# Prints a header, runs the command, records PASS/FAIL/SKIP, never aborts the
# run early so you see every problem in one pass.
run_gate() {
  local name="$1"; local hint="$2"; shift 2
  printf '\n%s━━ %s ━━%s\n' "$BOLD" "$name" "$RESET"
  if [ -n "$hint" ] && ! have "$hint"; then
    printf '%sSKIP%s  %s — %s not found. Install: pip install -r requirements-dev.txt\n' \
      "$YELLOW" "$RESET" "$name" "$hint"
    RESULTS+=("${YELLOW}SKIP${RESET}  $name (missing $hint)")
    return
  fi
  if "$@"; then
    RESULTS+=("${GREEN}PASS${RESET}  $name")
  else
    RESULTS+=("${RED}FAIL${RESET}  $name")
    FAILED=1
  fi
}

printf '%sHashview preflight%s  %s(interpreter: %s)%s\n' "$BOLD" "$RESET" "$DIM" "$PY" "$RESET"

# 1. Ruff — lint (imports, bugbear, pyupgrade, pycodestyle). Matches lint.yml.
run_gate "ruff" "ruff" \
  ruff check hashview/ hashview.py

# 2. Bandit — SAST vs committed baseline; only NEW findings fail. Matches lint.yml.
run_gate "bandit (vs baseline)" "bandit" \
  bandit -r hashview install/hashview-agent -c pyproject.toml -b .bandit-baseline.json -q

# 3. OpenAPI — structural validation of the committed spec. Matches lint.yml.
run_gate "openapi spec" "openapi-spec-validator" \
  openapi-spec-validator hashview/api_docs/openapi.yaml

# 4. pip-audit — known CVEs in production deps. Matches lint.yml. Network + slow.
if [ "$RUN_AUDIT" -eq 1 ]; then
  run_gate "pip-audit" "pip-audit" \
    pip-audit -r requirements.txt
else
  printf '\n%s━━ pip-audit ━━%s\n%sSKIP%s  (disabled)\n' "$BOLD" "$RESET" "$YELLOW" "$RESET"
  RESULTS+=("${YELLOW}SKIP${RESET}  pip-audit (disabled)")
fi

# 5. Pylint — full project, rules + fail-under from .pylintrc. Matches pylint.yml.
run_gate "pylint" "" \
  "$PY" -m pylint --jobs=1 --rcfile=.pylintrc --output-format=colorized --reports=n --score=y hashview/ hashview.py

# 6. Unit tests — in-memory SQLite, no DB/docker. No CI job; run locally.
if [ "$RUN_UNIT" -eq 1 ]; then
  run_gate "unit tests" "" \
    "$PY" -m pytest tests/unit -q
else
  printf '\n%s━━ unit tests ━━%s\n%sSKIP%s  (disabled)\n' "$BOLD" "$RESET" "$YELLOW" "$RESET"
  RESULTS+=("${YELLOW}SKIP${RESET}  unit tests (disabled)")
fi

# 7. E2E — docker-compose Playwright harness. Opt-in; heavy; needs docker.
if [ "$RUN_E2E" -eq 1 ]; then
  run_gate "e2e (docker)" "docker" \
    ./tests/run_e2e_compose.sh
else
  printf '\n%s━━ e2e (docker) ━━%s\n%sSKIP%s  (opt-in: pass --e2e)\n' "$BOLD" "$RESET" "$DIM" "$RESET"
fi

# --- summary ---------------------------------------------------------------
printf '\n%s━━ summary ━━%s\n' "$BOLD" "$RESET"
for line in "${RESULTS[@]}"; do printf '  %s\n' "$line"; done

if [ "$FAILED" -ne 0 ]; then
  printf '\n%sPreflight FAILED%s — fix the gates above before pushing.\n' "$RED$BOLD" "$RESET"
  exit 1
fi
printf '\n%sPreflight passed.%s\n' "$GREEN$BOLD" "$RESET"
exit 0
