# Testing

This document describes the local and CI testing setup for Hashview, including
how to run tests against the dev Docker containers and what each CI workflow
gates.

## Local prerequisites

- Python virtual environment in `.venv` (supported Python range is 3.11+)
- Docker + Docker Compose
- Playwright browsers installed (`python -m playwright install`) for the e2e suite
- Most suites import `hashview.*`, so install both requirement sets:
  ```
  ./.venv/bin/pip install -r requirements.txt -r requirements-dev.txt
  ```
  The e2e Playwright suite is the exception — it talks to a live container over
  HTTP and does not import the app, so a dev-only venv
  (`requirements-dev.txt`) is enough for it.

## Test suites overview

| Suite | Path | How it runs | Imports `hashview.*`? |
| --- | --- | --- | --- |
| Unit | `tests/unit/` (~78 files) | `pytest tests/unit` | Yes |
| Security | `tests/security/` | `pytest tests/security` (tests marked `security`) | Yes |
| Agent unit | `tests/agent_unit/` | `pytest tests/agent_unit` | No (imports `agent.*`) |
| Integration (MySQL) | `tests/integration/` | `pytest tests/integration -m mysql` | Yes |
| E2E (Playwright) | `tests/e2e/` | `pytest -m e2e` against a live host | No |
| E2E crack harness | `tests/crack/`, `tests/e2e/crack/` | `tests/run_e2e_crack_compose.sh` | Mixed |

Markers are declared in `pytest.ini`:

- `e2e` — end-to-end tests using Playwright
- `agent_sim` — agent simulator tests
- `security` — security-focused tests
- `e2e_crack` — dockerized multi-agent real-crack e2e test (opt-in)
- `mysql` — integration tests that run against a real MySQL/MariaDB backend
  (needs `HASHVIEW_TEST_DATABASE_URI`)

> **Note on invocation.** Suites are selected by *path*, not by a single marker.
> CI runs `python -m pytest tests/unit tests/security tests/agent_unit ...`
> directly. There is no umbrella `-m security` run that pulls in the unit suite —
> unit tests are not marked `security`. The `security` marker only matches the
> tests under `tests/security/`.

## Environment files

Tests load `.env.test` via `tests/conftest.py` (any var already in the
environment wins, so CI's exported block takes precedence). At minimum, set:

```
HASHVIEW_E2E_BASE_URL=http://127.0.0.1:5000
HASHVIEW_E2E_EMAIL=admin@example.com
HASHVIEW_E2E_PASSWORD=your_password
HASHVIEW_E2E_API_KEY=your_api_key
HASHVIEW_E2E_TASK_ID=1
HASHVIEW_E2E_JOB_ID=1
HASHVIEW_E2E_CUSTOMER_ID=1
HASHVIEW_E2E_HASHFILE_ID=1
HASHVIEW_E2E_TASK_NAME=Rockyou Wordlist
```

Optional:

```
HASHVIEW_E2E_CUSTOMER_NAME=E2E Customer
HASHVIEW_E2E_SETUP_EMAIL=admin@example.com
HASHVIEW_E2E_SETUP_PASSWORD=your_password
HASHVIEW_E2E_ENFORCE_OPEN_REDIRECT=1
HASHVIEW_E2E_SECOND_EMAIL=user@example.com      # enables the job-IDOR e2e test
HASHVIEW_E2E_SECOND_PASSWORD=your_password2
HASHVIEW_E2E_STRICT=1                            # see "Strict e2e mode" below
```

## Running the unit / security / agent suites locally

These import the app (and the agent), so install both requirement sets first:

```
./.venv/bin/pip install -r requirements.txt -r requirements-dev.txt
./.venv/bin/python -m pytest tests/unit tests/security tests/agent_unit -q
```

`tests/unit/conftest.py` is guarded with a `collect_ignore_glob` that skips the
directory if Flask isn't importable, so a stray `pytest tests/` against an
e2e-only venv won't error at collection.

### Property tests (Hypothesis)

`tests/unit/test_hash_parsers_properties.py` uses [Hypothesis] to fuzz the hash
parsers with generated inputs. It runs as part of the normal `tests/unit` run.

[Hypothesis]: https://hypothesis.readthedocs.io/

### Scheduler integration test

Most tests set `HASHVIEW_DISABLE_SCHEDULER` (the unit conftest disables the
background scheduler). `tests/unit/test_scheduler_integration.py` is the
exception: it drives the real `data_retention_cleanup` entry point against a
seeded DB to exercise the scheduled-cleanup path end to end.

## Running E2E tests locally (live host)

Run the app and DB with Docker Compose, then execute pytest:

```
docker compose up -d
set -a; source .env.test; set +a
./.venv/bin/python -m pytest -m e2e -vv -s --maxfail=1
```

E2E notes:

- Uses Playwright against a live host.
- `tests/e2e/test_agent_sim.py` runs a heartbeat-only agent simulation (no DB
  dependency); it validates heartbeat registration only.
- The open-redirect test is `xfail` by default. Set
  `HASHVIEW_E2E_ENFORCE_OPEN_REDIRECT=1` to make it a hard failure.
- Some tests are optional and may skip if credentials or IDs are missing
  (unless strict mode is on — see below).
- The dev venv only needs `requirements-dev.txt` (pytest + playwright); the app
  under test lives in docker so the runner doesn't import any `hashview.*`
  modules.

### Using the helper script

```
./tests/run_e2e_compose.sh
```

This script:
- Starts containers (`docker compose up -d --build`)
- Waits for the app at `HASHVIEW_E2E_BASE_URL`
- Seeds the DB and runs E2E tests
- Passes `--ignore=tests/security --ignore=tests/unit` so pytest doesn't try to
  import those dirs' conftests (which pull in Flask & friends)
- Prints Docker logs on failure

### Strict e2e mode

Set `HASHVIEW_E2E_STRICT=1` to turn e2e skips into hard failures (see
`tests/conftest.py`):

- The prerequisite fixtures (`live_server`, `ensure_setup`, the login helper)
  call `_skip_or_fail()`. In local/dev mode (default) a missing precondition
  **skips**; under strict mode it **fails** instead, so a missing server or
  unseeded DB can't silently pass.
- A skip-count gate (`pytest_sessionfinish`) fails the whole session if more
  than `STRICT_MAX_SKIPS` (currently `4`) results are skipped — counting each
  parametrized skip individually. This stops the suite from "passing" while
  quietly skipping nearly everything.

**Local** runs are non-strict by default: missing prerequisites skip, and skips
are allowed. **CI** (`e2e.yml`) sets `HASHVIEW_E2E_STRICT=1` plus a complete
deterministic `HASHVIEW_E2E_*` env block (admin + second-user credentials, the
seeded IDs, the API key), so the seeder provisions a known DB and the suite
genuinely runs instead of skipping almost everything (its previous behavior).

## Security suite

`tests/security/` holds two files:

- `test_command_injection_poc.py` — command-injection regression proof-of-concept
  tests.
- `test_security_hardening.py` — depth coverage for CSRF, command injection,
  path traversal, and IDOR. Two of these are **real, open findings** tracked as
  strict `xfail`s for the maintainer (the test asserts the safe behavior, the
  strict xfail proves it does not yet hold, and the test flips to a hard failure
  the moment the issue is fixed):
  - **Command injection (HIGH):** task mask / rule fields (`hc_mask`, `j_rule`,
    `k_rule`) flow unquoted/unescaped into the hashcat command built by
    `build_hashcat_command`, which the agent runs via `subprocess.Popen(shell=True)` —
    so shell metacharacters execute on the agent host.
  - **Missing CSRF (MEDIUM):** there is no global `CSRFProtect`, so
    state-changing POST routes that read their form without
    `validate_on_submit()` (e.g. `/customers/edit`) mutate state with no token.

Run it locally with the app deps installed:

```
./.venv/bin/python -m pytest tests/security -vv
```

## Agent unit suite

`tests/agent_unit/` covers the agent package shipped in
`install/hashview-agent/`. `tests/agent_unit/conftest.py` puts the agent root on
`sys.path`, so its modules import as `agent.*`. These tests have their own
coverage gate (see below) and do not need the full server stack.

## Multi-agent crack harness

A dockerized harness exercises a *real* crack across multiple agents:

- `tests/crack/test_multiagent_ntlm_crack.py` — the multi-agent NTLM crack test.
- `tests/e2e/crack/` — the harness: `agent-entrypoint.sh`, `seed_crack_db.py`,
  `gen_slices.py`, `verify_crack.py`, and a `shim/` that stands in for real
  cracking.
- `tests/run_e2e_crack_compose.sh` — builds the app + two agent images, brings up
  the multi-agent compose stack, and runs the crack.
- The `e2e-crack.yml` workflow fetches a checksummed `rockyou.txt` from a pinned
  SecLists release, verifies its SHA-256, then runs the harness with
  `ROCKYOU_PATH` pointed at it.

## Function coverage gate

Every function in `hashview/` must have a unit test that executes it. Verify
locally:

```
./.venv/bin/python -m pytest tests/unit -q --cov=hashview --cov-report=json:coverage.json
./.venv/bin/python tests/check_function_coverage.py coverage.json
```

The checker parses `coverage.json`, walks every `hashview/*.py` with `ast`, and
exits non-zero listing any function with zero executed body lines (migrations
excluded). Waivers (discouraged) go one-per-line in
`tests/function_coverage_allowlist.txt` as `hashview/path/file.py::function_name`
(the allowlist is kept empty). `pytest-cov` is required.

## Coverage quality

The unit job measures more than a single line number:

- **Line ratchet:** `--cov-fail-under=85` over `--cov=hashview`. Raise it as
  coverage improves; never lower it.
- **Branch coverage:** `--cov-branch` is enabled alongside the line ratchet, so
  the term-missing / XML / JSON reports flag partially-covered branches. The 85%
  threshold itself remains a *line* gate.
- **Function gate:** `tests/check_function_coverage.py` (above) still runs.
- **Agent coverage gate:** a separate `--cov=agent` run over `tests/agent_unit`
  with its own `--cov-fail-under` floor (currently 75%, a ratchet). It uses a
  different source root and intentionally emits no JSON report so it can't
  overwrite the `coverage.json` the function gate consumes.
- **Mutation testing:** a scheduled, non-blocking signal (see `mutation.yml`),
  not a PR gate.

## CI workflows

Six workflows run on push / PR (plus one scheduled). Each gates a distinct
slice:

| Workflow | Trigger | What it gates |
| --- | --- | --- |
| `unit-tests.yml` | push, PR | Unit + security + agent tests on Python 3.11/3.12/3.13 with the line ratchet, branch coverage, the function gate, and the agent coverage gate. The 3.11 leg uploads `coverage.xml`; pushes to the dev/main branches also publish a coverage badge. |
| `e2e.yml` | push, PR | The Playwright e2e suite via `run_e2e_compose.sh`, under `HASHVIEW_E2E_STRICT=1` + a deterministic `HASHVIEW_E2E_*` env block. |
| `e2e-crack.yml` | push, PR | The multi-agent real-crack harness via `run_e2e_crack_compose.sh`, using a pinned + checksummed SecLists rockyou. |
| `db-parity.yml` | push, PR | MySQL/MariaDB parity (see below). |
| `lint.yml` | push, PR | Ruff lint, Bandit SAST vs the committed baseline (server + agent), `pip-audit` of production deps, and OpenAPI spec validation. |
| `pylint.yml` | push | Pylint across Python 3.11/3.12/3.13. |
| `mutation.yml` | weekly cron + manual dispatch | Non-blocking `mutmut` campaign; uploads a survivor report artifact (never fails the build). |

### MySQL / MariaDB parity (`db-parity.yml`)

The unit suite runs on SQLite, so the Alembic chain's MySQL-only DDL is never
executed there (`tests/unit/test_migration_smoke.py` deliberately can't run it).
`db-parity.yml` closes that gap with a real `mariadb:11` service container:

1. Runs the real migration chain from an empty schema to head against MariaDB
   via `scripts/run_migrations.py` (`alembic upgrade head`). A migration error
   fails the job — the class of bug the SQLite suite can't see.
2. Runs the `mysql`-marked integration tests
   (`pytest tests/integration -m mysql`) against that migration-built schema.

Both are driven by `HASHVIEW_TEST_DATABASE_URI`
(`mysql+mysqlconnector://...?charset=utf8mb4`). The same variable, when set,
also overrides the unit-test database URI (`tests/unit/conftest.py`), and the
integration tests skip cleanly when it is unset (local dev).

## Mutation testing (`mutation.yml`)

A periodic quality signal — **not** a CI gate. It runs weekly (Mondays 06:00
UTC) and on manual dispatch, never on push/PR. Config lives in `[tool.mutmut]`
in `pyproject.toml` (`source_paths = ["hashview"]`, test selection scoped to
`tests/unit`, with `migrations/*` and `hashview/control/*` excluded). Surviving
mutants never fail the job (`continue-on-error`); the value is the uploaded
`mutation-report` artifact, which reviewers inspect for well-covered but
weakly-asserted code.

## CI / CD with dev Docker containers (manual)

To reproduce the e2e flow locally:

1) Build and start dev containers:

```
docker compose up -d --build
```

2) Run E2E:

```
set -a; source .env.test; set +a
./.venv/bin/python -m pytest -m e2e -vv -s --maxfail=1
```

3) Optionally run the security tests:

```
./.venv/bin/python -m pytest tests/security -vv
```

4) Tear down:

```
docker compose down -v
```

## Notes

- If Playwright browsers are missing in CI, install them once:

```
./.venv/bin/python -m playwright install
```
