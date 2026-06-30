# Test Architecture Hardening

Branch: `test-architecture-hardening` (off `v0.8.3-dev`).

Addresses the gaps found in the testing-architecture review. Issue #7 (restore
crack harness + wire into CI) is already done: the `tests/e2e-multiagent-ntlm-crack`
branch was merged in, restoring the harness, its component unit tests
(`tests/unit/test_crack_*.py`, all passing), and its CI workflow
(`.github/workflows/e2e-crack.yml`).

Each task below is independent and file-disjoint where possible. Implementers run
one at a time, TDD, with spec + code-quality review after each.

---

## Task A — Make CI e2e actually run and fail loudly (#1, #2)

**Problem:** `run_e2e_compose.sh` only seeds the DB when `HASHVIEW_E2E_*` vars are
set. CI has no `.env.test`, so seeding is skipped and every data-dependent e2e
test `pytest.skip`s. The `login` fixture also `skip`s on auth failure. Result: a
green E2E badge over a suite that exercises almost nothing.

**Fix:**
1. In `.github/workflows/e2e.yml`, export a deterministic e2e env block before
   `run_e2e_compose.sh` (fresh container, so we own the admin creds): set
   `HASHVIEW_E2E_BASE_URL`, `HASHVIEW_E2E_EMAIL`, `HASHVIEW_E2E_PASSWORD`,
   `HASHVIEW_E2E_API_KEY`, `HASHVIEW_E2E_SETUP_EMAIL/PASSWORD`, and the
   `*_ID`/`*_NAME` vars the seeder/tests expect. Add `HASHVIEW_E2E_STRICT=1`.
2. Add `HASHVIEW_E2E_STRICT` support in `tests/conftest.py`: when set, the
   `live_server`, `ensure_setup`, and `login` fixtures `pytest.fail(...)` instead
   of `pytest.skip(...)` — a missing server / failed setup / failed login in CI is
   a hard failure, not a silent pass.
3. Add a `pytest_sessionfinish` (or `pytest_terminal_summary`) hook in
   `tests/conftest.py` that, under strict mode, fails the run if the number of
   skipped e2e tests exceeds a small allowlist (the intentional ones, e.g. the
   open-redirect xfail). Print which tests skipped.
4. Wire the agent simulator (`docker-compose.test.yml`, `test` profile) into the
   e2e CI run so the heartbeat sim actually executes.

**Acceptance:** With the strict env, running the harness locally against the
compose stack fails (not skips) if login/seeding break. `pytest.skip` no longer
masks a regression in CI. Existing local (non-strict) behavior unchanged.

**Files:** `.github/workflows/e2e.yml`, `tests/conftest.py`,
`tests/run_e2e_compose.sh` (only if needed to plumb the agent sim / strict flag).

---

## Task B — MySQL/MariaDB parity in CI (#3)

**Problem:** unit + migration tests run on SQLite; production is MariaDB. The
migration smoke test *explicitly does not* run `upgrade head` because SQLite
can't do the FK/column ALTERs that "run fine against production MySQL" — so those
migrations are never executed anywhere in CI.

**Fix:** Add a CI job (new `.github/workflows/db-parity.yml`, or a job in
`unit-tests.yml`) with a `mariadb`/`mysql` service container that:
1. Runs the full Alembic migration chain (`upgrade head`) against MariaDB from an
   empty schema — the thing SQLite can't validate.
2. Runs a small set of integration tests against the MariaDB-backed app (point
   `SQLALCHEMY_DATABASE_URI` at the service via an env override the conftest
   honors). Reuse existing tests where possible; add a focused
   `tests/integration/` test if needed (gated by a `mysql` marker so it's skipped
   when no MySQL URL is present, and run explicitly in this job).

**Acceptance:** CI executes `alembic upgrade head` on real MariaDB and it
succeeds; a regression in a migration's MySQL-only DDL is caught. SQLite unit
runs unaffected.

**Files:** new workflow, `tests/conftest.py` / `tests/unit/conftest.py` (env
override for DB URL), possibly `tests/integration/`, `pytest.ini` (new `mysql`
marker), `requirements-dev.txt` (mysql driver if needed).

---

## Task C — Security depth (#4)

**Problem:** CSRF is disabled in the unit app (`WTF_CSRF_ENABLED: False`) so no
test ever exercises it; command construction for hashcat has a single PoC; no
IDOR/path-traversal coverage.

**Fix:**
1. CSRF: add a dedicated app fixture with `WTF_CSRF_ENABLED=True` and tests that a
   state-changing POST (e.g. a delete or create route) is rejected (400) without a
   token and accepted with one.
2. Command construction: expand `tests/security/test_command_injection_poc.py` (or
   add a sibling) to assert that hashcat command building (`build_job_task_commands`
   and related in `hashview/`) never interpolates user-controlled fields (task
   name, mask, wordlist/rule names, hashfile paths) into a shell string and is not
   invoked via `shell=True`; feed metacharacters and assert they are passed as
   argv elements / rejected.
3. Path traversal: tests that wordlist/hashfile/rule storage rejects `../` and
   absolute paths in user-supplied filenames.
4. IDOR: a unit test using two users asserting user B cannot read/delete user A's
   resource via direct ID.

**Acceptance:** New tests fail if CSRF is disabled on a protected route, if a
command is built via shell string interpolation, if a traversal filename is
accepted, or if cross-user access is allowed. All pass on current code (or expose
a real bug, which we then report).

**Files:** `tests/security/`, possibly `tests/unit/`, no app-code changes unless a
real vuln is found.

---

## Task D — Coverage quality: branch coverage + mutation testing (#5)

**Fix:**
1. Add `--cov-branch` to the CI pytest invocation in `unit-tests.yml` and document
   it. Keep `--cov-fail-under` (ratchet) — do not lower it.
2. Add mutation testing: `mutmut` (already feasible) config in `pyproject.toml`
   targeting `hashview/`, add to `requirements-dev.txt`, and a new
   `.github/workflows/mutation.yml` that runs on a schedule (cron) + manual
   dispatch (NOT on every push — too slow), non-blocking, uploading the survivor
   report as an artifact.

**Acceptance:** Branch coverage is measured in CI; mutation job runs on schedule
and produces a report without blocking PRs.

**Files:** `.github/workflows/unit-tests.yml`, `pyproject.toml`,
`requirements-dev.txt`, new `.github/workflows/mutation.yml`.

---

## Task E — Agent coverage gate (#6)

**Problem:** coverage is `--cov=hashview` only; `install/hashview-agent` has unit
tests (`tests/agent_unit/`) but no coverage measurement or floor.

**Fix:** Measure coverage of the agent package when running `tests/agent_unit`
(add `--cov=install/hashview-agent/agent` or the correct import root) and add a
`--cov-fail-under` floor for it. Either fold into the existing unit job's
coverage (multiple `--cov` targets) or a dedicated step. Ensure the function-
coverage gate logic isn't broken by the added source.

**Acceptance:** Agent code coverage is reported and gated in CI.

**Files:** `.github/workflows/unit-tests.yml`, possibly `tests/agent_unit/conftest.py`.

---

## Task F — Scheduler end-to-end integration test (#9)

**Problem:** `HASHVIEW_DISABLE_SCHEDULER` is set in all tests; retention is only
exercised via mocked inner branches.

**Fix:** Add an integration test that calls the real public entry point
`data_retention_cleanup(app)` (hashview/scheduler.py) against a seeded test DB
with old + recent records, asserting old records are purged and recent ones
retained — exercising the real code path, not just `_data_retention_cleanup_inner`
with mocks.

**Acceptance:** Test drives the real scheduler entry function against a real
(SQLite test) DB and verifies retention behavior end-to-end.

**Files:** `tests/unit/` (or `tests/integration/`).

---

## Task G — Update TESTING.md (#8)

**Fix:** Correct the stale `-m security` claim (unit tests are not marked
`security`; CI runs `pytest tests/unit tests/security tests/agent_unit`
directly). Document: the `agent_unit` suite, the Hypothesis property tests, the
crack harness + `e2e-crack.yml`, the new strict-e2e mode, the MySQL-parity job,
branch coverage, and the mutation-testing job.

**Acceptance:** TESTING.md accurately reflects the suite layout and CI as left by
tasks A–F.

**Files:** `TESTING.md`.
