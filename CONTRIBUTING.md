# Contributing to Hashview

Thanks for considering a contribution. This document covers the process:
branching, commit style, local gates, and the gotchas that repeatedly bite new
PRs. For suite-by-suite test detail, see [`TESTING.md`](TESTING.md) — this doc
won't repeat it.

## Before you start

Check the [Issues](https://github.com/hashview/hashview/issues) page first. If
there's no existing issue for what you want to do, open one — bug or feature
request — so we can discuss the approach before you sink time into code. We
accept pull requests; see the [feature requests](README.md#feature-requests)
note in the README if you'd rather just ask for something.

## Branching — target the dev branch, not `main`

**Open PRs against `v0.8.3-dev`, not `main`.** `main` tracks the last release;
active development happens on the current `vX.Y.Z-dev` branch. Because
`origin/HEAD` points at `main`, GitHub will pre-select `main` as your PR base —
change it explicitly before submitting.

Branch names follow a `type/short-description` pattern, matching the prefixes
already in use on `origin`: `feat/`, `fix/`, `test/`, `chore/`, `ci/`, `docs/`.
For example: `fix/hashfile-listing-group-by`, `test/api-hashfile-listing-perf`.

PRs are merged with a regular merge commit (not squash or rebase).

## Commit messages

This repo uses [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): subject

optional body
```

Types in use: `feat`, `fix`, `test`, `docs`, `style`, `refactor`, `perf`,
`chore`, `ci`. Scopes are usually a module or subsystem name (`api`, `jobs`,
`wordlists`, `githooks`, `migrations`, `analytics`). Reference an issue with
`(#123)` at the end of the subject when one exists.

Keep commits atomic — one logical change per commit. Don't bundle an unrelated
lint fix or refactor into a feature commit.

## Setting up a dev environment

```bash
git clone https://github.com/hashview/hashview
cd hashview
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
pre-commit install
```

Enable the pre-push hook (see below) — it's opt-in per clone:

```bash
git config core.hooksPath .githooks
```

Use a **relative** path (as above), not an absolute one, so each git worktree
picks up its own `.githooks` copy instead of another checkout's.

Config:

```bash
cp hashview/config.conf.example hashview/config.conf
```

Edit it with real DB credentials and a random `SECRET_KEY`. `config.conf` is
gitignored — never commit it. For Docker, set the DB host to `db` and match
`MYSQL_PASSWORD` in `docker-compose.yml`.

Before running the test suites, create the runtime control directories (they're
gitignored but expected to exist):

```bash
mkdir -p hashview/control/{hashes,logs,rules,tmp,wordlists,wordlists_import}
```

Run the app:

```bash
./setup.py
./hashview.py --debug
```

For local end-to-end / Docker testing, copy the `.env.test` template documented
in [`TESTING.md`](TESTING.md#environment-files) into your own `.env.test`
(gitignored) — don't commit real credentials there either.

## The pre-push hook

`.githooks/pre-push` is the main safety net before code leaves your machine.
It runs in two phases:

1. **Secret scan** over the lines you're pushing (added diff lines, plus your
   commit messages) for AWS keys, `password=`/`token=`/`api_key=`-style
   assignments, PEM blocks, **any URL**, **any IP address**, and `.env` file
   adds/modifications, plus whatever's in your local `.sensitive-keywords`
   (gitignored — this is where you'd add engagement- or client-specific
   keywords; never commit that file).
2. **CI mirror**: `ruff check .` → `bandit` (against the baseline) →
   `openapi-spec-validator` → `pytest tests/unit tests/security
   tests/agent_unit`. Skipped entirely on a delete-only push.

The hook prefers `.venv/bin/python`; if you don't have a `.venv` it falls back
to a system `python3` that likely lacks these tools and will fail confusingly.

If phase 1 flags something that's a legitimate false positive (an example URL
in a test fixture, a dummy API key, etc.), add a narrowly-scoped regex to the
**tracked** `.githooks/safe-allowlist.txt` rather than working around the hook.
Read the comments at the top of that file — patterns must match the *entire hit
line*, so anchor on the surrounding file path or unique text, not just the
trigger substring.

Don't push with `--no-verify` — it skips the secret scan along with everything
else. If a gate is genuinely broken (not your change's fault), say so in the PR
rather than bypassing silently.

## Local gates before opening a PR

Run everything CI runs, in one shot:

```bash
scripts/preflight.sh          # all static gates + unit tests
scripts/preflight.sh --fast   # skip pip-audit and unit tests
scripts/preflight.sh --e2e    # also run the docker e2e harness (slow)
```

It runs, in order: `ruff check hashview/ hashview.py`, `bandit` against the
baseline, `openapi-spec-validator`, `pip-audit`, `pylint`, and
`pytest tests/unit`.

**Note:** `preflight.sh` lints only `hashview/ hashview.py`, while CI's
`lint.yml` runs `ruff check .` across the whole repo (including `tests/`,
`install/`, `migrations/`). If you've touched files outside `hashview/`, also
run `ruff check .` directly, or trust CI to catch it.

Lint/format config lives in `pyproject.toml` (`[tool.ruff]`: Python 3.11
target, 100-column lines, `select = ["E","F","I","B","UP"]`) and `.pylintrc`.
`.bandit-baseline.json` is committed — only *new* Bandit findings fail a build,
so don't need to fix pre-existing ones in unrelated code.

## Tests

See [`TESTING.md`](TESTING.md) for the full suite map, markers, and CI
workflow table. The short version:

- The fast, always-imported gate is `pytest tests/unit tests/security
  tests/agent_unit` — this is what the pre-push hook and `unit-tests.yml` run.
- Everything else (`tests/integration` with `-m mysql`, `tests/e2e`,
  `tests/crack`) is opt-in and needs a live DB, Docker stack, or Playwright.
- Coverage floors are **ratchets, not targets** — 85% line+branch on
  `hashview`, 75% on `agent`, plus a function-coverage gate that fails on any
  function with zero executed body lines. Raise these as coverage improves;
  never lower them.
- If a bug is real but not yet fixed, add a **strict `xfail`** test named after
  the issue (see `tests/unit/test_api_issues_xfail.py`,
  `tests/security/test_csrf_xfail.py` for examples) rather than leaving it
  undocumented. Remove the marker in the same PR that fixes the bug — strict
  xfail turns an unexpected pass into a failure, so it'll tell you when it's
  safe to drop.
- A brand-new `tests/<subdir>/` needs its own `conftest.py` (even a trivial
  one) — the root e2e fixture is autouse and will silently skip everything
  under an unrecognized directory otherwise.

## CI workflows

All of the following run on push and PR unless noted:

| Workflow | Gates |
| --- | --- |
| `unit-tests.yml` | Unit + security + agent tests across Python 3.11/3.12/3.13, coverage ratchets, function-coverage gate |
| `lint.yml` | `ruff check .` (repo-wide), Bandit vs. baseline, `pip-audit`, OpenAPI spec validation |
| `pylint.yml` | Pylint across 3.11/3.12/3.13 (**push only**, not PR) |
| `e2e.yml` | Playwright e2e suite against a Docker Compose stack, strict mode |
| `e2e-crack.yml` | Multi-agent real-crack harness against a pinned, checksummed rockyou.txt |
| `db-parity.yml` | Real Alembic migration chain + `-m mysql` integration tests against MariaDB |
| `migration-e2e.yml` | `main` → dev upgrade path, using built Docker images of both |
| `mutation.yml` | Weekly `mutmut` campaign — quality signal only, never blocks a PR |

CI never runs real hashcat; `Dockerfile.agent` ships a shim binary at
`/opt/hcshim/hashcat` for the agent tests.

## Checklists for specific kinds of changes

**Database migration** (`migrations/versions/`)
- The unit suite runs on SQLite, so it can't catch MySQL-only DDL problems —
  `db-parity.yml` is what does. Keep your migration MySQL/MariaDB-safe.
- Bump the hardcoded `DEV_HEAD` in `tests/run_migration_e2e.sh` to your new
  head revision, or `migration-e2e.yml` will test against the wrong target.
- `migrations/versions/` is excluded from both ruff and pylint (autogenerated).

**`/v1` API / route change**
- Update `hashview/api_docs/openapi.yaml` to match. `tests/unit/test_openapi_spec.py`
  enforces route↔spec parity and will fail otherwise.

**New mutating POST route**
- There is no global `CSRFProtect`. CSRF protection only comes from
  `FlaskForm.validate_on_submit()`, so any new state-changing form route must
  use a `FlaskForm`, not raw `request.form` parsing.

**Hashview-Agent change** (`install/hashview-agent/`)
- Has its own `requirements.txt` and `VERSION.TXT`. Agents require hashcat
  6.2.x+ and must be approved by an admin after their first check-in.

**User-visible change**
- Add an entry to `CHANGELOG.md` under `## Current Release`, in the existing
  grouped `### Added` / feature-heading style, with the issue number if there
  is one.

## Things not to commit

`config.conf`, `.env.test`, `.sensitive-keywords`, and local artifacts like
`.coverage`, `coverage.json`, `.pytest_cache/`, `.ruff_cache/`, `.hypothesis/`,
and `.venv/`. All of these are already gitignored — if `git status` shows one
as untracked-but-should-stay-that-way, don't `git add -A` past it.

## License

By contributing, you agree your changes are licensed under the project's
[GNU GPLv3](LICENSE).
