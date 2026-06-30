# Design: Dockerized multi-agent true-crack e2e test (NTLM)

**Date:** 2026-06-22
**Branch:** `tests/e2e-multiagent-ntlm-crack` (off `v0.8.3-dev`)
**Status:** Approved for planning

## Goal

Prove the full hashview cracking pipeline end-to-end with real agent code and a
real recovery: two `hashview-agent.py` processes, each in its own container, pick
up real jobs from the server, **genuinely recover NTLM plaintexts** derived from
random rockyou entries via a CPU shim, and upload them — all verified against the
server database. This is the first test in the suite where a hash is actually
turned back into its plaintext, rather than the cracking step being mocked.

## Why a shim instead of real hashcat

The shim performs **mathematically real cracking** (it computes NTLM hashes of
wordlist candidates and matches them against the target hashes), but avoids the
hashcat binary/engine. This keeps the test:

- Dependency-light (no hashcat install, no GPU, no OpenCL/CUDA).
- Deterministic and fast on CPU-only CI.
- Focused on the *integration* (job assignment, sync, command execution, result
  upload, DB state transitions) while still genuinely recovering plaintext.

Real hashcat can be swapped in later by replacing the `HC_BIN_PATH` the agent is
given; nothing else in the harness needs to change.

## Scope

### In scope (v1)
- NTLM (hashcat mode `1000`), dictionary attack — one plain dict task and one
  dict **+ rules** task.
- 2 agent containers, 2 job tasks, real concurrent distribution.
- Real recovery of random rockyou-derived plaintexts.
- **Exercise the agent's wordlist sync AND rules sync code paths** (`/v1/wordlists`,
  `/v1/wordlists/{id}`, `/v1/rules`, `/v1/rules/{id}`) as real, verified steps —
  not mocked, and not dead files that are downloaded but unused.
- Verification of crack results, plaintext correctness, task/job completion,
  distinct-agent distribution, and that both sync paths actually ran, all
  observable in the server DB and agent container state.

### Out of scope (v1, but shim/harness structured to extend later)
- Other hash modes (MD5, masks, hybrid) — shim mode map is extensible.
- The full hashcat rule language — only the minimal subset above is supported.
- `limit_recovered` / one-and-done behavior.
- GPU code paths.
- Wordlist sources other than rockyou.

## Components

### 1. Hashcat shim — `tests/e2e/shim/hashcat`

A small standalone Python executable mimicking the subset of the hashcat CLI that
`hashview-agent.py` invokes (the command string is produced by the server's
`build_hashcat_command()` in `hashview/utils/utils.py`).

Responsibilities:
- Parse from the command line: `-m <mode>`, the hashfile path (positional), the
  wordlist path (positional), `-r <rulesfile>` (zero or more), `--outfile <path>`,
  `--outfile-format`, `--status-json` / `--status` flags, `--session`,
  `--potfile-path`.
- For each candidate in the wordlist, apply each rule from any `-r` rules file(s)
  to produce derived candidates, compute the hash for the given mode for each, and
  compare against the target hashes loaded from the hashfile. With no `-r`, the
  candidate is used verbatim.
- Write genuine matches to `--outfile` in hashcat **outfile-format `1,3`**
  (`hash:plaintext` form the server's upload parser expects).
- Emit `--status-json` status lines (to stdout and/or status file) so the agent's
  `monitor_hashcat()` / `hashcatParser()` can read progress.
- Exit `0` on completion.

Hashing:
- Mode→algorithm is a small dict. v1 contains `1000 → NTLM`.
- **NTLM = MD4(password.encode('utf-16-le'))**.
- The shim ships a **self-contained pure-Python MD4** implementation rather than
  relying on `hashlib.new('md4')`, because MD4 is frequently unavailable on
  OpenSSL 3.x (legacy provider) and we cannot guarantee its presence in the agent
  base image. This keeps the shim deterministic across base images.

Rule engine:
- The shim implements a **minimal subset of the hashcat rule language** — enough
  to make rules sync a genuine, verifiable step. v1 supports at least: passthrough
  `:`, append-char `$X`, prepend-char `^X`, and a simple case rule (e.g. `c`
  capitalize). Unknown rule tokens are skipped (logged), not fatal.
- The dict+rules task's targets are derived by **applying the seeded rule to base
  rockyou words** (e.g. base word `+ "1"` for a `$1` rule). The base words are in
  the slice but their *un-ruled* hashes are **not** the targets — so a successful
  crack proves the agent synced the rules file and the shim applied the rule.

The shim is intentionally *not* hashview code; it is a test double living under
`tests/e2e/shim/`.

### 2. Agent image — `Dockerfile.agent`

New image used only by the e2e stack:
- Base `python:3.8-slim` (matches the server's Python version).
- Install agent runtime deps (`requests`, `psutil`).
- Copy `install/hashview-agent/` into the image.
- Copy the shim onto a known path (e.g. `/opt/hcshim/hashcat`), executable.
- Create the agent `control/{tmp,hashes,outfiles,wordlists,rules}/` directories.
- A non-interactive entrypoint that writes `agent/config.conf` from environment
  variables, then `exec`s `python hashview-agent.py`.

Entrypoint env vars consumed:
- `HASHVIEW_SERVER`, `HASHVIEW_PORT`, `USE_SSL`
- `NAME`, `UUID`
- `HC_BIN_PATH` (points at the shim)

This bypasses the interactive first-run setup in `hashview-agent.py`
(approx lines 70–114) by pre-writing a valid `config.conf`.

### 3. Compose stack — `docker-compose.e2e.yml`

Services:
- `db` — MySQL 8 (mirrors `docker-compose.yml`).
- `app` — server, built from the existing `Dockerfile`, depends on `db`.
- `agent1`, `agent2` — built from `Dockerfile.agent`, each with a distinct
  `NAME` and fixed `UUID`, both pointed at `app:5000`, both depending on `app`.

The two agent services are defined so adding a third agent is just another
service block + UUID. Agent UUIDs are fixed constants shared with the seeding
step so the pre-authorized `Agents` rows match.

### 4. Test data, seeding, and driver — pytest under `tests/e2e/`

**rockyou sourcing fixture:**
- Locate rockyou via `ROCKYOU_PATH` env var.
- Else download once into a cache dir (e.g. under the repo's test cache).
- If neither available (e.g. offline CI without the env var),
  `pytest.skip(...)` with a clear, actionable message. No silent pass.

**Target + slice generation (per task):**
- Pick `TARGETS_PER_TASK` (default **3**) random lines from anywhere in rockyou.
- Build a bounded **~50k-line** wordlist slice from rockyou.
- Two tasks ⇒ two independent slices, two disjoint base-word sets (6 total):
  - **Task A (plain dict):** targets are the chosen words verbatim; those words
    are shuffled into slice A. Target hash = `ntlm(word)`.
  - **Task B (dict + rules):** the chosen *base* words are shuffled into slice B,
    but the targets are the **ruled** words (e.g. `word + "1"` for rule `$1`).
    Target hash = `ntlm(rule(word))`. The base word's plain `ntlm(word)` is **not**
    a target, so the crack only succeeds if the rule was synced and applied.

**Server seeding** (via DB and/or API against the running `app` container):
- A customer and an admin/owner user.
- Each slice registered as a **wordlist** (file written to the server's
  `control/wordlists/` storage **and** a corresponding DB row), so the agent
  fetches it through the real `/v1/wordlists/{id}` sync path.
- A **rules file** registered as a **rule** (file written to the server's
  `control/rules/` storage **and** a corresponding DB row) containing the rule
  used to derive Task B's targets (e.g. `$1`), so the agent fetches it through the
  real `/v1/rules` + `/v1/rules/{id}` sync path.
- A **hashfile** containing `ntlm(target)` for every target across both tasks,
  with the per-hash → per-task association the server expects.
- **Task A:** dictionary attack, `-m 1000`, referencing slice A's wordlist, no
  rule.
- **Task B:** dictionary attack, `-m 1000`, referencing slice B's wordlist **and
  the seeded rule** (the attack mode/rule fields that cause
  `build_hashcat_command()` to emit `-r <rulesfile>`).
- A **job** containing both tasks; both `JobTasks` set to status `Queued` and the
  job to the appropriate runnable state, with `command` populated by
  `build_hashcat_command()`.
- Two pre-authorized **Agents** rows whose `uuid`/`name` match the compose env
  for `agent1`/`agent2` and whose `status` is `Authorized` (skipping the manual
  approval flow).

## Flow

1. `db` + `app` come up; pytest seeds customer/user/wordlists/hashfile/tasks/job
   and the two authorized agents.
2. `agent1` and `agent2` start, each writes its `config.conf`, each begins
   heartbeating `POST /v1/agents/heartbeat`.
3. Server assigns one `Queued` job_task to each agent (`agent_id` set, status
   `Running`).
4. Each agent syncs its task's wordlist slice via `/v1/wordlists` + `/v1/wordlists/{id}`;
   the agent assigned **Task B** additionally syncs the rules file via `/v1/rules`
   + `/v1/rules/{id}`. Each downloads the hashfile via `/v1/hashfiles/{id}` and
   builds the run with the shim as `HC_BIN_PATH` (Task B's command includes
   `-r <synced-rulesfile>`).
5. Each shim scans its slice, computes NTLM for each candidate, writes real
   `hash:plaintext` matches to its `--outfile`, emits status JSON, exits 0.
6. Each agent uploads results via `POST /v1/uploadCrackFile/{job_task_id}` and
   reports task completion.

## Verification

The pytest driver polls the server DB (with an overall timeout and clear failure
diagnostics) until all of the following hold, then asserts:

1. **Every target hash** has `Hashes.cracked == 1` and `Hashes.plaintext`
   **exactly equals** the originally-chosen rockyou word (not just "something was
   recovered").
2. Both `JobTasks` reach status `Completed`.
3. The job reaches status `Completed`.
4. **The two job_tasks were claimed by two distinct `agent_id`s** — proving real
   concurrent multi-agent distribution rather than one agent doing both tasks.
5. Each task's specific targets were recovered (per-task target/plaintext match),
   not just the aggregate set.
6. **Wordlist sync ran:** the synced slice file is present in the relevant agent
   container's `control/wordlists/` directory.
7. **Rules sync ran:** the synced rules file is present in Task B's agent
   container's `control/rules/` directory. Because Task B's targets are the
   *ruled* words, recovering them already proves the rule was synced and applied;
   the file-presence check is an explicit, direct confirmation of the sync path.

Which agent claims Task A vs Task B is **not deterministic** (first-come
heartbeat wins). The driver therefore resolves the Task B → `agent_id` →
container mapping at runtime (from `JobTasks.agent_id` and the seeded
uuid/name↔container correspondence) before performing the container file-presence
checks, rather than assuming a fixed assignment.

On timeout, the test surfaces the relevant DB state (job/job_task statuses,
per-hash cracked flags) and, where feasible, agent container logs to aid
diagnosis.

## Integration / opt-in

- Marked `@pytest.mark.e2e_crack`, registered in the pytest config markers.
- **Excluded from the default test run** (heavy: builds images, starts a compose
  stack, may download rockyou).
- Run explicitly via a dedicated entry point (e.g. a `make test-e2e-crack`
  target and/or `pytest -m e2e_crack`), documented in the test module and/or
  the project test docs.

## Files

New:
- `tests/e2e/shim/hashcat` — real-cracking hashcat shim (incl. pure-Python MD4).
- `Dockerfile.agent` — agent image with shim + non-interactive entrypoint.
- `docker-compose.e2e.yml` — db + app + agent1 + agent2.
- `tests/e2e/test_multiagent_ntlm_crack.py` — seeding, orchestration, verification.
- Supporting helpers/fixtures as needed (rockyou sourcing, DB seeding), placed
  under `tests/e2e/` consistent with existing layout.

Touched:
- pytest config — register the `e2e_crack` marker.
- Test/build tooling — add the opt-in run target.

Reference (read, not necessarily modified):
- `install/hashview-agent/hashview-agent.py`, `agent/config.py`,
  `agent/http/http.py`, `agent/api/api.py`
- `hashview/models.py`, `hashview/api/routes.py`, `hashview/agents/routes.py`
- `hashview/utils/utils.py` (`build_hashcat_command`)
- existing `docker-compose.yml`, `docker-compose.test.yml`, `Dockerfile`,
  `tests/conftest.py`, `tests/agent/sim.py`

## Defaults (confirmed)

- 2 agents, 2 tasks, ~50k-line slice per task, 3 targets per task (6 total).
- NTLM (`-m 1000`); Task A = plain dict, Task B = dict + rules.
- Both wordlist sync and rules sync are exercised and verified.
- Real recovery from random rockyou entries; shim structured to extend to other
  modes and more rules later.
