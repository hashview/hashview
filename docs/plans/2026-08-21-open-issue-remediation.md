# Open-Issue Remediation Roadmap

**Date:** 2026-08-21
**Baseline:** `v0.8.3-dev` @ a8c08dd
**Scope:** every issue open on the board at the time of writing (77), triaged against the code rather than against the issue text.

## How to read this

This is a **portfolio roadmap, not an implementation plan.** It decides what gets fixed, in what order, and what has to be decided before work starts. Each wave gets its own detailed per-task plan written when that wave begins — writing seventy bite-sized TDD plans up front would guarantee most of them are stale before anyone opens an editor.

Every status below was verified by reading the code on `v0.8.3-dev`, not by trusting the issue. Where a claim could not be verified in this pass, it says so; treat those as unverified and check before starting the work.

## Sequencing principles

1. **Merge before build.** Ten open PRs already implement fixes for open issues. Landing them removes work from the board at review cost only, and several later waves touch the same files.
2. **Correctness before features.** A wrong number on the analytics page is worse than a missing one, because nobody knows to distrust it.
3. **One PR per code region, not one PR per issue.** Where several issues live in the same function, fixing them separately means three reviewers reading the same diff three times and two of them rebasing.
4. **Decide the design questions first.** Four items on the board are questions, not defects. Implementing them before the question is answered is how you get a feature nobody wanted.

---

## Wave 0 — Land what is already written

Ten PRs are open against issues on the board. Nine need no new code; this is review-and-merge capacity, and it is the single highest-yield thing on this roadmap.

| PR | Closes | Notes |
|---|---|---|
| #340 | #218 | Null-deref 500s. Verified the three unguarded sites still crash on `v0.8.3-dev`: `api/routes.py:936`, `:1661-1673`, `:1740-1741`. |
| #354 | #353 | Length-bucketed dynamic wordlists. Diff matches every acceptance criterion in the issue. |
| #356 | #355 | `$HEX[...]` decode in crack verifiers. **Caveat below.** |
| #358 | #357 | UTF-8 hashfile download; covers all three severities in the issue. |
| #391 | part of #385 | Analytics hang + shared-password miscount. Does **not** close #385. |
| #400 | — (refs #377) | Website-keywords crawl collision. **Does not close #377** — see below. |
| #408 | #105 | e2e coverage for every top-level page. |
| #415 | #409, #410, #411 | Machine-account / history filtering. Green, awaiting review. |
| #416 | #413, #414 | Server-side list filters; paginate and sort `/rules`. |
| #420 | #226 (reopened) | Makes the `control/tmp` cleanup actually run; see below. |

Three things to fix while merging:

- **PR #356's description overstates its diff.** The body claims it adds `verified`/`updated`/`unmatched`/`count` response fields and an `openapi.yaml` update. The actual diff touches only `hashview/utils/utils.py` and two test files — no route, no spec. It fixes #355 correctly; it does **not** fix #374. Do not close #374 on merge.
- **PR #400 references #377 but does not fix it.** It fixes the job-collision bug (one shared wordlist row, concurrent jobs overwriting each other's crawl), which is worth merging. But `words = crawl_website_keywords(target, settings)` is still unguarded — it appears in the diff only as context — and the `try`/`except OSError` blocks it adds wrap the tmp-file write and move, not the crawl. A raising crawl still serves the previous run's file. Leave #377 open.
- **#226 was not fixed, and PR #367 should not have been closed.** I closed both citing `api/routes.py:174-189`, which registers its unlink with `response.call_on_close()`. That callback never runs: `send_from_directory` sets `direct_passthrough=True` (werkzeug `utils.py:482`) and `Response.get_app_iter` returns the raw file wrapper for that case instead of wrapping it in a `ClosingIterator` (`response.py:541-545`), so `Response.close()` is never invoked by the WSGI layer. `control/tmp` still grew on every agent poll. Two tests hid it — a unit test that called `response.close()` by hand, and a **strict xfail for this very issue** sitting in the same suite. #226 is reopened; **PR #420** fixes it with `after_this_request`, the mechanism PR #367 proposed all along.

  The general lesson is worth carrying into the other waves: a green test that drives a helper directly can assert a contract the request path never exercises. Prefer a real request.

**Exit criteria:** all ten merged or explicitly rejected; #218, #226, #353, #355, #357, #105, #409, #410, #411, #413, #414 closed. #377 stays open.

---

## Wave 1 — Security and data integrity

Small, self-contained, high-consequence. Every item here is S effort except #298. Do these before anything cosmetic.

| # | What | Effort | Where |
|---|---|---|---|
| 206 | IDOR: a job can be assigned another customer's hashfile. `jobs/routes.py:434-437` assigns `request.form['hashfile_id']` with no customer check. | S | one guard clause |
| 373 | `.distinct('customer_id')` is silently ignored on MySQL and `HashfileHashes` has no such column — customer-delete computes the wrong count and can orphan hashes. `customers/routes.py:195`. | S | query rewrite |
| 389 | `/analytics/download` builds a `redirect()` on an unknown `?type` and never returns it, then serves an empty attachment off a full-table scan. `analytics/routes.py:547`. | S | one line |
| 382 | Inert `is not None` filter in the lucky-task query; `jobs/routes.py:615` should use `.isnot(None)`. | S | one line |
| 404 | Agent-timeout fallback compares Python UTC against DB-local `last_checkin`. PR #405 already provides the failing tests. | S | `scheduler.py`, `__init__.py` |
| 349 | `/api/docs` cannot be disabled; blueprint is registered unconditionally. Ship the config gate now, defer asset vendoring. | S | `__init__.py` + config flag |
| 223 | `AlchemyEncoder` is a name-based denylist over `dir(obj)` — fail-open, and `/v1/admin/settings` exposes it. | M | encoder + every serializing route |
| 298 | No global `CSRFProtect`; protection comes only from `FlaskForm.validate_on_submit`. Unprotected: `customers/routes.py:104-112`, `hashfiles/routes.py:153,178`, and `agents/routes.py:172-200` which mutates state on **GET** and therefore cannot be protected without becoming POST. | M | app factory + 3 blueprints + templates |

Sequencing: #206 first (only active cross-tenant vulnerability, one guard, zero dependencies). #298 last in the wave — it is the only one that touches templates and changes request methods, so it wants its own PR and its own e2e pass. #405's tests turn #404 into a red-to-green exercise.

**Also in this wave, pending a decision:** the read-side finding from the #171 audit. Mutation routes are uniformly owner-gated; **reads are uniformly not**. `hashfiles_download` (`hashfiles/routes.py:240-241`) carries only `@login_required`, and its `cracked`/`plains` formats return recovered plaintext for a guessable integer id. `tests/e2e/test_security.py:184` says the shared-view model is deliberate. Whether that is acceptable depends on whether all authenticated users are trusted across all client engagements. **Answer that before writing code.**

---

## Wave 2 — Analytics correctness

The analytics page currently disagrees with itself: cards and their own download endpoints compute different answers. Fix the cheap disagreements first, then the architectural one.

**2a — one PR, `analytics/routes.py` lines ~598-806.** These are the same bug three times ("a download endpoint reimplements the card's logic and has drifted from it"), in one region, and they collide if split:

- **#386** — shared-password download returns nothing for `$HEX[...]` plaintexts; the card decodes (`:328`), the download and `_shared_groups` do not.
- **#387** — `/analytics/download/fig9` groups by `hash_id` with a bare `COUNT(*)` and ignores `cracked` (three near-identical copies at `:625-628`, `:644-648`, `:665-667`), so it invents accounts and drops real ones. Replace all three with a call into `_shared_groups()`.
- **#388** — fig8 compares raw-case and splits the username on index `[1]`; the card lowercases and uses `_local_part()`'s last component (`:355`, `:80-88` vs `:749`, `:758`). Extract one helper, call it from both.

**2b — #385, its own PR, architectural.** The corpus is built from `Hashes ⋈ HashfileHashes` join rows with no dedup (`:328-332`, `total_cracked = len(corpus)`), so every plaintext-derived figure inflates when a hash lives in two hashfiles — the reuse donut reads 100%. Not a one-line `.distinct()`: it needs an explicit per-hash corpus (length, mask, charset, complexity, pattern intelligence, reuse) separated from the per-account corpus (username=password, shared passwords), and the template's unit labels changed to match. **PR #391 fixes only the shared-passwords slice; the rest of the page still counts join rows.** #385 is *not* a prerequisite for 2a — verified, they are independent.

**2c — follow-ons, after #385 settles the per-hash/per-account convention.** #50 (persist and display the insta-crack rate; the number is already computed at `jobs/routes.py:460-468` and `api/routes.py:1422-1430` and then thrown away — needs a column and a migration) and #412 (password history is dropped silently; at minimum report the dropped count, and treat the opt-in-keep design as a separate, migration-bearing change).

---

## Wave 3 — API completeness and correctness

**3a — one PR for `v1_api_post_add_job`.** #351 (cannot create a job on a fresh system: the effective-tasks gate requires `Hashes.task_id`, which only agent crediting sets, and there is no manual task selection), #352 (the job row is committed at `:1043-1044` before validation, so a failed call leaves an orphan), and the jobs/add half of #228 (re-query plus commit inside the per-task loop at `:1073-1077`). One restructuring — accept optional `task_ids`, defer the commit, bulk-insert the tasks — fixes all three. Splitting them means three rebases of the same function.

**3b — rules/wordlists CRUD, sequenced.** #397 (`DELETE /v1/rules/<id>`) and #398 (`DELETE /v1/wordlists/<id>`) are S each and mirror `v1_api_delete_job`. #399 (PUT/replace) is M and depends on both, and on **#395** — the safe-swap needs `os.replace` to work when `control/` is a mount.

**3c — independent API work,** in rough value order: #370 (audit coverage; PRs #371 and #403 already provide the strict-xfail acceptance tests — flip them green), #374 (report new/known/conflicting/unmatched founds counts; the loop already knows each outcome and discards it — do **not** assume PR #356 did this), #368 (hashfile export formats over `/v1`), #381 (`/v1/tasks/add` hardcodes `hc_attackmode=0` at `:1263`), #401 (task-group endpoints; decide the `TaskGroups.tasks` storage question first — widening the column is cheap, a join table is correct), the remaining half of #228.

**3d — #376 after #374.** Verifying founds for unsupported hash types by delegating to a local hashcat run rather than growing in-tree crypto. L effort, and it produces exactly #374's buckets, so #374's semantics must be settled first. Consistent with the standing objection to server-side hash generation: this verifies, it does not synthesize.

**Blocked on a decision: #221 and #350.** #221 (unauthorized responses return HTTP 200 — 33 `redirect("/v1/not_authorized")` sites and `v1_api_unauthorized` at `:194-200`) is an API contract change, and the agent's HTTP layer discards non-200 bodies today, so the agent must learn real status codes *first* or every deployed agent breaks. #350 (adopt flask-smorest) would resolve #221 and #349 as a side effect. **Decide #350 go/no-go before doing #221 piecemeal.**

---

## Wave 4 — Mask support (one workstream, not three issues)

#87, #384 and #402 are one feature. Sequence matters and is load-bearing:

1. **#384 — the store.** New `masks` table (migration; remember to bump the hardcoded `DEV_HEAD` in both migration-e2e test files), upload/list/delete endpoints, agent-side `sync_masks()`. Additive, so old agents keep working — they simply never call `/v1/masks`.
2. **#402's interim guard — same PR or immediately after.** `chunking.py:117-126` gives a path-shaped mask a keyspace of 1, so `plan_chunks` (`:224-234`) never chunks it and the ETA is nonsense. Today that is theoretical because no mask file can reach an agent. **The moment #384 lands it becomes real for every mask task.** Mark file-path masks non-chunkable (`is_chunkable`, `:56-68`, has no path detection at all) so there is never a window where mask tasks schedule against a fake keyspace.
3. **#402 full per-line chunking + real ETA** — L, independent improvement, later. The agent-side ETA clamp is separable and already speced test-only in PR #407; server and agent halves ship in either order without a protocol change.
4. **#87 closes as superseded** once #384 lands. Do not implement it separately.
5. **#35 (automatic top-masks job type)** builds on the store — the derived masks want a mask file, not `Tasks.hc_mask` (`String(50)`).

---

## Wave 5 — Throughput and UX

Verified in this pass: **#363** (per-row commits on hashfile import — batch the writes) and **#364** (move import to the background) are the same user complaint at two altitudes; do #363 first, since a fast import may make #364 optional. **#369**'s hard part is already done (`tasks/routes.py:396` and `:401` already distinguish job-held from group-held tasks); what remains is disabling the delete button and surfacing the reason. **#392** is a template-only filter with tests already written in PR #393 — merge that first so the xfails flip. **#135** (bulk job delete) should build on #416's pagination so select-all composes with paging. **#359** (combine several hashfiles at job creation) needs no migration. **#133** is a one-line template move (`jobs_add.html.j2:60-66` emits "add new" after the loop). **#382** is listed in Wave 1 but could ride along with any jobs-area PR rather than becoming a one-line PR of its own.

Since verified as genuinely still open, with the gap located: #34 (no potfile-import mechanism at all; the `--potfile-path` handling at `utils.py:980` is unrelated), #101 (the wordlist half exists via the `wordlist_import.py` drop folder; the hashfile half does not), #107 (complexity buckets hardcoded in `analytics/routes.py`), #122 (no manual hash:cleartext path — and per the standing rule it must verify, never generate), #123 (no charset or mask-attack option exists anywhere, so this is really "add mask attack support" and should be scoped down), #375 (`jobs/forms.py:60-61` still carries a blank `------SELECT------` default alongside the single NTLM option).

`#361` (dynamic pane widths) is closed — the phosphor redesign's `grid-template-columns: var(--sidebar-w) 1fr` plus the collapsible sidebar satisfies both halves of the ask.

**#314** (Werkzeug caps pasted-hash form fields around 488KB) reads as an accepted limitation the maintainer already documented, not actionable work. Either raise `MAX_FORM_MEMORY_SIZE` in config or close it; do not leave it open as if it were a bug.

---

## Wave 6 — Platform and deployment

**#395 first — it blocks #399 and #383.** Default wordlist/rule seeding fails with `EXDEV` from `os.replace` when `control/` is a mount, which is exactly the volume layout the #383 fix wants. Then **#383** (a rule row outliving its file makes `/v1/rules/<id>` 404 while agents retry the download forever) and **#396** (default "Rockyou" tasks seeded with hardcoded `wl_id` 2/3 that actually point at empty dynamic wordlists).

Then **#394** (drop the published `3306:3306` from `docker-compose.yml` — nothing in the repo uses it and it collides with the migration compose), and the older platform asks, none of them verified here: #39 (Settings → Database tab), #57 (`%` in the DB password), #68 (Windows agent), #73 (LDAP auth).

---

## Decisions needed before code

These are not defects and should not be picked up by an implementer:

1. **#350** — adopt flask-smorest? Gates the shape of #221 and #349.
2. **Read-side authorization** (from #171) — are all authenticated users trusted across all client engagements? Gates whether `hashfiles_download` gets customer scoping.
3. **#412** — should user password history be keepable, and flagged per row (migration) or derived at query time?
4. **#401** — widen `TaskGroups.tasks`, or normalize it into a join table (migration)?
5. **#123 / #314** — scope down, or close as won't-fix?

## Per-wave working agreement

Each wave, when it starts, gets: a detailed task-by-task plan; one branch per logical change off `v0.8.3-dev`; TDD with the failing test demonstrated red first; mutation-verification of each new guard (revert it, watch the test fail); the full gate (`pytest tests/unit tests/security tests/agent_unit`, pylint, ruff) green locally before push; a CHANGELOG entry; and a PR into `v0.8.3-dev`. Any migration bumps `DEV_HEAD` in both migration-e2e test files.

## Board hygiene done alongside this triage

Closed as already fixed, each with a code citation: #92, #129, #130, #141, #164, #361. (#226 was closed on the same basis and then **reopened** — the code it cited does not work; see Wave 0.) Closed as an environment/support thread: #116. Closed as superseded: PR #367 — also a mistake, corrected in a follow-up comment there. Commented rather than closed: #171 (its premise names a helper that does not exist; the mutation audit is clean, but the read-side question above came out of it) and PR #400 (references #377 without fixing it).

One new issue came out of this pass: **#421** — the analytics and agent-download routes serve from `control/tmp` with no cleanup at all, and the analytics export body is `username:hash:plaintext`, so recovered credentials accumulate on disk outside any retention policy. Not folded into PR #420 because it is a retention question as much as a leak, and it spans two more blueprints.

Nineteen older issues that this triage had not verified were then checked one at a time against the code — #34, #39, #57, #68, #73, #101, #107, #122, #123, #314, #361, #363, #364, #375, #377, #383, #394, #395, #396. Only #361 turned out to be resolved. The other eighteen are genuinely still open with the gap located, e.g. `config.py:19-24` still concatenates the DB password into the SQLAlchemy URI with no `quote_plus` (#57), `docker-compose.yml:25` still publishes `3306:3306` (#394), `setup/__init__.py:64,83` still call bare `os.replace` (#395), and `add_default_tasks` at `:24-41` still hardcodes `wl_id` 2/3 (#396). Worth knowing the board is not padded with stale entries.
