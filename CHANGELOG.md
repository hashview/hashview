# Change Log
Notable changes will be documented here

## Current Release
## [v0.8.3-Beta] - YYYY-MM-DD

### Added

**Redesigned Interface**
- New dark "phosphor" UI across the whole app, replacing the previous Bootstrap theme
- Light/dark theme support: per-user theme preference (System / Paper Terminal / Minimal Invert / Clean Light / Dark) chosen from the account settings modal, saved to your account, and applied without a flash of the wrong theme. "System" follows your operating system's light/dark setting.
- Card-style, drag-and-drop task queue when building a job
- Live recovery feed on the dashboard showing freshly cracked hashes with relative timestamps (e.g. "3 minutes ago")
- Scrollable, filterable "InstaCrack" panel showing which hashes are already recovered when a hashfile is added to a job

**Running-Jobs Dashboard**
- An **Auto-cancel** column shows how long an attack has before `Settings.max_runtime_tasks` stops it, measured from the earliest chunk start so it agrees with the reaper that enforces the cap. It renders only when the cap is enabled; chunk rows leave it blank, since the cap applies to the attack rather than to one chunk
- The live recovery feed gains a **Task** column naming the attack that cracked each password, resolved through the hash's stamped task rather than through the job (one job's attacks do not all touch the same hash). A crack that predates the column, or whose task has since been deleted, shows an em dash

**Single Sign-On (Microsoft Entra ID / Azure AD)**
- Optional OIDC web login alongside local accounts, with group-gated just-in-time user provisioning (configured under Settings)

**Slack Notifications**
- Per-user Slack direct messages as a third job-notification channel (email / Pushover / Slack)
- Opt-in admin and security notifications delivered to a Slack room

**Audit & Error Logging**
- On-disk JSON audit log of authentication and create/update/delete events, plus captured server errors, viewable and clearable from Settings

**Length-Bucketed Dynamic Wordlists**
- New `(DYNAMIC) Recovered Passwords (length ...)` wordlists split the recovered-password corpus by plaintext length into a fixed set of buckets — `0-5`, `6`, `7`, `8`, and a `9+` catch-all — so tasks can target only candidates of a relevant length. `$HEX[...]` plaintexts are decoded only to measure their true byte length for bucketing; they are stored in the wordlist in their original `$HEX[...]` form.

**API Documentation**
- The `/v1` API is now described by an OpenAPI spec with interactive Swagger UI at `/api/docs`
- `DELETE /v1/hashfiles/<id>` to remove a hashfile via the API

**Task-viability read API**
- `GET /v1/tasks` — list all tasks (metadata) in one call, complementing the existing single-task `GET /v1/tasks/{id}`
- `GET /v1/agents/benchmark` — read rig benchmark performance per hash type (slowest agent per mode; `?hash_type=` for one mode). Exposes already-stored benchmark data over the API for external viability tooling.

**API Expansion**
- `GET /v1/customers/<customer_id>/hashfiles` -- list every hashfile belonging to a customer in one call, replacing the downstream client-side loop over common hash types (which silently missed uncommon types). Counts cover the whole file (`total_hashes`/`cracked_hashes`) and `hash_type` is the file's representative mode; an unknown customer returns an empty list. (#346)
- `POST /v1/hashes/import/<hash_type>` now imports cracked hashes for any hash type the server can recompute locally, not just NTLM: MD5 (0), SHA1 (100), MySQL4.1/5 (300), MD4 (900), NTLM (1000), SHA2-256 (1400), and MSSQL 2012/2014 (1731). Each submitted `HASH:plaintext` pair is still verified server-side; unverifiable plaintext is never trusted. Imports are atomic: a single failing line rolls back the entire request.
- `GET /v1/task_groups` -- list task groups, with `tasks` returned as a parsed array of ids (#401)
- `POST /v1/task_groups/add` -- create a task group and its ordered task membership in one call (#401)
- `POST /v1/task_groups/<task_group_id>/tasks` -- replace or append a task group's task membership (#401)
- `DELETE /v1/task_groups/<task_group_id>` -- delete a task group, owner/admin only (#401)
- `POST /v1/jobs/add` now accepts a `priority` (1 lowest to 5 highest, the same scale the web UI offers) and lets the caller choose how the job's tasks are assigned via `mode`: `lucky` (the default and the previous behaviour -- up to the 10 historically most effective tasks for the hash type), `tasks` (an explicit ordered list of task ids), or `task_group` (a task group's members). Only `lucky` needs crack history, which is what made the endpoint unusable on a fresh system: it ranks tasks by cracked hashes carrying a `task_id`, and `POST /v1/hashes/import` does not set one, so API-only automation could never reach a state where a job could be created (#351). Priority is refused unless an administrator has enabled job priority weighting, rather than being silently discarded, and the no-duplicate rule the web UI enforces applies to `task_ids` too -- a task may repeat only if it uses a dynamic wordlist
- `POST /v1/jobs/stop/<job_id>` -- stop a running or queued job via the API, owner or admin only. Cancels the job and every task under it and clears each task's agent so the work is not dispatched again, mirroring the web UI's stop action. The API could previously start a job but never stop one, so an API-driven run had to be cancelled from the web UI
- `DELETE /v1/rules/<rule_id>` -- delete a rule via the API (#397). The v1 API could create rules but never remove one, and `POST /v1/rules/add` does not check the name, so a retried upload left duplicate rows that an API-only client could not clean up. Owner or admin only, and refused with a 409 while any task still uses the rule -- the same safeguard the web UI enforces, because `tasks.rule_id` has no foreign key and an orphaned reference leaves the task running hashcat against a rule file that is not there

**Encrypted Database Backup**
- Download an encrypted `mysqldump` of the database from Settings -> Data Management, protected by a one-time password

**Hashes Table Overview**
- Settings -> Data Management now shows what the `hashes` table actually holds: total / recovered / unrecovered across the instance, then a per-hash-type breakdown naming each hashcat mode. Counts come from the `hashes` table alone -- one row per unique (sub_ciphertext, hash_type) -- so a hash shared by several hashfiles is counted once, unlike the per-customer, per-account figures on Analytics
- Every figure in that table is a download link: click a total for those hashes, Recovered for `hash:plaintext` of the cracked ones, or Unrecovered for the hashes still outstanding. Each file holds exactly as many lines as the figure that linked to it. Exports are admin-only, audited, and streamed in primary-key pages so a full-corpus download doesn't buffer in the server's memory

**hashcat Version Interoperability CI**
- Added a hashcat version interoperability CI matrix: offline contract tests run Hashview's status/benchmark/outfile/flag parsers over committed captures from five hashcat releases on every PR, and a scheduled workflow re-runs them against the real binaries plus a live `--skip`/`--limit` slice check, filing an issue when a newer hashcat release appears.

**Agent Management**
- Configurable agent heartbeat timeout, with scheduled alerts when an agent goes offline or recovers
- Per-agent host-specific hashcat arguments via `HC_EXTRA_ARGS` (e.g. to pin specific GPUs)

**Jobs & Hashfiles**
- The job information window on the jobs list now lists the job's assigned tasks in queue order, each with its own status, rather than only counting them. The status shown is the attack's, derived exactly as the running-jobs dashboard derives it: an attack stopped after some of its chunks had already finished reads `CANCELED` (or `EXPIRED`, when a runtime cap stopped it) instead of falling back to `QUEUED`, and an attack waiting between chunks reads `QUEUED` rather than `COMPLETE`. Tasks on a job that has not been started yet read `NOT STARTED`. A job with more than 25 attacks lists the first 25 and says how many more there are
- Bulk-select and bulk-delete on the hashfiles list
- Per-hashfile `--hex-salt` option for salted hash types
- Custom hashcat hash-mode entry for the `$hash` and `$user:$hash` hashfile formats (#447), for operators running a hashcat build with modes not in Hashview's bundled list. No import-time shape validation is performed on a custom mode. An agent whose hashcat can't benchmark a mode reports it as unsupported instead of hanging: the mode is never re-requested from that agent and it is never dispatched tasks of that type

**Configuration**
- Optional `MAX_FORM_MEMORY_SIZE` key under `[SERVER]` in `config.conf`, capping the size of pasted (non-file) form data such as the pasted-hashes textarea. Defaults to Flask's own 500000 bytes when unset, so existing deployments are unaffected; raise it to allow larger pastes. Uploaded files are not counted against it, and values below 65536 are clamped up to that floor because a smaller cap would reject multipart file uploads outright (#314)
- Oversized submissions now return a clear "try uploading the hashes as a file instead" message — JSON for AJAX requests, a flash and redirect for normal form posts — rather than a bare Werkzeug 413 page or a misleading "You must assign a name to the hashfile" error (#314)

**Missing Catalog Files**
- Hashview now notices when a rule or wordlist row outlives its file on disk. The Rules and Wordlists pages badge such an entry `FILE MISSING`, disable its download, and report the count in the page header; the Tasks page badges any task that uses one, so "which of my tasks are broken?" is answerable at a glance. `GET /v1/rules` and `GET /v1/wordlists` carry a `missing` flag per row (always `false` for dynamic wordlists, which are regenerated from the database on every request). Previously the only symptom was an agent 404 that nothing on the server logged (#383)
- Administrators are alerted when a catalog file goes missing, and again when it comes back. An hourly `CATALOG_HEALTH` sweep sends one aggregated notification per sweep rather than one per row -- these failures are usually correlated, and admin alerts reach Pushover as a phone push -- naming each affected entry and the tasks that reference it, which is what decides whether to re-upload or delete. One alert per episode; it does not repeat while the file stays gone. Uses the existing per-admin "administrative notifications" preference, which already covers "agent errors & system health"
- A missing rule or wordlist can be **restored in place**: upload a replacement from the Rules/Wordlists page and it is written into the existing entry, keeping its id and filename, so every task, queued job command and crack-history attribution that references it keeps working. This is the answer to the hard case, where deletion is refused because tasks still use the entry -- re-uploading through the normal Add form always created a *new* entry and left the old references broken. Small rule files can also be restored by pasting their contents into the rule editor, which no longer refuses to open when the file is gone. The same control replaces a static wordlist's contents in place, which was previously not possible at all
- Rules and wordlists whose file is missing are no longer offered when building a task, in the web UI or via `POST /v1/tasks/add`, so a task that can never run cannot be created. An existing task keeps its reference, labelled `FILE MISSING`, and stays editable

**Testing**
- Job-creation performance e2e suite (`tests/e2e/test_job_creation_perf.py`) with a tunable volume seeder (`tests/seed_perf_db.py`), covering latency budgets for each wizard step plus strict-xfail scaling guards for the four endpoints in issue #422 whose cost grows with table size rather than page size
- API hashfile-listing performance suite (`tests/e2e/test_api_hashfile_listing_perf.py`), sharing that seeder. Asserts loop cost as a ratio to a same-route zero-hashfile floor rather than an absolute budget, so the threshold survives a change of hardware; carries regression guards for issue #228 (fixed in this release; the guard remains so a per-hashfile loop cannot return) and on `GET /v1/customers/<id>/hashfiles`, which runs one combined aggregate per hashfile and measures under the ceiling today

### Changed
- Lint (ruff) now covers the whole repo — tests, agent, migrations, and setup scripts — instead of only `hashview/`; all pre-existing violations were fixed (#437)
- The Rules listing is paginated (20 per page) with sortable Name / Rules / Owner / Last Updated columns and a server-side name filter, matching the Tasks listing
- Reintroduced distributed chunking: eligible mask/wordlist tasks are split into per-agent chunks sized from each agent's benchmark, and a chunked task now appears as a single attack in the job editor
- Wordlists are stored gzip-compressed at rest; agents sync and verify the compressed files
- Dynamic wordlists are now delivered on demand: an agent downloads a dynamic wordlist directly via `GET /v1/wordlists/<id>`, which regenerates it from the database into a unique per-request temp file and serves it gzipped. The separate `GET /v1/updateWordlist/<id>` endpoint (and the agent's update-then-resync step) has been removed, and the agent's wordlist sync now tracks static lists only
- Task groups now hold at most 10,000 tasks -- both the web UI and the `/v1` API reject an over-cap assignment with a clear error instead of letting the write fail at the database. The group modals stop you at the limit as you build the list, and `POST /v1/task_groups/<task_group_id>/tasks` applies the cap to the resulting membership, so `mode: append` is rejected when the existing tasks plus the new ones would exceed it (#401)
- `/v1` list and detail endpoints now return native JSON instead of a JSON-encoded string, so clients no longer double-parse
- Usernames and recovered plaintext are stored as UTF-8 text (`$HEX[...]` only for non-UTF-8 bytes) instead of latin-1 hex
- Creating and queuing a job now returns you to the dashboard
- The job-creation wizard gates "Next" until the current step's required fields are filled in
- Quantities throughout the UI are thousands-separated
- Alembic migrations for the dev line were consolidated into a single baseline
- Pinned Python to 3.11+; added a ruff / pylint / bandit / pre-commit lint-and-security stack, a LICENSE, and substantially expanded automated tests (unit, agent, end-to-end, and security)
- Every top-level page is now covered by a Playwright reachability test, and a guard fails CI when a new sidebar entry ships without one; Task Groups gained an end-to-end create/delete test
- The database parity CI job runs against MySQL 8.0 and 8.4 as well as MariaDB. MySQL is what production runs and the two engines do not reserve the same words, so an engine-specific SQL error could pass every check -- one did. The job also now exercises the duplicate-hash repair's queries, which nothing in the parity suite previously touched; adding the engine without that would still have gone green
- Customer names can be up to 255 characters, up from 40 -- the narrowest database column behind any name in Hashview, narrower than a job name (50) or a task name (100), and easily passed by a real customer name such as a legal entity plus an engagement qualifier. The wider column is applied by a database migration, which the server runs at startup; the forms read their limit from the schema, so they follow it with no further change. The migration only widens -- rolling it back narrows the column to 40 again, which MySQL refuses once longer names exist
- The ETA column on the dashboard reads compactly (`2h 48m` rather than `2 hours, 48 minutes`), matching the elapsed and runtime figures beside it; a value hashcat sends that is not a duration is left exactly as-is
- Collapsing the sidebar now widens the page instead of sliding it left. The content block was capped at a fixed maximum width with no left auto-margin, so giving up the rail moved both edges and the content jumped sideways

**Per-Agent Chunk Sizing and Keyspace Tracking**
- Chunks are now sized for the agent that asks for the work, rather than one flat size computed from the slowest benchmark in the fleet. An agent 50x faster than the slowest one previously still took 1/50th-sized bites of the keyspace; it now takes a proportionally larger slice, so the Settings target duration means what it says on every rig
- A job's queue now records where each attack stands in its keyspace, and which agent took which slice. Slices are cut when an agent asks for one instead of being planned in full up front — which is what makes per-agent sizing possible, since the right size is not knowable until an agent asks
- Mask tasks are chunked by keyspace range instead of by expanding the leading mask position. An agent measures the keyspace with `hashcat --keyspace` and reports it back, because the server cannot work it out: hashcat splits a mask between its own base and device loops based on the hash mode, so `?a?a?a?a?a?a` has a keyspace of 95^4 for a fast hash and 95^5 for a slow one. The old approach was also very coarse — a `?a`-by-8 task split into exactly 95 pieces of roughly 19 hours each, against a one-hour target. **Needs the updated agent**; until an agent reports a keyspace the task runs whole, exactly as an unsplittable one does today
- Agents now report their hashcat version. A keyspace measured under hashcat 6 cannot be sliced by an agent running hashcat 7 — version 7 redefines `--keyspace` and `--skip`/`--limit` to whole-run units, which is consistent within a version and silently wrong across one — so such an agent is given other work instead
- Job progress on the dashboard is now measured as keyspace covered rather than chunks counted, which also makes the not-yet-started portion of a task visible for the first time
- An expanded task's chunk rows read `Chunk #n` under the task name, with their keyspace in the Keyspace column rather than the Task cell, and every empty cell in the table shares one dash placeholder instead of each column inheriting its own colour and alignment

### Fixed
- The two default "Rockyou" tasks a fresh install ships with now actually use Rockyou. They referenced wordlists by database id, and those ids stopped being Rockyou's some time ago: the seeded dynamic wordlists grew from three to nine, so the tasks named `Rockyou Wordlist` and `Rockyou Wordlist + Best64 Rules` pointed at `(DYNAMIC) All Usernames` and `(DYNAMIC) All Customers` instead. Both are empty on a new install, so the most obvious first thing to try finished in seconds, reported success, and had cracked nothing -- which is a poor way to find out whether Hashview works. The tasks now look their wordlist and rule up by name, and if either has not been seeded yet no tasks are created at all rather than some that point nowhere; the next startup finishes the job. Existing installs keep whatever their tasks were seeded with -- check the two Rockyou tasks under Tasks if you set the instance up before this release
- The **Username = Password** download now lists every account its card counts. The card compares case-insensitively and after stripping the domain prefix; the download compared exactly, and took the wrong part of a `DOMAIN\user` name -- so `CORP\Frank` with the password `frank` appeared on screen and was missing from the file, and the badge count and the line count disagreed with nothing to explain it. Kerberos-style `*` names and recovered passwords stored in `$HEX[...]` form were dropped the same way. Both now answer the question in one place, so they cannot drift apart again
- Generating the `(DYNAMIC) All Usernames` wordlist no longer pulls the entire account table into memory to do it. Every row was fetched whole -- every column, as a full object -- to build what is ultimately a list of names, and that happens inside the request an agent makes when it downloads the wordlist. It now fetches the name column alone: on a 300,000-row sample, 2.6 seconds and 71 MB against 9.5 seconds and 476 MB, for exactly the same wordlist. Case variants are still kept apart (`Admin` and `admin` are both candidates), which is why the de-duplication stays in Python -- MySQL's default collation treats them as the same string and would silently drop one. This is the same shape of problem as the recovered-password corpus fix in this release, in the branch of the code right beside it
- Seeding the default wordlist and rule on first boot no longer depends on a shell, and no longer fails when `control/` is a mount. Both were unpacked with `gzip -d -k` and then moved into place with a rename, which cannot cross a filesystem boundary -- so on a deployment that mounts `control/wordlists` and `control/rules` as Docker volumes (the recommended fix for losing your data when the container is recreated) seeding died with a cross-device error on first boot, and on every boot after it, while the app carried on starting normally and only logged it. The shelled-out `gzip` had the same shape of problem: its exit status was never checked, so a missing `gzip` binary, or `gzip` refusing because a half-finished earlier attempt had left the file there, was indistinguishable from success. Both files are now written straight to their destination in Python, so there is no rename and nothing is left behind in `install/`
- The default Rockyou wordlist is seeded already compressed. Wordlists are stored gzip-compressed, so first boot used to expand the shipped 53 MB archive into 140 MB of plaintext purely so that the startup pass running seconds later could compress it straight back -- around 45 seconds of pointless work, and 140 MB of disk that had to be free for it, on the very first start
- Upgrading no longer stops dead when the `hashes` table already contains the same hash twice. The new uniqueness constraint on `(sub_ciphertext, hash_type)` cannot be created over duplicate rows, and refusing to create it used to abort the whole upgrade — which held two unrelated later migrations hostage and, because the app applies migrations at startup and only logs a failure, left the server quietly running on a schema its own code no longer matched. It now warns, skips just that constraint, and lets the rest of the upgrade finish. Duplicates arise from two imports of the same hash racing each other, which is exactly what the constraint prevents once it is in place
- New duplicate-hash repair, under Settings → Data management (and `scripts/repair_duplicate_hashes.py` for when the app will not start). It lists each group of duplicates with the hashfiles they appear in, any recovered password, and any alerts attached, and merges the ones you choose: one row is kept, every hashfile link and alert is moved onto it, and any recovered password is preserved. Groups where the data decides the answer are pre-selected; you are only asked when two copies were cracked to *different* plaintexts, or when the ciphertexts differ at all — which would mean something other than a duplicate and is never merged automatically. Note that the same string uploaded once as MD5 and once as NTLM is **not** a duplicate and is left alone
- Hash alerts left pointing at a deleted hash are now cleaned up. Such an alert could never fire — its hash is gone, so the notification pass skips over it without ever retiring it — while still being re-read in full on every recovered-hash upload, forever. They are cleared by the duplicate-hash repair. Hashfile links pointing at a deleted hash are reported alongside them but deliberately not removed: each one is the record that an account was in a hashfile and cannot be recovered without re-importing it, though they do stop the affected job from being dispatched and make its hashfile read as fully recovered
- Work left on an agent that died mid-task is returned to the queue once the agent passes its check-in timeout, and another agent picks it up. Previously nothing recovered it: the per-task and per-job runtime caps are only evaluated while an agent is checking in, so if the only agent on a job died neither could ever fire, and the sole way to recover the work was to delete the agent entirely. The task stayed "Running" forever and its job could never finish
- A job could report itself Completed while work remained. Cancelled tasks and tasks added to an already-running job were both counted as finished — the latter never ran at all, because a task assigned to a running job was invisible to the dispatcher as well. Jobs now end as Completed or Incomplete, and a task added to a running job is queued so it actually runs
- Two agents finishing a job's last two tasks at the same moment could both complete it — two end times, the runtime counted twice, and two sets of notifications
- A job's notification settings are no longer deleted when it completes, so re-running a job notifies you again. They were removed as they were sent, which also meant a premature completion destroyed the configuration permanently
- Two agents heartbeating at the same moment could be handed the same task. Assignment now claims the row atomically, so exactly one agent gets it and the other is given different work rather than losing a cycle
- An agent can no longer change the status of a task assigned to someone else, and `GET /v1/jobTasks/{id}` now honours the id it is given instead of returning whichever task the calling agent happened to hold
- Chunks of one task no longer share a potfile, crack outfile or target hashfile. Sharing a potfile makes hashcat skip hashes an earlier run already recovered, so the later run never reports them. This also affected a task using a dynamic wordlist that was assigned to the same job twice
- Reordering a running job no longer deletes rows an agent is actively cracking. It now reorders only the work not yet started, and a task removed from a running job is stopped before it is removed
- Starting a job that is already running is refused, matching the API. Re-queueing a live job left rows assigned to an agent that was still working on them while the dispatcher was free to hand the same work to someone else
- A wordlist replaced under the same name no longer silently invalidates a queued job's chunk offsets — the change is detected and the job is re-planned
- A mask beginning with `-` now runs instead of being rejected by hashcat as a command-line option. Distributed chunking manufactures these automatically: it splits a mask task by expanding the leading position over its character set, and `?s` — so also `?a` — contains `-`. A `?s?d?d` task plans 33 chunks, ten of which failed outright; `-1` through `-4` are hashcat's own custom-charset flags, so those exited with "option requires an argument" and would have consumed whatever argument followed them. The same failure applied to a mask an operator simply typed, with no chunking involved. The command now carries hashcat's `--` end-of-options marker when — and only when — the mask would otherwise be misread, so every other command is byte-for-byte unchanged. **Modes 6 and 7 (the hybrid attacks) with such a mask need the updated agent**; mode 3 works on an existing one
- A mask task whose Hashcat-mask field carries a custom charset is no longer split into chunks. The chunk planner read the charset *definition* as the leading mask position and expanded that, so `-1 ?u?l?d ?d?d?d` planned chunks like `-1 A?l?d ?d?d?d` — a mangled charset that hashcat accepts as a literal mask and cracks at the wrong keyspace, silently. Such a task now runs whole, which is correct. Bare masks chunk exactly as before
- A mask field with more than one space, or a tab, before a custom charset no longer leaves that whitespace on the end of the mask, where it made every candidate end in a space and so cracked nothing
- The agent no longer treats a `--` that came from an operator's mask field as the server's end-of-options marker. A field such as `?d?d -- ?d` made it insert `--status-json` ahead of a mask token, leaving hashcat with no mask at all — it answers that by running its own default mask
- The e2e crack shim mis-parsed `--skip`/`--limit` and the custom-charset flags: it dropped the flag but left its value in the positional arguments, so a chunked command was read as hashfile `"0"`. This made end-to-end coverage of any chunked run unsound, for wordlist chunks as much as mask ones
- A combinator task's *second* wordlist can no longer be deleted out from under it. The wordlist delete guard checked only `tasks.wl_id`, never `wl_id_2`, even though the wordlists listing and the hashcat command builder both count `wl_id_2` as a real reference -- so deleting one produced a task with a blank wordlist argument. Deletion is now refused for either reference (#383)
- A failed rule download no longer destroys the agent's good local copy. Any failure -- a single transient 502 was enough -- dropped the rule from the agent's manifest, and the orphan prune then deleted the file; the next task using that rule made hashcat fail on a missing file, which terminates the agent and leaves the job task stuck in Running. The local copy is now kept on failure, and a superseded file is removed only after its replacement is installed. The agent also skips downloading a rule or wordlist the server has flagged as missing, instead of re-requesting it on every task assignment. **Agents must be redeployed to pick this up** (#383)
- The rule and wordlist download pages now find a file whose stored path is relative -- the bundled Best64 rule and the seeded Rockyou wordlist both record one. They stat'ed the stored path directly, which only resolves when the server process happens to run from the repository root, while the agent-facing API resolved it correctly; the two now share one implementation and cannot disagree
- The rule info panel reports the real on-disk size instead of a hardcoded placeholder, and reports `file missing` when there is nothing on disk
- `GET /v1/wordlists/{id}`'s documented 404 now mentions the missing-file case the endpoint has always been able to return
- A task whose Hashcat-mask field carries a custom charset now runs. The field is free-form and the UI has no separate input for a charset, so operators put the whole invocation in it (`?1?1?1?1?1 -1 ?u?l?d`); that reached hashcat as a single argument and died with "Custom-charset 1 is undefined", so the task never cracked anything. The field is now split into separate arguments at option boundaries. Masks containing a literal space are deliberately left intact -- a space is a valid mask character, and `?u?l?l?l ?d?d?d?d` (for passphrases like "Word 1234") only works while it stays one argument, so splitting on every space would have swapped one bug for another
- A rejected `POST /v1/jobs/add` no longer leaves an orphan job behind. The job row was committed before the task-assignment step ran, so every refusal -- including the common "not enough data to determine effective tasks" one -- left a taskless `Ready` job that could never be started and that blocked deletion of its hashfile. The whole create is now one transaction with every input validated up front, and a failure rolls it back
- Deleting a rule now removes its file from `control/rules` as well as the database row, in both the web UI and the API. Previously the row went and the file stayed, unlike wordlist deletion which has always cleaned up after itself, so every deleted rule left a file behind for good (#397). The stored path is resolved to `control/rules/<basename>`, which keeps the removal inside that directory and handles the bundled Best64 rule whose row records a relative path; a file is kept if another rule row still points at it, and the row is always removed first so a failed unlink orphans a file rather than leaving a row that points at nothing
- The "assign the top 10 tasks" action can no longer queue a task that has been deleted. `hashes.task_id` outlives the task it names -- a task may be deleted once no job or task group still references it, while the hashes it cracked keep pointing at it -- and that column is what the action reads to decide what to queue. The query already excluded those tasks by joining `tasks` and still does; what changed is that the protection now lives in one shared helper with tests that fail if it is relaxed, because the task listing and Wrapped pages deliberately *do* show deleted tasks by name and someone could reasonably make this query match them. A deleted task does not use up one of the ten slots either: the next-best surviving task takes its place
- The web UI's copy of that query filtered nothing where it meant to exclude unattributed hashes -- `Hashes.task_id is not None` is a Python identity test on the column object, always true, rather than a SQL `IS NOT NULL`. The API copy was already correct after #219; the two are now one implementation so they cannot drift again
- Assigning a single task, or a task group listing an id whose task has since been removed, no longer creates an unrunnable job task. The single-task assign reports that the task no longer exists, and the task-group assign skips those entries and says how many it skipped
- The hourly data-retention cleanup no longer takes the whole server down while it runs. Deleting an aged hashfile was a single transaction covering every one of its `hashfile_hashes` rows plus every hash that became orphaned, and because the index on `hashfile_hashes.hashfile_id` holds very few distinct values, MySQL abandoned it for a full table scan on any large hashfile (measured: 691,589 rows, 67% of the table). Under REPEATABLE-READ that locks every row in the table, including hashfiles nobody was purging, so concurrent inserts blocked everywhere — agent crack uploads included. Each blocked query then held its pooled connection for up to `innodb_lock_wait_timeout` (50s), which is longer than the pool waits to hand one out (30s), so the connection pool emptied and every subsequent request — agents and web pages alike — failed with `QueuePool limit of size 5 overflow 10 reached`. The purge now deletes in committed batches restricted to primary keys, which cannot escalate to a table lock at any hashfile size, and is resumable: an interrupted run keeps its committed progress and the next hour finishes it, instead of rolling back an hour of work and re-emailing the owner. What gets deleted is unchanged — cracked recoveries and hashes shared with another hashfile are still kept — and a hash that gets re-shared or cracked while the purge is running is now kept rather than removed
- The database connection pool is sized deliberately (10 connections plus 20 overflow, tunable via `pool_size`/`max_overflow` in `config.conf`) instead of running on SQLAlchemy's 5-plus-10 default. Connections are validated before use, so a page load after an idle period no longer fails with "MySQL server has gone away", and are retired before MySQL's own `wait_timeout` closes them. This is headroom rather than a fix for the above: a larger pool still empties if something holds connections long enough
- Server-error log entries for a connection-pool timeout now record the pool's counters, so the log distinguishes "every connection was checked out, something was holding them" from "the pool is too small for this load" — the previous entry named the limit but not which. The retention job also logs the pool state as it finishes, so its runs can be lined up against request failures
- `GET /v1/hashfiles/hash_type/<t>` now answers with one grouped query instead of three per matching hashfile (issue #228). It previously took a DISTINCT list of hashfile ids and, for each, ran an ORM lookup plus two separate COUNTs, so the work above the fixed request cost grew with the number of matching files. On a production instance holding 7.85M NTLM hashes the endpoint took 549 seconds to return 13 KB — past every default client timeout, so callers saw not a slow listing but no listing, indistinguishable from a customer having no hashfiles. Response content is unchanged (verified byte-identical against MySQL for a populated type, an empty type and an unknown type), and results are now returned in hashfile-id order, which `GROUP BY` alone does not guarantee
- The Analytics page no longer hangs the browser on large datasets: the Shared Passwords and Username = Password cards render a capped preview (with the full total shown) instead of one form per group, and the complete lists remain available from the download buttons
- Analytics counted a password as "shared" when a single account's hash appeared in more than one hashfile, or when the rows had no username at all; shared passwords are now grouped by distinct named account
- The name filter on the Tasks and Jobs listings now searches every task/job instead of only the rows on the current page, so a match on a later page is no longer reported as "no match"
- The agent's HTTP/API layer is now resilient to non-200 and unexpected server responses instead of crashing with opaque errors
- Command-injection hardening: hashcat is invoked as an argv list with no shell
- CSRF: state-changing actions were moved from GET to POST and protected with CSRF tokens
- Fixed an open redirect on the login page
- Downloading a dynamic wordlist from the web UI no longer returns an empty file: the list is regenerated from the database for the download, instead of serving whatever the last manual refresh left on disk (a zero-byte placeholder on a fresh install)
- Wordlists with legacy/relative paths no longer 404; the download route returns a clear error and paths self-heal on startup
- The API returns JSON (not an HTML error page) for empty or invalid request bodies
- Task/job max-runtime is enforced on the parent task rather than per chunk
- Cracked-hash import compares hashes case-insensitively and normalizes the lookup so records stored (lowercased) by the hashfile import path match regardless of the submitted hash's case
- Analytics decode `$HEX[...]` values before length/complexity analysis
- Hashfile export downloads are UTF-8 encoded, so cracked plaintext/usernames containing non-Latin-1 characters (emoji, CJK, Cyrillic) are exported intact instead of being silently corrupted to `?`
- Agents survive a server restart mid-task, and a bug where agent status could show as empty was fixed
- Create/edit forms surface validation errors inside their modal instead of redirecting away
- Several data-retention cleanup failures and hash-type/validator parsing bugs (e.g. PKZIP `$pkzip$`/`$pkzip2$`)
- The `main` -> v0.8.3 database upgrade is now idempotent under schema drift: migrations skip columns/tables that already exist instead of aborting on a duplicate-column error (which previously stranded the whole upgrade and left the app reporting "Unknown column"). The `tasks.hc_attackmode` conversion is also guarded so it can't misclassify tasks if re-run on an already-integer column. The `main` -> v0.8.3 upgrade also reconciles `jobs.limit_recovered` to the same `DEFAULT 0` a fresh install gets (it was previously added default-less on the main line), so an upgraded schema matches a freshly built one.
- The "I'm Feeling Lucky" button on a job's task queue said "top 5" while actually assigning up to the top 10 historically effective tasks (or fewer, if fewer exist); the label now says "top 10" to match (#379)
- The rules, wordlist and hashfile download endpoints now really do delete the scratch file they create in `control/tmp`. The previous cleanup was registered with `response.call_on_close()`, which never runs for a `send_from_directory` response because Werkzeug bypasses the closing wrapper for direct-passthrough responses — so the directory kept growing on every agent poll. Cleanup now runs via `after_this_request` (#226)
- Machine accounts are now filtered on every import format that carries a username from an AD dump (pwdump, `user:hash` NTLM family, NetNTLM), instead of pwdump alone. DCC2 hash-only is exempt: domain cached credentials cache interactive logons for user accounts, never computer accounts, so a trailing `$` there is a real username. Kerberos ticket imports are unchanged. An NTDS dump cut down to `user:hash` previously imported `COMPUTER$` as if it were a real account, inflating the hashfile's account count and depressing its reported crack rate (#409). The pwdump filter was also case-sensitive, so an uppercased `COMPUTER$` slipped through (#410), and the NetNTLM filter only looked for a trailing `$` in some cases (#411).
- Password-history entries (`secretsdump.py -history`) are no longer dropped wholesale. Only the account's first history row (`alice_history0`, or bare `alice_history` when a dumper omits the index) is filtered, and only when that account's current-password row (`alice`) is also present in the same file, since that specific row duplicates the current-password hash and adds nothing. `alice_history1` and any higher index are real, distinct prior passwords and are always imported, across pwdump, `user:hash` (AD-fed hash types), DCC2, and NetNTLM — previously they were silently and unconditionally discarded everywhere, with no way to recover them for password-reuse or rotation analysis (#412). The history suffix is matched anchored to the end of the name, so a real account such as `bob_historyclub` is not affected.
- The Customers page no longer slows to a crawl as hash volume grows. It computed each customer's totals with its own `COUNT`/`SUM` query joining `hashes` to `hashfile_hashes`, so it ran one query per customer and each one's cost scaled with the whole hash table rather than with the page -- on a large instance the page could run for minutes and time out behind a reverse proxy, appearing to hang. The counts are now computed in four queries whose cost does not grow with the number of customers (measured 4.6 s -> 0.8 s on a 869k-hash database), and the displayed numbers are unchanged
- Deleting a customer no longer issues one query per hash. It walked hashfiles -> hash links -> each hash individually, so removing a customer holding hundreds of thousands of hashes meant hundreds of thousands of queries and would hang or half-complete; the cascade is now four set-based statements in one transaction. The orphan cleanup is also shared with the hashfile delete paths rather than reimplemented, and no longer relies on `Query.distinct('customer_id')`, which is PostgreSQL-only `DISTINCT ON`, is silently ignored on MySQL, and is deprecated. Which hashes survive a customer delete is unchanged
- Adding a task to a group from the Assign Tasks page no longer accepts a task that does not exist. `GET /task_groups/assigned_tasks/<task_group_id>/add_task/<task_id>` took the id straight from the URL and appended it unchecked, so a stale or hand-edited link stored a phantom id in the group's membership -- invisible on the group listing, which only renders ids it can match to a task, but still counted toward the group's size. Flask's `<int:>` converter has no upper bound either, so an arbitrarily wide integer could be stored, pushing the serialized list past the column's byte limit in a handful of clicks (#401)
- Kerberos service tickets roasted with impacket's `GetUserSPNs.py` (or Rubeus, or NetExec) are no longer rejected. AES tickets carry the service principal name in an extra field -- `$krb5tgs$18$user$REALM$*MSSQLSvc/host.dom.local:1433*$<checksum>$<edata2>` -- and the `$krb5tgs$17$`/`$krb5tgs$18$` filter had no slot for it, so users had to hand-delete that segment before hashview would take the paste or the file. Both shapes are accepted now; hashcat cracks either one and ignores the SPN. The hash is stored in the form hashcat echoes back when it cracks, so the recovered password is matched to the right row instead of being silently discarded. The `$*user$realm$spn*$` shape that Invoke-Kerberoast and PowerView emit for AES tickets is still rejected, because hashcat cannot load it either
- AES Kerberos hashes with an upper-case or mixed-case service account name are no longer stored uncrackable. Imports lower-cased the whole hash line, but for the AES etypes the account name is part of the Kerberos salt -- so a ticket for an account like `SQLSvc` was accepted, queued, and could never crack, with the job running to exhaustion and reporting nothing. Kerberos hashes are now stored the way hashcat itself normalises them: hex lower-cased, account name and realm left exactly as supplied. Affects hash types 19600, 19700, 19800, 19900, 28800 and 28900; the RC4 types (7500, 13100, 18200) derive their key without a salt, so they are unaffected and keep the previous form. Hashes already imported in the wrong case cannot be repaired automatically -- the original capitalisation is gone -- so re-import any AES Kerberos hashfile that has never produced a crack
- Kerberos hashfile validation now matches what hashcat actually accepts, mode by mode. Every field length was established by sweeping hashcat 6.2.6 one character at a time rather than inferred from its example hashes. Hashes that were being rejected outright: `$krb5pa$17$` / `$krb5pa$18$` (19800, 19900) accepted only a 112-character blob when the real window is 104-112, and `$krb5asrep$` (18200) required the `23$` etype field that Rubeus and John omit. Hashes that were accepted but could never run -- the paste succeeded and the job later died with "No hashes loaded", with nothing to connect that to what was typed: `$krb5pa$23$` (7500), `$krb5db$17$` (28800) and `$krb5db$18$` (28900) took any length of trailing hex where hashcat wants exactly 104, 32 and 64, and 13100 / 18200 / 19600 / 19700 took a truncated encrypted blob where hashcat needs at least 64 characters. `$krb5tgs$23$` also no longer accepts a `*` nested inside the `*user$realm$spn*` triple, which hashcat rejects. Alongside that, AS-REP usernames are read correctly when the etype field is absent, and `$krb5tgs$23$` usernames no longer keep the triple's leading `*`
- Kerberos service tickets (modes 19600, 19700) whose service account name or realm contains an asterisk are now rejected at import instead of being accepted and later failing on the agent with "No hashes loaded". Hashcat interprets the asterisk as the start of the optional Service Principal Name field; when the asterisk is not a valid SPN boundary, hashcat cannot parse the hash.
- Analytics no longer double-counts accounts in the password figures. Every plaintext-derived figure was computed per hashfile-hash link rather than per account, so one account reached through two hashfiles -- or listed twice in the same hashfile, which happens whenever the source file had repeated lines -- counted as two people. The Password Reuse donut was the visible symptom, reading 100% reused on a customer whose recovered passwords were all distinct. Reuse, top passwords, length, masks, charset, complexity, themes and the account tiles are now counted per account, and the "Accounts" figures agree with the chart denominators instead of quoting a different total. Deduplicating per *hash* would have been wrong in the opposite direction -- hashes are shared between accounts by design, so it would report ~0% reuse however widely a password is shared. Figures for scopes without duplicate links are unchanged (#385)
- Analytics downloads are now scoped the same way the page is. The page resolves the hashfile selector first, but the export routes re-implemented the scoping and only honoured a hashfile *inside* a customer selection -- so a link carrying only a hashfile id (as job-completion mail and the hashfile pages can produce) rendered that one hashfile's charts and then exported every hash in the instance. "Download recovered", "Download uncracked", the Username = Password export and the shared-password export all now use the same scope resolution as the charts above them. The shared-password export also stops listing an account that merely appears twice in one hashfile as sharing a password with itself (#385)
- The duplicate-hash repair works again on MySQL. `SELECT COUNT(*) AS groups` in the count query is a syntax error on MySQL 8.0.2 and later, which reserved `GROUPS` for window functions, so `scripts/repair_duplicate_hashes.py` aborted with a 1064 and the whole repair section of Settings -> Data management -- counts, listing and Review button alike -- never appeared. That left no way to act on the upgrade's own warning that duplicate rows were blocking the uniqueness constraint. Neither SQLite (the unit tests) nor MariaDB (the parity job) reserves the word, so every check passed; a test now scans the app's raw SQL against MySQL's reserved list so the next collision fails locally
- A failed data-health check on the Settings page no longer reads as a clean database. The counts fell back to zero on any error, and the section only renders when a count is non-zero, so a broken query rendered exactly like having nothing to repair -- the page asserted all was well while the upgrade log said otherwise. It now says the check itself failed, and shows why
- The hashes uniqueness constraint can now actually be created after a duplicate cleanup. The migration that creates it skips when it finds duplicates and then returns normally, so Alembic records it as applied -- which made its own advice, "re-run the upgrade afterwards to create the constraint", do nothing at all: the upgrade starts from a revision above it and never reattempts. An operator could merge every duplicate, run the upgrade, see success, and still have no constraint and no sign of it. `repair_duplicate_hashes.py --apply` now creates it as soon as the last duplicate is merged, Hashview retries it on every start until it succeeds, and a follow-up migration creates it for databases already cleaned up. The old advice has been corrected in place
- Typing more into a field than it can hold no longer produces a server error with your input discarded. Almost nothing checked the length of a single-line form field, so an over-long value went straight to the database, which refuses it, and the page came back as a 500. Every such field in the web interface -- customer, job, task, task-group, agent, wordlist, rule and hashfile names, hashcat masks and the `-j`/`-k` rules, your own name, email address, Pushover keys and Slack member ID, and the Slack bot token, Slack admin room and Entra ID fields under Settings -- is now limited to exactly what its database column stores. Where you type the value, the field stops accepting characters at the limit (a longer paste is trimmed to fit) and the server refuses an over-long value with a message naming the limit. Wordlist and rule names are taken from the file you choose rather than typed, so those are shortened to fit instead of refused -- those modals have no name box to correct, and a `.rule` filename passes the 50-character rule-name column easily. The `/v1` API is unchanged and still writes these columns unchecked
- Your first and last name could not be longer than 20 characters even though the database stores 64, so a longer name could not be saved through the add-user form, your account settings or first-run setup. This was the one place a form was stricter than the database rather than the other way round
- Renaming a customer, and editing a user from the Users page, checked nothing about the length of what you typed: both read the submitted form directly instead of going through their form definitions, so neither picked up the limits above. Both check before saving now -- editing a user this way was also the one route through which a name longer than the old 20-character cap could be saved
- Creating a hashfile by uploading a file names the row after the file, and that name never passes through a form, so nothing had ever checked its length before writing it. It is checked against the column now, as is the name box used when pasting hashes in, which was not checked either until this release
- A refused save on the Settings page no longer vanishes without a word. The page flashed nothing when validation failed and the Entra ID fields showed no message of their own, so one bad value discarded every other setting on the page at the same time and the page came back looking unchanged -- an out-of-range agent timeout already did this before length limits existed
- Downloading a dynamic recovered-password wordlist no longer fails on a large corpus. The list was built with one `SELECT DISTINCT plaintext FROM hashes WHERE cracked`, which had no index to cover it: MySQL built an on-disk temporary table over the whole corpus before sending a single row, and on an instance with 5.9 million distinct plaintexts that took about 50 seconds -- past `net_write_timeout`, so the server closed the connection and the agent's download died with "2013 Lost connection to MySQL server during query", which looks like a dead database and is not one. There is now an index on `(cracked, plaintext)` covering that query (measured on a 2-million-row copy: 10.7s to 1.3s, and the temporary table is gone), and the corpus is walked in bounded batches rather than fetched whole, so neither the server nor Hashview holds millions of rows at once. The wordlist produced is unchanged
- Dynamic recovered-password wordlists generate quickly again. The batched walk added earlier in this release compared `cracked IS true` rather than `cracked = true`, and MySQL treats IS TRUE as a boolean test rather than an equality comparison, so it cannot use it for index range access. The walk silently abandoned the `(cracked, plaintext)` index and scanned the plaintext index instead, looking up a row per entry to test `cracked` -- work proportional to every plaintext in the table rather than to the recovered ones. On a 4-million-row table at 25% cracked that turned 1.8 seconds into 129.7. The generated wordlist was always correct; only the time to produce it was affected
- A single stalled TLS connection can no longer stop Hashview serving. Werkzeug wraps the *listening* socket in TLS, so the handshake runs inline on the one thread that accepts connections, with no deadline -- and one client that completes the TCP handshake and never sends a ClientHello stopped the server accepting anything at all, permanently. The process stayed alive with idle CPU, flat memory and a quiet database, which is what made it so hard to read: everything looked healthy except that nothing answered. Agents are a ready source, since their HTTP client sets no timeout and retries up to 100 times. The handshake now has a 30-second deadline, lifted the moment it completes so a slow multi-gigabyte wordlist download is unaffected. Terminating TLS in front of Hashview (nginx, caddy) remains the better production shape; this makes the built-in server survivable for deployments that do not
- The agent no longer waits forever on an unresponsive server. Every request it made was issued with no timeout, on top of a 100-attempt retry policy, so an agent whose server had gone away -- or was behind a black-holed port -- never gave up and never moved on, and each attempt left a half-open connection behind on the server. Requests now have a 10-second connect and 120-second read budget, both tunable with optional `connect_timeout` / `read_timeout` keys under `[HASHVIEW]` in the agent's `config.conf`. The read budget is the gap between bytes rather than a limit on the whole response, so a large wordlist download is unaffected for as long as it keeps arriving. Needs an agent redeploy
- Cancelling work is now recorded in the audit log. Stopping a job from the jobs list and cancelling a task from the dashboard were both invisible -- only the API's stop-job route wrote an entry, so the same action was audited over `/v1` and unaudited in the UI, and a task marked `Canceled` carried no record of who stopped it. Automatic cancellations are recorded too: a task killed by `max_runtime_tasks` or a job killed by `max_runtime_jobs` now writes an entry naming the cap that fired, attributed to `system` rather than to a user. That attribution matters -- these fire inside an agent's heartbeat, so a request exists but no user does, and the entries would otherwise have read as anonymous user actions
- A job owner is emailed when somebody else stops their work. Every stop route authorises "admin or owner", so a canceller who is not the owner is necessarily an administrator -- and that is exactly the case an owner could not see before: their job or task simply turned up `Canceled`. The email names the job (and the task, when one task was stopped rather than the whole job), when it was canceled, and who canceled it. Nothing is sent when you stop your own job, or when email is disabled instance-wide, and a stop still succeeds if the mail server is unreachable
- A finished attack no longer stalls the whole dispatch queue. The dispatcher walked every ledger of a queued or running job and, on reaching an attack that had finished but was still past `max_runtime_tasks`, re-closed it and returned -- without ever looking at the attacks behind it. On a long-running job any finished attack eventually exceeds the cap, so the queue could stop handing out work entirely while agents sat idle and every heartbeat still answered OK. Terminal attacks are now skipped before the cap is checked, and an over-cap attack that still has work moves on to the next position instead of ending the heartbeat, so one attack cannot starve the rest. A finished attack also keeps its real close reason instead of being stamped `runtime_cap`
- A job is now marked Running when its first slice is actually dispatched, instead of when an agent reports a status the row already has. The row was stamped Running server-side at issue time and the agent's report became idempotent, which together removed the only caller that promoted the job -- so a job could be cracking for hours while the dashboard showed it queued with no task and no progress. The promotion is a compare-and-swap on `Queued`, so concurrent heartbeats cannot re-stamp the start time, and it clears a stale end time left over from an earlier run
- "Remove all tasks" on a job now removes the job's ledger as well as its task rows. The ledger is the authoritative record of a job's attacks, so the two halves disagreed: the page kept listing attacks while the delete route found none, and every delete answered "That task is no longer on this job" -- the job was unrecoverable through the UI. Deleting one task also resolves its ledger before checking whether the task exists, so an already-orphaned ledger can be removed, and the holding agent is released first so it is not left cracking work nobody awaits
- A task added to a job that is already queued or running now gets its ledger entry. It was queued and dispatchable but invisible everywhere the UI reads (the ledger is authoritative and raw rows of a ledgered job are skipped), so the page looked unchanged while an agent quietly started cracking it -- and with no card rendered there was no per-task remove button either. Every "is this task in use?" check -- the task delete, bulk delete and edit guards, the job summary's assign-at-least-one gate, the Add-Task dropdown, the tasks list's lock badge and the dashboard's task count -- now counts rows *and* ledgers, so live work is not reported as absent between chunks
- The settings singleton is now resolved deterministically. Every reader used a bare `Settings.query.first()` with no `ORDER BY`, which has no defined result in SQL -- on an instance whose `settings` table had accumulated duplicate rows, whether the real configuration or an all-zero row won depended on the query plan. A zero row winning would silently disable chunking and the runtime caps and set retention to zero, with nothing in any log to explain it. All readers now go through `Settings.current()`, which orders by id, and a test fails if a bare `.first()` reappears
- "Restore" on a wordlist or rule is now offered only when the file is actually missing on disk. It was also offered on healthy wordlists, where it silently overwrote the file in place and changed the candidate set under every task that cites it and every finished job whose results claim to have used it. The rules list already gated it this way; both routes now also refuse server-side. The consequence is that there is no longer any way to change a static wordlist's contents in place -- add a new list instead, which mints a new row and requires repointing the tasks that used the old one
- The Recovered column on the dashboard now shows recovered out of the hashfile's total accounts, not out of what is left to crack. Both numbers moved as cracks accumulated and the ratio never reached 1 -- a completed hashfile rendered as "4/0". The per-hashfile cracked-count aggregate that fed the subtraction is gone with it, one fewer grouped query on a table that polls every 20 seconds
- Admin notifications for an agent error now carry hashcat's actual message instead of its Python byte-literal (`b'No hashes loaded.\n\n'`). The captured stderr was passed through `str()` rather than decoded, and the same repr was used for the two suppression checks. It is decoded once at the capture site and used for the log line, both checks and the notification, and an empty or whitespace-only message is no longer reported as an alert with a blank body (#499)
- New **Expired** status for jobs and tasks, so a runtime cap is no longer indistinguishable from someone hitting stop. A task that exceeds `max_runtime_tasks` and a job that exceeds `max_runtime_jobs` are now marked Expired rather than Canceled; an operator can finally tell which stopped jobs ran out of their allotted time and which a person intervened on. Expired jobs show the Info and Analytics panels and can be restarted, exactly like cancelled ones
- A job that reaches the end of its queue is now reported **Completed**, whatever stopped its individual attacks. Previously a single cancelled or capped task dragged the whole job to Incomplete, which read as a failure even when every remaining attack had finished normally. A job that really was cut short still says so directly -- Expired when the job runtime cap stopped it, Canceled when a person did. As a result **Incomplete now means exactly one thing**: a job that was created but never queued, which is also why it is the one status with no Info or Analytics to show
- The job-priority slider now says what the number means. It showed pips and "3/5", so a user moving it had to already know whether 5 was fastest or slowest; each position is now named (Lowest, Lower, Normal, Higher, Highest), updating as the slider moves. The names match the ones the job form already used for the same five values rather than introducing a second vocabulary
- The dashboard queue table now shows how many hashes each pending job is aimed at, in a Hashes column between Tasks and Priority. Two queued jobs previously looked identical whether one targeted forty hashes or four million. The figure is the same one the Recovered column of the running-job tables reads X/Y against, so the two agree; a job queued before a hashfile is attached shows a dash rather than a misleading zero

### Security
- The rule-file editor at `/rules/edit/<id>` now requires a CSRF token. It read the submitted contents straight off the request, and Hashview has no global CSRF protection, so a single cross-site POST from any page an owner or administrator visited could rewrite a rule file — and, since this release taught the route to create a file for a row whose file is gone, create one (#383)
- `/rules/delete/<id>` no longer accepts GET. Hashview has no global CSRF protection, so a single `<img src="/rules/delete/1">` on any page an administrator visited was enough to delete a rule. Every legitimate caller already used POST (#383)
- The agent no longer runs any command through a shell. Rule files downloaded during sync are decompressed and installed in-process (`gzip` + `os.replace`) instead of shelling out to `gunzip`/`mv` with the server-supplied filename interpolated into the command line, and rule/wordlist names from the server are reduced to a plain filename before they are used as a path. A rule name carrying shell metacharacters (possible on installs upgraded from before the path randomization) can no longer execute on the agent host, and a corrupt download now skips that one rule instead of killing the agent. The agent image also no longer needs `gzip`/`coreutils`.
- Hardened wordlist/rules file handling against a reported authenticated command-injection advisory (CWE-78 / CWE-22): the download API compresses files in-process instead of shelling out to `gzip`, and uploaded filenames are never reused to build on-disk paths — closing a path-traversal write. Reported by tonghuaroot.

## [v0.8.2-Beta] - 2026-06-01

### Added

**Attack Modes**
- Combinator attack (mode 1): combine two wordlists with optional `-j` and `-k` rules per task
- Hybrid Wordlist+Mask attack (mode 6) and Hybrid Mask+Wordlist attack (mode 7)

**Dynamic Wordlists**
- New auto-generated "All Usernames" dynamic wordlist, built from all uploaded hashfiles (splits `DOMAIN\user` into both components)
- New auto-generated "All Customers" dynamic wordlist, built from all customer names
- New auto-generated NTLM ciphertext dynamic wordlist

**"I'm Feeling Lucky" Task Assignment**
- One-click button on job creation that auto-assigns the top 10 historically most effective tasks for the job's hash type

**"One and Done" Job Mode**
- New checkbox when creating a job to automatically stop after the first hash is recovered, saving compute time when you only need to prove one credential is crackable

**Home Page Activity Graph**
- Dashboard now shows a line chart of passwords recovered over the past 7 days

**Hashview Wrapped**
- Year-in-review statistics page showing longest recovered passwords, most effective tasks, per-user leaderboards, and hash-type breakdowns for the previous calendar year

**Analytics: Shared Password Detection**
- New analytics figure identifying accounts that share the same password hash, with downloadable results
- Downloadable results for the username-equals-password figure

**Analytics: Recovery by Task**
- New analytics figure ranking the tasks that recovered passwords in the selected scope (hashfile, customer, or all hashes), showing each task's attack mode, contribution, recovered count, and share of recoveries
- Replaces the previous "How They Fell" attack-method breakdown

**Rules Editor**
- View and edit hashcat rule file contents directly in the browser
- Rules attached to queued tasks are protected from edits

**API Expansion**
- `GET /v1/admin/settings` -- retrieve server settings
- `GET /v1/customers` -- list customers
- `POST /v1/customers/add` -- create a customer
- `POST /v1/wordlists/add/<name>` -- upload a wordlist
- `POST /v1/hashfiles/upload/<customer_id>/<file_format>/<hash_type>/<name>` -- upload hashfiles (all 6 formats supported)
- `POST /v1/jobs/add` -- create a job with auto-assigned tasks
- `POST /v1/jobs/start/<job_id>` -- start a job
- `POST /v1/hashes/import/<hash_type>` -- import pre-cracked hashes
- `POST /v1/error` -- agents can report errors to admins
- API documentation added under `API.MD`

**Hash Type Support**
- DCC/MS Cache NT (31500), DCC2/MS Cache 2 NT (31600)
- Kerberos 5 etype 23 TGS-REP NT (35300), AS-REP NT (35400)
- KeePass Argon2 KDBX v4 (34300), KeePass AESKDF KDBX v4 (34301)
- MS Office 2007 (9400), 2010 (9500), 2013 (9600)
- NTLM hash-only import (no username required)

**User Management**
- Admins can promote and demote users between admin and regular roles
- Users can update their own email address from the profile page

**Notifications**
- Job notifications now support receiving both email and Pushover simultaneously (previously one or the other)

### Changed
- Upgraded to Bootstrap 5.3 from 4.5
- Server FQDN and port are now collected during first-run setup and stored in config
- Jobs list is paginated (20 per page) with a "show only mine" filter
- Tasks list is paginated with sortable columns, including a column showing how many passwords each task has historically recovered
- Hovering over running jobs/tasks on the home page now shows time remaining
- Duplicate task assignments in a job are now allowed when the task uses a dynamic wordlist
- Agent-to-server file manifests switched from pipe-delimited text to JSON
- PWDump import now filters out Active Directory `$_history` entries
- Hashfile deletion properly cascades through all related records
- Uploading a hashfile with zero valid hashes now shows a clear error instead of creating an empty entry
- Searching for hashes not linked to a hashfile no longer errors; results are shown gracefully
- Non-admin users attempting restricted actions now see a flash message instead of a bare 403 page

### Fixed
- Sessions and CSRF tokens no longer break on server restart (SECRET_KEY is now persisted in config instead of regenerated randomly on each startup)
- Agents now report errors back to the server, and admins receive email/Pushover notifications when an agent encounters a failure
- Fixed race condition where two agents requesting the same dynamic wordlist simultaneously would both fail
- Fixed hashfile deletion removing hashes that belonged to other hashfiles
- Fixed search results returning no results when referencing by hash ID
- Fixed hashfile name not being stored in the database when uploaded during job creation
- Fixed analytics download filenames using the wrong ID
- Fixed parenthesis bug in first-run setup that prevented SERVER_NAME from being written to config
- Fixed crash during first-time setup when no admin user exists yet
- Fixed dynamic wordlists failing to be added
- Fixed several template rendering errors from unresolved merge conflicts in settings, jobs, and other pages
- Fixed several hash import parsing issues

## [v0.8.1-Beta] - 2023-08-18
### Added
- Added support for max runtimes both for Jobs and Tasks. Admins can set the value (in hours) with = 0 being indefinate. 
- Added _some_ sanity checks for new hashes. Probably need to go back and update the rest.
- Added job priority levels. If enabled by the administrator in the settings pane, users can select the priority in which their job gets handled by agents. If disabled. all jobs are treated as first started, first processed.
- Added ability to Edit existing Tasks
- Added protections to prevent users from editing a job while its currently running
- Added ability for users to generate user API key to interface with the hashview server api
- Added new search API
- Added Test Email button to users profile
- Added Test Email button to settings page as well
- Added Analytics Table to display accounts where user:password are the same
- Added Analytics Table to display Recovered Hashes rate (as opposed to recovered accounts)
### Changed
- Swapped instances of `time` for `datetime`
- Improved performance when deleting hashfiles. Its much much quicker now
- Changed homepage display to split queued jobs and running jobs. Order is now based on queued_at time and priority
- Refactored the Selection, Parsing, validation and assignment of hashfiles, and their types. Should _hopefully_ be clearer
- Modifed API authentication to allow for user and agent auth
### Fixed
- Fixed issue where listing hashfiles w/o a valid hash_type resulted in an error preventing access to the page

## [v0.8.0-Beta] - 2022-06-11
### Added
- Added support for pushover & email notifications
- Added support for data retention
- User roles. Now you have admins and non-admins.
- Added a last login date to the users list.
### Changed
- Everything is now python
- Moved SMTP settings to config file
- Hashview Agent is now packaged with hashview (server) under install directory. Can be downloaded from agents menu as admin
- Changed from itsdangerous to authlib for password reset token generation (please make sure to update your environments to include authlib).
- Changed from the python-pushover package, to a call directly to the Pushover API.
- Changed from Flask-Bcrypt to Bcrypt-Flask.
### Removed
- Removed hashview agent from local processing. If you want to run hashview AND crack hashes on the same box run the hashview-agent in a seperate screen/tmux session

## [v0.7.4-beta] - 2018-11-20
### Added
- Added new Analytics portlet "charset breakdown"
- Extended Masks list to be to 10 instead of top 4.
- Added Hashfile to Job listings
- Added ability to create new tasks mid job creation. New tasks are automatically applied to the job.
- Added new wordlist type (dynamic). These wordlists are dynamic as in they are ever changing based on outside conditions.
- Newly imported hashfiles automatically trigger and generate a corresponding dynamic wordlist. 
- Added more info for Tasks and Wordlists, now you can easily see which tasks are assigned to what job, and what wordlists are assigned to what tasks.
- Added dynamic chunking! Now each agent will work on chunks based off of their computed benchmarks.
- Added fail check when hashfile fails import and loads a hashfile of 0/0.
- Added ability to create task group ( a predefined set of tasks for easy job assignment)
- Added ability to perform pre/post shell commands per task (Thanks: https://github.com/dmaasland)

### Changed
- The Last Updated value for jobs has been changed to Job Owner. This value is no longer updated when a user edits a job.
- Updated Gems and Base Ruby to 2.4.4 (Thanks https://github.com/HugoPouliquen)

### Removed
- Removed Smart Wordlists in favor Customer/Hashfile/All dynamic wordlists.

### Fixed
- Fixed issue where homepage fails to render if remote agents dont checkin
- Fixed issue when reordering tasks.
- Fixed bug where getBusy? function was incorrectly citing if hashview was busy.
- Now prevents the creation of a job with no tasks assigned.
- Fixed time run calculation bug used in hashfiles
- Fixed bug where keyspace was improperly being calculated for new task when hashcat was actively running.
- Fixed bug where rule name was not properly displaying in jobs listing
- Fixed bug where hashfiles were failing to delete as they were falsely reporting as being associated to a job.
- Fixed bug where emails were not sending on job completion (Thanks: https://github.com/dmaasland)

## [v0.7.3-beta] - 2018-01-10
### Added
- Added support for $user:$hash:$salt hashtypes (thanks https://github.com/GrepItAll): https://github.com/hashview/hashview/issues/373
- Added support for sequel (vs data mapper) (MAJOR THANKS to https://github.com/nicbrink)
- Added support for hashtype 2811 (IPB 2+)
- Added support for optimized drivers (-O)

### Removed

### Fixed
- Fixed issue with chunking calculations: https://github.com/hashview/hashview/issues/358
- Fixed calculation of password complexity in analytics page: https://github.com/hashview/hashview/issues/360 
- Fixed hard crash error when attempting to delete non-existent file: https://github.com/hashview/hashview/issues/365
- Updated Gemlock to require rubocop 0.51.0 due to security vulns.
- Fixed issue where Time Remaining listed in the jumbo tron was not properly populating (note requires agent update if using distributed): https://github.com/hashview/hashview/issues/371
- Fixed task list when adding tasks to new jobs. Now no longer lets you select a task that was already assigned.

## [v0.7.2-beta] - 2017-10-19
### Added
 - Added Logging Facility, logs should now be under /hashview/logs/\*.log and /hashview/logs/jobs/\*.log (Logs will rotate daily. Logs greater than 30 days will be automatically deleted
 - Added collapsing window in analytics in Weak Account Password
 - Added ability to download user accounts/passwords for accounts that are found to be weak in csv format
 - Added ability to set OTP passwords for users using google authenticate (thanks: https://github.com/nicbrink)
 
### Removed
 - Wordlist Checksums is no longer a background task that fires every 5 seconds. Instead its queued up by wordlist importer.

### Fixed
 - Fixed calculation bug where SmartWordlist was being refactored into new SmartWordlist. Now calculations are quicker
 - Fixed (hopefully) bug where hashview prematurely 'completes' a job (and subsequently kills a running task). This only happens in rare cases where multiple agents are involved. 
 - Fixed (hopefully) issue where threads not exiting when they're told to. This resulted in issues related to: https://github.com/hashview/hashview/issues/264
 - Fixed issue where rules listed under task details was displaying rule.id, and not the rule.name: https://github.com/hashview/hashview/issues/342
 - Fixed SMTP sender error experienced when user sends test message
 https://github.com/hashview/hashview/issues/341
 - Fixed issue where foreign DB's listed in config were not being connected too: https://github.com/hashview/hashview/issues/351

## [v0.7.1-beta] - 2017-09-04
### Added
 - Rake task to reset db (thanks: nicbrink)
 - New hub route/tab if registered
 - Additional step in job creation (if hub enabled) asking permission to check for cracked hashes before continuing
 - Added ability to reorder & delete tasks of a job mid creation and edit. 

### Removed
 - Hub check upon loading hashfiles list (no one was using it)
 - Hub upload function upon searches, job creation (no one was using it)

### Fixed
 - Fixed issue where importing the same hash twice into the db where one had an incorrect hashtype resulted in a 500 error. Now the entry is updated with the new hashtype.
 - Fixed timeouts when searching large hash sets with Hashview Hub

## [v0.7.0-beta] - 2017-07-22
### Added
 - Support for distributed cracking through hashview-agents
 - New type of wordlist 'Smart Wordlist'
 - Beta Hashview Hub (tm) integration
 - New management console for agents and Rules (you can now edit your rules within the app)
 - 3 new analytic portlets
 - Support for 50 more hashes

### Fixed
 - Calculation error on Analytics where on the global page for number of cracked hashes vs uncracked hashes.
 
## [v0.6.1-beta] - 2017-04-25
### Added
 - Support for 38 more hashes
### Fixed
 - Raced condition when importing wordlists (both via gui and cli)
 - Bug where NetNTLMv1 and NetNTLMv2 hashes were not properly importing
 - Bug where usernames were not being parsed when importing NetNTLMv1 and NetNTLMv2 hashes

## [v0.6.0-beta] - 2017-03-28
### Added
 - Resque 'management' queue for system jobs
 - Background job for automatically importing wordlists scp'd to control/wordlists
 - Background job for removing old temp files.
 - Support for user to set a SMTP Sender Name
 - Themes!! (we personally like slate)
 - Support for new hashcat settings: --force, --opencl-device-types, --workload-profile, --gpu-temp-disable, --gpu-temp-abort, --gpu-temp-retain
 - Ability to copy/paste hashfiles into new jobs as their being created
 - Support for smart hashdump and username:[NTLM hash] hashfiles
 - Two new rule sets for high and low utility
 - Support for cracking and importing hashes with salts
 - Support for more hashes: [import only] md5($pass.$salt), md5($salt.$pass), md5(unicode($pass).$salt), md5($salt.unicode($pass)), 	HMAC-MD5 (key = $pass), HMAC-MD5 (key = $salt), sha1($pass.$salt), sha1($salt.$pass), sha1(unicode($pass).$salt), sha1($salt.unicode($pass)), HMAC-SHA1 (key = $pass), HMAC-SHA1 (key = $salt), Domain Cached Credentials (DCC), MS Cache, 	sha256($pass.$salt), sha256($salt.$pass), sha256(unicode($pass).$salt), sha256($salt.unicode($pass)), HMAC-SHA256 (key = $pass), HMAC-SHA256 (key = $salt), vBulletin < v3.8.5 and vBulletin >= v3.8.5
 
### Changed
 - Moved queue management for cracking tasks from redis/resqueu to mysqld
 - Expanded hashes table to allow for hashes up to 1024 characters in length
 - Rake task db:upgrade will now automatically detect previous versions (starting with v0.5.1) and automatically upgrade your db and import current settings, users, cracked hashes, wordlists to new versions as they come out
 - Startup proccess from two cmds to single foreman cmd
 - Cracked output is now in hex format (better for importing symbols and other characters)
 - Default sender address of emails from no-reply@Pony to no-reply@hashview
 - Global settings is split into multiple panels for easier use.
 
### Fixed
 - Bug in combinator crack command
 - Searches now include wildcards before/after submitted string
 - Searches now remember what search type you entered
 - Jumbo tron now properly updates status on page refresh
 - Issue where Queued jobs are not being displayed on home page should be fixed
 - You should now be prevented from editing a job that is running or queued
 - Prevent the assignment of the same task twice to a job

## [v0.5.1-beta] - 2016-02-19
### Changed
- changed from Sinatra classic style to modular style

## [v0.5-beta] - 2016-02-04
### Changed
- changed db schema to accomadate very large datasets
- improved performance via db queries

## [v0.4-beta] - 2016-10-18
### Changed
- Encompasses all changes since the v0.3 tagged release

## [v0.3-beta] - 2016-10-18
### Changed
- Moved retrochecks from hashfile import to job start

### Fixed
- Fixed unauth message on invalid login attempts

## 2016-10-11
### Added
- Added download of uncracked hashes in download section

### Fixed
- Fixed bug where download file name of cracked passwords was not properly rendering

## 2016-10-10
### Fixed
- Fixed bug where stopping jobs and tasks failed to handle properly

### Changed
- Updated Job descriptions

## 2016-10-09
### Changed
- Changed support format for DSUser from v1.2 to v1.3

## 2016-10-07
### Changed
- Code Cleanup

## 2016-10-06
### Added
- Added support for Combinator attacks

## 2016-10-03
### Added
- Added Support for NTDSXtract (dsusers)
- Added 'importing' status for jobs and tasks

## 2016-10-02
### Removed
- Removed ability for basewords in analytics to be null

### Changed
- Rounded Run time calculated in analytics
- Prevented the deletion of a task if un an active job

## 2016-09-29
### Changed
- Code Cleanup

## 2016-09-28
### Added
- Expanded test cases
- Removed old 

## 2016-09-26
### Changed
- Fixed NetNTLMv1 and NetNTLMv2 parse bug
- Updated Jobsq to support NetNTLMv1 and NetNTLMv2

## 2016-09-23
### Removed
- Removed implicit downcase for non-LM hash imports


[v0.5.1-beta]: https://github.com/hashview/hashview/compare/v0.5-beta...v0.5.1-beta
[v0.5-beta]: https://github.com/hashview/hashview/compare/v0.4-beta...v0.5-beta
[v0.4-beta]: https://github.com/hashview/hashview/compare/v0.3-beta...v0.4-beta
[v0.3-beta]: https://github.com/hashview/hashview/compare/v0.1-alpha...v0.3-beta
