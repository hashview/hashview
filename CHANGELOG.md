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

**Single Sign-On (Microsoft Entra ID / Azure AD)**
- Optional OIDC web login alongside local accounts, with group-gated just-in-time user provisioning (configured under Settings)

**Slack Notifications**
- Per-user Slack direct messages as a third job-notification channel (email / Pushover / Slack)
- Opt-in admin and security notifications delivered to a Slack room

**Audit & Error Logging**
- On-disk JSON audit log of authentication and create/update/delete events, plus captured server errors, viewable and clearable from Settings

**API Documentation**
- The `/v1` API is now described by an OpenAPI spec with interactive Swagger UI at `/api/docs`
- `DELETE /v1/hashfiles/<id>` to remove a hashfile via the API

**Task-viability read API**
- `GET /v1/tasks` — list all tasks (metadata) in one call, complementing the existing single-task `GET /v1/tasks/{id}`
- `GET /v1/agents/benchmark` — read rig benchmark performance per hash type (slowest agent per mode; `?hash_type=` for one mode). Exposes already-stored benchmark data over the API for external viability tooling.

**API Expansion**
- `GET /v1/customers/<customer_id>/hashfiles` -- list every hashfile belonging to a customer in one call, replacing the downstream client-side loop over common hash types (which silently missed uncommon types). Counts cover the whole file (`total_hashes`/`cracked_hashes`) and `hash_type` is the file's representative mode; an unknown customer returns an empty list. (#346)
- `POST /v1/hashes/import/<hash_type>` now imports cracked hashes for any hash type the server can recompute locally, not just NTLM: MD5 (0), SHA1 (100), MySQL4.1/5 (300), MD4 (900), NTLM (1000), SHA2-256 (1400), and MSSQL 2012/2014 (1731). Each submitted `HASH:plaintext` pair is still verified server-side; unverifiable plaintext is never trusted. Imports are atomic: a single failing line rolls back the entire request.

**Encrypted Database Backup**
- Download an encrypted `mysqldump` of the database from Settings -> Data Management, protected by a one-time password

**Agent Management**
- Configurable agent heartbeat timeout, with scheduled alerts when an agent goes offline or recovers
- Per-agent host-specific hashcat arguments via `HC_EXTRA_ARGS` (e.g. to pin specific GPUs)

**Jobs & Hashfiles**
- Bulk-select and bulk-delete on the hashfiles list
- Per-hashfile `--hex-salt` option for salted hash types
- New "Website Keywords" dynamic wordlist that crawls a per-job URL to build a targeted wordlist

**Testing**
- Job-creation performance e2e suite (`tests/e2e/test_job_creation_perf.py`) with a tunable volume seeder (`tests/seed_perf_db.py`), covering latency budgets for each wizard step plus strict-xfail scaling guards for the four endpoints in issue #422 whose cost grows with table size rather than page size

### Changed
- The Rules listing is paginated (20 per page) with sortable Name / Rules / Owner / Last Updated columns and a server-side name filter, matching the Tasks listing
- Reintroduced distributed chunking: eligible mask/wordlist tasks are split into per-agent chunks sized from each agent's benchmark, and a chunked task now appears as a single attack in the job editor
- Wordlists are stored gzip-compressed at rest; agents sync and verify the compressed files
- `/v1` list and detail endpoints now return native JSON instead of a JSON-encoded string, so clients no longer double-parse
- Usernames and recovered plaintext are stored as UTF-8 text (`$HEX[...]` only for non-UTF-8 bytes) instead of latin-1 hex
- Creating and queuing a job now returns you to the dashboard
- The job-creation wizard gates "Next" until the current step's required fields are filled in
- Quantities throughout the UI are thousands-separated
- Alembic migrations for the dev line were consolidated into a single baseline
- Pinned Python to 3.11+; added a ruff / pylint / bandit / pre-commit lint-and-security stack, a LICENSE, and substantially expanded automated tests (unit, agent, end-to-end, and security)

### Fixed
- The Analytics page no longer hangs the browser on large datasets: the Shared Passwords and Username = Password cards render a capped preview (with the full total shown) instead of one form per group, and the complete lists remain available from the download buttons
- Analytics counted a password as "shared" when a single account's hash appeared in more than one hashfile, or when the rows had no username at all; shared passwords are now grouped by distinct named account
- The name filter on the Tasks and Jobs listings now searches every task/job instead of only the rows on the current page, so a match on a later page is no longer reported as "no match"
- The agent's HTTP/API layer is now resilient to non-200 and unexpected server responses instead of crashing with opaque errors
- Command-injection hardening: hashcat is invoked as an argv list with no shell
- CSRF: state-changing actions were moved from GET to POST and protected with CSRF tokens
- Fixed an open redirect on the login page
- Wordlists with legacy/relative paths no longer 404; the download route returns a clear error and paths self-heal on startup
- The API returns JSON (not an HTML error page) for empty or invalid request bodies
- Task/job max-runtime is enforced on the parent task rather than per chunk
- Cracked-hash import compares hashes case-insensitively and normalizes the lookup so records stored (lowercased) by the hashfile import path match regardless of the submitted hash's case
- Analytics decode `$HEX[...]` values before length/complexity analysis
- Agents survive a server restart mid-task, and a bug where agent status could show as empty was fixed
- Create/edit forms surface validation errors inside their modal instead of redirecting away
- Several data-retention cleanup failures and hash-type/validator parsing bugs (e.g. PKZIP `$pkzip$`/`$pkzip2$`)
- The `main` -> v0.8.3 database upgrade is now idempotent under schema drift: migrations skip columns/tables that already exist instead of aborting on a duplicate-column error (which previously stranded the whole upgrade and left the app reporting "Unknown column"). The `tasks.hc_attackmode` conversion is also guarded so it can't misclassify tasks if re-run on an already-integer column. The `main` -> v0.8.3 upgrade also reconciles `jobs.limit_recovered` to the same `DEFAULT 0` a fresh install gets (it was previously added default-less on the main line), so an upgraded schema matches a freshly built one.
- The "I'm Feeling Lucky" button on a job's task queue said "top 5" while actually assigning up to the top 10 historically effective tasks (or fewer, if fewer exist); the label now says "top 10" to match (#379)
- The rules, wordlist and hashfile download endpoints now really do delete the scratch file they create in `control/tmp`. The previous cleanup was registered with `response.call_on_close()`, which never runs for a `send_from_directory` response because Werkzeug bypasses the closing wrapper for direct-passthrough responses — so the directory kept growing on every agent poll. Cleanup now runs via `after_this_request` (#226)
- Machine accounts and NTLM password-history entries are now filtered on every import format that carries a username from an AD dump (pwdump, `user:hash`, NetNTLM, and DCC2 hash-only), instead of pwdump alone. Kerberos ticket imports are unchanged. An NTDS dump cut down to `user:hash` previously imported `COMPUTER$` and `COMPUTER$_history1` as if they were real accounts, inflating the hashfile's account count and depressing its reported crack rate (#409). The pwdump filter was also case-sensitive, so an uppercased `COMPUTER$_HISTORY0` slipped through (#410), and the NetNTLM filter only looked for a trailing `$` (#411). The history suffix is now matched anchored to the end of the name, so a real account such as `bob_historyclub` is no longer dropped. Filtering stays scoped to the NTLM family of hash types, so a trailing-`$` username in a non-NTLM `user:hash` dump is still imported.

### Security
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
