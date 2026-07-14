-- Main-era seed for the end-to-end main->dev migration test.
--
-- Loaded into the `db` container AFTER the hashview:main app image has booted
-- and run its own migrations (schema at main head dba208b9344c). Every column
-- list below matches main's `SHOW CREATE TABLE` exactly (see the design doc);
-- only columns that EXIST on main are referenced -- the dev-only columns are
-- added later by the migrations under test and backfilled from server_defaults.
--
-- Fixed ids in the 900 / 9001+ range sit above main's auto-seeded rows
-- (wordlists auto_increment=7, tasks=4, users id=1) so there are no collisions.
-- owner_id / recovered_by reuse the pre-existing admin user (id=1).
--
-- The hex-encoded username/plaintext values below are the LEGACY storage format;
-- the dev app's decode_legacy_hex_if_needed backfill rewrites them to text on
-- boot. Values are kept in sync with tests/migration/expected_hex.py.

-- A settings row MUST exist: decode_legacy_hex_if_needed early-returns when
-- Settings.query.first() is None, and the a1f7c4e9d2b3 migration only flips
-- passwords_decoded->0 on EXISTING rows. Without this row the hex backfill would
-- never fire. `enabled_job_weights` is the only NOT NULL column with no default.
INSERT INTO settings (id, retention_period, max_runtime_jobs, max_runtime_tasks, enabled_job_weights)
VALUES (1, NULL, NULL, NULL, 0);

-- Customer + hashfile (hashfile.hex_salt is added on dev -> expect 0 after migrate).
INSERT INTO customers (id, name) VALUES (900, 'MigrationTestCo');
INSERT INTO hashfiles (id, name, uploaded_at, runtime, customer_id, owner_id)
VALUES (900, 'mig-hashfile', NOW(), NULL, 900, 1);

-- hashes.plaintext legacy-hex cases (markers align with expected_hex.PLAINTEXT_CASES).
-- ciphertext is a 400-char value (<= main's VARCHAR(500)); the widen-to-TEXT
-- migration is asserted via column type, not by overflowing the main column.
INSERT INTO hashes (id, sub_ciphertext, ciphertext, cracked, plaintext, hash_type, recovered_at, task_id, recovered_by) VALUES
  (9001, 'mig1', REPEAT('a', 400), 1, '70617373', 1000, NULL, NULL, 1),   -- p_ascii  -> 'pass'
  (9002, 'mig2', REPEAT('b', 400), 1, 'f09f9880', 1000, NULL, NULL, 1),   -- p_utf8   -> 😀
  (9003, 'mig3', REPEAT('c', 400), 1, 'ff',       1000, NULL, NULL, 1);   -- p_nonutf8 -> $HEX[ff]

-- hashfile_hashes.username legacy-hex cases (markers align with expected_hex.USERNAME_CASES).
-- hash_id points at a seeded hashes row; hashfile_id at the seeded hashfile.
INSERT INTO hashfile_hashes (id, hash_id, username, hashfile_id) VALUES
  (9001, 9001, '41646d696e',    900),  -- u_ascii     -> 'Admin'
  (9002, 9001, 'c3a9',          900),  -- u_utf8      -> 'é'
  (9003, 9001, 'ff01',          900),  -- u_nonutf8   -> '$HEX[ff01]'
  (9004, 9001, 'already-text',  900),  -- u_plaintext -> unchanged (not valid hex)
  (9005, 9001, REPEAT('ff', 126), 900);-- u_overflow  -> unchanged ($HEX[...] form 258 > 256)

-- An agent (dev adds offline_notified/gpu telemetry/agent_timeout columns).
INSERT INTO agents (id, name, src_ip, uuid, status, hc_status, benchmark, cpu_count, gpu_count, last_checkin)
VALUES (900, 'mig-agent', '127.0.0.1', 'mig-uuid-900', 'Ready', NULL, NULL, NULL, NULL, NULL);

-- A wordlist (dev adds byte_size, nullable -> expect NULL after migrate).
-- owner_id FKs to users(id=1); size/checksum/path are NOT NULL on main.
INSERT INTO wordlists (id, name, last_updated, owner_id, type, path, size, checksum)
VALUES (900, 'mig-wl', NOW(), 1, 'static', '/tmp/mig-wl', 0, 'seedchecksum');

-- A task (dev adds loopback, server_default 0 -> expect 0 after migrate).
-- owner_id FKs to users(id=1); hc_attackmode is NOT NULL.
INSERT INTO tasks (id, name, hc_attackmode, owner_id)
VALUES (900, 'mig-task', 0, 1);
