# Multi-agent NTLM true-crack e2e test

A true end-to-end test: two real `hashview-agent` containers pick up a real job
and genuinely recover NTLM plaintexts (random rockyou entries) using a
CPU "hashcat" shim that really computes NTLM and applies a minimal rule set.
Exercises agent registration, wordlist sync, rules sync, concurrent task
distribution, crack upload, and job completion — all verified in the DB.

## Run

```sh
ROCKYOU_PATH=/usr/share/wordlists/rockyou.txt ./tests/run_e2e_crack_compose.sh
```

Requires Docker + a rockyou wordlist. The test is opt-in (`-m e2e_crack`) and is
not part of the default suite.

## How it works

1. `gen_slices.py` (host) picks random rockyou targets and builds two ~50k-line
   slices + a manifest. Task A = plain dict; Task B = dict + `$1` rule (targets
   are `<base>1`, so a crack proves rules sync + rule application).
2. `seed_crack_db.py` (in the app container) builds the customer/user/wordlists/
   rule/hashfile/NTLM-hashes/tasks/job/job_tasks and authorizes both agents.
3. `docker-compose.e2e.yml` runs `agent1` + `agent2` (built from
   `Dockerfile.agent`) with the shim as `HC_BIN_PATH`.
4. `verify_crack.py` (in the app container) dumps DB state; the pytest test polls
   it and asserts every target recovered with the exact plaintext, both tasks
   Completed by two DISTINCT agents, and per-task attribution.

## Components

| File | Role |
|------|------|
| `shim/hcshim.py`, `shim/hashcat` | real-cracking hashcat shim (NTLM + rules) |
| `gen_slices.py` | host: rockyou → slices + manifest |
| `seed_crack_db.py` | in-container: build job + authorize agents |
| `verify_crack.py` | in-container: dump DB state |
| `../../../Dockerfile.agent` | agent image |
| `../../../docker-compose.e2e.yml` | agent1 + agent2 services |
| `../../run_e2e_crack_compose.sh` | orchestrator |
| `../test_multiagent_ntlm_crack.py` | assertions |
