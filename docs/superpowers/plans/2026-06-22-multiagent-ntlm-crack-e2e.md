# Dockerized Multi-Agent NTLM True-Crack E2E Test — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an opt-in end-to-end test where two real `hashview-agent.py` containers pick up a real job, genuinely recover rockyou-derived NTLM plaintexts via a CPU "hashcat" shim, and the result is verified in the server DB — including real wordlist AND rules sync and concurrent multi-agent distribution.

**Architecture:** A standalone Python shim mimics the hashcat CLI the server builds and performs *real* recovery (pure-Python MD4→NTLM + a minimal rule engine). A new agent Docker image runs the unmodified agent against the existing server+MySQL compose stack. A host generator slices rockyou and chooses random targets; an in-container seeder builds the customer/user/wordlists/rule/hashfile/hashes/tasks/job/job-tasks and authorizes both agents; an in-container verifier dumps DB state that the pytest test polls and asserts on.

**Tech Stack:** Python 3.8 (agent image) / 3.11 (host venv), Docker Compose, Flask-SQLAlchemy 1.4, pytest, MySQL 8.

**Spec:** `docs/superpowers/specs/2026-06-22-multiagent-ntlm-crack-e2e-design.md`

**Key codebase facts the implementation depends on (verified):**
- Agent runs (in `install/hashview-agent/hashview-agent.py:631`): `replaceHashcatBinPath(job_task['command']) + ' --status-json | tee control/outfiles/hcoutput_<job>_<jobtask>.txt'` under `shell=True`. **`run_command` treats ANY stderr output as a fatal error** (`hashview-agent.py:123-130`) → the shim must write NOTHING to stderr on success.
- `build_hashcat_command` (`hashview/utils/utils.py:653`) emits, for attackmode 0: `@HASHCATBINPATH@ -O -w 3 --session <hex> -m <type> --potfile-path <pot> --status --status-timer=15 --outfile-format 1,3 --outfile control/outfiles/hc_cracked_<job>_<task>.txt [-r control/rules/<file>] control/hashes/hashfile_<job>_<task>.txt control/wordlists/<hex>.gz`.
- Target hashfile served by `/v1/hashfiles/<id>` is **one ciphertext per line** (`hashview/api/routes.py:1180-1186`).
- Crack upload (`/v1/uploadCrackFile/<jobtask>`, `routes.py:1248`) splits each line on `:`, treats the LAST field as hex-plaintext (`hexplain_to_text`), rejoins the rest as ciphertext, and matches `Hashes.sub_ciphertext == md5(ciphertext)` with `hash_type` and `cracked='0'`; on match sets `plaintext`, `cracked=1`, `task_id=job_task.task_id`, `recovered_by=job.owner_id`.
- Agent authorization (`routes.py:agentAuthorized`) requires `Agents.status` ∈ {`Online`,`Working`,`Idle`,`Authorized`}. Unknown UUIDs auto-create as `Pending` ("Go Away"). Idle heartbeat assigns the first `JobTasks.status=='Queued'` (order by priority desc, id) → sets `agent_id`, `status='Running'`, `started_at`.
- Version gate: cookie `agent_version` (read from `VERSION.TXT` in agent CWD) must be `>=` `hashview.__version__` or the server returns 426.
- NTLM `hash_type` integer is `1000`. Static wordlist `checksum` = sha256 of the stored `.gz`; rule `checksum` = sha256 of the plaintext file (`ingest_static_wordlist_file` at `utils.py:153`; rules at `hashview/rules/routes.py:94`).
- Wordlist/rule filenames line up between server `path` basename and the agent's synced filename (`ensure_gz`), so the server-built command paths resolve on the agent.

**Fixed shared constants (must match across compose + manifest):**
- `AGENT1_UUID = 11111111-1111-1111-1111-111111111111`, name `e2e-agent-1`, compose service `agent1`
- `AGENT2_UUID = 22222222-2222-2222-2222-222222222222`, name `e2e-agent-2`, compose service `agent2`
- `JOB_NAME = e2e-crack-job`, `CUSTOMER_ID = 9001`
- Task B rule body = `$1\n` (append "1"); Task B targets = base word + `1`
- `TARGETS_PER_TASK = 3`, `SLICE_SIZE = 50000`

---

## File Structure

New:
- `tests/e2e/crack/shim/hcshim.py` — shim logic (importable, unit-tested)
- `tests/e2e/crack/shim/hashcat` — thin executable wrapper (the agent's `HC_BIN_PATH`)
- `tests/e2e/crack/gen_slices.py` — host: rockyou → slices + manifest
- `tests/e2e/crack/seed_crack_db.py` — in-container DB seeder
- `tests/e2e/crack/verify_crack.py` — in-container DB state dumper
- `Dockerfile.agent` — agent image (agent code + shim + entrypoint)
- `tests/e2e/crack/agent-entrypoint.sh` — writes `agent/config.conf`, execs agent
- `docker-compose.e2e.yml` — adds `agent1` + `agent2`
- `tests/run_e2e_crack_compose.sh` — orchestrator
- `tests/e2e/test_multiagent_ntlm_crack.py` — the `e2e_crack` test
- `tests/unit/test_crack_shim.py`, `tests/unit/test_crack_gen_slices.py`, `tests/unit/test_crack_seed_verify.py` — host unit tests
- `tests/e2e/crack/README.md` — how to run

Modified:
- `pytest.ini` — register `e2e_crack` marker

---

## Task 1: Register the `e2e_crack` pytest marker

**Files:**
- Modify: `pytest.ini:4-7`

- [ ] **Step 1: Add the marker**

In `pytest.ini`, change the `markers =` block to add the new marker:

```ini
markers =
    e2e: end-to-end tests using Playwright
    agent_sim: agent simulator tests
    security: security-focused tests
    e2e_crack: dockerized multi-agent real-crack e2e test (opt-in; needs compose + rockyou)
```

- [ ] **Step 2: Verify it is registered**

Run: `python -m pytest --markers | grep e2e_crack`
Expected: prints `@pytest.mark.e2e_crack: dockerized multi-agent real-crack e2e test ...`

- [ ] **Step 3: Commit**

```bash
git add pytest.ini
git commit -m "test(e2e): register e2e_crack pytest marker"
```

---

## Task 2: Shim — NTLM/MD4 + rule engine + arg parsing + crack

**Files:**
- Create: `tests/e2e/crack/shim/hcshim.py`
- Create: `tests/e2e/crack/shim/hashcat`
- Test: `tests/unit/test_crack_shim.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_crack_shim.py`:

```python
import gzip
import importlib.util
import subprocess
import sys
from pathlib import Path

SHIM_DIR = Path(__file__).resolve().parents[1] / "e2e" / "crack" / "shim"


def _load():
    spec = importlib.util.spec_from_file_location("hcshim", SHIM_DIR / "hcshim.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_ntlm_hex_matches_known_vector():
    hcshim = _load()
    # NTLM("password") = 8846f7eaee8fb117ad06bdd830b7586c
    assert hcshim.ntlm_hex("password") == "8846f7eaee8fb117ad06bdd830b7586c"


def test_apply_rule_append_and_passthrough():
    hcshim = _load()
    assert hcshim.apply_rule("cat", "$1") == "cat1"
    assert hcshim.apply_rule("cat", ":") == "cat"
    assert hcshim.apply_rule("cat", "^x") == "xcat"
    assert hcshim.apply_rule("cat", "u") == "CAT"


def test_parse_args_dict_with_rule():
    hcshim = _load()
    argv = ("-O -w 3 --session ab12 -m 1000 --potfile-path p.pot --status "
            "--status-timer=15 --outfile-format 1,3 --outfile out.txt "
            "-r control/rules/r.txt control/hashes/h.txt control/wordlists/w.gz "
            "--status-json").split()
    mode, outfile, fmt, rules, positionals = hcshim.parse_args(argv)
    assert mode == 1000
    assert outfile == "out.txt"
    assert rules == ["control/rules/r.txt"]
    assert positionals == ["control/hashes/h.txt", "control/wordlists/w.gz"]


def test_crack_recovers_plain_and_ruled(tmp_path):
    hcshim = _load()
    # Targets: NTLM("cat") plain, and NTLM("dog1") via $1 rule on base "dog".
    target_cat = hcshim.ntlm_hex("cat").upper()       # echoed verbatim regardless of case
    target_dog1 = hcshim.ntlm_hex("dog1")
    hashfile = tmp_path / "h.txt"
    hashfile.write_text(target_cat + "\n" + target_dog1 + "\n")
    wl = tmp_path / "w.gz"
    with gzip.open(wl, "wt") as f:
        f.write("cat\ndog\nbird\n")
    rules = tmp_path / "r.txt"
    rules.write_text("$1\n")

    # No rule -> only "cat" cracks (plain wordlist words).
    found = hcshim.crack(1000, [target_cat, target_dog1], str(wl), [])
    assert found == {target_cat: "cat"}

    # With $1 rule -> only "dog1" cracks (ruled candidates).
    found2 = hcshim.crack(1000, [target_cat, target_dog1], str(wl), [str(rules)])
    assert found2 == {target_dog1: "dog1"}


def test_executable_writes_outfile_and_no_stderr(tmp_path):
    hcshim = _load()
    target = hcshim.ntlm_hex("cat")
    hashfile = tmp_path / "h.txt"
    hashfile.write_text(target + "\n")
    wl = tmp_path / "w.gz"
    with gzip.open(wl, "wt") as f:
        f.write("cat\n")
    out = tmp_path / "cracked.txt"
    proc = subprocess.run(
        [sys.executable, str(SHIM_DIR / "hashcat"),
         "-m", "1000", "--outfile-format", "1,3", "--outfile", str(out),
         str(hashfile), str(wl), "--status-json"],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0
    assert proc.stderr == ""                      # CRITICAL: agent treats stderr as fatal
    # outfile-format 1,3 -> hash:hex_plain ; hex("cat") == 636174
    assert out.read_text().strip() == f"{target}:636174"
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python -m pytest tests/unit/test_crack_shim.py -v`
Expected: FAIL (no such file `hcshim.py`).

- [ ] **Step 3: Write the shim logic**

Create `tests/e2e/crack/shim/hcshim.py`:

```python
"""Test double for hashcat used by the multi-agent crack e2e test.

Performs REAL recovery (it computes NTLM and matches the target hashfile); it
just isn't the optimized hashcat engine. Parses the server-built hashcat
command, reads the gzip wordlist, applies any -r rules, and writes genuine
hash:hex_plain matches to --outfile (outfile-format 1,3).

CRITICAL: never write to stderr on the happy path — the agent's run_command
treats any stderr output as a fatal error and kills the agent.
"""
import binascii
import gzip
import json
import struct
import sys
import time


# --- pure-Python MD4 (NTLM); OpenSSL 3 frequently lacks md4 ----------------
def _lrot(x, n):
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def md4(data):
    A, B, C, D = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    msg = bytearray(data)
    bit_len = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", bit_len)
    for off in range(0, len(msg), 64):
        X = list(struct.unpack("<16I", msg[off:off + 64]))
        a, b, c, d = A, B, C, D
        for i in range(0, 16, 4):
            a = _lrot(a + ((b & c) | (~b & d)) + X[i], 3)
            d = _lrot(d + ((a & b) | (~a & c)) + X[i + 1], 7)
            c = _lrot(c + ((d & a) | (~d & b)) + X[i + 2], 11)
            b = _lrot(b + ((c & d) | (~c & a)) + X[i + 3], 19)
        for i in (0, 1, 2, 3):
            a = _lrot(a + ((b & c) | (b & d) | (c & d)) + X[i] + 0x5A827999, 3)
            d = _lrot(d + ((a & b) | (a & c) | (b & c)) + X[i + 4] + 0x5A827999, 5)
            c = _lrot(c + ((d & a) | (d & b) | (a & b)) + X[i + 8] + 0x5A827999, 9)
            b = _lrot(b + ((c & d) | (c & a) | (d & a)) + X[i + 12] + 0x5A827999, 13)
        for i in (0, 2, 1, 3):
            a = _lrot(a + (b ^ c ^ d) + X[i] + 0x6ED9EBA1, 3)
            d = _lrot(d + (a ^ b ^ c) + X[i + 8] + 0x6ED9EBA1, 9)
            c = _lrot(c + (d ^ a ^ b) + X[i + 4] + 0x6ED9EBA1, 11)
            b = _lrot(b + (c ^ d ^ a) + X[i + 12] + 0x6ED9EBA1, 15)
        A = (A + a) & 0xFFFFFFFF
        B = (B + b) & 0xFFFFFFFF
        C = (C + c) & 0xFFFFFFFF
        D = (D + d) & 0xFFFFFFFF
    return struct.pack("<4I", A, B, C, D)


def ntlm_hex(plaintext):
    return binascii.hexlify(md4(plaintext.encode("utf-16le", "surrogatepass"))).decode("ascii")


# --- minimal hashcat rule engine -------------------------------------------
def apply_rule(word, rule_line):
    """Apply one space-separated rule line. Unknown ops are silently skipped
    (never stderr). Supported: ':' '$X' '^X' 'l' 'u' 'c'."""
    for op in rule_line.split():
        if op == ":":
            continue
        if op[0] == "$":
            word = word + op[1:]
        elif op[0] == "^":
            word = op[1:] + word
        elif op == "l":
            word = word.lower()
        elif op == "u":
            word = word.upper()
        elif op == "c":
            word = (word[:1].upper() + word[1:].lower()) if word else word
        # else: skip
    return word


def _load_rule_lines(path):
    lines = []
    with open(path, "r", encoding="utf-8", errors="surrogateescape") as f:
        for raw in f:
            line = raw.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            lines.append(line)
    return lines


def _candidates(word, rule_lines):
    return [word] if not rule_lines else [apply_rule(word, r) for r in rule_lines]


def _iter_words(path):
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="surrogateescape") as f:
        for line in f:
            yield line.rstrip("\n")


def _load_targets(path):
    with open(path, "r", encoding="utf-8", errors="surrogateescape") as f:
        return [line.rstrip("\n") for line in f if line.strip()]


def crack(mode, targets, wordlist_path, rule_files):
    """Return {original_target_line: plaintext} for recovered hashes."""
    if mode != 1000:
        return {}                       # v1 supports NTLM only
    want = {}
    for t in targets:
        want.setdefault(t.strip().lower(), t.strip())
    rule_lines = []
    for rf in rule_files:
        rule_lines += _load_rule_lines(rf)
    found = {}
    for word in _iter_words(wordlist_path):
        for cand in _candidates(word, rule_lines):
            h = ntlm_hex(cand).lower()
            if h in want and want[h] not in found:
                found[want[h]] = cand
        if len(found) == len(want):
            break
    return found


def _write_outfile(path, found):
    import os
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for target_line, plain in found.items():
            hexplain = binascii.hexlify(plain.encode("utf-8", "surrogateescape")).decode("ascii")
            f.write(target_line + ":" + hexplain + "\n")


def _emit_status(total, recovered):
    # One --status-json line so the agent's hashcatParser has parseable input.
    status = {
        "status": 5,
        "recovered_hashes": [recovered, total],
        "estimated_stop": int(time.time()) + 1,
        "devices": [{"speed": 1000000}],
    }
    print(json.dumps(status), flush=True)


VALUE_FLAGS = {"-m", "-w", "--session", "--potfile-path", "--outfile",
               "--outfile-format", "-a", "-r", "-j", "-k"}
FLAG_ONLY = {"-O", "--status", "--status-json", "--loopback", "--force"}


def parse_args(argv):
    mode, outfile, outfile_format, rules, positionals = 0, None, "1,3", [], []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a.startswith("--") and "=" in a:
            k, v = a.split("=", 1)
            if k == "--outfile-format":
                outfile_format = v
            i += 1
            continue
        if a in VALUE_FLAGS:
            v = argv[i + 1] if i + 1 < len(argv) else ""
            if a == "-m":
                mode = int(v)
            elif a == "--outfile":
                outfile = v
            elif a == "--outfile-format":
                outfile_format = v
            elif a == "-r":
                rules.append(v)
            i += 2
            continue
        if a in FLAG_ONLY or a.startswith("-"):
            i += 1
            continue
        positionals.append(a)
        i += 1
    return mode, outfile, outfile_format, rules, positionals


def main(argv):
    mode, outfile, _fmt, rules, positionals = parse_args(argv)
    if len(positionals) < 2:
        sys.stderr.write("hcshim: expected hashfile and wordlist positionals\n")
        return 1
    hashfile, wordlist = positionals[0], positionals[1]
    targets = _load_targets(hashfile)
    _emit_status(len(targets), 0)
    found = crack(mode, targets, wordlist, rules)
    if outfile:
        _write_outfile(outfile, found)
    _emit_status(len(targets), len(found))
    return 0
```

- [ ] **Step 4: Write the executable wrapper**

Create `tests/e2e/crack/shim/hashcat`:

```python
#!/usr/bin/env python3
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hcshim  # noqa: E402

sys.exit(hcshim.main(sys.argv[1:]))
```

Then: `chmod +x tests/e2e/crack/shim/hashcat`

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python -m pytest tests/unit/test_crack_shim.py -v`
Expected: PASS (5 tests).

- [ ] **Step 6: Commit**

```bash
git add tests/e2e/crack/shim/hcshim.py tests/e2e/crack/shim/hashcat tests/unit/test_crack_shim.py
git commit -m "test(e2e): add real-cracking hashcat shim (NTLM + rule engine)"
```

---

## Task 3: rockyou slicer + manifest generator (host)

**Files:**
- Create: `tests/e2e/crack/gen_slices.py`
- Test: `tests/unit/test_crack_gen_slices.py`

Behavior: pick `TARGETS_PER_TASK` random lines from rockyou for each of the two tasks; Task A targets are those words (plain), Task B *base* words are those words and its `target_plaintexts` are `base + "1"`. Each task's ~`SLICE_SIZE` slice is built from rockyou and guaranteed to contain that task's base words. Writes `sliceA.txt`, `sliceB.txt`, and `manifest.json` to an output dir.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_crack_gen_slices.py`:

```python
import importlib.util
import json
from pathlib import Path

GEN = Path(__file__).resolve().parents[1] / "e2e" / "crack" / "gen_slices.py"


def _load():
    spec = importlib.util.spec_from_file_location("gen_slices", GEN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_generate_builds_two_tasks_and_slices(tmp_path):
    gen = _load()
    rockyou = tmp_path / "rockyou.txt"
    rockyou.write_text("\n".join(f"word{i}" for i in range(500)) + "\n")
    out = tmp_path / "out"
    manifest = gen.generate(str(rockyou), str(out), targets_per_task=3, slice_size=100, seed=42)

    assert len(manifest["tasks"]) == 2
    a, b = manifest["tasks"]
    assert a["use_rule"] is False and b["use_rule"] is True
    assert manifest["rule_body"].strip() == "$1"
    assert len(a["target_plaintexts"]) == 3
    assert all(pt.endswith("1") for pt in b["target_plaintexts"])

    # Slice files exist, are bounded, and contain the needed base words.
    sa = Path(a["slice_host_path"]).read_text().splitlines()
    sb = Path(b["slice_host_path"]).read_text().splitlines()
    assert len(sa) <= 100 and len(sb) <= 100
    for pt in a["target_plaintexts"]:
        assert pt in sa
    for pt in b["target_plaintexts"]:
        assert pt[:-1] in sb        # base word (without the appended "1")


def test_manifest_is_json_serializable(tmp_path):
    gen = _load()
    rockyou = tmp_path / "rockyou.txt"
    rockyou.write_text("\n".join(f"w{i}" for i in range(200)) + "\n")
    out = tmp_path / "out"
    gen.generate(str(rockyou), str(out), targets_per_task=2, slice_size=50, seed=1)
    data = json.loads((out / "manifest.json").read_text())
    assert data["job_name"] == "e2e-crack-job"
    assert data["customer_id"] == 9001
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python -m pytest tests/unit/test_crack_gen_slices.py -v`
Expected: FAIL (no `gen_slices.py`).

- [ ] **Step 3: Write the generator**

Create `tests/e2e/crack/gen_slices.py`:

```python
"""Host-side: derive random rockyou targets and bounded wordlist slices, plus a
manifest the in-container seeder and the pytest verifier both read.

Reads rockyou from $ROCKYOU_PATH (or the path given to generate()). The two
agents/tasks: Task A is a plain dictionary attack; Task B is dictionary + a
'$1' rule, so its targets are <base>+"1" and the crack only succeeds if the
rule was synced and applied.
"""
import json
import os
import random
import sys

JOB_NAME = "e2e-crack-job"
CUSTOMER_ID = 9001
RULE_BODY = "$1\n"
RULE_SUFFIX = "1"
CONTAINER_SLICE_DIR = "/tmp/crack"        # where slices are cp'd inside the app container


def _read_lines(path):
    with open(path, "r", encoding="utf-8", errors="surrogateescape") as f:
        return [line.rstrip("\n") for line in f if line.strip()]


def _build_slice(pool, must_include, slice_size, rng):
    chosen = set(must_include)
    if len(pool) > slice_size:
        chosen.update(rng.sample(pool, slice_size - len(must_include)))
    else:
        chosen.update(pool)
    out = list(chosen)
    rng.shuffle(out)
    return out[:slice_size]


def generate(rockyou_path, out_dir, targets_per_task=3, slice_size=50000, seed=None):
    rng = random.Random(seed)
    os.makedirs(out_dir, exist_ok=True)
    pool = _read_lines(rockyou_path)
    if len(pool) < targets_per_task * 2:
        raise RuntimeError(f"rockyou at {rockyou_path} too small ({len(pool)} lines)")

    picks = rng.sample(pool, targets_per_task * 2)
    a_words = picks[:targets_per_task]
    b_base = picks[targets_per_task:]

    a_slice = _build_slice(pool, a_words, slice_size, rng)
    b_slice = _build_slice(pool, b_base, slice_size, rng)

    a_path = os.path.join(out_dir, "sliceA.txt")
    b_path = os.path.join(out_dir, "sliceB.txt")
    with open(a_path, "w", encoding="utf-8", errors="surrogateescape") as f:
        f.write("\n".join(a_slice) + "\n")
    with open(b_path, "w", encoding="utf-8", errors="surrogateescape") as f:
        f.write("\n".join(b_slice) + "\n")

    manifest = {
        "job_name": JOB_NAME,
        "customer_id": CUSTOMER_ID,
        "rule_body": RULE_BODY,
        "agents": [
            {"name": "e2e-agent-1", "uuid": "11111111-1111-1111-1111-111111111111"},
            {"name": "e2e-agent-2", "uuid": "22222222-2222-2222-2222-222222222222"},
        ],
        "tasks": [
            {
                "name": "e2e-crack-task-dict",
                "use_rule": False,
                "slice_host_path": a_path,
                "slice_container_path": os.path.join(CONTAINER_SLICE_DIR, "sliceA.txt"),
                "target_plaintexts": list(a_words),
            },
            {
                "name": "e2e-crack-task-rules",
                "use_rule": True,
                "slice_host_path": b_path,
                "slice_container_path": os.path.join(CONTAINER_SLICE_DIR, "sliceB.txt"),
                "target_plaintexts": [w + RULE_SUFFIX for w in b_base],
            },
        ],
    }
    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    return manifest


def main():
    rockyou = os.getenv("ROCKYOU_PATH")
    out_dir = os.getenv("CRACK_ARTIFACT_DIR", "tests/e2e/crack/.artifacts")
    if not rockyou or not os.path.exists(rockyou):
        print("gen_slices: ROCKYOU_PATH not set or file missing", file=sys.stderr)
        return 2
    generate(rockyou, out_dir)
    print(os.path.join(out_dir, "manifest.json"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/unit/test_crack_gen_slices.py -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add tests/e2e/crack/gen_slices.py tests/unit/test_crack_gen_slices.py
git commit -m "test(e2e): add rockyou slicer + manifest generator"
```

---

## Task 4: In-container DB seeder + verifier

**Files:**
- Create: `tests/e2e/crack/seed_crack_db.py`
- Create: `tests/e2e/crack/verify_crack.py`
- Test: `tests/unit/test_crack_seed_verify.py`

Both scripts run inside the `app` container with `PYTHONPATH=/` and `-w /` (same pattern as `tests/seed_e2e_db.py`). They build a Flask app from `hashview.config.Config`, bind `db`, and operate in an app context.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_crack_seed_verify.py`:

```python
import importlib.util
import json
from pathlib import Path

CRACK = Path(__file__).resolve().parents[1] / "e2e" / "crack"


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, CRACK / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _make_app(tmp_path):
    from flask import Flask
    from flask_bcrypt import Bcrypt
    from hashview.models import db
    app = Flask(__name__, root_path=str(tmp_path))
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{tmp_path/'t.db'}"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db.init_app(app)
    Bcrypt(app)
    for sub in ("control/wordlists", "control/rules", "control/tmp"):
        (tmp_path / sub).mkdir(parents=True, exist_ok=True)
    with app.app_context():
        db.create_all()
    return app


def _manifest(tmp_path):
    # NTLM("cat")=plain target ; base "dog" -> Task B target "dog1"
    a = tmp_path / "sliceA.txt"
    a.write_text("cat\nalpha\nbeta\n")
    b = tmp_path / "sliceB.txt"
    b.write_text("dog\ngamma\ndelta\n")
    return {
        "job_name": "e2e-crack-job",
        "customer_id": 9001,
        "rule_body": "$1\n",
        "agents": [
            {"name": "e2e-agent-1", "uuid": "11111111-1111-1111-1111-111111111111"},
            {"name": "e2e-agent-2", "uuid": "22222222-2222-2222-2222-222222222222"},
        ],
        "tasks": [
            {"name": "e2e-crack-task-dict", "use_rule": False,
             "slice_container_path": str(a), "target_plaintexts": ["cat"]},
            {"name": "e2e-crack-task-rules", "use_rule": True,
             "slice_container_path": str(b), "target_plaintexts": ["dog1"]},
        ],
    }


def test_seed_creates_full_job_and_authorizes_agents(tmp_path):
    seed = _load("seed_crack_db", "seed_crack_db.py")
    app = _make_app(tmp_path)
    manifest = _manifest(tmp_path)
    seed.seed(app, manifest)

    from hashview.models import (Agents, Hashes, JobTasks, Jobs, Rules,
                                 Tasks, Wordlists)
    with app.app_context():
        assert Wordlists.query.count() == 2
        assert Rules.query.count() == 1
        assert Hashes.query.count() == 2
        assert Tasks.query.count() == 2
        job = Jobs.query.filter_by(name="e2e-crack-job").first()
        assert job is not None and job.status == "Queued"
        jts = JobTasks.query.filter_by(job_id=job.id).all()
        assert len(jts) == 2
        assert all(jt.status == "Queued" for jt in jts)
        # Each command references the agent control paths the server built.
        cmds = " ".join(jt.command for jt in jts)
        assert "-m 1000" in cmds
        assert "control/hashes/hashfile_" in cmds
        assert "control/wordlists/" in cmds
        assert "-r control/rules/" in cmds            # Task B emits a rule
        agents = Agents.query.all()
        assert {a.uuid for a in agents} == {
            "11111111-1111-1111-1111-111111111111",
            "22222222-2222-2222-2222-222222222222",
        }
        assert all(a.status == "Authorized" for a in agents)


def test_seed_is_idempotent(tmp_path):
    seed = _load("seed_crack_db", "seed_crack_db.py")
    app = _make_app(tmp_path)
    manifest = _manifest(tmp_path)
    seed.seed(app, manifest)
    seed.seed(app, manifest)
    from hashview.models import Jobs
    with app.app_context():
        assert Jobs.query.filter_by(name="e2e-crack-job").count() == 1


def test_verify_dumps_state(tmp_path, capsys):
    seed = _load("seed_crack_db", "seed_crack_db.py")
    verify = _load("verify_crack", "verify_crack.py")
    app = _make_app(tmp_path)
    manifest = _manifest(tmp_path)
    seed.seed(app, manifest)
    state = verify.collect(app, "e2e-crack-job")
    assert state["job_status"] == "Queued"
    assert len(state["job_tasks"]) == 2
    assert len(state["hashes"]) == 2
    assert all(h["cracked"] is False for h in state["hashes"])
    # JSON-printable
    json.dumps(state)
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python -m pytest tests/unit/test_crack_seed_verify.py -v`
Expected: FAIL (no `seed_crack_db.py` / `verify_crack.py`).

- [ ] **Step 3: Write the seeder**

Create `tests/e2e/crack/seed_crack_db.py`:

```python
"""In-container seeder for the multi-agent crack e2e test. Idempotent.

Builds the full job the agents will execute and authorizes both agents:
  user(id=1) + Settings + Customer + 2 static wordlists (the rockyou slices) +
  1 rule + 1 hashfile with NTLM hashes of every target + 2 tasks (A: dict,
  B: dict+rule) + 1 job (Queued) + 2 job_tasks (Queued, command built) +
  2 Authorized agents.

Run inside the app container:  PYTHONPATH=/ python /tmp/seed_crack_db.py /tmp/crack/manifest.json
"""
import json
import os
import secrets
import sys

from flask import Flask
from flask_bcrypt import Bcrypt

from hashview.config import Config
from hashview.models import (Agents, Customers, HashfileHashes, Hashes,
                             Hashfiles, JobTasks, Jobs, Rules, Settings, Tasks,
                             Users, Wordlists, db)
from hashview.utils.utils import (build_hashcat_command, get_filehash,
                                  get_linecount, get_md5_hash,
                                  ingest_static_wordlist_file, ntlm_hash_hex)


def build_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    Bcrypt(app)
    return app


def _ensure_admin(app):
    admin = db.session.get(Users, 1)
    if admin is None:
        bcrypt = Bcrypt(app)
        admin = Users(
            id=1, first_name="E2E", last_name="Crack",
            email_address="e2e-crack@example.com",
            password=bcrypt.generate_password_hash("e2e-crack-pw").decode("utf-8"),
            admin=True,
        )
        db.session.add(admin)
    if db.session.query(Settings).first() is None:
        db.session.add(Settings(retention_period=0, max_runtime_jobs=0, max_runtime_tasks=0))
    db.session.flush()
    return admin


def seed(app, manifest):
    with app.app_context():
        # Idempotency: if the job already exists, only (re)authorize agents and return.
        existing = Jobs.query.filter_by(name=manifest["job_name"]).first()
        if existing is not None:
            _authorize_agents(manifest)
            db.session.commit()
            return

        admin = _ensure_admin(app)
        customer_id = manifest["customer_id"]
        if db.session.get(Customers, customer_id) is None:
            db.session.add(Customers(id=customer_id, name="E2E Crack Customer"))

        # Rule (plaintext at rest; checksum over plaintext — matches rules_add).
        rules_dir = os.path.join(app.root_path, "control/rules")
        os.makedirs(rules_dir, exist_ok=True)
        rule_path = os.path.join(rules_dir, secrets.token_hex(8) + ".txt")
        with open(rule_path, "w", encoding="utf-8") as f:
            f.write(manifest["rule_body"])
        rule = Rules(name="e2e-crack-rule", owner_id=admin.id, path=rule_path,
                     size=get_linecount(rule_path), checksum=get_filehash(rule_path))
        db.session.add(rule)
        db.session.flush()

        # Hashfile shared by both tasks.
        hashfile = Hashfiles(name="e2e-crack-hashfile", customer_id=customer_id,
                             owner_id=admin.id)
        db.session.add(hashfile)
        db.session.flush()

        job = Jobs(name=manifest["job_name"], status="Queued", customer_id=customer_id,
                   hashfile_id=hashfile.id, owner_id=admin.id)
        db.session.add(job)
        db.session.flush()

        for t in manifest["tasks"]:
            # Wordlist (ingest the slice exactly like a UI upload -> correct checksum/type).
            wl = ingest_static_wordlist_file(t["slice_container_path"], admin.id, t["name"] + "-wl")
            db.session.add(wl)
            db.session.flush()

            # NTLM hashes for this task's targets, attached to the shared hashfile.
            for pt in t["target_plaintexts"]:
                ciphertext = ntlm_hash_hex(pt)           # uppercase hex
                h = Hashes(hash_type=1000, ciphertext=ciphertext,
                           sub_ciphertext=get_md5_hash(ciphertext), cracked=0)
                db.session.add(h)
                db.session.flush()
                db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hashfile.id,
                                              username=t["name"]))

            task = Tasks(name=t["name"], hc_attackmode=0, owner_id=admin.id,
                         wl_id=wl.id, rule_id=(rule.id if t["use_rule"] else None),
                         loopback=False)
            db.session.add(task)
            db.session.flush()

            jt = JobTasks(job_id=job.id, task_id=task.id, status="Queued", priority=3)
            db.session.add(jt)
            db.session.flush()
            jt.command = build_hashcat_command(job.id, task.id)

        _authorize_agents(manifest)
        db.session.commit()


def _authorize_agents(manifest):
    for a in manifest["agents"]:
        agent = Agents.query.filter_by(uuid=a["uuid"]).first()
        if agent is None:
            db.session.add(Agents(name=a["name"], uuid=a["uuid"], src_ip="0.0.0.0",
                                  status="Authorized"))
        else:
            agent.status = "Authorized"
            agent.name = a["name"]


def main():
    if len(sys.argv) < 2:
        print("usage: seed_crack_db.py <manifest.json>", file=sys.stderr)
        return 2
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        manifest = json.load(f)
    seed(build_app(), manifest)
    print("seed_crack_db: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Write the verifier**

Create `tests/e2e/crack/verify_crack.py`:

```python
"""In-container verifier: dump the crack job's DB state as JSON for the pytest
poll loop. Run:  PYTHONPATH=/ python /tmp/verify_crack.py <job_name>
"""
import json
import sys

from flask import Flask
from flask_bcrypt import Bcrypt

from hashview.config import Config
from hashview.models import (HashfileHashes, Hashes, JobTasks, Jobs, db)


def build_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    Bcrypt(app)
    return app


def collect(app, job_name):
    with app.app_context():
        job = Jobs.query.filter_by(name=job_name).first()
        if job is None:
            return {"job_status": None, "job_tasks": [], "hashes": []}
        job_tasks = [
            {"id": jt.id, "task_id": jt.task_id, "status": jt.status, "agent_id": jt.agent_id}
            for jt in JobTasks.query.filter_by(job_id=job.id).all()
        ]
        rows = (db.session.query(Hashes)
                .join(HashfileHashes, Hashes.id == HashfileHashes.hash_id)
                .filter(HashfileHashes.hashfile_id == job.hashfile_id).all())
        hashes = [
            {"sub_ciphertext": h.sub_ciphertext, "cracked": bool(h.cracked),
             "plaintext": h.plaintext, "task_id": h.task_id}
            for h in rows
        ]
        return {"job_status": job.status, "job_tasks": job_tasks, "hashes": hashes}


def main():
    job_name = sys.argv[1] if len(sys.argv) > 1 else "e2e-crack-job"
    print(json.dumps(collect(build_app(), job_name)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python -m pytest tests/unit/test_crack_seed_verify.py -v`
Expected: PASS (3 tests).

- [ ] **Step 6: Commit**

```bash
git add tests/e2e/crack/seed_crack_db.py tests/e2e/crack/verify_crack.py tests/unit/test_crack_seed_verify.py
git commit -m "test(e2e): add in-container crack-job seeder and verifier"
```

---

## Task 5: Agent Docker image + entrypoint

**Files:**
- Create: `tests/e2e/crack/agent-entrypoint.sh`
- Create: `Dockerfile.agent`

- [ ] **Step 1: Write the entrypoint**

Create `tests/e2e/crack/agent-entrypoint.sh`:

```sh
#!/usr/bin/env sh
# Non-interactive agent bootstrap for the e2e crack test: write agent/config.conf
# from env vars (bypassing hashview-agent.py's interactive first-run setup), then
# run the real agent. CWD is /agent (WORKDIR), where VERSION.TXT + agent/ live.
set -e

mkdir -p agent control/tmp control/hashes control/outfiles control/wordlists control/rules

cat > agent/config.conf <<EOF
[HASHVIEW]
server = ${HASHVIEW_SERVER}
port = ${HASHVIEW_PORT}
use_ssl = ${USE_SSL:-False}

[AGENT]
name = ${NAME}
uuid = ${UUID}
HC_BIN_PATH = ${HC_BIN_PATH}
EOF

exec python hashview-agent.py
```

- [ ] **Step 2: Write the Dockerfile**

Create `Dockerfile.agent`:

```dockerfile
# syntax=docker/dockerfile:1
# Agent image for the multi-agent crack e2e test: the real hashview agent plus a
# real-cracking hashcat shim (no GPU/engine). Used only by docker-compose.e2e.yml.
FROM python:3.8-slim
WORKDIR /agent

# gzip + coreutils: the agent shells out to `gunzip` / `mv` during rules sync.
RUN apt-get update \
    && apt-get install -y --no-install-recommends gzip coreutils \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir requests psutil

# Real agent code (includes its own agent/ package + control/ dirs).
COPY install/hashview-agent/ /agent/

# Real-cracking shim; HC_BIN_PATH points here.
COPY tests/e2e/crack/shim/ /opt/hcshim/
RUN chmod +x /opt/hcshim/hashcat

COPY tests/e2e/crack/agent-entrypoint.sh /agent-entrypoint.sh
RUN chmod +x /agent-entrypoint.sh

# VERSION.TXT must be >= the server's __version__ or the server returns 426.
# Derive it from the server package so the two never drift.
COPY hashview/__init__.py /tmp/hv_init.py
RUN python -c "import re,sys; m=re.search(r'__version__\s*=\s*[\'\"]([^\'\"]+)', open('/tmp/hv_init.py').read()); open('/agent/VERSION.TXT','w').write(m.group(1)+'\n')"

RUN mkdir -p control/tmp control/hashes control/outfiles control/wordlists control/rules

ENTRYPOINT ["/agent-entrypoint.sh"]
```

- [ ] **Step 3: Verify the image builds**

Run: `docker build -f Dockerfile.agent -t hashview-agent-e2e .`
Expected: builds successfully; final image tagged.

- [ ] **Step 4: Verify VERSION.TXT was derived**

Run: `docker run --rm --entrypoint cat hashview-agent-e2e /agent/VERSION.TXT`
Expected: prints the same version string as `python -c "import hashview; print(hashview.__version__)"`.

- [ ] **Step 5: Commit**

```bash
git add Dockerfile.agent tests/e2e/crack/agent-entrypoint.sh
git commit -m "test(e2e): add agent Docker image with real-cracking shim"
```

---

## Task 6: Compose overlay for the two agents

**Files:**
- Create: `docker-compose.e2e.yml`

- [ ] **Step 1: Write the compose overlay**

Create `docker-compose.e2e.yml` (used together with the base file: `-f docker-compose.yml -f docker-compose.e2e.yml`):

```yaml
# Overlay adding two real agents for the crack e2e test. The UUIDs/names MUST
# match tests/e2e/crack/gen_slices.py manifest "agents" (the seeder authorizes
# exactly these UUIDs).
services:
  agent1:
    build:
      context: .
      dockerfile: Dockerfile.agent
    platform: ${DOCKER_PLATFORM:-linux/amd64}
    environment:
      HASHVIEW_SERVER: app
      HASHVIEW_PORT: "5000"
      USE_SSL: "False"
      NAME: e2e-agent-1
      UUID: 11111111-1111-1111-1111-111111111111
      HC_BIN_PATH: /opt/hcshim/hashcat
    depends_on:
      app:
        condition: service_started

  agent2:
    build:
      context: .
      dockerfile: Dockerfile.agent
    platform: ${DOCKER_PLATFORM:-linux/amd64}
    environment:
      HASHVIEW_SERVER: app
      HASHVIEW_PORT: "5000"
      USE_SSL: "False"
      NAME: e2e-agent-2
      UUID: 22222222-2222-2222-2222-222222222222
      HC_BIN_PATH: /opt/hcshim/hashcat
    depends_on:
      app:
        condition: service_started
```

- [ ] **Step 2: Validate the merged compose config**

Run: `docker compose -f docker-compose.yml -f docker-compose.e2e.yml config`
Expected: prints merged config including `agent1`, `agent2`, `app`, `db` (no errors).

- [ ] **Step 3: Commit**

```bash
git add docker-compose.e2e.yml
git commit -m "test(e2e): add compose overlay for two crack agents"
```

---

## Task 7: Orchestrator script

**Files:**
- Create: `tests/run_e2e_crack_compose.sh`

This mirrors `tests/run_e2e_compose.sh`: write `hashview/config.conf`, build the host venv, generate slices, bring up `db`+`app`, seed (which also authorizes agents), bring up `agent1`+`agent2`, run `pytest -m e2e_crack`, then tear down. It exports `HASHVIEW_E2E_CRACK_MANIFEST` and `HASHVIEW_E2E_CRACK_COMPOSE` for the test.

- [ ] **Step 1: Write the orchestrator**

Create `tests/run_e2e_crack_compose.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export DOCKER_PLATFORM="${DOCKER_PLATFORM:-linux/amd64}"
COMPOSE="${COMPOSE_BIN:-docker compose} -f docker-compose.yml -f docker-compose.e2e.yml"
BASE_URL="${HASHVIEW_E2E_BASE_URL:-http://127.0.0.1:5000}"
KEEP="${HASHVIEW_E2E_KEEP_CONTAINERS:-0}"
ARTIFACTS="$ROOT_DIR/tests/e2e/crack/.artifacts"

if [ -z "${ROCKYOU_PATH:-}" ] || [ ! -f "${ROCKYOU_PATH:-}" ]; then
  echo "ROCKYOU_PATH not set or file missing; set it to a rockyou wordlist to run this test." >&2
  exit 2
fi

# Server config (matches docker-compose.yml db credentials).
if [ ! -f hashview/config.conf ]; then
  cat > hashview/config.conf <<'EOF'
[SERVER]
SERVER_NAME = 127.0.0.1:5000
SECRET_KEY = e2e-crack-secret-key

[database]
host = db
username = hashview
password = hashview

[SMTP]
server = smtp.example.com
port = 25
use_tls = False
username =
password =
default_sender =
EOF
fi

if [ ! -x .venv/bin/python ]; then
  python3 -m venv .venv
  ./.venv/bin/pip install -r requirements-dev.txt
fi

echo "Generating rockyou slices + manifest..."
rm -rf "$ARTIFACTS"
CRACK_ARTIFACT_DIR="$ARTIFACTS" ./.venv/bin/python tests/e2e/crack/gen_slices.py
MANIFEST="$ARTIFACTS/manifest.json"

echo "Building + starting db and app..."
$COMPOSE up -d --build app

cleanup() {
  if [ "$KEEP" = "1" ]; then
    echo "Keeping containers (HASHVIEW_E2E_KEEP_CONTAINERS=1)."
  else
    $COMPOSE down -v
  fi
}
trap cleanup EXIT

echo "Waiting for app at $BASE_URL ..."
for _ in {1..60}; do
  curl -fsS "$BASE_URL/login" >/dev/null 2>&1 && { echo "App up."; break; }
  sleep 2
done
if ! curl -fsS "$BASE_URL/login" >/dev/null 2>&1; then
  echo "App did not become ready."; $COMPOSE logs --tail 200 app; exit 1
fi

echo "Seeding crack job + authorizing agents..."
$COMPOSE cp tests/e2e/crack/seed_crack_db.py app:/tmp/seed_crack_db.py
$COMPOSE cp tests/e2e/crack/verify_crack.py app:/tmp/verify_crack.py
$COMPOSE exec -T app mkdir -p /tmp/crack
$COMPOSE cp "$ARTIFACTS/sliceA.txt" app:/tmp/crack/sliceA.txt
$COMPOSE cp "$ARTIFACTS/sliceB.txt" app:/tmp/crack/sliceB.txt
$COMPOSE cp "$MANIFEST" app:/tmp/crack/manifest.json
$COMPOSE exec -T -e PYTHONPATH=/ -w / app python /tmp/seed_crack_db.py /tmp/crack/manifest.json

echo "Starting agents..."
$COMPOSE up -d --build agent1 agent2

echo "Running pytest -m e2e_crack ..."
set +e
HASHVIEW_E2E_CRACK_MANIFEST="$MANIFEST" \
HASHVIEW_E2E_CRACK_COMPOSE="$COMPOSE" \
  ./.venv/bin/python -m pytest -m e2e_crack tests/e2e/test_multiagent_ntlm_crack.py -vv -s
EXIT=$?
set -e

if [ "$EXIT" -ne 0 ]; then
  echo "--- app logs ---";    $COMPOSE logs --tail 100 app
  echo "--- agent1 logs ---"; $COMPOSE logs --tail 100 agent1
  echo "--- agent2 logs ---"; $COMPOSE logs --tail 100 agent2
fi
exit "$EXIT"
```

- [ ] **Step 2: Make it executable**

Run: `chmod +x tests/run_e2e_crack_compose.sh`

- [ ] **Step 3: Commit**

```bash
git add tests/run_e2e_crack_compose.sh
git commit -m "test(e2e): add crack e2e orchestrator script"
```

---

## Task 8: The pytest e2e test

**Files:**
- Create: `tests/e2e/test_multiagent_ntlm_crack.py`

The test is thin: it polls the in-container verifier (via `docker compose exec`) and asserts the end state. It is skipped unless the orchestrator set `HASHVIEW_E2E_CRACK_MANIFEST` and `HASHVIEW_E2E_CRACK_COMPOSE`.

- [ ] **Step 1: Write the test**

Create `tests/e2e/test_multiagent_ntlm_crack.py`:

```python
import json
import os
import shlex
import subprocess
import time

import pytest

POLL_SECONDS = 5
DEADLINE_SECONDS = 240


def _verify(compose, job_name):
    """Run the in-container verifier and return its parsed JSON state."""
    cmd = shlex.split(compose) + [
        "exec", "-T", "-e", "PYTHONPATH=/", "-w", "/", "app",
        "python", "/tmp/verify_crack.py", job_name,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    # The verifier prints exactly one JSON line on stdout.
    line = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
    if not line:
        raise AssertionError(f"verifier produced no output: {proc.stderr}")
    return json.loads(line)


@pytest.mark.e2e_crack
def test_two_agents_really_crack_ntlm_job():
    manifest_path = os.getenv("HASHVIEW_E2E_CRACK_MANIFEST")
    compose = os.getenv("HASHVIEW_E2E_CRACK_COMPOSE")
    if not manifest_path or not compose:
        pytest.skip("Run via tests/run_e2e_crack_compose.sh (sets manifest + compose env).")

    manifest = json.loads(open(manifest_path).read())
    job_name = manifest["job_name"]
    expected_plaintexts = {pt for t in manifest["tasks"] for pt in t["target_plaintexts"]}

    state = None
    deadline = time.time() + DEADLINE_SECONDS
    while time.time() < deadline:
        state = _verify(compose, job_name)
        done = (state["job_status"] == "Completed"
                and state["hashes"]
                and all(h["cracked"] for h in state["hashes"]))
        if done:
            break
        time.sleep(POLL_SECONDS)

    assert state is not None, "verifier never returned state"

    # 1. Every target hash recovered with the EXACT chosen plaintext.
    cracked = {h["plaintext"] for h in state["hashes"] if h["cracked"]}
    assert cracked == expected_plaintexts, (
        f"recovered {cracked!r}, expected {expected_plaintexts!r}; state={state}")

    # 2. Job + both job_tasks Completed.
    assert state["job_status"] == "Completed", state
    assert len(state["job_tasks"]) == 2, state
    assert all(jt["status"] == "Completed" for jt in state["job_tasks"]), state

    # 3. Real concurrent distribution: two DISTINCT agents, neither None.
    agent_ids = {jt["agent_id"] for jt in state["job_tasks"]}
    assert len(agent_ids) == 2 and None not in agent_ids, (
        f"expected two distinct agent_ids, got {agent_ids}; state={state}")

    # 4. Per-task attribution: each task's targets recovered under that task's id.
    task_ids = {jt["task_id"] for jt in state["job_tasks"]}
    recovered_task_ids = {h["task_id"] for h in state["hashes"] if h["cracked"]}
    assert recovered_task_ids == task_ids, (
        f"recovered task_ids {recovered_task_ids} != job task_ids {task_ids}; state={state}")
```

- [ ] **Step 2: Verify it is collected and skips cleanly without the env**

Run: `python -m pytest tests/e2e/test_multiagent_ntlm_crack.py -m e2e_crack -v`
Expected: 1 skipped (message: "Run via tests/run_e2e_crack_compose.sh ...").

- [ ] **Step 3: Commit**

```bash
git add tests/e2e/test_multiagent_ntlm_crack.py
git commit -m "test(e2e): add multi-agent NTLM crack assertions"
```

---

## Task 9: Full stack run + docs

**Files:**
- Create: `tests/e2e/crack/README.md`

- [ ] **Step 1: Run the entire flow end-to-end**

Run: `ROCKYOU_PATH=/path/to/rockyou.txt ./tests/run_e2e_crack_compose.sh`
Expected: builds images, starts db/app, seeds, starts both agents, and `pytest -m e2e_crack` reports `1 passed`. (If hashcat-style timing is slow, the 240s deadline still covers two ~50k pure-Python NTLM scans, which complete in a few seconds each.)

- [ ] **Step 2: If it fails, debug with systematic-debugging**

Common failure points to check first:
- Agent killed early → something wrote to stderr. Inspect `docker compose ... logs agent1`. The shim must be silent on stderr.
- Hashes never crack → ciphertext case mismatch between seeded `Hashes.ciphertext` and the shim's echoed target line, or wordlist `.gz` filename mismatch. Confirm the served hashfile lines equal the seeded ciphertext.
- Only one agent gets work → the second `Queued` job_task wasn't created, or both agents share a UUID. Confirm two `job_tasks` are `Queued` after seeding (`verify_crack.py`).
- 426 from server → agent `VERSION.TXT` < server `__version__`. Re-check the Dockerfile derivation step.

- [ ] **Step 3: Write the README**

Create `tests/e2e/crack/README.md`:

```markdown
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
```

- [ ] **Step 4: Commit**

```bash
git add tests/e2e/crack/README.md
git commit -m "docs(e2e): document the multi-agent crack e2e test"
```

---

## Self-Review (completed during authoring)

- **Spec coverage:** shim real-crack + pure MD4 (Task 2) ✓; minimal rule engine (Task 2) ✓; 2 agents + 2 queued tasks + distinct-agent assertion (Tasks 6, 8) ✓; wordlist sync exercised via server-built `.gz` path (Tasks 4, 5) ✓; rules sync exercised + proven by ruled targets (Tasks 3, 4, 8) ✓; rockyou random targets + ~50k slice (Task 3) ✓; opt-in `e2e_crack` marker excluded from default suite (Tasks 1, 8) ✓; exact-plaintext + per-task verification (Task 8) ✓; non-deterministic assignment handled by querying `agent_id` at verify time (Task 8) ✓; rockyou-missing → clean skip/exit (Tasks 3, 7) ✓.
- **Placeholder scan:** none — every step has full code or an exact command.
- **Type/name consistency:** `seed(app, manifest)` / `collect(app, job_name)` / `generate(...)` / `parse_args`/`crack`/`apply_rule`/`ntlm_hex` signatures match across their unit tests and call sites; manifest keys (`job_name`, `customer_id`, `rule_body`, `agents[].uuid/name`, `tasks[].use_rule/slice_container_path/target_plaintexts`) are identical in `gen_slices.py`, `seed_crack_db.py`, the orchestrator, and the test; fixed UUIDs match between `docker-compose.e2e.yml` and the generated manifest.
```
