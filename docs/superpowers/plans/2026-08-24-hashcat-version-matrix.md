# hashcat Version Interoperability CI — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detect when a new hashcat release changes the machine-readable output or flag semantics Hashview depends on, before it reaches an operator.

**Architecture:** Three tiers. Tier 1 runs Hashview's real parsers over committed golden fixtures on every PR (fast, offline). Tier 2 downloads pinned hashcat releases in CI, captures fresh artifacts from the real binary, and runs the same assertions plus a live `--skip`/`--limit` slice check. Tier 3 does the same for any release newer than the pinned matrix and files a GitHub issue instead of failing.

**Tech Stack:** Python 3.11+, pytest, bash, GitHub Actions, pocl (CPU OpenCL runtime), p7zip.

**Spec:** `docs/superpowers/specs/2026-08-24-hashcat-version-matrix-design.md`

## Global Constraints

- Work happens in the worktree `/tmp/hashview-hashcat-matrix` on branch `ci/hashcat-version-matrix`. Verify with `git rev-parse --abbrev-ref HEAD` before every commit.
- Python floor is 3.11 (matches `setup.py`); the unit matrix is 3.11 / 3.12 / 3.13.
- `unit-tests.yml` enforces two coverage ratchets: `--cov=hashview --cov-fail-under=85` over `tests/unit tests/security tests/agent_unit`, and `--cov=agent --cov-fail-under=75` over `tests/agent_unit`. Never lower either. Any new file under `install/hashview-agent/agent/` must be exercised by a test in `tests/agent_unit/` or the agent ratchet will fall.
- `tests/check_function_coverage.py` fails if any function in `hashview/` has zero executed body lines.
- No real or client-derived hashes, wordlists, plaintexts, hostnames, or IPs in fixtures or scripts. All test data is synthetic.
- The agent must never write to stderr on the happy path; `run_hashcat` treats stderr output as fatal.
- Pinned hashcat versions and their release-archive SHA-256 sums (verified 2026-08-24):

  | Version | SHA-256 of `hashcat-<v>.7z` |
  |---|---|
  | 6.2.6 | `96697e9ef6a795d45863c91d61be85a9f138596e3151e7c2cd63ccf48aaa8783` |
  | 7.0.0 | `19e126642e1db7902125072dce539c53485c721735325a747bd03e8af3135d78` |
  | 7.1.0 | `37be13b2dfdd1da7a3f68847ff817a22c144fc8d76170f51aae412e8b3ee24fd` |
  | 7.1.1 | `e09f88233ae8a88e0e60d68c20e4f5094d9122af533a7d186a45d8d55d08f3a0` |
  | 7.1.2 | `80db0316387794ce9d14ed376da75b8a7742972485b45db790f5f8260307ff98` |

- Release archive URL: `https://github.com/hashcat/hashcat/releases/download/v<version>/hashcat-<version>.7z`, unpacking to a `hashcat-<version>/` directory containing `hashcat.bin`.
- The single synthetic test hash is NTLM (mode 1000) of the plaintext `password`: `8846f7eaee8fb117ad06bdd830b7586c`.

---

## File Structure

| Path | Responsibility |
|---|---|
| `install/hashview-agent/agent/status.py` | **Create.** Dependency-free parsing of hashcat `--status-json` output into the agent's status dict. Extracted verbatim from `hashview-agent.py`. |
| `install/hashview-agent/hashview-agent.py` | **Modify.** Import the three moved functions from `agent.status` instead of defining them. |
| `tests/agent_unit/test_agent_status.py` | **Create.** Unit tests for the extracted parser (synthetic input, no fixtures). Carries the `--cov=agent` credit for `status.py`. |
| `tests/hashcat_matrix/fetch.sh` | **Create.** Download + checksum-verify + unpack one release. |
| `tests/hashcat_matrix/capture.sh` | **Create.** Run a hashcat binary and emit the five artifacts. |
| `tests/hashcat_matrix/summarize.py` | **Create.** Reduce a capture directory to a volatile-free `summary.json` for diffing. |
| `tests/hashcat_matrix/test_chunk_coverage.py` | **Create.** Tier 2 only: live `--skip`/`--limit` slice semantics. |
| `tests/fixtures/hashcat/<version>/` | **Create.** Committed captures for the five pinned versions. |
| `tests/agent_unit/test_hashcat_contract.py` | **Create.** Tier 1: the five contract assertions over every committed fixture. |
| `.github/workflows/hashcat-matrix.yml` | **Create.** Tiers 2 and 3. |
| `pytest.ini` | **Modify.** Register the `hashcat_matrix` marker. |
| `TESTING.md`, `CHANGELOG.md` | **Modify.** Document the new job and how to refresh fixtures. |

Task 1 is a prerequisite for Task 3 (the contract test needs an importable parser). Tasks 2 and 4 are independent of each other. Task 5 depends on 2, 3, and 4.

---

### Task 1: Extract the hashcat status parser into `agent/status.py`

`hashcatParser` currently lives in `install/hashview-agent/hashview-agent.py`, which runs `argparse.ArgumentParser().parse_args()` at import time and imports `psutil`. That makes it impossible to import from a test. `agent/bench.py` already establishes the pattern for dependency-free, unit-testable agent parsers; this task moves the status parsing alongside it.

This is a pure move. Do not change behaviour, messages, or return values.

**Files:**
- Create: `install/hashview-agent/agent/status.py`
- Modify: `install/hashview-agent/hashview-agent.py` (remove `time_difference` at line 533, `convert_speed` at 573, `hashcatParser` at 583; add an import)
- Test: `tests/agent_unit/test_agent_status.py`

**Interfaces:**
- Consumes: `agent.bench.parse_device_info(json_data) -> (gpu_count, gpu_model, temps_csv)`
- Produces:
  - `agent.status.time_difference(future_timestamp) -> str`
  - `agent.status.convert_speed(speed) -> str`
  - `agent.status.hashcat_status(filepath) -> dict` — the moved `hashcatParser` body, renamed to snake_case for the new module. `hashview-agent.py` keeps calling it as `hashcatParser` via an aliased import so its call site at line 712 is untouched.

- [ ] **Step 1: Write the failing test**

Create `tests/agent_unit/test_agent_status.py`:

```python
"""Unit tests for the agent-side hashcat --status-json parser
(install/hashview-agent/agent/status.py).

status.py is dependency-free (json/logging/datetime + agent.bench) so it can be
imported without pulling in the agent script's argparse side effects. The
agent_unit conftest puts the agent root on sys.path and stubs agent.config.
"""
import json

from agent.status import convert_speed, hashcat_status, time_difference


def _write_status(tmp_path, obj, prefix_noise=True):
    path = tmp_path / "hc.out"
    lines = []
    if prefix_noise:
        # hashcat prints a banner and progress text around the JSON lines; the
        # parser must skip anything that does not start with '{'.
        lines.append("hashcat (v7.1.2) starting")
        lines.append("")
    lines.append(json.dumps(obj))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(path)


def _status_obj(**overrides):
    obj = {
        "status": 3,
        "recovered_hashes": [1, 4],
        "estimated_stop": 4102444800,   # 2100-01-01, always in the future
        "devices": [
            {"device_id": 1, "device_name": "NVIDIA GeForce RTX 4090",
             "device_type": "GPU", "speed": 1500000000, "temp": 71},
            {"device_id": 2, "device_name": "NVIDIA GeForce RTX 4090",
             "device_type": "GPU", "speed": 1500000000, "temp": 70},
        ],
    }
    obj.update(overrides)
    return obj


def test_hashcat_status_maps_a_full_status_line(tmp_path):
    status = hashcat_status(_write_status(tmp_path, _status_obj()))
    assert status["Recovered"] == "1/4"
    assert status["Speed #"] == "3.0 GH/s"
    assert status["GPU_Count"] == 2
    assert status["GPU_Model"] == "RTX 4090"
    assert status["Temps"] == "71,70"
    assert status["Time_Estimated"].startswith("(") and status["Time_Estimated"].endswith(")")


def test_hashcat_status_skips_unparseable_lines_and_keeps_the_last_good_one(tmp_path):
    path = tmp_path / "hc.out"
    good = json.dumps(_status_obj(recovered_hashes=[1, 4]))
    later = json.dumps(_status_obj(recovered_hashes=[3, 4]))
    # A truncated line (hashcat is still writing) between two good ones.
    path.write_text(good + "\n" + '{"status": 3, "recov' + "\n" + later + "\n",
                    encoding="utf-8")
    status = hashcat_status(str(path))
    assert status["Recovered"] == "3/4"


def test_hashcat_status_returns_empty_when_no_json_lines(tmp_path):
    path = tmp_path / "hc.out"
    path.write_text("hashcat (v7.1.2) starting\nNo hashes loaded.\n", encoding="utf-8")
    assert hashcat_status(str(path)) == {}


def test_hashcat_status_tolerates_non_utf8_bytes(tmp_path):
    path = tmp_path / "hc.out"
    payload = json.dumps(_status_obj()).encode("utf-8")
    path.write_bytes(b"Recovered candidate: \xff\xfe\n" + payload + b"\n")
    assert hashcat_status(str(path))["Recovered"] == "1/4"


def test_time_difference_reports_a_past_timestamp():
    assert time_difference(0) == "The specified time is in the past."


def test_convert_speed_scales_units():
    assert convert_speed(500) == "500 H/s"
    assert convert_speed(1_500_000) == "1.5 MH/s"
    assert convert_speed(2_500_000_000) == "2.5 GH/s"
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /tmp/hashview-hashcat-matrix
python -m pytest tests/agent_unit/test_agent_status.py -q
```

Expected: collection error — `ModuleNotFoundError: No module named 'agent.status'`.

- [ ] **Step 3: Create `install/hashview-agent/agent/status.py`**

Copy the bodies of `time_difference`, `convert_speed`, and `hashcatParser` out of `hashview-agent.py` unchanged. The only edits are the function rename (`hashcatParser` → `hashcat_status`) and a module-level logger, because the script's `LOG` global is not available here.

```python
"""hashcat --status-json output parsing.

Kept dependency-free (json / logging / datetime plus agent.bench) so it is
unit-testable on its own, like agent/bench.py. The agent's status poll tees
hashcat's stdout to a file and feeds the path here.

Extracted verbatim from hashview-agent.py so the parser can be exercised
against real output captured from multiple hashcat releases
(tests/fixtures/hashcat, .github/workflows/hashcat-matrix.yml).
"""
import json
import logging
from datetime import datetime

LOG = logging.getLogger('hashview-agent')


def time_difference(future_timestamp):
    """Humanise the gap between now and a future epoch timestamp, to the two
    largest non-zero units (e.g. '2 days, 3 hours')."""
    delta = datetime.fromtimestamp(future_timestamp) - datetime.now()

    if delta.total_seconds() < 0:
        return "The specified time is in the past."

    years = delta.days // 365
    months = (delta.days % 365) // 30
    days = (delta.days % 365) % 30
    hours, remainder = divmod(delta.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)

    components = [
        (years, "year"),
        (months, "month"),
        (days, "day"),
        (hours, "hour"),
        (minutes, "minute"),
        (seconds, "second")
    ]

    components = [(value, name) for value, name in components if value > 0]

    if len(components) == 0:
        return "The specified time is very close to now."
    elif len(components) == 1:
        return f"{components[0][0]} {components[0][1]}{'s' if components[0][0] > 1 else ''}"

    largest_two = components[:2]
    return ', '.join(f"{value} {name}{'s' if value > 1 else ''}" for value, name in largest_two)


def convert_speed(speed):
    """Render a raw hashes/sec integer as a human unit string."""
    if speed > 1000000000:
        return str(round((speed / 1000000000), 1)) + " GH/s"
    elif speed > 1000000:
        return str(round((speed / 1000000), 1)) + " MH/s"
    elif speed > 1000:
        return str(round((speed / 1000), 1)) + " KH/s"
    else:
        return str(speed) + " H/s"


def hashcat_status(filepath):
    """Parse a tee'd hashcat stdout file into the agent's status dict.

    Returns {} when the file holds no parseable --status-json line.
    """
    from agent.bench import parse_device_info
    status = {}
    # hashcat's stdout can contain arbitrary non-UTF-8 bytes (recovered plaintext
    # / candidate bytes). We only need the ASCII --status-json lines, so decode
    # tolerantly (errors='replace') instead of crashing on a stray byte.
    with open(filepath, 'r', encoding='utf-8', errors='replace') as hashcat_output:
        for line in hashcat_output:
            # Iterate the whole file; the last valid status line wins. We read this
            # while hashcat is still writing it (via tee), so a line can be partial
            # or malformed -- skip those rather than aborting the status poll.
            if not line.startswith('{'):
                continue
            try:
                json_data = json.loads(line)
                status['Time_Estimated'] = "(" + time_difference(json_data['estimated_stop']) + ")"
                status['Recovered'] = (str(json_data['recovered_hashes'][0]) + "/"
                                       + str(json_data['recovered_hashes'][1]))
                status['Speed #'] = convert_speed(sum(d['speed'] for d in json_data['devices']))
                gpu_count, gpu_model, temps = parse_device_info(json_data)
                status['GPU_Count'] = gpu_count
                status['GPU_Model'] = gpu_model
                status['Temps'] = temps
            except (ValueError, KeyError, IndexError, TypeError) as err:
                LOG.debug('Skipping unparseable hashcat status line: %s', err)
    return status
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd /tmp/hashview-hashcat-matrix
python -m pytest tests/agent_unit/test_agent_status.py -q
```

Expected: 6 passed.

- [ ] **Step 5: Remove the moved functions from `hashview-agent.py`**

Delete the `time_difference`, `convert_speed`, and `hashcatParser` definitions (currently lines 533-607). Add this import next to the other `agent.*` imports in the script's import block, keeping the old call-site name working:

```python
from agent.status import hashcat_status as hashcatParser
from agent.status import convert_speed, time_difference  # noqa: F401 - re-exported for callers
```

Then confirm nothing else in the script referenced the removed bodies:

```bash
cd /tmp/hashview-hashcat-matrix
grep -n "time_difference\|convert_speed\|hashcatParser" install/hashview-agent/hashview-agent.py
```

Expected: only the two import lines and the existing call site (`hc_status = hashcatParser(output_file)`).

- [ ] **Step 6: Verify the whole agent + unit suite still passes**

```bash
cd /tmp/hashview-hashcat-matrix
python -m pytest tests/unit tests/security tests/agent_unit -q
python -m pytest tests/agent_unit --cov=agent --cov-report=term-missing --cov-fail-under=75 -q
```

Expected: all pass, and the `--cov=agent` line stays at or above 75%.

- [ ] **Step 7: Commit**

```bash
cd /tmp/hashview-hashcat-matrix
git rev-parse --abbrev-ref HEAD   # must print ci/hashcat-version-matrix
git add install/hashview-agent/agent/status.py \
        install/hashview-agent/hashview-agent.py \
        tests/agent_unit/test_agent_status.py
git commit -m "Extract hashcat status parsing into agent/status.py

The parser lived in hashview-agent.py, which parses argv at import time and
pulls in psutil, so it could not be imported by a test. Moving it beside
bench.py (same dependency-free pattern) makes it directly testable against
real captured hashcat output. Pure move: no behaviour change."
```

---

### Task 2: Capture scripts and golden fixtures

Two scripts with one responsibility each, so a developer can point `capture.sh` at a locally built hashcat without touching the download path.

**Files:**
- Create: `tests/hashcat_matrix/fetch.sh`, `tests/hashcat_matrix/capture.sh`, `tests/hashcat_matrix/summarize.py`
- Create: `tests/fixtures/hashcat/{6.2.6,7.0.0,7.1.0,7.1.1,7.1.2}/`

**Interfaces:**
- Produces: `fetch.sh <version> <sha256> <destdir>` → unpacks to `<destdir>/hashcat-<version>/`, prints that path on stdout.
- Produces: `capture.sh <hashcat-bin> <outdir>` → writes `version.txt`, `status.txt`, `benchmark.txt`, `outfile.txt`, `help.txt` into `<outdir>`.
- Produces: `summarize.py <capture-dir>` → writes `<capture-dir>/summary.json` with the volatile-free structural summary consumed by the workflow's drift diff.

- [ ] **Step 1: Write `tests/hashcat_matrix/fetch.sh`**

```bash
#!/usr/bin/env bash
# Download, verify, and unpack one hashcat release.
#
#   fetch.sh <version> <sha256> <destdir>
#
# Prints the unpacked directory on stdout. A checksum mismatch is a hard
# failure: a corrupted download must never be mistaken for an interop break.
set -euo pipefail

version="${1:?usage: fetch.sh <version> <sha256> <destdir>}"
sha256="${2:?missing expected sha256}"
destdir="${3:?missing destination directory}"

archive="${destdir}/hashcat-${version}.7z"
url="https://github.com/hashcat/hashcat/releases/download/v${version}/hashcat-${version}.7z"

mkdir -p "${destdir}"
curl -fsSL --retry 3 --retry-delay 5 -o "${archive}" "${url}"
echo "${sha256}  ${archive}" | sha256sum -c - >&2
7z x -y -o"${destdir}" "${archive}" >/dev/null

unpacked="${destdir}/hashcat-${version}"
test -x "${unpacked}/hashcat.bin" || {
  echo "fetch.sh: ${unpacked}/hashcat.bin missing or not executable" >&2
  exit 1
}
echo "${unpacked}"
```

- [ ] **Step 2: Write `tests/hashcat_matrix/capture.sh`**

The synthetic corpus is a five-word wordlist whose third word is the plaintext of the one NTLM target, so `--skip 2 --limit 2` is the only slice that recovers it. `--status-timer=1` keeps the run short. stderr is captured separately rather than discarded, so a leg that produces no status lines can report why.

Every hashcat invocation redirects stdin from `/dev/null`. hashcat reads stdin for interactive keypress commands, so with stdin inherited its behaviour depends on what the caller happens to have attached — and it will consume the caller's input. A loop feeding versions on stdin gets silently truncated after the first iteration.

```bash
#!/usr/bin/env bash
# Capture the machine-readable artifacts Hashview parses, from one hashcat binary.
#
#   capture.sh <path-to-hashcat.bin> <outdir>
#
# Writes: version.txt status.txt benchmark.txt outfile.txt help.txt stderr.txt
# Knows nothing about assertions -- tests/agent_unit/test_hashcat_contract.py
# and tests/hashcat_matrix/test_chunk_coverage.py do the asserting.
set -euo pipefail

hcbin="${1:?usage: capture.sh <hashcat.bin> <outdir>}"
outdir="${2:?missing output directory}"
mkdir -p "${outdir}"

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

# Synthetic corpus. 'password' sits at index 2 so a --skip 2 --limit 2 slice is
# the only one that recovers the target.
printf 'aaaaaa\nbbbbbb\npassword\ncccccc\ndddddd\n' > "${work}/wordlist.txt"
printf '8846f7eaee8fb117ad06bdd830b7586c\n' > "${work}/hashes.txt"

"${hcbin}" --version > "${outdir}/version.txt" 2>>"${outdir}/stderr.txt" </dev/null
"${hcbin}" --help    > "${outdir}/help.txt"    2>>"${outdir}/stderr.txt" </dev/null

# Benchmark: the agent runs `hashcat -b -m <mode>` and feeds stdout to
# agent.bench.parse_benchmark_speed, which needs a `Speed.#<n>...: <n> <unit>H/s`
# line. CUDA/HIP are ignored so a runner without them does not emit warnings.
"${hcbin}" -b -m 1000 --backend-ignore-cuda --backend-ignore-hip \
  > "${outdir}/benchmark.txt" 2>>"${outdir}/stderr.txt" </dev/null

# Crack: the exact flag set build_hashcat_command emits for attack mode 0.
"${hcbin}" -O -w 3 --session capture -m 1000 \
  --potfile-path "${work}/capture.pot" \
  --status --status-timer=1 \
  --outfile-format 1,3 --outfile "${outdir}/outfile.txt" \
  --status-json \
  "${work}/hashes.txt" "${work}/wordlist.txt" \
  > "${outdir}/status.txt" 2>>"${outdir}/stderr.txt" </dev/null || true

test -s "${outdir}/status.txt" || {
  echo "capture.sh: hashcat produced no stdout; stderr follows" >&2
  cat "${outdir}/stderr.txt" >&2
  exit 1
}
```

- [ ] **Step 3: Write `tests/hashcat_matrix/summarize.py`**

Raw captures carry timestamps, speeds, session ids, and paths, so they cannot be byte-compared across runs. The drift diff compares this structural summary instead.

```python
#!/usr/bin/env python3
"""Reduce a hashcat capture directory to a volatile-free structural summary.

Raw captures embed timestamps, measured speeds, and temp paths, so they are not
byte-comparable between runs. This emits only the shape Hashview depends on:
which keys appear in the status JSON, which keys appear per device, which flags
the binary advertises, and how many colon-separated fields the outfile has.

    summarize.py <capture-dir>     ->  writes <capture-dir>/summary.json
"""
import json
import re
import sys
from pathlib import Path

# Flags build_hashcat_command (hashview/utils/utils.py) can emit.
REQUIRED_FLAGS = [
    "-O", "-w", "--session", "-m", "--potfile-path", "--status",
    "--status-timer", "--outfile-format", "--outfile", "--skip", "--limit",
    "--loopback", "--hex-salt", "-a", "-r", "-j", "-k",
]


def status_objects(capture_dir):
    """Every parseable --status-json object in the captured stdout."""
    text = (capture_dir / "status.txt").read_text(encoding="utf-8", errors="replace")
    objects = []
    for line in text.splitlines():
        if not line.startswith("{"):
            continue
        try:
            objects.append(json.loads(line))
        except ValueError:
            continue
    return objects


def summarize(capture_dir):
    objects = status_objects(capture_dir)
    status_keys, device_keys = set(), set()
    for obj in objects:
        status_keys.update(obj.keys())
        for device in obj.get("devices") or []:
            device_keys.update(device.keys())

    help_text = (capture_dir / "help.txt").read_text(encoding="utf-8", errors="replace")
    # Match the flag as a whole token so '-a' does not match '--attack-mode'.
    advertised = sorted(f for f in REQUIRED_FLAGS
                        if re.search(r"(?<![\w-])" + re.escape(f) + r"(?![\w-])", help_text))

    outfile_lines = [ln for ln in
                     (capture_dir / "outfile.txt").read_text(encoding="utf-8",
                                                             errors="replace").splitlines()
                     if ln.strip()]

    bench = (capture_dir / "benchmark.txt").read_text(encoding="utf-8", errors="replace")

    return {
        "version": (capture_dir / "version.txt").read_text(encoding="utf-8").strip(),
        "status_line_count": len(objects),
        "status_keys": sorted(status_keys),
        "device_keys": sorted(device_keys),
        "advertised_flags": advertised,
        "outfile_line_count": len(outfile_lines),
        "outfile_field_counts": sorted({len(ln.split(":")) for ln in outfile_lines}),
        "benchmark_speed_lines": len(re.findall(r"Speed\.#\d+", bench)),
    }


def main(argv):
    if len(argv) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    capture_dir = Path(argv[0])
    summary = summarize(capture_dir)
    (capture_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
```

- [ ] **Step 4: Make the scripts executable and generate the five fixtures**

The runner has no GPU and no vendor OpenCL, so pocl provides a CPU device. This runs in a container to match the CI environment; on a Linux host with pocl and p7zip installed, drop the `docker run` wrapper.

```bash
cd /tmp/hashview-hashcat-matrix
chmod +x tests/hashcat_matrix/fetch.sh tests/hashcat_matrix/capture.sh

docker run --rm --platform linux/amd64 -v "$PWD":/repo -w /repo ubuntu:24.04 bash -c '
  set -eu
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq curl p7zip-full pocl-opencl-icd ocl-icd-libopencl1 python3
  while read -r v sha; do
    dir="$(tests/hashcat_matrix/fetch.sh "$v" "$sha" /tmp/hc)"
    mkdir -p "tests/fixtures/hashcat/$v"
    tests/hashcat_matrix/capture.sh "$dir/hashcat.bin" "tests/fixtures/hashcat/$v"
    python3 tests/hashcat_matrix/summarize.py "tests/fixtures/hashcat/$v"
  done <<EOF
6.2.6 96697e9ef6a795d45863c91d61be85a9f138596e3151e7c2cd63ccf48aaa8783
7.0.0 19e126642e1db7902125072dce539c53485c721735325a747bd03e8af3135d78
7.1.0 37be13b2dfdd1da7a3f68847ff817a22c144fc8d76170f51aae412e8b3ee24fd
7.1.1 e09f88233ae8a88e0e60d68c20e4f5094d9122af533a7d186a45d8d55d08f3a0
7.1.2 80db0316387794ce9d14ed376da75b8a7742972485b45db790f5f8260307ff98
EOF
'
```

- [ ] **Step 5: Verify each fixture directory is complete and non-empty**

```bash
cd /tmp/hashview-hashcat-matrix
for v in 6.2.6 7.0.0 7.1.0 7.1.1 7.1.2; do
  d="tests/fixtures/hashcat/$v"
  for f in version.txt status.txt benchmark.txt outfile.txt help.txt summary.json; do
    test -s "$d/$f" || echo "EMPTY OR MISSING: $d/$f"
  done
  printf '%-8s %s  status_lines=%s\n' "$v" \
    "$(cat "$d/version.txt")" \
    "$(python3 -c "import json,sys;print(json.load(open('$d/summary.json'))['status_line_count'])")"
done
```

Expected: no `EMPTY OR MISSING` lines, and every version reports at least one status line. If 7.1.0 or 7.1.1 report zero status lines, that is the known machine-readable-status breakage — record it in the commit message and continue; Task 3 marks those two versions non-blocking.

- [ ] **Step 6: Confirm the fixtures contain no non-synthetic data**

```bash
cd /tmp/hashview-hashcat-matrix
grep -rniE "trustedsec|gitrdun|192\.168\.|10\.[0-9]+\.|172\.(1[6-9]|2[0-9]|3[01])\." tests/fixtures/hashcat/ || echo "clean"
```

Expected: `clean`. Device names from the runner (e.g. a CPU model string) are acceptable; anything naming internal infrastructure is not.

- [ ] **Step 7: Commit**

```bash
cd /tmp/hashview-hashcat-matrix
git rev-parse --abbrev-ref HEAD   # must print ci/hashcat-version-matrix
git add tests/hashcat_matrix/fetch.sh tests/hashcat_matrix/capture.sh \
        tests/hashcat_matrix/summarize.py tests/fixtures/hashcat/
git commit -m "Add hashcat capture scripts and golden fixtures for five releases

fetch.sh verifies a pinned release archive by sha256; capture.sh runs the flag
set build_hashcat_command emits and saves the status/benchmark/outfile/help
artifacts; summarize.py reduces a capture to a volatile-free structural summary
so drift can be diffed across runs. Fixtures captured for 6.2.6, 7.0.0, 7.1.0,
7.1.1 and 7.1.2."
```

---

### Task 3: Tier 1 contract test over the committed fixtures

Lives in `tests/agent_unit/` because that directory is included in both coverage runs in `unit-tests.yml`, so the test earns credit for `agent/status.py` and for the `hashview` functions it exercises.

**Files:**
- Create: `tests/agent_unit/test_hashcat_contract.py`

**Interfaces:**
- Consumes: `agent.status.hashcat_status`, `agent.bench.parse_benchmark_speed`, `agent.bench.parse_device_info`, `hashview.utils.utils.hexplain_to_text`, and `tests/hashcat_matrix/summarize.py:REQUIRED_FLAGS`.

- [ ] **Step 1: Write the failing test**

```python
"""Contract tests: Hashview's parsers against real hashcat output.

Every fixture under tests/fixtures/hashcat/<version>/ is a capture from a real
hashcat release (see tests/hashcat_matrix/capture.sh). These tests run the
production parsers over those captures, so a hashcat release that changes the
machine-readable surface fails here rather than silently blanking the dashboard
-- hashcatParser swallows unparseable status lines with a LOG.debug.

Assertions are structural, never value-exact: speeds, timestamps and device
names differ per machine.

Versions in KNOWN_BROKEN_STATUS_JSON are xfail(strict=False). hashcat 7.0.0
emits structurally INVALID JSON from --status-json: each device object closes
with a stray '}' instead of a ',' before the "power" key, so json.loads fails
on every status line (upstream issue #4393). 7.1.0 fixed it. On 7.0.0 the agent
would therefore report no status at all, silently. It is kept in the matrix as
a canary proving these tests detect a real break.
"""
import importlib.util
import json
from pathlib import Path

import pytest

from agent.bench import parse_benchmark_speed, parse_device_info
from agent.status import hashcat_status
from hashview.utils.utils import hexplain_to_text

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = REPO_ROOT / "tests" / "fixtures" / "hashcat"

_SUMMARIZE_PATH = REPO_ROOT / "tests" / "hashcat_matrix" / "summarize.py"
_spec = importlib.util.spec_from_file_location("hv_hc_summarize", _SUMMARIZE_PATH)
summarize = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(summarize)

KNOWN_BROKEN_STATUS_JSON = {"7.0.0"}

# The plaintext capture.sh cracks, and its NTLM hash.
EXPECTED_PLAINTEXT = "password"
EXPECTED_HASH = "8846f7eaee8fb117ad06bdd830b7586c"


def _versions():
    if not FIXTURE_ROOT.is_dir():
        return []
    return sorted(p.name for p in FIXTURE_ROOT.iterdir() if p.is_dir())


def _param(version):
    marks = [pytest.mark.xfail(reason="hashcat 7.0.0 emits invalid --status-json (upstream #4393)",
                               strict=False)] if version in KNOWN_BROKEN_STATUS_JSON else []
    return pytest.param(version, marks=marks)


ALL_VERSIONS = [pytest.param(v) for v in _versions()]
STATUS_VERSIONS = [_param(v) for v in _versions()]


def test_fixtures_exist():
    """Guard: an empty fixture tree would make every test below vacuously pass."""
    assert _versions(), f"no hashcat fixtures under {FIXTURE_ROOT}"


# --- contract 1: --status-json ---------------------------------------------

@pytest.mark.parametrize("version", STATUS_VERSIONS)
def test_every_status_line_is_valid_json(version):
    text = (FIXTURE_ROOT / version / "status.txt").read_text(encoding="utf-8",
                                                             errors="replace")
    candidates = [ln for ln in text.splitlines() if ln.startswith("{")]
    assert candidates, "hashcat emitted no --status-json lines"
    for line in candidates:
        json.loads(line)      # raises -> the contract is broken


@pytest.mark.parametrize("version", STATUS_VERSIONS)
def test_agent_parses_the_status_file(version):
    status = hashcat_status(str(FIXTURE_ROOT / version / "status.txt"))
    assert set(status) >= {"Time_Estimated", "Recovered", "Speed #",
                           "GPU_Count", "GPU_Model", "Temps"}
    recovered, total = status["Recovered"].split("/")
    assert recovered.isdigit() and total.isdigit()
    assert status["Speed #"].endswith("H/s")


@pytest.mark.parametrize("version", STATUS_VERSIONS)
def test_status_json_carries_the_fields_the_agent_reads(version):
    objects = summarize.status_objects(FIXTURE_ROOT / version)
    assert objects
    for obj in objects:
        assert isinstance(obj["estimated_stop"], int)
        assert len(obj["recovered_hashes"]) == 2
        assert obj["devices"]
        for device in obj["devices"]:
            assert isinstance(device["speed"], int)
            assert isinstance(device["device_name"], str)
            assert isinstance(device["device_type"], str)


@pytest.mark.parametrize("version", STATUS_VERSIONS)
def test_device_info_parses(version):
    objects = summarize.status_objects(FIXTURE_ROOT / version)
    count, model, temps = parse_device_info(objects[-1])
    assert count >= 1
    assert isinstance(model, str)
    # temps is a CSV of ints (possibly empty when hashcat reports no sensor).
    assert all(part.lstrip("-").isdigit() for part in temps.split(",") if part)


# --- contract 2: benchmark speed line --------------------------------------

@pytest.mark.parametrize("version", ALL_VERSIONS)
def test_benchmark_speed_parses_to_a_positive_int(version):
    text = (FIXTURE_ROOT / version / "benchmark.txt").read_text(encoding="utf-8",
                                                                errors="replace")
    speed = parse_benchmark_speed(text)
    assert speed is not None, "no Speed.#<n> line found"
    assert speed > 0


# --- contract 3: outfile format 1,3 ----------------------------------------

@pytest.mark.parametrize("version", ALL_VERSIONS)
def test_outfile_is_hash_colon_hexplain(version):
    lines = [ln for ln in (FIXTURE_ROOT / version / "outfile.txt")
             .read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]
    assert lines, "hashcat recovered nothing"
    for line in lines:
        hash_value, hexplain = line.rsplit(":", 1)
        assert hash_value.lower() == EXPECTED_HASH
        assert hexplain_to_text(hexplain) == EXPECTED_PLAINTEXT


# --- contract 4: flag acceptance -------------------------------------------

@pytest.mark.parametrize("version", ALL_VERSIONS)
def test_binary_advertises_every_flag_the_server_emits(version):
    summary = json.loads((FIXTURE_ROOT / version / "summary.json")
                         .read_text(encoding="utf-8"))
    missing = sorted(set(summarize.REQUIRED_FLAGS) - set(summary["advertised_flags"]))
    assert not missing, f"hashcat {version} no longer advertises: {missing}"
```

- [ ] **Step 2: Run the test to verify it fails before fixtures/parser exist**

If Tasks 1 and 2 are already complete this test should pass on first run. To prove it is not vacuous, temporarily rename one fixture's `status.txt` and confirm the corresponding version's tests fail:

```bash
cd /tmp/hashview-hashcat-matrix
cp tests/fixtures/hashcat/7.1.2/status.txt /tmp/status-backup.txt
printf 'not json\n' > tests/fixtures/hashcat/7.1.2/status.txt
python -m pytest tests/agent_unit/test_hashcat_contract.py -q -k 7.1.2
```

Expected: failures on the status tests for 7.1.2.

Do NOT use `git checkout` to restore — that would discard the file, since the fixtures may still be unstaged. Restore from the copy:

```bash
cp /tmp/status-backup.txt tests/fixtures/hashcat/7.1.2/status.txt
```

- [ ] **Step 3: Run the full contract suite**

```bash
cd /tmp/hashview-hashcat-matrix
python -m pytest tests/agent_unit/test_hashcat_contract.py -q -rxX
```

Expected: all pass, with the four 7.0.0 status tests reported as `xfail`. The captured fixtures confirm this is real: 6.2.6, 7.1.0, 7.1.1 and 7.1.2 each yield 2 parseable status objects, while 7.0.0 yields 0 parseable and 2 invalid.

- [ ] **Step 4: Verify both coverage ratchets still hold**

```bash
cd /tmp/hashview-hashcat-matrix
mkdir -p hashview/control/{hashes,logs,rules,tmp,wordlists,wordlists_import}
python -m pytest tests/unit tests/security tests/agent_unit \
  --cov=hashview --cov-branch --cov-report=term-missing \
  --cov-report=json:coverage.json --cov-fail-under=85 -q
python tests/check_function_coverage.py coverage.json
python -m pytest tests/agent_unit --cov=agent --cov-report=term-missing --cov-fail-under=75 -q
```

Expected: all three pass.

- [ ] **Step 5: Commit**

```bash
cd /tmp/hashview-hashcat-matrix
git rev-parse --abbrev-ref HEAD
git add tests/agent_unit/test_hashcat_contract.py
git commit -m "Add offline hashcat contract tests over the golden fixtures

Runs the production status, benchmark, outfile and flag parsers against real
captures from five hashcat releases. 7.1.0 and 7.1.1 are non-strict xfail for
the status-json assertions: those releases broke machine-readable status, which
7.1.2's notes say it restored. They stay in the matrix as canaries."
```

---

### Task 4: Live `--skip`/`--limit` slice semantics test

Contract item 5. This needs a real binary, so it is Tier 2 only and skips unless `HASHCAT_BIN` is set. The unreleased 7.1.x changelog states "`--skip` and `--limit` now apply to the whole run" — a semantics change to the flags `build_hashcat_command` uses for chunking. This test is what catches it.

**Files:**
- Create: `tests/hashcat_matrix/__init__.py` (empty), `tests/hashcat_matrix/test_chunk_coverage.py`
- Modify: `pytest.ini`

**Interfaces:**
- Consumes: `HASHCAT_BIN` environment variable (absolute path to a `hashcat.bin`).

- [ ] **Step 1: Register the marker in `pytest.ini`**

Add to the `markers` block, after the existing `migration` line:

```
    hashcat_matrix: live hashcat interop tests (opt-in; needs HASHCAT_BIN)
```

- [ ] **Step 2: Write the failing test**

```python
"""Live hashcat --skip/--limit slice semantics (contract item 5).

hashview.utils.chunking plans wordlist chunks as {'skip': n, 'limit': m} word
ranges, and build_hashcat_command passes them straight through. hashcat's
unreleased 7.1.x changelog states "--skip and --limit now apply to the whole
run" -- if that ships, chunk boundaries would be computed against a different
keyspace than hashcat applies them to, silently skipping or duplicating
candidates.

Needs a real binary; set HASHCAT_BIN to run. Skipped by default.
"""
import os
import subprocess

import pytest

HASHCAT_BIN = os.environ.get("HASHCAT_BIN")

pytestmark = [
    pytest.mark.hashcat_matrix,
    pytest.mark.skipif(not HASHCAT_BIN, reason="set HASHCAT_BIN to run live hashcat tests"),
]

# NTLM of each word; 'password' is the only target and sits at index 2.
WORDS = ["aaaaaa", "bbbbbb", "password", "cccccc", "dddddd", "eeeeee"]
TARGET_HASH = "8846f7eaee8fb117ad06bdd830b7586c"
TARGET_INDEX = 2


def _run_slice(tmp_path, skip, limit):
    """Run one --skip/--limit slice; return the recovered hashes as a set."""
    wordlist = tmp_path / f"wl-{skip}-{limit}.txt"
    wordlist.write_text("\n".join(WORDS) + "\n", encoding="utf-8")
    hashes = tmp_path / "hashes.txt"
    hashes.write_text(TARGET_HASH + "\n", encoding="utf-8")
    outfile = tmp_path / f"out-{skip}-{limit}.txt"

    subprocess.run(
        [HASHCAT_BIN, "-m", "1000", "-a", "0",
         "--potfile-path", str(tmp_path / f"p-{skip}-{limit}.pot"),
         "--outfile-format", "1,3", "--outfile", str(outfile),
         "--skip", str(skip), "--limit", str(limit),
         "--quiet", str(hashes), str(wordlist)],
        check=False, capture_output=True, timeout=300,
    )
    if not outfile.exists():
        return set()
    return {ln.rsplit(":", 1)[0].lower()
            for ln in outfile.read_text(encoding="utf-8").splitlines() if ln.strip()}


def test_slice_containing_the_word_recovers_it(tmp_path):
    assert _run_slice(tmp_path, TARGET_INDEX, 2) == {TARGET_HASH}


@pytest.mark.parametrize("skip,limit", [(0, 2), (4, 2)])
def test_slices_not_containing_the_word_recover_nothing(tmp_path, skip, limit):
    assert _run_slice(tmp_path, skip, limit) == set()


def test_planned_chunks_cover_the_wordlist_exactly_once(tmp_path):
    """The union of a full chunk plan recovers the target exactly once: no gap,
    no double coverage. Chunk size 2 over 6 words -> 3 slices."""
    slices = [(0, 2), (2, 2), (4, 2)]
    recovered = [_run_slice(tmp_path, skip, limit) for skip, limit in slices]
    hits = [s for s in recovered if TARGET_HASH in s]
    assert len(hits) == 1, (
        f"target recovered by {len(hits)} of {len(slices)} slices; "
        "--skip/--limit no longer slice the wordlist as the chunk planner assumes"
    )
```

- [ ] **Step 3: Verify it skips cleanly without a binary**

```bash
cd /tmp/hashview-hashcat-matrix
python -m pytest tests/hashcat_matrix -q -rs
```

Expected: 4 skipped, reason "set HASHCAT_BIN to run live hashcat tests". No errors, no collection failures.

- [ ] **Step 4: Verify it passes against a real binary**

```bash
cd /tmp/hashview-hashcat-matrix
docker run --rm --platform linux/amd64 -v "$PWD":/repo -w /repo ubuntu:24.04 bash -c '
  set -eu
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq curl p7zip-full pocl-opencl-icd ocl-icd-libopencl1 python3 python3-pytest
  dir="$(tests/hashcat_matrix/fetch.sh 7.1.2 80db0316387794ce9d14ed376da75b8a7742972485b45db790f5f8260307ff98 /tmp/hc)"
  HASHCAT_BIN="$dir/hashcat.bin" python3 -m pytest tests/hashcat_matrix -q -p no:cacheprovider
'
```

Expected: 4 passed.

- [ ] **Step 5: Confirm the default suite still ignores these tests**

```bash
cd /tmp/hashview-hashcat-matrix
python -m pytest tests/unit tests/security tests/agent_unit -q
```

Expected: unchanged pass count from Task 3.

- [ ] **Step 6: Commit**

```bash
cd /tmp/hashview-hashcat-matrix
git rev-parse --abbrev-ref HEAD
git add pytest.ini tests/hashcat_matrix/__init__.py tests/hashcat_matrix/test_chunk_coverage.py
git commit -m "Add live --skip/--limit slice semantics test

hashcat's unreleased 7.1.x changelog says --skip and --limit will apply to the
whole run rather than the wordlist base loop. That would silently break the
chunk planner's boundaries, so assert the semantics against a real binary.
Opt-in via HASHCAT_BIN; skipped in the default suite."
```

---

### Task 5: The `hashcat-matrix.yml` workflow (Tiers 2 and 3)

**Files:**
- Create: `.github/workflows/hashcat-matrix.yml`

**Interfaces:**
- Consumes: `tests/hashcat_matrix/fetch.sh`, `capture.sh`, `summarize.py`, `tests/agent_unit/test_hashcat_contract.py`, `tests/hashcat_matrix/test_chunk_coverage.py`.

- [ ] **Step 1: Write the workflow**

Action versions match the repo's existing pins (`checkout@v5`, `setup-python@v6`, `upload-artifact@v6`).

```yaml
name: hashcat Matrix

# Interoperability guard: Hashview parses hashcat's --status-json, benchmark
# and outfile output and depends on the flags build_hashcat_command emits.
# None of that is a stable API, and hashcatParser swallows unparseable status
# lines, so upstream drift would otherwise surface as a blank dashboard.
#
# Tier 2 (pinned) runs the real binary for each pinned release. Tier 3
# (floating) does the same for any release newer than the matrix and opens an
# issue rather than failing.

on:
  schedule:
    # Mondays 07:00 UTC.
    - cron: "0 7 * * 1"
  workflow_dispatch:
  pull_request:
    paths:
      - "install/hashview-agent/**"
      - "hashview/utils/utils.py"
      - "hashview/utils/chunking.py"
      - "tests/hashcat_matrix/**"
      - "tests/fixtures/hashcat/**"
      - ".github/workflows/hashcat-matrix.yml"

permissions:
  contents: read

jobs:
  pinned:
    name: "hashcat ${{ matrix.version }}"
    runs-on: ubuntu-latest
    timeout-minutes: 20
    # 7.0.0 emits structurally invalid --status-json (stray '}' before "power"
    # in each device object; upstream issue #4393, fixed in 7.1.0). It stays in
    # the matrix as a canary proving the contract tests detect a real break,
    # but must not hold CI red.
    continue-on-error: ${{ matrix.blocking == false }}
    strategy:
      fail-fast: false
      matrix:
        include:
          - version: "6.2.6"
            sha256: "96697e9ef6a795d45863c91d61be85a9f138596e3151e7c2cd63ccf48aaa8783"
            blocking: true
          - version: "7.0.0"
            sha256: "19e126642e1db7902125072dce539c53485c721735325a747bd03e8af3135d78"
            blocking: false
          - version: "7.1.0"
            sha256: "37be13b2dfdd1da7a3f68847ff817a22c144fc8d76170f51aae412e8b3ee24fd"
            blocking: true
          - version: "7.1.1"
            sha256: "e09f88233ae8a88e0e60d68c20e4f5094d9122af533a7d186a45d8d55d08f3a0"
            blocking: true
          - version: "7.1.2"
            sha256: "80db0316387794ce9d14ed376da75b8a7742972485b45db790f5f8260307ff98"
            blocking: true
    steps:
      - uses: actions/checkout@v5

      - uses: actions/setup-python@v6
        with:
          python-version: "3.11"
          cache: pip
          cache-dependency-path: |
            requirements.txt
            requirements-dev.txt

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt -r requirements-dev.txt

      # The runner has no GPU and no vendor OpenCL. pocl supplies a CPU device,
      # which is enough for a five-word NTLM crack and an NTLM benchmark.
      - name: Install pocl and p7zip
        run: |
          sudo apt-get update -qq
          sudo apt-get install -y -qq p7zip-full pocl-opencl-icd ocl-icd-libopencl1

      - name: Fetch hashcat ${{ matrix.version }}
        id: fetch
        run: |
          dir="$(tests/hashcat_matrix/fetch.sh \
            '${{ matrix.version }}' '${{ matrix.sha256 }}' "${RUNNER_TEMP}/hc")"
          echo "dir=${dir}" >> "$GITHUB_OUTPUT"

      - name: Capture machine-readable output
        run: |
          tests/hashcat_matrix/capture.sh \
            '${{ steps.fetch.outputs.dir }}/hashcat.bin' \
            "${RUNNER_TEMP}/capture"
          python tests/hashcat_matrix/summarize.py "${RUNNER_TEMP}/capture"

      # Run the SAME assertions Tier 1 runs offline, but against output captured
      # from the real binary moments ago.
      - name: Assert the interop contract against the live capture
        run: |
          rm -rf "tests/fixtures/hashcat/${{ matrix.version }}"
          mkdir -p "tests/fixtures/hashcat/${{ matrix.version }}"
          cp "${RUNNER_TEMP}"/capture/* "tests/fixtures/hashcat/${{ matrix.version }}/"
          python -m pytest tests/agent_unit/test_hashcat_contract.py -q -rxX \
            -k '${{ matrix.version }}'

      - name: Assert --skip/--limit slice semantics
        env:
          HASHCAT_BIN: ${{ steps.fetch.outputs.dir }}/hashcat.bin
        run: python -m pytest tests/hashcat_matrix -q

      # Structural drift against the committed fixture. Raw captures embed
      # timestamps and measured speeds, so compare the volatile-free summary.
      - name: Diff the live capture against the committed fixture
        run: |
          git diff --no-index --exit-code \
            <(git show "HEAD:tests/fixtures/hashcat/${{ matrix.version }}/summary.json") \
            "${RUNNER_TEMP}/capture/summary.json"

      - name: Upload capture on failure
        if: failure()
        uses: actions/upload-artifact@v6
        with:
          name: hashcat-capture-${{ matrix.version }}
          path: ${{ runner.temp }}/capture
          retention-days: 14

  floating:
    name: "hashcat (newest release)"
    runs-on: ubuntu-latest
    timeout-minutes: 20
    # Schedule and manual runs only: a new upstream release must not fail a PR
    # that did not cause it.
    if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'
    permissions:
      contents: read
      issues: write
    steps:
      - uses: actions/checkout@v5

      - uses: actions/setup-python@v6
        with:
          python-version: "3.11"
          cache: pip
          cache-dependency-path: |
            requirements.txt
            requirements-dev.txt

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt -r requirements-dev.txt

      - name: Install pocl and p7zip
        run: |
          sudo apt-get update -qq
          sudo apt-get install -y -qq p7zip-full pocl-opencl-icd ocl-icd-libopencl1

      # Newest release tag with no fixture directory of its own.
      - name: Find an unpinned release
        id: newest
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          latest="$(gh api repos/hashcat/hashcat/releases/latest --jq '.tag_name' | sed 's/^v//')"
          echo "version=${latest}" >> "$GITHUB_OUTPUT"
          if [ -d "tests/fixtures/hashcat/${latest}" ]; then
            echo "Newest release ${latest} is already pinned; nothing to do."
            echo "unpinned=false" >> "$GITHUB_OUTPUT"
          else
            echo "unpinned=true" >> "$GITHUB_OUTPUT"
          fi

      # No pinned checksum exists for an unseen release, so record what was
      # actually downloaded and put it in the issue body for a human to pin.
      - name: Fetch and capture
        id: capture
        if: steps.newest.outputs.unpinned == 'true'
        continue-on-error: true
        run: |
          version='${{ steps.newest.outputs.version }}'
          url="https://github.com/hashcat/hashcat/releases/download/v${version}/hashcat-${version}.7z"
          mkdir -p "${RUNNER_TEMP}/hc"
          curl -fsSL --retry 3 -o "${RUNNER_TEMP}/hc/hashcat.7z" "$url"
          sha="$(sha256sum "${RUNNER_TEMP}/hc/hashcat.7z" | cut -d' ' -f1)"
          echo "sha256=${sha}" >> "$GITHUB_OUTPUT"
          7z x -y -o"${RUNNER_TEMP}/hc" "${RUNNER_TEMP}/hc/hashcat.7z" >/dev/null
          bin="${RUNNER_TEMP}/hc/hashcat-${version}/hashcat.bin"
          echo "bin=${bin}" >> "$GITHUB_OUTPUT"
          tests/hashcat_matrix/capture.sh "$bin" "${RUNNER_TEMP}/capture"
          python tests/hashcat_matrix/summarize.py "${RUNNER_TEMP}/capture"
          mkdir -p "tests/fixtures/hashcat/${version}"
          cp "${RUNNER_TEMP}"/capture/* "tests/fixtures/hashcat/${version}/"
          python -m pytest tests/agent_unit/test_hashcat_contract.py -q -rxX -k "${version}"
          HASHCAT_BIN="$bin" python -m pytest tests/hashcat_matrix -q

      - name: Upload capture
        if: steps.newest.outputs.unpinned == 'true'
        uses: actions/upload-artifact@v6
        with:
          name: hashcat-capture-${{ steps.newest.outputs.version }}
          path: ${{ runner.temp }}/capture
          retention-days: 30
          if-no-files-found: warn

      # Idempotent: search for an open issue with the same title before creating.
      - name: Open an issue for the unpinned release
        if: steps.newest.outputs.unpinned == 'true'
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          VERSION: ${{ steps.newest.outputs.version }}
          SHA256: ${{ steps.capture.outputs.sha256 }}
          RESULT: ${{ steps.capture.outcome }}
        run: |
          title="hashcat ${VERSION} is not in the interop matrix"
          existing="$(gh issue list --state open --search "\"${title}\" in:title" \
            --json number --jq '.[0].number // empty')"
          if [ -n "${existing}" ]; then
            echo "Issue #${existing} already open; not filing a duplicate."
            exit 0
          fi
          {
            echo "hashcat **${VERSION}** has been released and is not pinned in"
            echo "\`.github/workflows/hashcat-matrix.yml\`."
            echo
            echo "Contract test result against the new release: **${RESULT}**."
            echo
            if [ "${RESULT}" != "success" ]; then
              echo "The interop contract did NOT hold. Download the"
              echo "\`hashcat-capture-${VERSION}\` artifact from this run to see the"
              echo "actual output before changing any parser."
              echo
            fi
            echo "To pin it, add to the \`pinned\` matrix:"
            echo
            echo '```yaml'
            echo "          - version: \"${VERSION}\""
            echo "            sha256: \"${SHA256}\""
            echo "            blocking: true"
            echo '```'
            echo
            echo "and commit a fixture directory for it (see TESTING.md,"
            echo "\"Refreshing hashcat fixtures\")."
            echo
            echo "Filed automatically by the hashcat Matrix workflow."
          } > /tmp/issue-body.md
          gh issue create --title "${title}" --body-file /tmp/issue-body.md
```

- [ ] **Step 2: Validate the workflow parses**

```bash
cd /tmp/hashview-hashcat-matrix
python -c "import yaml,sys; yaml.safe_load(open('.github/workflows/hashcat-matrix.yml')); print('yaml ok')"
```

Expected: `yaml ok`.

- [ ] **Step 3: Confirm the paths the workflow references all exist**

```bash
cd /tmp/hashview-hashcat-matrix
for p in tests/hashcat_matrix/fetch.sh tests/hashcat_matrix/capture.sh \
         tests/hashcat_matrix/summarize.py \
         tests/agent_unit/test_hashcat_contract.py tests/hashcat_matrix/test_chunk_coverage.py; do
  test -e "$p" || echo "MISSING: $p"
done
test -x tests/hashcat_matrix/fetch.sh || echo "NOT EXECUTABLE: fetch.sh"
test -x tests/hashcat_matrix/capture.sh || echo "NOT EXECUTABLE: capture.sh"
echo done
```

Expected: only `done`.

- [ ] **Step 4: Dry-run the pinned leg end to end for one version**

This mirrors what the workflow does, including the drift diff, so a mistake in the sequencing is caught before pushing.

```bash
cd /tmp/hashview-hashcat-matrix
docker run --rm --platform linux/amd64 -v "$PWD":/repo -w /repo ubuntu:24.04 bash -c '
  set -eu
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq curl p7zip-full pocl-opencl-icd ocl-icd-libopencl1 python3 git
  dir="$(tests/hashcat_matrix/fetch.sh 7.1.2 80db0316387794ce9d14ed376da75b8a7742972485b45db790f5f8260307ff98 /tmp/hc)"
  tests/hashcat_matrix/capture.sh "$dir/hashcat.bin" /tmp/capture
  python3 tests/hashcat_matrix/summarize.py /tmp/capture
  diff /tmp/capture/summary.json tests/fixtures/hashcat/7.1.2/summary.json && echo "DRIFT DIFF: clean"
'
```

Expected: `DRIFT DIFF: clean`. If it differs, the summary is capturing something machine-dependent — narrow `summarize.py` rather than loosening the diff.

- [ ] **Step 5: Commit**

```bash
cd /tmp/hashview-hashcat-matrix
git rev-parse --abbrev-ref HEAD
git add .github/workflows/hashcat-matrix.yml
git commit -m "Add the hashcat version matrix workflow

Pinned legs run each release's real binary under pocl, assert the interop
contract against the fresh capture, check --skip/--limit slice semantics, and
diff the structural summary against the committed fixture. The floating leg
runs any release newer than the matrix on a schedule and opens an issue instead
of failing a build."
```

---

### Task 6: Documentation

**Files:**
- Modify: `TESTING.md`, `CHANGELOG.md`

- [ ] **Step 1: Add a TESTING.md section**

Append a section, matching the surrounding heading style:

```markdown
## hashcat version interoperability

Hashview parses hashcat's `--status-json`, benchmark and outfile output, and
depends on the flags `build_hashcat_command` emits. None of that is a stable
API, and `hashcatParser` swallows unparseable status lines, so drift would
otherwise surface as a blank dashboard rather than an error.

Three tiers guard it:

| Tier | What runs | When |
|---|---|---|
| Offline contract tests | `tests/agent_unit/test_hashcat_contract.py` runs the real parsers over committed captures in `tests/fixtures/hashcat/<version>/` | every PR, in `unit-tests.yml` |
| Pinned matrix | `.github/workflows/hashcat-matrix.yml` downloads each pinned release, captures fresh output, re-runs the contract, and checks `--skip`/`--limit` slicing | weekly, on dispatch, and on PRs touching the agent or the chunking/command builder |
| Floating release check | Same, for any release newer than the matrix; opens an issue instead of failing | weekly and on dispatch |

`7.0.0` is in the matrix deliberately. It emits structurally invalid
`--status-json`: each device object closes with a stray `}` instead of a `,`
before the `"power"` key, so every status line fails `json.loads` (upstream
issue #4393, fixed in 7.1.0). Because `hashcatParser` swallows unparseable
lines, an agent running 7.0.0 reports no status at all and the dashboard simply
goes blank. Its status assertions are non-strict `xfail` and its matrix leg is
`continue-on-error`, so it demonstrates the tests catch a real break without
holding CI red.

**If you run hashcat 7.0.0 in production, upgrade to 7.1.0 or later.**

### Running the live tests locally

Needs a CPU OpenCL runtime (`pocl-opencl-icd`) and `p7zip-full`:

```bash
dir="$(tests/hashcat_matrix/fetch.sh 7.1.2 <sha256> /tmp/hc)"
HASHCAT_BIN="$dir/hashcat.bin" python -m pytest tests/hashcat_matrix -q
```

Without `HASHCAT_BIN` these tests skip.

### Refreshing hashcat fixtures

Only do this deliberately. A fixture diff means either hashcat changed or the
capture environment did; decide which before overwriting the evidence.

```bash
dir="$(tests/hashcat_matrix/fetch.sh <version> <sha256> /tmp/hc)"
tests/hashcat_matrix/capture.sh "$dir/hashcat.bin" tests/fixtures/hashcat/<version>
python tests/hashcat_matrix/summarize.py tests/fixtures/hashcat/<version>
```

To add a version, commit its fixture directory and add a `version`/`sha256`/
`blocking` entry to the `pinned` matrix in the workflow.
```

- [ ] **Step 2: Add a CHANGELOG entry**

Add under the current unreleased/dev heading, matching the file's existing bullet style:

```markdown
- Added a hashcat version interoperability CI matrix: offline contract tests run
  Hashview's status/benchmark/outfile/flag parsers over committed captures from
  five hashcat releases on every PR, and a scheduled workflow re-runs them
  against the real binaries plus a live `--skip`/`--limit` slice check, filing an
  issue when a newer hashcat release appears.
```

- [ ] **Step 3: Verify the docs reference only paths that exist**

```bash
cd /tmp/hashview-hashcat-matrix
grep -oE "tests/[a-z_/]*\.(py|sh)|\.github/workflows/[a-z-]*\.yml" TESTING.md \
  | sort -u | while read -r p; do test -e "$p" || echo "MISSING: $p"; done
echo checked
```

Expected: only `checked`.

- [ ] **Step 4: Commit**

```bash
cd /tmp/hashview-hashcat-matrix
git rev-parse --abbrev-ref HEAD
git add TESTING.md CHANGELOG.md
git commit -m "Document the hashcat interop matrix and fixture refresh process"
```

---

## Final verification

- [ ] **Run the full gates the way CI does**

```bash
cd /tmp/hashview-hashcat-matrix
mkdir -p hashview/control/{hashes,logs,rules,tmp,wordlists,wordlists_import}
python -m pytest tests/unit tests/security tests/agent_unit \
  --cov=hashview --cov-branch --cov-report=term-missing \
  --cov-report=json:coverage.json --cov-fail-under=85 -q
python tests/check_function_coverage.py coverage.json
python -m pytest tests/agent_unit --cov=agent --cov-report=term-missing --cov-fail-under=75 -q
```

- [ ] **Lint**

These are the exact commands `lint.yml` and `pylint.yml` run. Note that ruff and
pylint scan only `hashview/` and `hashview.py`, so the new test and script files
are outside their scope; bandit, however, does scan `install/hashview-agent`, so
`agent/status.py` must not introduce a new finding.

```bash
cd /tmp/hashview-hashcat-matrix
ruff check hashview/ hashview.py
pylint --jobs=1 --rcfile=.pylintrc --reports=n --score=y hashview/ hashview.py
bandit -r hashview install/hashview-agent -c pyproject.toml -b .bandit-baseline.json
```

- [ ] **Confirm the branch and push**

The pre-push hook needs a `.venv` in the worktree; a symlink to the primary
checkout's virtualenv is already in place. Never bypass the hook with
`--no-verify`.

```bash
cd /tmp/hashview-hashcat-matrix
git rev-parse --abbrev-ref HEAD   # ci/hashcat-version-matrix
git log --oneline origin/v0.8.3-dev..HEAD
git push -u origin ci/hashcat-version-matrix
```

- [ ] **Open the PR against `v0.8.3-dev`, not `main`.**
