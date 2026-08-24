# hashcat Version Interoperability CI — Design

Date: 2026-08-24
Status: Approved for implementation

## Problem

Hashview's server and agent parse hashcat's machine-readable output and depend
on the acceptance and semantics of the flags the server emits. Neither is a
stable API. When a new hashcat release changes them, Hashview degrades quietly:
`hashcatParser` swallows unparseable status lines with a `LOG.debug`, so a
broken status schema surfaces as a blank dashboard rather than an error.

Today CI never runs real hashcat. The multi-agent crack e2e test
(`docker-compose.e2e.yml`) points `HC_BIN_PATH` at `tests/e2e/crack/shim/`, a
Python test double. The shim emits a hand-written four-key status object, so it
proves the agent's plumbing works but cannot detect upstream drift.

Two concrete drift items already exist:

- hashcat 7.1.2's release notes state it "restores backward compatibility in
  machine-readable status view mode", which means 7.1.0 and 7.1.1 broke it.
- The unreleased 7.1.x changelog states "`--skip` and `--limit` now apply to the
  whole run". Those are the exact flags `build_hashcat_command` emits to slice
  work across agents. If that ships as written, chunk boundaries would be
  computed against a different keyspace than hashcat applies them to, producing
  overlapping or skipped candidates with no error.

## Interoperability contract

Five machine-readable surfaces, each traced to its consumer in the codebase.
These are what the tests assert; nothing else about hashcat's output is pinned.

1. **`--status-json` status line.** Every line beginning with `{` parses as
   JSON, and each carries `estimated_stop` (integer epoch seconds),
   `recovered_hashes` (2-element array), and a `devices` array whose entries
   carry `speed`, `device_type`, and `device_name`. `temp` is optional.
   Consumer: `hashcatParser` and `parse_device_info`
   (`install/hashview-agent/hashview-agent.py`, `agent/bench.py`).
2. **Benchmark speed line.** `hashcat -b -m <mode>` emits at least one
   `Speed.#<n>...: <number> <unit>H/s` line that `parse_benchmark_speed`
   resolves to a positive integer. Consumer: `agent/bench.py`.
3. **Outfile format.** `--outfile-format 1,3` writes `<hash>:<hex_plain>`, and
   `decode_hex_plain` recovers the original plaintext byte-for-byte.
   Consumer: `hashview/utils/utils.py`.
4. **Flag acceptance.** Every token `build_hashcat_command` can emit is accepted
   by the binary: `-O`, `-w`, `--session`, `-m`, `--potfile-path`, `--status`,
   `--status-timer=`, `--outfile-format`, `--outfile`, `--skip`, `--limit`,
   `--loopback`, `--hex-salt`, `-a`, `-r`, `-j`, `-k`.
   Consumer: `hashview/utils/utils.py:build_hashcat_command`.
5. **`--skip`/`--limit` slice semantics.** With a wordlist of N words and rules
   applied, a `--skip`/`--limit` slice covers the word range the chunk planner
   intends. Asserted behaviourally: the union of all planned chunks recovers
   every hash exactly once, with no gaps and no double coverage.
   Consumer: `hashview/utils/chunking.py`.

## Architecture

Three tiers, separated because they answer different questions. Tier 1 asks
"did we break our parser". Tier 2 asks "did hashcat change under us". Tier 3
asks "has something new shipped upstream". Collapsing them would make every
parser refactor wait on five binary downloads.

### Tier 1 — offline contract tests

`tests/agent_unit/test_hashcat_contract.py` runs the real parser functions over
committed golden fixtures at `tests/fixtures/hashcat/<version>/`, one directory
per matrix version containing `version.txt`, `status.txt` (raw stdout, so the
skip-non-JSON path is exercised too), `benchmark.txt`, `outfile.txt`,
`help.txt`, and a derived `summary.json`. No hashcat binary, no network.
Parameterised over every fixture directory present, so adding a version is a
directory drop.

It lives in `tests/agent_unit/` rather than `tests/unit/` because
`unit-tests.yml` includes that directory in *both* coverage runs, so the test
earns credit under `--cov=agent` and `--cov=hashview` alike.

Reaching the status parser requires a prerequisite refactor: `hashcatParser`
currently lives in `hashview-agent.py`, which calls `argparse.parse_args()` at
import time and imports `psutil`, so no test can import it. It moves verbatim
into a new dependency-free `install/hashview-agent/agent/status.py`, following
the pattern `agent/bench.py` already set. Behaviour is unchanged.

Runs in the existing `unit-tests.yml` job on every PR. This is the only tier
that gates ordinary PRs.

### Tier 2 — real hashcat matrix

New workflow `.github/workflows/hashcat-matrix.yml`, one matrix leg per pinned
version. Each leg installs `pocl-opencl-icd` and `p7zip-full`, downloads the
sha256-pinned release archive from GitHub, and runs a capture script that
produces the same artifacts Tier 1 consumes. It then runs the Tier 1 assertions
against the freshly captured artifacts, plus the chunk-coverage check from
contract item 5, and diffs the capture against the committed fixture so an
upstream change to a *pinned* version is also caught.

The drift diff compares `summary.json`, not the raw capture. Raw output embeds
timestamps, measured speeds, session ids, and temp paths, none of which are
stable between runs. The summary keeps only the shape Hashview depends on:
which keys appear in the status objects, which keys appear per device, which of
our flags the binary advertises, the outfile field count, and the number of
benchmark speed lines.

A stock `ubuntu-latest` runner with pocl and no GPU is sufficient; this was
verified by running prebuilt 6.2.6 and 7.1.2 binaries in a clean
`ubuntu:24.04` container, both of which cracked a real NTLM hash and emitted
parseable status JSON.

Starting matrix:

| Version | Blocking | Rationale |
|---|---|---|
| 6.2.6 | yes | The version `hashview/utils/hashcat_modes.py` is generated from |
| 7.0.0 | yes | First 7.x release |
| 7.1.0 | no | Known-broken machine-readable status |
| 7.1.1 | no | Known-broken machine-readable status |
| 7.1.2 | yes | Current release |

7.1.0 and 7.1.1 are included deliberately as canaries: they demonstrate the job
detects a real break. They are non-blocking so a known-bad upstream release
does not hold CI red.

Triggers: weekly schedule, `workflow_dispatch`, and pull requests touching
`install/hashview-agent/**`, `hashview/utils/utils.py`,
`hashview/utils/chunking.py`, `tests/fixtures/hashcat/**`, or the workflow
itself.

### Tier 3 — floating release check

A scheduled, never-blocking job that queries the GitHub releases API for any
release tag newer than the highest pinned version and runs the Tier 2 capture
and assertions against it. On failure or divergence it opens a GitHub issue
containing the diff rather than failing the build, so a new upstream release
arrives as a ticket instead of a red X on a branch that did not cause it.

Issue creation is idempotent: the job searches for an open issue with the same
title before creating one.

## Components

| Component | Path | Responsibility |
|---|---|---|
| Status parser | `install/hashview-agent/agent/status.py` | Dependency-free `--status-json` parsing, extracted from `hashview-agent.py` so it is importable. |
| Capture script | `tests/hashcat_matrix/capture.sh` | Given a hashcat binary and an output dir, produce `version.txt`, `status.txt`, `benchmark.txt`, `outfile.txt`, `help.txt`. Knows nothing about assertions. |
| Fetch script | `tests/hashcat_matrix/fetch.sh` | Given a version and expected sha256, download, verify, and unpack a release. Knows nothing about capture. |
| Summarizer | `tests/hashcat_matrix/summarize.py` | Reduce a capture to a volatile-free `summary.json` for the drift diff. |
| Contract assertions | `tests/agent_unit/test_hashcat_contract.py` | Assert contract items 1-4 against a fixture directory. Pure pytest, no subprocess. |
| Chunk coverage test | `tests/hashcat_matrix/test_chunk_coverage.py` | Contract item 5. Needs a live binary, so it is Tier 2 only. |
| Fixtures | `tests/fixtures/hashcat/<version>/` | Committed captures. |
| Workflow | `.github/workflows/hashcat-matrix.yml` | Tiers 2 and 3. |

The split between fetch and capture keeps each independently runnable: a
developer can point `capture.sh` at a locally built hashcat without touching
the download path.

## Test data

A five-word wordlist and a single NTLM hash (mode 1000), all synthetic. NTLM is
chosen because it is fast under pocl, is the mode the existing crack e2e uses,
and exercises the hex-plain outfile path. Chunk-coverage uses a longer
synthetic wordlist so the planner produces more than one chunk.

No real or client-derived hashes, wordlists, or plaintexts appear in fixtures.

## Error handling

- Download or checksum failure fails the leg immediately; a corrupted archive
  must not be silently treated as an interop break.
- A leg that produces zero status lines fails with the captured stderr
  attached, distinguishing "hashcat would not run here" from "hashcat's output
  changed".
- Captured artifacts upload as workflow artifacts on failure so the actual
  output is inspectable without rerunning.
- Tier 3 never fails the workflow run; its outcome is an issue.

## Out of scope

- GPU runners and vendor runtimes (CUDA, HIP, Metal).
- Hash modes other than NTLM. The contract is about output format, not mode
  coverage; `hashcat_modes.py` regeneration is a separate concern.
- Automatically updating fixtures or the pinned matrix. A human decides whether
  a drift is a hashcat bug to wait out or a Hashview change to make.
