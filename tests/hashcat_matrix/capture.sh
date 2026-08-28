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
