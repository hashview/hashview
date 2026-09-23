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
#
# Two lists, not one, because "hashcat documents this flag" and "hashcat still
# accepts this flag" are different claims and they have now come apart. What
# Hashview actually depends on is the second one: the command it builds has to
# run. Advertisement in --help is only ever a proxy for that, and checking a
# proxy means a purely cosmetic upstream edit reads as an interop break while a
# flag quietly becoming a hard error would not be caught until a job died.
#
# ADVERTISED_FLAGS is still checked against the text of --help, which is all an
# offline fixture can support. ACCEPTED_ONLY_FLAGS is exempt from that and is
# probed by actually invoking the binary -- see
# tests/hashcat_matrix/test_flag_acceptance.py. Every flag in either list is
# probed; only the advertised ones additionally have to appear in --help.

# Documented, and expected to stay documented. A flag vanishing from --help here
# is worth a human looking, even when it still works.
ADVERTISED_FLAGS = [
    "-O", "--session", "-m", "--potfile-path", "--status",
    "--status-timer", "--outfile-format", "--outfile", "--skip", "--limit",
    "--loopback", "--hex-salt", "-a", "-r", "-j", "-k",
]

# Accepted by the parser but no longer documented. Empty right now, and kept
# rather than deleted because the distinction is the point: -w lived here for
# exactly as long as build_hashcat_command emitted a flag hashcat had stopped
# documenting, and the next retirement upstream will need somewhere to go that
# is not a red build. A flag belongs here only while the command builder still
# emits it; -w does not any more, so it is in neither list.
ACCEPTED_ONLY_FLAGS = []

# Everything the command builder can emit, both kinds together.
REQUIRED_FLAGS = ADVERTISED_FLAGS + ACCEPTED_ONLY_FLAGS

# Top-level keys that hashcat_status (install/hashview-agent/agent/status.py) reads.
# The summary is diffed across machines in CI, so it must contain only
# environment-independent facts, excluding per-device telemetry keys that vary by driver.
REQUIRED_STATUS_KEYS = ["devices", "estimated_stop", "recovered_hashes"]

# Per-device keys that hashcat_status and parse_device_info (install/hashview-agent/agent/bench.py)
# read. Excludes temp, fanspeed, corespeed, memoryspeed, buslanes, power: their presence varies
# by device and driver, making them unsuitable for cross-machine CI diff.
REQUIRED_DEVICE_KEYS = ["device_name", "device_type", "speed"]


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

    # Keep only the keys Hashview actually reads, not every key hashcat emits.
    status_keys = sorted(status_keys & set(REQUIRED_STATUS_KEYS))
    device_keys = sorted(device_keys & set(REQUIRED_DEVICE_KEYS))

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
        "advertised_flags": advertised,
        "benchmark_speed_lines": len(re.findall(r"Speed\.#\d+", bench)),
        "device_keys": device_keys,
        "has_parseable_status": bool(objects),
        "outfile_field_counts": sorted({len(ln.split(":")) for ln in outfile_lines}),
        "outfile_line_count": len(outfile_lines),
        "status_keys": status_keys,
        "version": (capture_dir / "version.txt").read_text(encoding="utf-8").strip(),
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
