"""Live proof that a measured mask keyspace tiles exactly once.

This is the assertion the mask-chunking redesign rests on, and the gap that let
the previous approach ship: the unit tests only ever checked a sub-mask against
Hashview's OWN parser, which happily accepts a mask hashcat rejects, and nothing
checked that the server's arithmetic agreed with hashcat's.

Two independent facts are pinned here.

1. `--keyspace` is not a function of the mask. hashcat splits a mask between its
   base loop -- which is what --skip/--limit index -- and its own device-side
   loop, based on the HASH MODE. `?a?a?a?a?a?a` reports 95**4 for a fast mode and
   95**5 for a slow one. That is why the server cannot compute this and an agent
   has to measure it.

2. total / keyspace is always an exact integer. That is what makes a reported
   keyspace checkable (record_keyspace_measurement refuses a remainder) rather
   than merely trusted, and it is the conversion between an agent's speed in
   candidates/sec and a cursor counting base-loop units.

Then the coverage itself: a full plan of --skip/--limit slices over the measured
keyspace recovers every planted target EXACTLY once, for -a 3, -a 6 and -a 7.

Needs a real binary; set HASHCAT_BIN to run. Skipped by default, exactly like
test_chunk_coverage.py -- the CI matrix job sets it.
"""
import hashlib
import os
import subprocess

import pytest

HASHCAT_BIN = os.environ.get("HASHCAT_BIN")

pytestmark = [
    pytest.mark.hashcat_matrix,
    pytest.mark.skipif(not HASHCAT_BIN, reason="set HASHCAT_BIN to run live hashcat tests"),
]

MD5 = 0


def _md5(text):
    return hashlib.md5(text.encode()).hexdigest()  # nosec B324 - test target, not a security control


def _keyspace(*attack_args):
    """What `hashcat --keyspace` reports. Takes NO hashfile positional: passing
    one is a usage error, which is why the server builds this argv directly
    rather than stripping flags off the run command."""
    proc = subprocess.run([HASHCAT_BIN, "--keyspace", *attack_args],
                          capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, f"--keyspace failed: {proc.stdout}{proc.stderr}"
    numbers = [line.strip() for line in proc.stdout.splitlines() if line.strip().isdigit()]
    assert numbers, f"no keyspace in output: {proc.stdout!r} {proc.stderr!r}"
    return int(numbers[-1])


def _crack(tmp_path, tag, hashes, attack_args, skip=None, limit=None):
    """Run one slice; return the set of hashes it recovered."""
    hashfile = tmp_path / f"h-{tag}.txt"
    hashfile.write_text("\n".join(hashes) + "\n", encoding="utf-8")
    outfile = tmp_path / f"o-{tag}.txt"
    potfile = tmp_path / f"p-{tag}.pot"
    argv = [HASHCAT_BIN, "-m", str(MD5), "--quiet",
            "--potfile-path", str(potfile),
            "--outfile", str(outfile), "--outfile-format", "1,3"]
    if skip is not None:
        argv += ["--skip", str(skip), "--limit", str(limit)]
    argv += [str(hashfile), *attack_args]
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=900)
    # 0 = all cracked, 1 = exhausted with some left. Anything else means the run
    # never happened, which would make "recovered nothing" pass for the wrong
    # reason.
    assert proc.returncode in (0, 1), (
        f"hashcat exited {proc.returncode}: {proc.stdout}{proc.stderr}")
    if not outfile.exists():
        return set()
    return {line.split(":", 1)[0] for line in
            outfile.read_text(encoding="utf-8").splitlines() if line.strip()}


def _plan(keyspace, slices):
    """Contiguous [skip, limit) ranges tiling [0, keyspace), as issue_slice cuts."""
    step = keyspace // slices
    plan, cursor = [], 0
    while cursor < keyspace:
        take = min(step, keyspace - cursor)
        plan.append((cursor, take))
        cursor += take
    assert sum(limit for _, limit in plan) == keyspace
    return plan


def test_the_keyspace_depends_on_the_hash_mode_not_just_the_mask():
    """The reason the server cannot compute this itself."""
    fast = _keyspace("-m", "0", "-a", "3", "?a?a?a?a?a?a")
    slow = _keyspace("-m", "1800", "-a", "3", "?a?a?a?a?a?a")

    assert fast != slow, "same mask, different keyspace -- so it must be measured"
    assert fast == 95 ** 4
    assert slow == 95 ** 5


@pytest.mark.parametrize("mode", ["0", "100", "1800", "3200"])
def test_the_candidate_total_divides_by_the_keyspace_exactly(mode):
    """`total % keyspace == 0` is what makes a reported keyspace checkable.

    record_keyspace_measurement refuses any number that leaves a remainder, and
    total // keyspace is the amplifier that converts an agent's candidates/sec
    into base-loop units.
    """
    mask, total = "?d?d?d?d?d", 10 ** 5
    keyspace = _keyspace("-m", mode, "-a", "3", mask)

    assert 0 < keyspace <= total
    assert total % keyspace == 0, f"-m {mode}: {total} % {keyspace} != 0"


def test_mask_slices_cover_the_keyspace_exactly_once(tmp_path):
    """-a 3. Four targets spread through the space, one full plan, each found once.

    hashcat's base loop is over the LATER mask positions, so which candidates fall
    in which slice is not the obvious lexicographic split -- which is exactly why
    the server must never try to predict it and only ever counts units.
    """
    plaintexts = ["00001", "31415", "77777", "99999"]
    hashes = [_md5(p) for p in plaintexts]
    attack = ["-a", "3", "?d?d?d?d?d"]

    whole = _crack(tmp_path, "whole", hashes, attack)
    assert whole == set(hashes), "the un-sliced run must find all four"

    keyspace = _keyspace("-m", str(MD5), *attack)
    hits = {h: 0 for h in hashes}
    for index, (skip, limit) in enumerate(_plan(keyspace, 4)):
        for found in _crack(tmp_path, f"s{index}", hashes, attack, skip, limit):
            hits[found] += 1

    assert hits == {h: 1 for h in hashes}, f"not exactly-once: {hits}"


def test_hybrid_slices_cover_the_keyspace_exactly_once(tmp_path):
    """-a 6 (word+mask) and -a 7 (mask+word).

    The two differ in which side is the base loop -- measured: -a 6 reports the
    wordlist's line count, -a 7 reports the mask's keyspace -- so a plan that
    tiles one does not automatically tile the other.
    """
    words = ["aa", "bb", "cc", "dd"]
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("\n".join(words) + "\n", encoding="utf-8")

    for mode, plaintexts, attack in (
        ("6", ["aa00", "bb42", "cc77", "dd99"], [str(wordlist), "?d?d"]),
        ("7", ["00aa", "42bb", "77cc", "99dd"], ["?d?d", str(wordlist)]),
    ):
        hashes = [_md5(p) for p in plaintexts]
        whole = _crack(tmp_path, f"whole{mode}", hashes, ["-a", mode, *attack])
        assert whole == set(hashes), f"-a {mode}: the un-sliced run must find all four"

        keyspace = _keyspace("-m", str(MD5), "-a", mode, *attack)
        hits = {h: 0 for h in hashes}
        for index, (skip, limit) in enumerate(_plan(keyspace, min(4, keyspace))):
            for found in _crack(tmp_path, f"{mode}s{index}", hashes,
                                ["-a", mode, *attack], skip, limit):
                hits[found] += 1

        assert hits == {h: 1 for h in hashes}, f"-a {mode} not exactly-once: {hits}"


def test_the_server_built_probe_argv_agrees_with_hashcat():
    """The argv build_keyspace_command emits must be one hashcat actually accepts.

    Rebuilt here rather than imported, because tests/hashcat_matrix runs without
    the server's dependencies; the shape is asserted against the real binary,
    which is the half that cannot be unit-tested.
    """
    argv = ["-O", "-w", "3", "-m", "0", "-a", "3", "?d?d?d?d"]
    assert _keyspace(*argv) == _keyspace("-m", "0", "-a", "3", "?d?d?d?d"), (
        "-O and -w must not change the measured keyspace")
