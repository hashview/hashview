"""Live hashcat coverage for MASK chunks (issue: mask read as a command option).

tests/test_chunk_coverage.py covers the wordlist chunk path (--skip/--limit).
The mask path had no live coverage at all, and that is exactly why a broken
chunk shipped: chunking plans mask chunks by expanding the leading mask position
into literal characters, and ?s (so also ?a) contains '-'. The resulting argv
element '-?d?d' is claimed by hashcat's OPTION parser before the mask parser
sees it. The unit tests could not catch it, because they assert a sub-mask is
valid using Hashview's OWN parser -- and parse_mask('-?d?d') is perfectly happy.

So every assertion here runs REAL hashcat over the REAL planner output, built
through the REAL argv assembler. Nothing is hand-written; a hand-written list
would drift from what production emits, which is the failure mode being fixed.

Needs a real binary; set HASHCAT_BIN to run. Skipped by default.
"""
import os
import subprocess

import pytest

from hashview.utils.chunking import plan_chunks
from hashview.utils.utils import mask_attack_argv

HASHCAT_BIN = os.environ.get("HASHCAT_BIN")

pytestmark = [
    pytest.mark.hashcat_matrix,
    pytest.mark.skipif(not HASHCAT_BIN, reason="set HASHCAT_BIN to run live hashcat tests"),
]

# ?s?d?d split at the leading position -> 33 chunks of '<literal>?d?d', one of
# which is '-?d?d'. ?s rather than ?a keeps the run inside the CI budget (33
# hashcat invocations instead of 95) while exercising the identical code path
# and the identical character.
MASK = "?s?d?d"
TARGET_SECONDS = 100

# Two targets in two different chunks: '-77' is reachable only from the '-?d?d'
# chunk (the one that is broken without the fix) and '!33' only from '!?d?d'.
TARGETS = {
    "75f7508e6d57bac3a6260f7932f19d0d": "-77",
    "210ab2db60aab1d743ffcfe90290ac64": "!33",
}


def _submasks():
    specs = plan_chunks(3, mask=MASK, slowest_speed=1, target_seconds=TARGET_SECONDS)
    masks = [s["mask"] for s in specs]
    # Guard the premise: if the planner ever stops producing a '-'-leading chunk
    # this file silently stops testing anything.
    assert len(masks) > 1, f"mask did not chunk: {specs}"
    assert "-?d?d" in masks, f"no '-'-leading chunk in the plan: {masks}"
    return masks


def _run(tmp_path, argv, tag, extra=()):
    """Run one chunk's argv the way the agent does, and report what it recovered."""
    hashes = tmp_path / f"h-{tag}.txt"
    hashes.write_text("\n".join(TARGETS) + "\n", encoding="utf-8")
    outfile = tmp_path / f"o-{tag}.txt"

    full = [HASHCAT_BIN, "-m", "0", "-O", "-w", "3",
            "--potfile-path", str(tmp_path / f"p-{tag}.pot"),
            "--outfile-format", "1,3", "--outfile", str(outfile),
            "--session", f"mc{tag}", *extra,
            *[str(hashes) if t == "@HASHES@" else t for t in argv]]
    proc = subprocess.run(full, check=False, capture_output=True,
                          timeout=300, text=True, cwd=str(tmp_path))
    recovered = set()
    if outfile.exists():
        recovered = {ln.rsplit(":", 1)[0].lower()
                     for ln in outfile.read_text(encoding="utf-8").splitlines() if ln.strip()}
    return proc, recovered


def _argv(submask, attackmode=3, wordlist=""):
    return mask_attack_argv(attackmode, "@HASHES@", wordlist, submask, from_chunk=True)


def test_every_planned_submask_runs(tmp_path):
    """The bug, stated as a test: today ten of these exit 255 with
    "hashcat: invalid option" -- and '-1'..'-4' with "option requires an
    argument", because those are hashcat's custom-charset flags."""
    broken = []
    for i, submask in enumerate(_submasks()):
        proc, _ = _run(tmp_path, _argv(submask), f"run{i}")
        if (proc.returncode not in (0, 1)
                or "invalid option" in proc.stderr
                or "No such file or directory" in proc.stderr):
            broken.append((submask, proc.returncode, proc.stderr.strip().splitlines()[:1]))
    assert not broken, f"sub-masks hashcat refused: {broken}"


def test_the_dash_chunk_is_what_breaks_without_the_sentinel(tmp_path):
    """Negative control. Without this, a refactor that quietly dropped '--'
    would leave the test above green for the wrong reason."""
    argv = [t for t in _argv("-?d?d") if t not in ("--", "--status-json")]
    proc, _ = _run(tmp_path, argv, "nosentinel")
    assert proc.returncode == 255
    assert "invalid option" in proc.stderr


def test_planned_chunks_cover_the_targets_exactly_once(tmp_path):
    """Union of the full plan recovers both targets, and each is recovered by
    exactly one chunk: no gap, no double coverage."""
    hits = {h: 0 for h in TARGETS}
    for i, submask in enumerate(_submasks()):
        _, recovered = _run(tmp_path, _argv(submask), f"cov{i}")
        for h in recovered:
            assert h in hits, f"chunk {submask!r} recovered an unexpected hash {h}"
            hits[h] += 1
    assert hits == {h: 1 for h in TARGETS}, f"coverage is not exactly-once: {hits}"


@pytest.mark.parametrize("attackmode", [3, 6, 7])
def test_sentinel_carries_a_dash_mask_in_every_mask_mode(tmp_path, attackmode):
    """Modes 6 and 7 put the mask in a different positional slot, so each needs
    its own proof that the sentinel lands in the right place."""
    wordlist = tmp_path / f"wl{attackmode}.txt"
    wordlist.write_text("\n", encoding="utf-8")   # one empty word: mask-only
    submask = "-?d?d"
    proc, recovered = _run(tmp_path, _argv(submask, attackmode, str(wordlist)),
                           f"mode{attackmode}")

    assert proc.returncode in (0, 1), (
        f"mode {attackmode} exited {proc.returncode}: {proc.stderr.strip()!r}")
    assert "invalid option" not in proc.stderr
    assert "75f7508e6d57bac3a6260f7932f19d0d" in recovered, (
        f"mode {attackmode} did not recover '-77': {proc.stderr.strip()!r}")


def test_server_emitted_status_json_is_honoured_before_the_sentinel(tmp_path):
    """The constraint that shaped the whole design.

    Everything after '--' is a positional, so a --status-json placed there is not
    honoured at all. build_hashcat_command therefore emits the flag PAIRED with
    the sentinel, ahead of it.

    "Honoured" is asserted from hashcat's own output shape: with --status-json in
    effect it emits no human-readable 'Status...:' block. That is deterministic
    even on a run far too short to reach the status timer, unlike counting JSON
    objects. (Placement itself is unit-tested in tests/agent_unit and
    tests/unit/test_mask_argv.py; what needs a real binary is whether hashcat
    honours it there.)
    """
    argv = _argv("-?d?d")
    assert argv.index("--status-json") < argv.index("--")

    proc, recovered = _run(tmp_path, argv, "sj", extra=("--status", "--status-timer=1"))
    assert proc.returncode in (0, 1), proc.stderr.strip()
    assert "75f7508e6d57bac3a6260f7932f19d0d" in recovered
    assert not [ln for ln in proc.stdout.splitlines() if ln.startswith("Status.")], (
        "hashcat printed its human-readable status block, so --status-json was "
        f"not honoured: {proc.stdout[:400]!r}")


def test_status_json_only_after_the_sentinel_is_ignored(tmp_path):
    """Negative control, and the reason the agent had to change: an agent that
    appends the flag (the pre-fix behaviour) puts it after '--', where hashcat
    silently ignores it -- no error, telemetry just stops."""
    argv = [t for t in _argv("-?d?d") if t != "--status-json"] + ["--status-json"]
    proc, _ = _run(tmp_path, argv, "sjafter", extra=("--status", "--status-timer=1"))

    assert proc.returncode in (0, 1), proc.stderr.strip()
    assert [ln for ln in proc.stdout.splitlines() if ln.startswith("Status.")], (
        "expected the human-readable status block, i.e. --status-json ignored")


@pytest.mark.parametrize("attackmode", [3, 6, 7])
def test_an_old_agents_duplicate_flag_across_every_mask_mode(tmp_path, attackmode):
    """The back-compat claim, verified live in all three mask modes.

    An un-upgraded agent appends --status-json to whatever it is sent, and after
    the sentinel that token is an extra POSITIONAL. Whether that is harmless
    depends entirely on how many positionals the mode already has:

      * mode 3 takes <hashfile> <mask>, so the duplicate is a third positional
        hashcat ignores. The chunk runs, cracks, and still reports status.
      * mode 6 takes <hashfile> <wordlist> <mask>; the duplicate becomes a
        fourth, and hashcat opens the MASK as a wordlist.
      * mode 7 takes <hashfile> <mask> <wordlist>; it opens --status-json as one.

    Both hybrids exit 255. That is not a regression -- they are equally broken
    with a dash mask before this change -- and it is what the CHANGELOG means by
    "modes 6 and 7 with such a mask need the updated agent". Pinned per mode so
    the claim rests on measurement rather than on mode 3 generalised.
    """
    wordlist = tmp_path / f"dupwl{attackmode}.txt"
    wordlist.write_text("\n", encoding="utf-8")   # one empty word: mask-only
    argv = _argv("-?d?d", attackmode, str(wordlist)) + ["--status-json"]
    proc, recovered = _run(tmp_path, argv, f"dup{attackmode}",
                           extra=("--status", "--status-timer=1"))

    if attackmode == 3:
        assert proc.returncode in (0, 1), proc.stderr.strip()
        assert "75f7508e6d57bac3a6260f7932f19d0d" in recovered
        assert not [ln for ln in proc.stdout.splitlines() if ln.startswith("Status.")]
    else:
        assert proc.returncode == 255, (
            f"mode {attackmode} unexpectedly survived the duplicate: "
            f"{proc.returncode} {proc.stderr.strip()!r}")
        assert "No such file or directory" in proc.stderr, proc.stderr.strip()
