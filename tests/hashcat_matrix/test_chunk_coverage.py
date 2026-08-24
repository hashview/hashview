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
