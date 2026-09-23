"""Live check that hashcat still ACCEPTS every flag the server emits.

`test_binary_advertises_every_documented_flag_the_server_emits` reads the text
of `--help`, which is all a committed fixture can support. That is a proxy, and
it is wrong in both directions:

  * a flag can vanish from `--help` and keep working -- hashcat retired workload
    profiles in 083046e7 and kept `-w` "accepted and ignored", which the help
    check reported as an interop break when nothing had broken;
  * a flag can stay in `--help` and stop working, and the help check would
    never notice. That direction is the dangerous one. Hashview builds its
    command from these flags, so a flag becoming a hard error does not degrade
    anything gracefully: every job dies at launch.

So this asks the binary instead of reading its documentation. Needs a real
hashcat; skipped by default, and run by both the pinned matrix and the
bleeding-edge tier.

Probed bare, without a value, on purpose. Several of these need an argument and
will complain about the missing one -- that is fine and is not what is being
measured. hashcat distinguishes the two cases in its own words: an unknown
option is "unrecognized option", while a known option given a bad value gets a
message about the VALUE (`-j x` -> "Invalid or unsupported rule specified").
Matching on that phrase rather than on the exit status is what lets one probe
cover flags with and without arguments, and it is why `-j` is testable here at
all.
"""
import importlib.util
import os
import subprocess
from pathlib import Path

import pytest

# Loaded by path rather than as `tests.hashcat_matrix.summarize`, matching
# tests/agent_unit/test_hashcat_contract.py. The package import only resolves
# when pytest is invoked from the repo root, and collection here must not depend
# on the caller's working directory -- a collection error in this directory is
# indistinguishable from the gate being switched off.
_SUMMARIZE_PATH = Path(__file__).resolve().parent / "summarize.py"
_spec = importlib.util.spec_from_file_location("hv_hc_summarize_flags", _SUMMARIZE_PATH)
summarize = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(summarize)

HASHCAT_BIN = os.environ.get("HASHCAT_BIN")

pytestmark = [
    pytest.mark.hashcat_matrix,
    pytest.mark.skipif(not HASHCAT_BIN, reason="set HASHCAT_BIN to run live hashcat tests"),
]

# hashcat's own wording for an option it does not know. Anything else -- a
# missing argument, an out-of-range value -- means the flag itself parsed.
_UNKNOWN = "unrecognized option"


def _probe(flag):
    """Everything hashcat says when handed `flag` with nothing else to do."""
    proc = subprocess.run(
        [HASHCAT_BIN, flag, "--version"],
        capture_output=True, timeout=60,
    )
    return (proc.stdout + proc.stderr).decode("utf-8", "replace")


@pytest.mark.parametrize("flag", summarize.REQUIRED_FLAGS)
def test_hashcat_still_accepts_the_flag(flag):
    """Every flag build_hashcat_command can emit, advertised or not."""
    output = _probe(flag)
    assert _UNKNOWN not in output.lower(), (
        f"hashcat no longer accepts {flag}, which build_hashcat_command emits; "
        f"every job would die at launch. Output: {output.strip()[:200]}")


def test_the_probe_can_tell_an_unknown_flag_apart():
    """Negative control. Without this the test above passes for any flag at all
    the moment hashcat changes its wording, and a whole contract silently
    becomes a no-op that always reports green."""
    output = _probe("--definitely-not-a-hashcat-flag")
    assert _UNKNOWN in output.lower(), (
        "hashcat did not say 'unrecognized option' for a flag that does not "
        f"exist, so the acceptance probe proves nothing. Output: {output.strip()[:200]}")


def test_anything_claiming_the_help_exemption_is_at_least_accepted():
    """ACCEPTED_ONLY_FLAGS is an exemption from the --help check, so nothing may
    sit in it unverified -- that would be a flag checked by nothing at all,
    which is worse than the proxy this split replaced. Empty today, and this
    passes vacuously; it exists for the next flag upstream retires."""
    for flag in summarize.ACCEPTED_ONLY_FLAGS:
        assert _UNKNOWN not in _probe(flag).lower(), (
            f"{flag} is exempt from the --help check and is not accepted "
            f"either, so nothing is verifying it")


def test_the_command_builder_no_longer_asks_for_a_workload_profile():
    """hashcat 083046e7 retired workload profiles, so -w is dead weight in a
    command the agent runs verbatim. Pinned because nothing else would notice
    it coming back: the flag is still accepted, so a reintroduced -w would run
    perfectly well and simply stop meaning anything."""
    assert "-w" not in summarize.REQUIRED_FLAGS, (
        "-w is back in the flag contract; build_hashcat_command should not be "
        "emitting it")
