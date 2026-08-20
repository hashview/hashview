"""xfail tests pinning the agent ETA bug from issue #402.

#402 is chiefly about mask files bypassing chunking. This file covers the
user-visible ETA symptom of the same root cause, which is independent of the
planner and fixable on its own.

hashcat's ``estimated_stop`` is the absolute epoch at which the CURRENT attack
ends. With a mask file every line is its own attack, so the value resets per
line and, on the terminal status line of each mask, equals the moment the mask
finished. ``time_difference`` (install/hashview-agent/hashview-agent.py:533)
subtracts ``datetime.now()`` and, for any delta <= 0, returns the sentence
"The specified time is in the past." ``hashcatParser`` wraps that in parens as
``Time_Estimated`` (:598) and the dashboard's ``_eta_text``
(hashview/main/routes.py:170) prints whatever is between the parentheses, so an
operator sees:

    eta (The specified time is in the past.)

hashcat itself never does this. At 100% progress its own status output reads
``Time.Estimated...: <date> (0 secs)`` — it clamps the relative figure at zero.
The tests below assert only that the error sentence does not reach the ETA
field; they deliberately do not pin an exact replacement string. See the note
above test_completed_attack_clamps_instead_of_reporting_an_error for why that
choice is a design decision rather than something the measurement settles.

Measured against hashcat v7.1.2-484-g64e1bff93 (single GPU, -m 0, three long
masks, --status-timer=2). The countdown is accurate while a mask runs
(+9s, +6s, +3s, +2s, 0s) and only the terminal line of each mask goes negative,
so this is a sawtooth that repeats once per line of the file rather than an
artefact of cheap masks. STATUS_JSON_TERMINAL below is a real captured line
from that run.

Each xfail asserts the DESIRED behaviour and is ``strict=True``: when the bug
is fixed the test passes and strict-xfail turns that unexpected pass into a
failure, as a reminder to drop the marker. Matches the convention in
tests/agent_unit/test_issue_xfail_agent_robustness.py.
"""
import importlib.util
import json
import os
import sys
import time
import types
from pathlib import Path
from unittest import mock

import pytest

AGENT_ROOT = Path(__file__).resolve().parents[2] / "install" / "hashview-agent"


def _load_agent_main():
    # Mirrors the loader in test_issue_xfail_agent_robustness.py: the agent is a
    # script, parses argv and has an interactive first-run gate at import time,
    # and imports psutil (not a test dependency), so stub and patch around it.
    if "psutil" not in sys.modules:
        stub = types.ModuleType("psutil")

        class _PsutilError(Exception):
            pass

        stub.Error = _PsutilError
        stub.NoSuchProcess = type("NoSuchProcess", (_PsutilError,), {})
        stub.AccessDenied = type("AccessDenied", (_PsutilError,), {})
        stub.ZombieProcess = type("ZombieProcess", (_PsutilError,), {})
        stub.process_iter = lambda *a, **k: []
        sys.modules["psutil"] = stub

    real_exists = os.path.exists
    path = AGENT_ROOT / "hashview-agent.py"
    with mock.patch.object(sys, "argv", ["hashview-agent.py"]), \
         mock.patch(
             "os.path.exists",
             side_effect=lambda p: True if str(p).endswith("agent/config.conf") else real_exists(p),
         ):
        spec = importlib.util.spec_from_file_location("hashview_agent_main_eta", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    return mod


agent_main = _load_agent_main()

PAST_SENTINEL = "The specified time is in the past."

# A real --status-json line captured at the terminal status of a mask
# (progress 100%, estimated_stop == the second the mask ended). Trimmed to the
# fields hashcatParser reads, plus the guess.* block. The target is hashcat's
# own documented example hash for -m 0.
STATUS_JSON_TERMINAL = {
    "session": "hashcat",
    "guess": {
        "guess_base": "?d?d?d?d?d?d?d?d?d?d?d",
        "guess_base_count": 3,
        "guess_base_offset": 1,
        "guess_base_percent": 33.33,
        "guess_mode": 9,
    },
    "status": 5,
    "target": "8743b52063cd84097a65d1633f5c74f5",
    "progress": [100000000000, 100000000000],
    "recovered_hashes": [0, 1],
    "recovered_salts": [0, 1],
    "devices": [{"device_id": 1, "device_name": "test", "device_type": "GPU",
                 "speed": 1000000, "temp": -1, "util": 0}],
    "time_start": 1787243729,
    "estimated_stop": 1787243729,
}


# ---------------------------------------------------------------------------
# Regression guard — the normal path must keep working through any fix
# ---------------------------------------------------------------------------
def test_future_estimated_stop_still_formats_as_a_duration():
    """Mid-mask, a future estimated_stop renders as a human duration."""
    # +2h rather than +1h: the sub-second part of now() truncates the delta, so
    # exactly 3600s away renders as "59 minutes, 59 seconds".
    out = agent_main.time_difference(int(time.time()) + 7200)
    assert PAST_SENTINEL not in out
    assert "hour" in out


# ---------------------------------------------------------------------------
# #402 — time_difference must clamp at zero the way hashcat does
#
# NOTE ON THE ORACLE — this assertion encodes a design decision, not a
# measurement, and a maintainer may legitimately want to change it.
#
# What is measured, and not in dispute: hashcat emits estimated_stop == now on
# the terminal status line of every mask, we read it up to one 15s poll later,
# and time_difference turns any delta <= 0 into a sentence that reaches the
# dashboard as the ETA value. That the current output is wrong is a fact.
#
# What is chosen: WHAT the right output is. These tests assert only that the
# error sentence is absent, deliberately not asserting an exact replacement
# string, because at least three answers are defensible:
#
#   * "0 seconds" / "(0 secs)"  — matches hashcat's own clamp, so the UI reads
#     the same as `hashcat --status`. What the issue comment argues for.
#   * "finishing" / "almost done" — arguably truer, since the mask really is
#     done and only the next one's autotune is pending.
#   * None / empty — let the dashboard decide how to render "no estimate",
#     rather than baking a display string into the agent.
#
# A fix picking any of those passes these tests. Only a fix that still lets
# PAST_SENTINEL reach Time_Estimated fails them. If the project settles on a
# specific string, tightening these asserts to match it is the right follow-up.
# ---------------------------------------------------------------------------
@pytest.mark.xfail(
    strict=True,
    reason="#402: hashcat clamps a completed attack to '(0 secs)'; "
           "time_difference returns the sentence 'The specified time is in "
           "the past.' for any delta <= 0, which the dashboard then renders "
           "as the ETA value.",
)
@pytest.mark.parametrize(
    "label,offset",
    [
        ("estimated_stop == now (hashcat's value at 100%)", 0),
        ("terminal line, 1s stale", -1),
        ("terminal line, sampled one 15s poll later", -15),
    ],
)
def test_completed_attack_clamps_instead_of_reporting_an_error(label, offset):
    out = agent_main.time_difference(int(time.time()) + offset)
    assert PAST_SENTINEL not in out, f"{label}: got {out!r}"


# ---------------------------------------------------------------------------
# #402 — the string must not reach Time_Estimated via hashcatParser
# ---------------------------------------------------------------------------
@pytest.mark.xfail(
    strict=True,
    reason="#402: hashcatParser wraps time_difference's output as "
           "Time_Estimated, so a terminal status line puts an error sentence "
           "in the field the dashboard prints as the ETA.",
)
def test_terminal_status_line_does_not_yield_an_error_string_as_the_eta(tmp_path):
    status_file = tmp_path / "hashcat.out"
    status_file.write_text(json.dumps(STATUS_JSON_TERMINAL) + "\n")

    status = agent_main.hashcatParser(str(status_file))

    assert PAST_SENTINEL not in status.get("Time_Estimated", "")


# ---------------------------------------------------------------------------
# Documents the data available for a real fix (asserts hashcat's format, not
# ours, so it is a guard rather than a lock on current behaviour).
# ---------------------------------------------------------------------------
def test_status_json_carries_the_mask_queue_position():
    """hashcat reports 'mask N of M' as guess_base_offset/guess_base_count.

    Displayed by hashcat as ``Guess.Queue......: 1/3 (33.33%)``. hashcatParser
    reads only estimated_stop, recovered_hashes and devices, so file-level
    progress needs no new computation to report — only forwarding.
    """
    guess = STATUS_JSON_TERMINAL["guess"]
    assert guess["guess_base_count"] == 3
    assert guess["guess_base_offset"] == 1
    assert guess["guess_base_percent"] == pytest.approx(33.33)
