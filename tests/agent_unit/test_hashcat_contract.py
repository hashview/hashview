"""Contract tests: Hashview's parsers against real hashcat output.

Every fixture under tests/fixtures/hashcat/<version>/ is a capture from a real
hashcat release (see tests/hashcat_matrix/capture.sh). These tests run the
production parsers over those captures, so a hashcat release that changes the
machine-readable surface fails here rather than silently blanking the dashboard
-- hashcatParser swallows unparseable status lines with a LOG.debug.

Assertions are structural, never value-exact: speeds, timestamps and device
names differ per machine.
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

# The plaintext capture.sh cracks, and its NTLM hash.
EXPECTED_PLAINTEXT = "password"
EXPECTED_HASH = "8846f7eaee8fb117ad06bdd830b7586c"


def _as_tuple(version):
    """'7.1.10' -> (7, 1, 10). Numeric so ordering is by version rather than by
    string, where '7.1.10' sorts before '7.1.2' and '10.0' before '7.0'. A
    non-numeric component sorts last rather than raising, so an odd directory
    name cannot break collection for every other version."""
    parts = []
    for part in version.split("."):
        parts.append(int(part) if part.isdigit() else float("inf"))
    return tuple(parts)


def _versions():
    if not FIXTURE_ROOT.is_dir():
        return []
    return sorted((p.name for p in FIXTURE_ROOT.iterdir() if p.is_dir()),
                  key=_as_tuple)


ALL_VERSIONS = [pytest.param(v) for v in _versions()]
# No pinned version currently emits broken --status-json, so the status-contract
# tests run the same set; kept as a separate name for those tests below.
STATUS_VERSIONS = ALL_VERSIONS


def test_fixtures_exist():
    """Guard: an empty fixture tree would make every test below vacuously pass."""
    assert _versions(), f"no hashcat fixtures under {FIXTURE_ROOT}"


# Nothing below this is pinned, captured or claimed to work. 6.2.6 and 7.0.0
# were both dropped from the CI matrices and their fixture directories deleted;
# this keeps them gone. Bump it in the same commit that raises the matrix.
MATRIX_FLOOR = (7, 1)


def test_no_fixture_sits_below_the_matrix_floor():
    """A fixture directory is what makes a version part of the offline contract,
    so a stray old directory would quietly put a version back under test that
    CI no longer downloads or verifies. Compared as integer tuples, not as
    strings: '10.0' sorts before '7.0' lexically, which would let a future
    hashcat 10 read as below the floor. Note (7, 0, 0) > (7, 0), so a bare
    7.0 floor would not have excluded the 7.0.0 fixture this commit deletes."""
    below = [v for v in _versions() if _as_tuple(v) < MATRIX_FLOOR]
    assert not below, (
        f"fixtures below the {MATRIX_FLOOR[0]}.{MATRIX_FLOOR[1]} floor: {below}")


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
def test_binary_advertises_every_documented_flag_the_server_emits(version):
    """Only ADVERTISED_FLAGS, not every flag the command builder emits.

    What Hashview depends on is that its command runs, and --help is only a
    proxy for that. The proxy broke once already: hashcat retired workload
    profiles and dropped -w from --help while still accepting it, which is a
    documentation change this assertion reported as an interop break. Flags in
    that state live in ACCEPTED_ONLY_FLAGS and are checked by actually running
    the binary -- see tests/hashcat_matrix/test_flag_acceptance.py."""
    summary = json.loads((FIXTURE_ROOT / version / "summary.json")
                         .read_text(encoding="utf-8"))
    missing = sorted(set(summarize.ADVERTISED_FLAGS) - set(summary["advertised_flags"]))
    assert not missing, f"hashcat {version} no longer advertises: {missing}"


def test_the_two_flag_lists_stay_disjoint_and_complete():
    """A flag in both lists would be checked twice and mean nothing; a flag in
    neither is emitted by the command builder and verified by nothing at all,
    which is the failure mode this split could quietly introduce."""
    advertised = set(summarize.ADVERTISED_FLAGS)
    accepted_only = set(summarize.ACCEPTED_ONLY_FLAGS)
    assert not advertised & accepted_only, (
        f"flags in both lists: {sorted(advertised & accepted_only)}")
    assert advertised | accepted_only == set(summarize.REQUIRED_FLAGS)
