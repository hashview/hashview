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
