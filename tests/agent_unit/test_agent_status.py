"""Unit tests for the agent-side hashcat --status-json parser
(install/hashview-agent/agent/status.py).

status.py is dependency-free (json/logging/datetime + agent.bench) so it can be
imported without pulling in the agent script's argparse side effects. The
agent_unit conftest puts the agent root on sys.path and stubs agent.config.
"""
import json

from agent.status import convert_speed, hashcat_status, time_difference


def _write_status(tmp_path, obj, prefix_noise=True):
    path = tmp_path / "hc.out"
    lines = []
    if prefix_noise:
        # hashcat prints a banner and progress text around the JSON lines; the
        # parser must skip anything that does not start with '{'.
        lines.append("hashcat (v7.1.2) starting")
        lines.append("")
    lines.append(json.dumps(obj))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(path)


def _status_obj(**overrides):
    obj = {
        "status": 3,
        "recovered_hashes": [1, 4],
        "estimated_stop": 4102444800,   # 2100-01-01, always in the future
        "devices": [
            {"device_id": 1, "device_name": "NVIDIA GeForce RTX 4090",
             "device_type": "GPU", "speed": 1500000000, "temp": 71},
            {"device_id": 2, "device_name": "NVIDIA GeForce RTX 4090",
             "device_type": "GPU", "speed": 1500000000, "temp": 70},
        ],
    }
    obj.update(overrides)
    return obj


def test_hashcat_status_maps_a_full_status_line(tmp_path):
    status = hashcat_status(_write_status(tmp_path, _status_obj()))
    assert status["Recovered"] == "1/4"
    assert status["Speed #"] == "3.0 GH/s"
    assert status["GPU_Count"] == 2
    assert status["GPU_Model"] == "RTX 4090"
    assert status["Temps"] == "71,70"
    assert status["Time_Estimated"].startswith("(") and status["Time_Estimated"].endswith(")")


def test_hashcat_status_skips_unparseable_lines_and_keeps_the_last_good_one(tmp_path):
    path = tmp_path / "hc.out"
    good = json.dumps(_status_obj(recovered_hashes=[1, 4]))
    later = json.dumps(_status_obj(recovered_hashes=[3, 4]))
    # A truncated line (hashcat is still writing) between two good ones.
    path.write_text(good + "\n" + '{"status": 3, "recov' + "\n" + later + "\n",
                    encoding="utf-8")
    status = hashcat_status(str(path))
    assert status["Recovered"] == "3/4"


def test_hashcat_status_returns_empty_when_no_json_lines(tmp_path):
    path = tmp_path / "hc.out"
    path.write_text("hashcat (v7.1.2) starting\nNo hashes loaded.\n", encoding="utf-8")
    assert hashcat_status(str(path)) == {}


def test_hashcat_status_tolerates_non_utf8_bytes(tmp_path):
    path = tmp_path / "hc.out"
    payload = json.dumps(_status_obj()).encode("utf-8")
    path.write_bytes(b"Recovered candidate: \xff\xfe\n" + payload + b"\n")
    assert hashcat_status(str(path))["Recovered"] == "1/4"


def test_time_difference_reports_a_past_timestamp():
    assert time_difference(0) == "The specified time is in the past."


def test_convert_speed_scales_units():
    assert convert_speed(500) == "500 H/s"
    assert convert_speed(1_500_000) == "1.5 MH/s"
    assert convert_speed(2_500_000_000) == "2.5 GH/s"
