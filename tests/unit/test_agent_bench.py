"""Unit tests for the agent-side benchmark parsers (install/hashview-agent/
agent/bench.py).

bench.py is deliberately dependency-free (only re/shlex) so it can be tested
without importing the rest of the agent (which pulls in psutil and runs argv
side effects at import). It lives outside the importable ``hashview`` package,
so we load it directly by file path.
"""

import importlib.util
from pathlib import Path

_BENCH_PATH = (Path(__file__).resolve().parents[2]
               / "install" / "hashview-agent" / "agent" / "bench.py")
_spec = importlib.util.spec_from_file_location("hv_agent_bench", _BENCH_PATH)
bench = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bench)


# --- parse_hc_extra_args ----------------------------------------------------

def test_parse_hc_extra_args_empty_is_empty_list():
    assert bench.parse_hc_extra_args("") == []
    assert bench.parse_hc_extra_args(None) == []


def test_parse_hc_extra_args_splits_like_shell():
    assert bench.parse_hc_extra_args("-d 3,4 --force") == ["-d", "3,4", "--force"]
    # quoted token stays intact
    assert bench.parse_hc_extra_args('-O --opts "a b"') == ["-O", "--opts", "a b"]


def test_parse_hc_extra_args_falls_back_on_unbalanced_quotes():
    # shlex.split raises on the dangling quote; we fall back to whitespace split.
    assert bench.parse_hc_extra_args('-d 3 "oops') == ["-d", "3", '"oops']


# --- parse_benchmark_speed --------------------------------------------------

def test_parse_benchmark_speed_sums_per_device_with_units():
    out = (
        "Speed.#1.........:  1000.0 MH/s (10.00ms)\n"
        "Speed.#2.........:  2000.0 MH/s (10.00ms)\n"
    )
    assert bench.parse_benchmark_speed(out) == 3_000_000_000


def test_parse_benchmark_speed_ignores_aggregate_star_line():
    # The 'Speed.#*' total must not be double-counted alongside #1/#2.
    out = (
        "Speed.#1.........:  500 kH/s\n"
        "Speed.#2.........:  500 kH/s\n"
        "Speed.#*.........:  1000 kH/s\n"
    )
    assert bench.parse_benchmark_speed(out) == 1_000_000


def test_parse_benchmark_speed_none_when_no_speed_line():
    assert bench.parse_benchmark_speed("No devices found.\n") is None


def test_parse_benchmark_speed_zero_is_a_valid_result():
    # 0 H/s (device can't run the mode) is returned, not None, so the server
    # stops re-asking for that hash type.
    assert bench.parse_benchmark_speed("Speed.#1.........:  0 H/s\n") == 0


# --- parse_device_info ------------------------------------------------------

def test_parse_device_info_picks_gpus_and_shortens_name():
    data = {"devices": [
        {"device_type": "CPU", "device_name": "Intel i9", "temp": 40},
        {"device_type": "GPU", "device_name": "NVIDIA GeForce RTX 4090", "temp": 71},
        {"device_type": "GPU", "device_name": "NVIDIA GeForce RTX 4090", "temp": 70},
    ]}
    count, model, temps = bench.parse_device_info(data)
    assert count == 2
    assert model == "RTX 4090"
    assert temps == "71,70"


def test_parse_device_info_falls_back_to_all_devices_when_untyped():
    data = {"devices": [{"device_name": "AMD Radeon RX 7900", "temp": 60}]}
    count, model, temps = bench.parse_device_info(data)
    assert count == 1
    assert model == "RX 7900"
    assert temps == "60"


def test_parse_device_info_empty_is_safe():
    assert bench.parse_device_info({}) == (0, "", "")
    assert bench.parse_device_info(None) == (0, "", "")
