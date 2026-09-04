"""Tests for run_benchmark function in the hashview agent.

When a hashcat build can't benchmark a requested mode (subprocess raises or
parse_benchmark_speed returns None), the agent now:
1. Records the mode in results with speed=0
2. Collects failed modes and calls api.sendError once with all failed modes named
3. Still calls report_benchmark with the full results dict (including 0 entries)

This ensures the server records "attempted, unsupported" for each mode and stops
re-asking for it every heartbeat.
"""
import importlib.util
import os
import sys
import types
from pathlib import Path
from unittest import mock

import pytest

AGENT_ROOT = Path(__file__).resolve().parents[2] / "install" / "hashview-agent"


def _load_agent_main():
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
        spec = importlib.util.spec_from_file_location("hashview_agent_main_benchmark", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    return mod


agent_main = _load_agent_main()


def test_run_benchmark_subprocess_exception_records_zero_speed_and_sends_error(monkeypatch):
    """When subprocess.run raises for a mode, record speed=0 and send error."""
    failed_mode = 1000

    # Mock the dependencies
    mock_run = mock.MagicMock()
    mock_run.side_effect = RuntimeError("hashcat not found")
    monkeypatch.setattr(agent_main.subprocess, "run", mock_run)

    mock_send_error = mock.MagicMock()
    monkeypatch.setattr(agent_main.api, "sendError", mock_send_error)
    mock_report = mock.MagicMock()
    monkeypatch.setattr(agent_main, "report_benchmark", mock_report)

    # Run the benchmark
    agent_main.run_benchmark([failed_mode])

    # Verify: speed=0 in results, sendError called, report_benchmark called
    assert mock_report.call_count == 1
    results = mock_report.call_args[0][0]
    assert results == {'1000': 0}

    assert mock_send_error.call_count == 1
    error_msg = mock_send_error.call_args[0][0]
    assert '1000' in error_msg
    assert 'could not benchmark' in error_msg


def test_run_benchmark_parse_none_records_zero_speed_and_sends_error(monkeypatch):
    """When parse_benchmark_speed returns None for a mode, record speed=0 and send error."""
    failed_mode = 2000

    # Mock subprocess to succeed but return output that can't be parsed
    mock_proc = mock.MagicMock()
    mock_proc.stdout = b"Some output"
    mock_proc.stderr = b""
    mock_run = mock.MagicMock(return_value=mock_proc)
    monkeypatch.setattr(agent_main.subprocess, "run", mock_run)

    # Mock parse_benchmark_speed to return None
    import agent.bench
    original_parse = agent.bench.parse_benchmark_speed
    mock_parse = mock.MagicMock(return_value=None)
    agent.bench.parse_benchmark_speed = mock_parse

    mock_send_error = mock.MagicMock()
    monkeypatch.setattr(agent_main.api, "sendError", mock_send_error)
    mock_report = mock.MagicMock()
    monkeypatch.setattr(agent_main, "report_benchmark", mock_report)

    try:
        agent_main.run_benchmark([failed_mode])

        # Verify: speed=0 in results, sendError called, report_benchmark called
        assert mock_report.call_count == 1
        results = mock_report.call_args[0][0]
        assert results == {'2000': 0}

        assert mock_send_error.call_count == 1
        error_msg = mock_send_error.call_args[0][0]
        assert '2000' in error_msg
        assert 'could not benchmark' in error_msg
    finally:
        agent.bench.parse_benchmark_speed = original_parse


def test_run_benchmark_mixed_success_and_failure(monkeypatch):
    """When some modes succeed and some fail, all are in results and sendError only names failed."""
    success_mode = 0
    failed_mode = 1000

    # Mock subprocess for the success case
    mock_proc_success = mock.MagicMock()
    mock_proc_success.stdout = b"Speed.#1.........: 12345 H/s"
    mock_proc_success.stderr = b""

    # Subprocess raises for the failure case
    def subprocess_side_effect(argv, **kwargs):
        mode = argv[-1]  # last arg is the mode
        if mode == str(success_mode):
            return mock_proc_success
        else:
            raise RuntimeError("unsupported hash type")

    mock_run = mock.MagicMock(side_effect=subprocess_side_effect)
    monkeypatch.setattr(agent_main.subprocess, "run", mock_run)

    # Mock parse_benchmark_speed to return speed for success mode
    import agent.bench
    original_parse = agent.bench.parse_benchmark_speed
    mock_parse = mock.MagicMock(side_effect=lambda o: 12345 if "12345" in o else None)
    agent.bench.parse_benchmark_speed = mock_parse

    mock_send_error = mock.MagicMock()
    monkeypatch.setattr(agent_main.api, "sendError", mock_send_error)
    mock_report = mock.MagicMock()
    monkeypatch.setattr(agent_main, "report_benchmark", mock_report)

    try:
        agent_main.run_benchmark([success_mode, failed_mode])

        # Verify: both in results, only failed mode in error message
        assert mock_report.call_count == 1
        results = mock_report.call_args[0][0]
        assert results['0'] == 12345
        assert results['1000'] == 0

        assert mock_send_error.call_count == 1
        error_msg = mock_send_error.call_args[0][0]
        assert '1000' in error_msg
        # Verify that the error message only mentions failed modes, not successful ones.
        # The error should say "1000" but not list "0" as a separate failed mode.
        # We can verify this by checking that the message doesn't contain both
        # the mode number 0 AND a comma-separated mode list that includes it.
        import re
        # Extract modes from message using regex for "mode(s): <list>"
        modes_match = re.search(r'mode\(s\): ([^.]+)', error_msg)
        assert modes_match
        modes_text = modes_match.group(1)
        assert modes_text == '1000', f"Expected only '1000' in failed modes, got: {modes_text}"
        assert 'could not benchmark' in error_msg
    finally:
        agent.bench.parse_benchmark_speed = original_parse


def test_run_benchmark_no_failures_does_not_send_error(monkeypatch):
    """When all modes benchmark successfully, sendError is not called."""
    success_modes = [0, 1000]

    # Mock subprocess to always succeed
    mock_proc = mock.MagicMock()
    mock_proc.stdout = b"Speed.#1.........: 12345 H/s"
    mock_proc.stderr = b""
    mock_run = mock.MagicMock(return_value=mock_proc)
    monkeypatch.setattr(agent_main.subprocess, "run", mock_run)

    # Mock parse_benchmark_speed to always return a speed
    import agent.bench
    original_parse = agent.bench.parse_benchmark_speed
    mock_parse = mock.MagicMock(return_value=12345)
    agent.bench.parse_benchmark_speed = mock_parse

    mock_send_error = mock.MagicMock()
    monkeypatch.setattr(agent_main.api, "sendError", mock_send_error)
    mock_report = mock.MagicMock()
    monkeypatch.setattr(agent_main, "report_benchmark", mock_report)

    try:
        agent_main.run_benchmark(success_modes)

        # Verify: sendError not called, report_benchmark called with both modes
        assert mock_report.call_count == 1
        results = mock_report.call_args[0][0]
        assert results == {'0': 12345, '1000': 12345}

        assert mock_send_error.call_count == 0
    finally:
        agent.bench.parse_benchmark_speed = original_parse


def test_run_benchmark_empty_modes_list(monkeypatch):
    """When hash_modes is empty or None, do nothing."""
    mock_send_error = mock.MagicMock()
    monkeypatch.setattr(agent_main.api, "sendError", mock_send_error)
    mock_report = mock.MagicMock()
    monkeypatch.setattr(agent_main, "report_benchmark", mock_report)

    # Both empty list and None should be handled
    agent_main.run_benchmark([])
    assert mock_report.call_count == 0
    assert mock_send_error.call_count == 0

    agent_main.run_benchmark(None)
    assert mock_report.call_count == 0
    assert mock_send_error.call_count == 0
