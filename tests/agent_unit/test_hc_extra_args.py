"""Tests for HC_EXTRA_ARGS parsing (agent/bench.parse_hc_extra_args).

HC_EXTRA_ARGS lets an agent host pin per-host hashcat flags (most often device
selection, e.g. '-d 3,4'). The benchmark execs hashcat via the list form
``subprocess.run([HC_BIN_PATH, *args, '-b', '-m', mode])`` — so the args must be
split into individual argv tokens. (Cramming them onto HC_BIN_PATH produced
``FileNotFoundError: '/usr/local/bin/hashcat -d 3,4'``; this is the fix.)
"""
import pytest
from agent.bench import parse_hc_extra_args


@pytest.mark.parametrize("value", ["", "   ", None])
def test_blank_returns_no_args(value):
    # No HC_EXTRA_ARGS (or an older config without the line) -> behave as before.
    assert parse_hc_extra_args(value) == []


def test_single_flag_with_value():
    assert parse_hc_extra_args("-d 3,4") == ["-d", "3,4"]


def test_multiple_flags():
    assert parse_hc_extra_args("-d 3,4 -w 3") == ["-d", "3,4", "-w", "3"]


def test_quoted_value_with_space_is_one_token():
    assert parse_hc_extra_args('--brain-host "1 2"') == ["--brain-host", "1 2"]


def test_unbalanced_quote_falls_back_to_whitespace_split():
    # shlex would raise ValueError on the dangling quote; we degrade gracefully
    # rather than crash the benchmark.
    assert parse_hc_extra_args('-d 3,4 "oops') == ["-d", "3,4", '"oops']


def test_benchmark_argv_shape():
    # The exact argv run_benchmark builds — this is the shape that previously
    # raised FileNotFoundError when the args were glued onto HC_BIN_PATH.
    hc_bin = "/usr/local/bin/hashcat"
    argv = [hc_bin, *parse_hc_extra_args("-d 3,4"), "-b", "-m", "0"]
    assert argv == [hc_bin, "-d", "3,4", "-b", "-m", "0"]
