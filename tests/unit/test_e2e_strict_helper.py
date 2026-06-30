"""Unit tests for the strict-mode helpers in tests/conftest.py.

These guard the e2e CI hardening: under HASHVIEW_E2E_STRICT the prerequisite
fixtures must hard-fail (not skip), and the skip-count gate has a named
threshold. No live server is needed — we test the pure helper logic directly.
"""
import importlib

import pytest


def _load_root_conftest():
    # tests/conftest.py is importable as the `conftest` module once pytest has
    # collected it; importlib keeps this resilient to import ordering.
    return importlib.import_module("conftest")


@pytest.mark.parametrize(
    "value,expected",
    [
        ("1", True),
        ("true", True),
        ("TRUE", True),
        ("True", True),
        (" 1 ", True),
        ("0", False),
        ("false", False),
        ("yes", False),  # only "1"/"true" are truthy, by design
        ("", False),
        (None, False),
    ],
)
def test_e2e_strict_parsing(monkeypatch, value, expected):
    conftest = _load_root_conftest()
    if value is None:
        monkeypatch.delenv("HASHVIEW_E2E_STRICT", raising=False)
    else:
        monkeypatch.setenv("HASHVIEW_E2E_STRICT", value)
    assert conftest._e2e_strict() is expected


def test_skip_or_fail_skips_when_not_strict(monkeypatch):
    conftest = _load_root_conftest()
    monkeypatch.delenv("HASHVIEW_E2E_STRICT", raising=False)
    with pytest.raises(pytest.skip.Exception):
        conftest._skip_or_fail("nope")


def test_skip_or_fail_fails_when_strict(monkeypatch):
    conftest = _load_root_conftest()
    monkeypatch.setenv("HASHVIEW_E2E_STRICT", "1")
    with pytest.raises(pytest.fail.Exception):
        conftest._skip_or_fail("missing prereq")


def test_strict_max_skips_is_a_small_named_constant():
    conftest = _load_root_conftest()
    assert isinstance(conftest.STRICT_MAX_SKIPS, int)
    assert 0 <= conftest.STRICT_MAX_SKIPS <= 10
