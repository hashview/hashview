"""Unit tests for the strict-mode helpers in tests/conftest.py.

These guard the e2e CI hardening: under HASHVIEW_E2E_STRICT the prerequisite
fixtures must hard-fail (not skip), and the skip-count gate has a named
threshold. No live server is needed — we test the pure helper logic directly.
"""
import importlib.util
from pathlib import Path

import pytest


def _load_root_conftest():
    # Load tests/conftest.py by explicit file path under a unique module name.
    # Several conftest.py files (tests/, tests/unit/, tests/security/,
    # tests/agent_unit/) have no __init__.py, so pytest registers them all under
    # the bare module name "conftest". In the combined CI run
    # importlib.import_module("conftest") could return the wrong one (lacking
    # _e2e_strict/_skip_or_fail). Loading by path under a collision-free name
    # guarantees we get the ROOT conftest.
    path = Path(__file__).resolve().parents[1] / "conftest.py"  # tests/conftest.py
    spec = importlib.util.spec_from_file_location("hashview_root_conftest", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


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
