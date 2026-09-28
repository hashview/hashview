"""Runtime dependencies must be pinned exactly, including Werkzeug.

Werkzeug is not a direct import for most of the app -- it arrives through Flask,
which only asks for ``werkzeug>=3.1`` -- so it was left out of requirements.txt
and floated. Werkzeug 3.1.9 then changed form-size enforcement and cookie
parsing, and CI on the base branch went red with no commit on our side (#563).
Pinning it makes that kind of change arrive as a deliberate bump instead.
"""
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
_PINNED = re.compile(r"^[A-Za-z0-9_.\-\[\]]+==[^=<>!~\s]+$")


def _requirements():
    lines = (REPO_ROOT / "requirements.txt").read_text().splitlines()
    return [line.strip() for line in lines
            if line.strip() and not line.strip().startswith("#")]


def test_every_runtime_requirement_is_pinned_exactly():
    unpinned = [req for req in _requirements() if not _PINNED.match(req)]
    assert unpinned == []


def test_werkzeug_is_pinned():
    names = {req.split("==")[0].lower() for req in _requirements()}
    assert "werkzeug" in names
