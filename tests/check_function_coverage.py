#!/usr/bin/env python
"""Fail when any function in hashview/ has zero executed body lines.

Usage:
    ./.venv/bin/python -m pytest tests/unit -q --cov=hashview --cov-report=json:coverage.json
    ./.venv/bin/python tests/check_function_coverage.py [coverage.json]

Exit codes: 0 = every function covered (or allowlisted), 1 = gaps found,
2 = coverage.json missing/unreadable.

Waivers go in tests/function_coverage_allowlist.txt, one per line, as
``hashview/path/file.py::function_name``. Lines starting with ``#`` are
comments. The allowlist is expected to stay empty.
"""

import ast
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST = REPO_ROOT / "tests" / "function_coverage_allowlist.txt"


def load_allowlist():
    if not ALLOWLIST.exists():
        return set()
    entries = set()
    for line in ALLOWLIST.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            entries.add(line)
    return entries


def body_lines(node):
    """Line numbers of a function body, excluding a leading docstring."""
    body = node.body
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        body = body[1:]
    lines = set()
    for stmt in body:
        lines.update(range(stmt.lineno, (stmt.end_lineno or stmt.lineno) + 1))
    return lines


def normalize(path):
    """Coverage paths relative to the repo root, or None if outside it."""
    p = Path(path)
    if p.is_absolute():
        try:
            return str(p.resolve().relative_to(REPO_ROOT))
        except ValueError:
            return None
    return str(p)


def main():
    cov_path = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO_ROOT / "coverage.json"
    try:
        cov = json.loads(cov_path.read_text())
    except OSError as exc:
        print(f"cannot read coverage data: {exc}", file=sys.stderr)
        print("run: pytest tests/unit --cov=hashview --cov-report=json:coverage.json", file=sys.stderr)
        return 2

    allow = load_allowlist()
    missing = []
    total = 0
    for path, data in sorted(cov["files"].items()):
        rel = normalize(path)
        if rel is None or not rel.startswith("hashview/") or rel.startswith("hashview/migrations"):
            continue
        executed = set(data["executed_lines"])
        try:
            tree = ast.parse((REPO_ROOT / rel).read_text())
        except OSError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                total += 1
                key = f"{rel}::{node.name}"
                if not (body_lines(node) & executed) and key not in allow:
                    missing.append((rel, node.lineno, node.name))

    print(f"functions scanned: {total}; zero-coverage: {len(missing)}")
    for rel, lineno, name in missing:
        print(f"  {rel}:{lineno}  {name}")
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
