"""A workflow must not run twice on the same commit.

`push` and `pull_request` are separate events. A workflow that subscribes to
both with no branch filter on `push` fires twice for every commit pushed to a
branch that has a PR open -- two full matrices, two sets of containers, two
sets of check results on one SHA. That cost is invisible: both runs go green,
the PR shows duplicated check names, and the only tell is the run list.

It also breaks the check rollup. When one of the duplicate runs fails on a
transient (a registry 502 during an image build, say), re-running the other one
does not clear it, and the PR stays red against a commit whose tests passed.

The fix is to scope `push` to the long-lived branches, so a PR branch is
covered once by `pull_request` and a merge to a long-lived branch is covered
once by `push`. This test keeps it that way.

Deliberately NOT asserted: that every workflow subscribes to both events. A
scheduled-only or dispatch-only workflow (mutation, the hashcat floating tiers)
is free to subscribe to whatever it needs.
"""
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"

# The branches a merge lands on, and so the only ones a `push` run is for.
# A glob rather than a literal: the dev branch is renamed every release
# (v0.8.3-dev -> v0.8.4-dev), and a literal would silently drop push coverage
# on the day that happens.
EXPECTED_PUSH_BRANCHES = ["main", "v*-dev"]


def _workflow_files():
    return sorted(WORKFLOWS.glob("*.yml"))


def _triggers(path):
    """The workflow's `on:` block.

    PyYAML follows YAML 1.1, where a bare `on` key resolves to the boolean
    True rather than the string "on", so both spellings are checked.
    """
    doc = yaml.safe_load(path.read_text())
    for key in (True, "on"):
        if key in doc:
            return doc[key]
    raise AssertionError(f"{path.name} has no `on:` block")


def test_there_are_workflows_to_check():
    """Guard: a bad path here would make every test below vacuously pass."""
    assert _workflow_files(), f"no workflows found under {WORKFLOWS}"


def test_some_workflow_subscribes_to_both_events():
    """Guard: if nothing subscribed to both, the real test below would pass
    without ever checking anything."""
    both = [p.name for p in _workflow_files()
            if {"push", "pull_request"} <= set(_triggers(p) or {})]
    assert both, "no workflow subscribes to both push and pull_request"


@pytest.mark.parametrize("path", _workflow_files(), ids=lambda p: p.name)
def test_push_is_branch_scoped_when_pull_request_is_also_used(path):
    """Subscribing to both events without scoping `push` doubles every run."""
    on = _triggers(path)

    # `on: [push, pull_request]` -- the flow-list form cannot carry a branch
    # filter at all, so it is always the duplicating shape.
    if isinstance(on, list):
        assert not {"push", "pull_request"} <= set(on), (
            f"{path.name} uses the list form `on: {on}`, which cannot filter "
            f"branches. Use the mapping form and scope push to "
            f"{EXPECTED_PUSH_BRANCHES}.")
        return

    if not {"push", "pull_request"} <= set(on):
        return

    push = on["push"] or {}
    branches = push.get("branches")
    assert branches, (
        f"{path.name} subscribes to both push and pull_request but does not "
        f"filter push by branch, so every PR-branch commit runs it twice. "
        f"Add `branches: {EXPECTED_PUSH_BRANCHES}` under push.")
    assert branches == EXPECTED_PUSH_BRANCHES, (
        f"{path.name} scopes push to {branches}; expected "
        f"{EXPECTED_PUSH_BRANCHES} so every workflow agrees on which branches "
        f"a push run is for.")
