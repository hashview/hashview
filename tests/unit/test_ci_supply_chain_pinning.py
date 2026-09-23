"""CI must pin what it executes, by digest rather than by tag.

A tag is mutable. `actions/checkout@v5` is a branch-like pointer the action's
owner can move at any time, and `mysql:8.0` is repointed at every 8.0.x patch
release. Both mean CI runs something different today than it ran yesterday with
no change on our side, which costs twice:

  * supply chain -- a compromised or simply repointed tag executes in a job that
    has a checkout of this repo and a GITHUB_TOKEN. Pinning to a commit SHA is
    what GitHub's own hardening guide and OpenSSF Scorecard ask for;
  * debuggability -- db-parity exists to compare database engines. If the image
    underneath it can change on its own, a parity failure cannot be told apart
    from an upstream image bump, which is the one thing that job is for.

Deliberately NOT covered here: `Dockerfile`, `Dockerfile.agent` and
`docker-compose.yml`. Those are deployment artifacts that users and the dev box
build from, and freezing their base images by digest would mean no upstream
security patch reaches a deployment until someone edits this repo. Floating
there is the right default; floating in a test harness is not. See the
`_HARNESS_COMPOSE` note below.
"""
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"

# `uses: <owner>/<repo>@<ref>`, ignoring any trailing comment.
_USES = re.compile(r"^\s*-?\s*uses:\s*(?P<ref>\S+)", re.MULTILINE)
_SHA = re.compile(r"^[0-9a-f]{40}$")

# Compose files that exist only to run tests. Their images are inputs to a
# result we assert on, so they get pinned; the deployment compose file does not.
_HARNESS_COMPOSE = ("docker-compose.test.yml", "docker-compose.migration.yml")

# A locally built tag, produced by the runner earlier in the same job rather
# than pulled from a registry, so there is no digest to pin it to.
_LOCALLY_BUILT = re.compile(r"^hashview:(main|dev)$")

_IMAGE = re.compile(r"^\s*image:\s*(?P<ref>\S+)", re.MULTILINE)


def _workflow_files():
    return sorted(WORKFLOWS.glob("*.yml"))


def test_there_are_workflows_to_check():
    """Guard: a bad path here would make every test below vacuously pass."""
    assert _workflow_files(), f"no workflows found under {WORKFLOWS}"


@pytest.mark.security
@pytest.mark.parametrize("path", _workflow_files(), ids=lambda p: p.name)
def test_every_action_is_pinned_to_a_commit_sha(path):
    """A tag ref is mutable; only a full 40-character commit SHA is not."""
    unpinned = []
    for match in _USES.finditer(path.read_text()):
        ref = match.group("ref")
        if ref.startswith("./"):        # a composite action inside this repo
            continue
        _, _, rev = ref.partition("@")
        if not _SHA.match(rev):
            unpinned.append(ref)
    assert not unpinned, (
        f"{path.name} uses mutable action refs: {unpinned}. Pin to the commit "
        f"SHA the tag points at and note the version in a trailing comment.")


@pytest.mark.parametrize("path", _workflow_files(), ids=lambda p: p.name)
def test_every_pinned_action_records_the_version_it_pins(path):
    """A bare 40-hex SHA is unreadable and unreviewable -- nobody can tell
    v5.1.0 from a fork's HEAD by eye, and nobody can tell whether a pin is a
    year stale. The trailing comment is what makes the pin maintainable, so it
    is part of the convention rather than decoration."""
    missing = []
    for line in path.read_text().splitlines():
        if "uses:" not in line:
            continue
        ref = _USES.match(line)
        if not ref or ref.group("ref").startswith("./"):
            continue
        _, _, rev = ref.group("ref").partition("@")
        if _SHA.match(rev) and not re.search(r"#\s*v?\d+\.\d+", line):
            missing.append(line.strip())
    assert not missing, (
        f"{path.name} has SHA pins with no version comment: {missing}")


@pytest.mark.security
@pytest.mark.parametrize("name", _HARNESS_COMPOSE)
def test_test_harness_images_are_pinned_by_digest(name):
    """`mysql:8` moves with every patch release. A harness whose server can
    change underneath it turns a real regression and an upstream image bump
    into the same red X."""
    path = REPO_ROOT / name
    assert path.is_file(), f"{name} is missing; update _HARNESS_COMPOSE"
    unpinned = [
        ref for ref in (m.group("ref").strip('"\'')
                        for m in _IMAGE.finditer(path.read_text()))
        if "@sha256:" not in ref and not _LOCALLY_BUILT.match(ref)
    ]
    assert not unpinned, (
        f"{name} references images by mutable tag: {unpinned}")


@pytest.mark.security
def test_db_parity_services_are_pinned_by_digest():
    """The engine comparison is the whole product of this job, so the engines
    are the last thing that should be allowed to drift on their own."""
    text = (WORKFLOWS / "db-parity.yml").read_text()
    unpinned = [
        ref for ref in (m.group("ref").strip('"\'')
                        for m in _IMAGE.finditer(text))
        if "@sha256:" not in ref and not ref.startswith("${{")
    ]
    assert not unpinned, f"db-parity.yml has unpinned service images: {unpinned}"
