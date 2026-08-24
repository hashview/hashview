"""The pre-push secret scanner must see the lines a push actually adds.

Regression tests for #418. `.githooks/pre-push` built its scan range with
`git rev-list` syntax (`<sha> --not --remotes`) and then handed those same
arguments to `git diff`, which has no notion of `--not`/`--remotes` as range
exclusion and emits a *combined* diff instead. On a new-branch push the
scanner could therefore receive an empty haystack and report
"sensitive-content scan clean." for a commit containing an AWS key.

These tests drive the real hook script through its stdin protocol against
throwaway repositories. They assert on the hook's scan *output* rather than
its exit status: the hook also runs a ruff/bandit/pytest gate after the scan,
which exits non-zero in a throwaway repo for unrelated reasons, so exit
status alone cannot distinguish "blocked by the scanner" from "gate failed".
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
HOOK = REPO_ROOT / ".githooks" / "pre-push"
ZERO = "0" * 40

# Secret-shaped fixtures, assembled at runtime so this file holds no literal
# that a secret scanner (this hook, GitHub push protection, gitleaks) would
# flag. The strings the tests write to disk are complete and do match; only the
# source text here does not. AKIA... is AWS's own published example key ID.
FAKE_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
FAKE_PASSWORD = "sup3r" + "s3cret_value"


def _assignment(name, value):
    """Render `name = "value"` as file content.

    Going through a helper keeps the assignment shape the scanner looks for
    out of this file's own source, while the text written to disk still has
    it. Inlining an f-string here would make this file trip the very patterns
    these tests exercise.
    """
    return f'{name} = "{value}"\n'

pytestmark = pytest.mark.skipif(
    shutil.which("git") is None or shutil.which("bash") is None,
    reason="needs git and bash",
)


def _clean_env():
    """Environment with git's own variables stripped out.

    These tests can run *inside* a git hook -- the pre-push gate they cover
    invokes the test suite -- and git exports GIT_DIR, GIT_INDEX_FILE and
    friends to hooks. Inherited, they redirect every `git` call below at the
    real repository instead of the throwaway one, so each must be scrubbed.
    """
    return {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}


def _git(cwd, *args):
    return subprocess.run(("git",) + args, cwd=cwd, check=True,
                          capture_output=True, text=True,
                          env=_clean_env()).stdout


def _build_repo(tmp_path):
    """An upstream plus a clone with main and an older fork branch pushed.

    The older fork branch matters: it gives `--remotes` more than one ref, so
    the buggy `git diff` invocation produces a multi-parent combined diff
    rather than something that coincidentally resembles a real one.
    """
    upstream = tmp_path / "up.git"
    clone = tmp_path / "clone"
    subprocess.run(["git", "init", "-q", "--bare", str(upstream)], check=True,
                   env=_clean_env())
    subprocess.run(["git", "clone", "-q", str(upstream), str(clone)], check=True,
                   env=_clean_env())
    _git(clone, "config", "user.email", "t@t.test")
    _git(clone, "config", "user.name", "T")
    _git(clone, "config", "commit.gpgsign", "false")

    (clone / "app.py").write_text("value = 1\n")
    _git(clone, "add", "app.py")
    _git(clone, "commit", "-q", "-m", "initial")
    _git(clone, "branch", "-M", "main")
    _git(clone, "push", "-q", "origin", "main")

    # A fork branch pushed before the content main gains below.
    _git(clone, "checkout", "-q", "-b", "oldfork", "main")
    _git(clone, "push", "-q", "origin", "oldfork")

    # main then gains a line holding a URL, which no later branch touches.
    _git(clone, "checkout", "-q", "main")
    (clone / "app.py").write_text(
        'value = 1\nnotify("https://hooks.example.com/notify")\n')
    _git(clone, "add", "app.py")
    _git(clone, "commit", "-q", "-m", "add notify url")
    _git(clone, "push", "-q", "origin", "main")

    hooks = clone / ".githooks"
    hooks.mkdir(exist_ok=True)
    shutil.copy(HOOK, hooks / "pre-push")
    _git(clone, "fetch", "-q", "origin")
    return upstream, clone


def _run_hook(clone, upstream, local_ref, local_sha, remote_sha):
    """Invoke the hook exactly as git would, and return its combined output."""
    stdin = f"{local_ref} {local_sha} {local_ref} {remote_sha}\n"
    proc = subprocess.run(
        ["bash", str(clone / ".githooks" / "pre-push"), "origin", str(upstream)],
        cwd=clone, input=stdin, capture_output=True, text=True,
        env=_clean_env(),
    )
    return proc.stdout + proc.stderr


def _scan_output(text):
    """Just the scanner's portion, before the ruff/bandit/pytest gate."""
    return text.split("pre-push: running ruff")[0]


def test_new_branch_push_scans_secrets_in_added_lines(tmp_path):
    """The core #418 regression: a new branch's added lines must be scanned."""
    upstream, clone = _build_repo(tmp_path)
    _git(clone, "checkout", "-q", "-b", "feature/x", "main")
    (clone / "leak.py").write_text(_assignment("AWS_KEY", FAKE_AWS_KEY))
    _git(clone, "add", "leak.py")
    _git(clone, "commit", "-q", "-m", "add a key")
    sha = _git(clone, "rev-parse", "HEAD").strip()

    out = _scan_output(_run_hook(clone, upstream, "refs/heads/feature/x", sha, ZERO))

    assert "sensitive-content scan clean" not in out
    assert "AWS access key ID" in out


def test_new_branch_push_scans_generic_secret_assignments(tmp_path):
    upstream, clone = _build_repo(tmp_path)
    _git(clone, "checkout", "-q", "-b", "feature/y", "main")
    (clone / "conf.py").write_text(_assignment("password", FAKE_PASSWORD))
    _git(clone, "add", "conf.py")
    _git(clone, "commit", "-q", "-m", "add config")
    sha = _git(clone, "rev-parse", "HEAD").strip()

    out = _scan_output(_run_hook(clone, upstream, "refs/heads/feature/y", sha, ZERO))

    assert "sensitive-content scan clean" not in out
    assert "Generic secret assign" in out


def test_new_branch_push_flags_added_env_file(tmp_path):
    """The changed-files list had the same broken range, so .env slipped by."""
    upstream, clone = _build_repo(tmp_path)
    _git(clone, "checkout", "-q", "-b", "feature/env", "main")
    (clone / ".env").write_text("DB_PASSWORD=hunter2\n")
    _git(clone, "add", "-f", ".env")
    _git(clone, "commit", "-q", "-m", "add env")
    sha = _git(clone, "rev-parse", "HEAD").strip()

    out = _scan_output(_run_hook(clone, upstream, "refs/heads/feature/env", sha, ZERO))

    assert ".env file added/modified" in out


def test_new_branch_push_scans_every_commit_not_just_the_tip(tmp_path):
    """A secret in an earlier commit of the branch is still caught."""
    upstream, clone = _build_repo(tmp_path)
    _git(clone, "checkout", "-q", "-b", "feature/multi", "main")
    (clone / "early.py").write_text(_assignment("AWS_KEY", FAKE_AWS_KEY))
    _git(clone, "add", "early.py")
    _git(clone, "commit", "-q", "-m", "first commit with the key")
    (clone / "later.py").write_text("harmless = True\n")
    _git(clone, "add", "later.py")
    _git(clone, "commit", "-q", "-m", "second, innocent commit")
    sha = _git(clone, "rev-parse", "HEAD").strip()

    out = _scan_output(_run_hook(clone, upstream, "refs/heads/feature/multi", sha, ZERO))

    assert "AWS access key ID" in out


def test_existing_branch_push_still_scans_secrets(tmp_path):
    """The two-dot range path already worked; keep it working."""
    upstream, clone = _build_repo(tmp_path)
    base = _git(clone, "rev-parse", "origin/main").strip()
    _git(clone, "checkout", "-q", "main")
    (clone / "leak.py").write_text(_assignment("AWS_KEY", FAKE_AWS_KEY))
    _git(clone, "add", "leak.py")
    _git(clone, "commit", "-q", "-m", "add a key")
    sha = _git(clone, "rev-parse", "HEAD").strip()

    out = _scan_output(_run_hook(clone, upstream, "refs/heads/main", sha, base))

    assert "sensitive-content scan clean" not in out
    assert "AWS access key ID" in out


def test_clean_new_branch_push_does_not_report_untouched_upstream_lines(tmp_path):
    """A clean branch scans clean; upstream's URL line is not attributed to it.

    Note: this guards the false-positive direction reported in #418, but it is
    not a strict reproduction of it -- the observed noise depended on the real
    repository's ref topology (many divergent fork branches) and does not
    reproduce minimally. It would have passed before the fix as well.
    """
    upstream, clone = _build_repo(tmp_path)
    _git(clone, "checkout", "-q", "-b", "feature/clean", "main")
    (clone / "helper.py").write_text("def add(a, b):\n    return a + b\n")
    _git(clone, "add", "helper.py")
    _git(clone, "commit", "-q", "-m", "add helper")
    sha = _git(clone, "rev-parse", "HEAD").strip()

    out = _scan_output(_run_hook(clone, upstream, "refs/heads/feature/clean", sha, ZERO))

    assert "hooks.example.com" not in out
    assert "sensitive-content scan clean" in out


def test_merge_only_push_is_not_blocked_and_is_still_scanned(tmp_path):
    """A push whose only new commit is a merge must not trip the guard.

    `git log -p` omits merge diffs by default, so a naive "empty patch means
    the range is broken" check would reject the merge commits this project
    pushes routinely. The merge's content must also still be scanned.
    """
    upstream, clone = _build_repo(tmp_path)
    # A side branch that is already on the remote, carrying a secret.
    _git(clone, "checkout", "-q", "-b", "side", "main")
    (clone / "leak.py").write_text(_assignment("AWS_KEY", FAKE_AWS_KEY))
    _git(clone, "add", "leak.py")
    _git(clone, "commit", "-q", "-m", "side work")
    _git(clone, "push", "-q", "origin", "side")

    # Locally merge it into main; only the merge commit is new to the remote.
    _git(clone, "checkout", "-q", "main")
    _git(clone, "merge", "-q", "--no-ff", "side", "-m", "Merge side")
    sha = _git(clone, "rev-parse", "HEAD").strip()
    base = _git(clone, "rev-parse", "origin/main").strip()

    out = _scan_output(_run_hook(clone, upstream, "refs/heads/main", sha, base))

    assert "could not compute a diff" not in out, \
        "the fail-closed guard must not fire on a legitimate merge-only push"
    assert "AWS access key ID" in out, \
        "content brought in by a merge must still be scanned"


def test_empty_commit_push_is_not_blocked(tmp_path):
    """`git commit --allow-empty` has no patch and must still be pushable.

    The sanity check keys on files touched rather than on the commit count for
    exactly this reason.
    """
    upstream, clone = _build_repo(tmp_path)
    base = _git(clone, "rev-parse", "origin/main").strip()
    _git(clone, "checkout", "-q", "main")
    _git(clone, "commit", "-q", "--allow-empty", "-m", "empty commit to retrigger CI")
    sha = _git(clone, "rev-parse", "HEAD").strip()

    out = _scan_output(_run_hook(clone, upstream, "refs/heads/main", sha, base))

    assert "no diff could be computed" not in out
    assert "sensitive-content scan clean" in out


def test_deletion_push_is_skipped(tmp_path):
    """Deleting a remote branch has nothing to scan."""
    upstream, clone = _build_repo(tmp_path)

    out = _scan_output(_run_hook(clone, upstream, "refs/heads/gone", ZERO, ZERO))

    assert "sensitive-content scan clean" in out
