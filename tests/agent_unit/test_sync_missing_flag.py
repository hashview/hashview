"""Agent handling of the server's `missing` flag, and the rule-prune data loss.

Two behaviours, both from issue #383:

1. The server now flags a rule/wordlist row whose file is gone. The agent must
   skip the download (it would only 404) and keep any local copy, instead of
   re-asking on every task assignment and logging a bare HTTP 404.

2. Independently: ANY failed rule download used to drop the id from the new
   manifest, and _prune_orphan_files then DELETED the agent's still-good local
   copy. The next task using that rule made hashcat fail, which makes
   run_hashcat SIGINT the whole agent and leaves the JobTask wedged in Running.
   sync_wordlists has always guarded against this; sync_rules did not.

Reuses test_sync_no_shell's loader/fixtures: agent.api is monkeypatched, so no
live server is involved.
"""
import gzip
import hashlib

import pytest

from tests.agent_unit.test_sync_no_shell import RULE_BODY, agent_main

NEW_BODY = b"c\nd\ne\nf\n"    # different content -> different checksum


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


@pytest.fixture()
def agent_cwd(tmp_path, monkeypatch):
    """A throwaway agent working tree with fresh, empty manifests."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "control" / "rules").mkdir(parents=True)
    (tmp_path / "control" / "wordlists").mkdir(parents=True)
    (tmp_path / "control" / "tmp").mkdir(parents=True)
    monkeypatch.setattr(agent_main, "rules_manifest",
                        agent_main.Manifest(str(tmp_path / "control" / "rules_manifest.json")))
    monkeypatch.setattr(agent_main, "wordlists_manifest",
                        agent_main.Manifest(str(tmp_path / "control" / "wordlists_manifest.json")))
    return tmp_path


@pytest.fixture()
def no_shell(monkeypatch):
    """Any attempt to spawn a process during the sync is a hard failure."""
    def forbidden(*args, **kwargs):
        raise AssertionError(f"sync spawned a process: {args!r} {kwargs!r}")

    monkeypatch.setattr(agent_main.subprocess, "Popen", forbidden)
    monkeypatch.setattr(agent_main.os, "system", forbidden, raising=False)
    return forbidden


def _seed_local_rule(agent_cwd, filename="existing-rule", body=RULE_BODY):
    """A rule already installed locally and recorded in the manifest."""
    (agent_cwd / "control" / "rules" / filename).write_bytes(body)
    agent_main.rules_manifest.data = {
        "7": {"checksum": _sha256(body), "filename": filename}}
    agent_main.rules_manifest.save()
    return agent_cwd / "control" / "rules" / filename


def _serve_rules(monkeypatch, entries, downloader=None):
    monkeypatch.setattr(agent_main.api, "rules_list", lambda: entries)
    monkeypatch.setattr(agent_main.api, "get_rules_file",
                        downloader or (lambda rid: gzip.compress(RULE_BODY)))


# ------------------------------------------------------ honouring `missing`

def test_missing_flagged_rule_is_not_downloaded(agent_cwd, no_shell, monkeypatch):
    calls = []
    _serve_rules(monkeypatch,
                 [{"id": 7, "path": "control/rules/gone", "checksum": "x", "missing": True}],
                 downloader=lambda rid: calls.append(rid))

    agent_main.sync_rules()
    assert calls == []


def test_missing_flagged_rule_keeps_the_local_copy(agent_cwd, no_shell, monkeypatch):
    """The agent's copy may be the only one left; the prune must not eat it."""
    local = _seed_local_rule(agent_cwd)
    _serve_rules(monkeypatch,
                 [{"id": 7, "path": "control/rules/existing-rule",
                   "checksum": "changed-on-the-server", "missing": True}],
                 downloader=lambda rid: pytest.fail("should not download a missing rule"))

    agent_main.sync_rules()
    assert local.exists()
    assert agent_main.rules_manifest.data["7"]["filename"] == "existing-rule"


def test_absent_missing_key_behaves_exactly_as_before(agent_cwd, no_shell, monkeypatch):
    """Old server, new agent: no `missing` key means download as usual."""
    _serve_rules(monkeypatch,
                 [{"id": 7, "path": "control/rules/newrule", "checksum": _sha256(RULE_BODY)}])

    agent_main.sync_rules()
    assert (agent_cwd / "control" / "rules" / "newrule").read_bytes() == RULE_BODY


# ----------------------------------------- the prune-on-failed-download bug

def test_failed_rule_download_does_not_delete_the_local_copy(agent_cwd, no_shell, monkeypatch):
    """One transient 502 used to take the rig down. Fails on main."""
    local = _seed_local_rule(agent_cwd)
    _serve_rules(monkeypatch,
                 [{"id": 7, "path": "control/rules/existing-rule",
                   "checksum": "changed-on-the-server"}],
                 downloader=lambda rid: None)          # server error

    agent_main.sync_rules()
    assert local.exists()
    assert agent_main.rules_manifest.data["7"]["filename"] == "existing-rule"


def test_checksum_mismatch_does_not_delete_the_local_copy(agent_cwd, no_shell, monkeypatch):
    """A corrupted download is a failed download; same guarantee."""
    local = _seed_local_rule(agent_cwd)
    _serve_rules(monkeypatch,
                 [{"id": 7, "path": "control/rules/existing-rule",
                   "checksum": "not-the-checksum-of-what-we-serve"}])

    agent_main.sync_rules()
    assert local.exists()


def test_rule_rename_removes_the_old_file_only_after_a_successful_install(
        agent_cwd, no_shell, monkeypatch):
    """The old file used to be unlinked BEFORE the download was attempted."""
    old = _seed_local_rule(agent_cwd, filename="old-name")
    _serve_rules(monkeypatch,
                 [{"id": 7, "path": "control/rules/new-name", "checksum": _sha256(NEW_BODY)}],
                 downloader=lambda rid: gzip.compress(NEW_BODY))

    agent_main.sync_rules()
    assert not old.exists()
    assert (agent_cwd / "control" / "rules" / "new-name").read_bytes() == NEW_BODY


def test_rule_rename_keeps_the_old_file_when_the_download_fails(agent_cwd, no_shell, monkeypatch):
    old = _seed_local_rule(agent_cwd, filename="old-name")
    _serve_rules(monkeypatch,
                 [{"id": 7, "path": "control/rules/new-name", "checksum": _sha256(NEW_BODY)}],
                 downloader=lambda rid: None)
    agent_main.sync_rules()
    assert old.exists()


# ----------------------------------------------------------- wordlists side

def test_missing_flagged_wordlist_is_not_downloaded(agent_cwd, no_shell, monkeypatch):
    calls = []
    monkeypatch.setattr(agent_main.api, "getWordlists", lambda: [
        {"id": 4, "path": "control/wordlists/gone.gz", "checksum": "x",
         "type": "static", "missing": True}])
    monkeypatch.setattr(agent_main.api, "get_wordlists_file",
                        lambda wid: calls.append(wid))

    agent_main.sync_wordlists()
    assert calls == []


def test_missing_flagged_wordlist_keeps_the_local_copy(agent_cwd, no_shell, monkeypatch):
    local = agent_cwd / "control" / "wordlists" / "kept.gz"
    local.write_bytes(gzip.compress(b"a\nb\n"))
    agent_main.wordlists_manifest.data = {"4": {"checksum": "old", "filename": "kept.gz"}}
    agent_main.wordlists_manifest.save()
    monkeypatch.setattr(agent_main.api, "getWordlists", lambda: [
        {"id": 4, "path": "control/wordlists/kept", "checksum": "changed",
         "type": "static", "missing": True}])
    monkeypatch.setattr(agent_main.api, "get_wordlists_file",
                        lambda wid: pytest.fail("should not download a missing wordlist"))

    agent_main.sync_wordlists()
    assert local.exists()


def test_wordlist_absent_missing_key_behaves_as_before(agent_cwd, no_shell, monkeypatch):
    body = gzip.compress(b"a\nb\n")
    monkeypatch.setattr(agent_main.api, "getWordlists", lambda: [
        {"id": 4, "path": "control/wordlists/fresh", "checksum": _sha256(body),
         "type": "static"}])
    monkeypatch.setattr(agent_main.api, "get_wordlists_file", lambda wid: body)

    agent_main.sync_wordlists()
    assert (agent_cwd / "control" / "wordlists" / "fresh.gz").exists()
