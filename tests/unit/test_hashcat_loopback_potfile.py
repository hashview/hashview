"""Unit tests for the per-task --loopback toggle and per-jobtask potfile.

Covers the change to ``build_hashcat_command`` (hashview/utils/utils.py):
  - every command now points at a per-jobtask potfile
    (``control/outfiles/hc_potfile_<job>_<task>.pot``) instead of the old global
    ``--potfile-disable``;
  - ``--loopback`` is emitted ONLY for straight mode (-a 0) WITH a rule when the
    task opted in (``Tasks.loopback``); it is suppressed for dict-without-rule,
    combinator, mask, and hybrid (hashcat only supports loopback with -a 0 +
    rules);
  - the tasks add/edit routes persist + clear ``Tasks.loopback``.

Mirrors the in-memory-app + control-dir-cleanup pattern of
tests/unit/test_wordlist_gzip_storage.py. The test body runs inside the ``app``
fixture's app context, so ``build_hashcat_command`` (which reads ``current_app``
indirectly via the DB session) works without a nested context.
"""

import os
from pathlib import Path

import pytest

from hashview.models import (
    Hashes,
    HashfileHashes,
    Hashfiles,
    Jobs,
    Rules,
    Tasks,
    Users,
    db,
)
from hashview.utils.utils import build_hashcat_command, ingest_static_wordlist_file

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTROL = REPO_ROOT / "hashview" / "control"
WORDLISTS_DIR = CONTROL / "wordlists"
TMP_DIR = CONTROL / "tmp"
COOKIE_DOMAIN = "localhost.test"


@pytest.fixture(autouse=True)
def _clean_control_dirs():
    """Remove any files these tests create under the real control dirs."""
    def snapshot(d):
        return set(os.listdir(d)) if d.exists() else set()
    before_wl = snapshot(WORDLISTS_DIR)
    before_tmp = snapshot(TMP_DIR)
    yield
    for d, before in ((WORDLISTS_DIR, before_wl), (TMP_DIR, before_tmp)):
        if not d.exists():
            continue
        for name in set(os.listdir(d)) - before:
            try:
                os.remove(d / name)
            except OSError:
                pass


def _make_user(api_key="loopkey"):
    user = Users(first_name="A", last_name="D", email_address="a@e.com",
                 password="x" * 60, admin=True, api_key=api_key)
    db.session.add(user)
    db.session.commit()
    return user


def _login(client, user):
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True


def _wordlist(user, name="WL"):
    """Ingest a tiny static wordlist (stored compressed at rest)."""
    src = TMP_DIR / ("src_" + name)
    src.write_bytes(b"alpha\nbravo\n")
    wl = ingest_static_wordlist_file(str(src), user.id, name)
    db.session.add(wl)
    db.session.commit()
    if src.exists():
        os.remove(src)
    return wl


def _rule(user, name="best64"):
    rule = Rules(name=name, owner_id=user.id, path="control/rules/best64.rule",
                 checksum="0" * 64, size=1)
    db.session.add(rule)
    db.session.commit()
    return rule


def _build(user, *, attackmode, wl=None, wl_id_2=None, rule_id=None,
           loopback=False, mask=None):
    """Create a job+task for one wordlist and return (cmd, job, task)."""
    hsh = Hashes(sub_ciphertext="0" * 8, ciphertext="abcd", hash_type=0, cracked=False)
    db.session.add(hsh)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=hsh.id, hashfile_id=1))
    job = Jobs(name="j", status="Queued", hashfile_id=1, customer_id=1, owner_id=user.id)
    db.session.add(job)
    task = Tasks(name="t", hc_attackmode=attackmode, owner_id=user.id,
                 wl_id=(wl.id if wl else None), wl_id_2=wl_id_2, rule_id=rule_id,
                 hc_mask=mask, loopback=loopback)
    db.session.add(task)
    db.session.commit()
    cmd = build_hashcat_command(job.id, task.id)
    return cmd, job, task


# ---------------------------------------------------------------------------
# Potfile: every mode gets a unique --potfile-path, never --potfile-disable
# ---------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.parametrize("attackmode", [0, 1, 3, 6, 7])
def test_potfile_path_replaces_potfile_disable(app, attackmode):
    user = _make_user()
    wl = _wordlist(user)
    rule = _rule(user)
    kwargs = {"attackmode": attackmode, "wl": wl}
    if attackmode == 0:
        kwargs["rule_id"] = rule.id
    elif attackmode == 1:
        kwargs["wl_id_2"] = wl.id
    elif attackmode in (3, 6, 7):
        kwargs["mask"] = "?d?d?d"

    cmd, job, task = _build(user, **kwargs)

    assert "--potfile-disable" not in cmd
    expected = "--potfile-path control/outfiles/hc_potfile_%d_%d.pot" % (job.id, task.id)
    assert expected in cmd


# ---------------------------------------------------------------------------
# --loopback gating
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_loopback_emitted_for_straight_with_rule_when_enabled(app):
    user = _make_user()
    wl = _wordlist(user)
    rule = _rule(user)
    cmd, _, _ = _build(user, attackmode=0, wl=wl, rule_id=rule.id, loopback=True)
    assert " --loopback" in cmd
    assert "-r control/rules/best64.rule" in cmd        # still a dict+rule command


@pytest.mark.security
def test_no_loopback_when_disabled(app):
    user = _make_user()
    wl = _wordlist(user)
    rule = _rule(user)
    cmd, _, _ = _build(user, attackmode=0, wl=wl, rule_id=rule.id, loopback=False)
    assert "--loopback" not in cmd


@pytest.mark.security
def test_no_loopback_for_straight_without_rule(app):
    """loopback=True but no rule selected -> hashcat would reject it, so suppress."""
    user = _make_user()
    wl = _wordlist(user)
    cmd, _, _ = _build(user, attackmode=0, wl=wl, rule_id=None, loopback=True)
    assert "--loopback" not in cmd


@pytest.mark.security
@pytest.mark.parametrize("attackmode,extra", [
    (1, {"wl_id_2": "self"}),
    (3, {"mask": "?d?d?d"}),
    (6, {"mask": "?d?d?d"}),
    (7, {"mask": "?d?d?d"}),
])
def test_no_loopback_for_non_straight_modes(app, attackmode, extra):
    """Even with loopback=True, only -a 0 + rule emits it; other modes never do."""
    user = _make_user()
    wl = _wordlist(user)
    kwargs = {"attackmode": attackmode, "wl": wl, "loopback": True}
    if extra.get("wl_id_2") == "self":
        kwargs["wl_id_2"] = wl.id
    if "mask" in extra:
        kwargs["mask"] = extra["mask"]
    cmd, _, _ = _build(user, **kwargs)
    assert "--loopback" not in cmd


@pytest.mark.security
def test_no_loopback_when_chunked(app):
    """--loopback is mutually exclusive with --limit in hashcat, so a chunked
    slice (which carries --skip/--limit) must omit --loopback even on -a 0 + rule."""
    user = _make_user()
    wl = _wordlist(user)
    rule = _rule(user)
    _, job, task = _build(user, attackmode=0, wl=wl, rule_id=rule.id, loopback=True)
    # whole task still emits --loopback
    assert "--loopback" in build_hashcat_command(job.id, task.id)
    # a chunk slice drops --loopback and adds --skip/--limit
    chunked = build_hashcat_command(job.id, task.id, chunk={"skip": 0, "limit": 50},
                                    job_task_id=999)
    assert "--loopback" not in chunked
    assert "--skip 0 --limit 50" in chunked


# ---------------------------------------------------------------------------
# Chunked commands: mask-mode sub-mask override + per-jobtask temp file keying
# ---------------------------------------------------------------------------


def test_mask_chunk_overrides_task_mask(app):
    """A mask chunk ({'mask': ...}) runs its sub-mask in place of the task's mask
    (mask base-loop modes 3/7) and never carries --skip/--limit."""
    user = _make_user()
    task_mask = "?d?d?d?d"
    _, job, task = _build(user, attackmode=3, mask=task_mask)
    # whole task runs the task's own mask
    assert build_hashcat_command(job.id, task.id).endswith(task_mask)
    # a mask chunk substitutes its sub-mask for the task mask
    chunked = build_hashcat_command(job.id, task.id, chunk={"mask": "00?d?d"},
                                    job_task_id=42)
    assert chunked.endswith("00?d?d")
    assert "-a 3 " in chunked
    assert task_mask not in chunked          # original mask fully replaced
    assert "--skip" not in chunked and "--limit" not in chunked


def test_chunk_temp_files_keyed_on_job_task_id(app):
    """job_task_id keys the per-run temp files so two chunks of one task never
    collide on target/outfile/potfile; omitting it falls back to task_id."""
    user = _make_user()
    wl = _wordlist(user)
    rule = _rule(user)
    _, job, task = _build(user, attackmode=0, wl=wl, rule_id=rule.id)

    # whole task (no job_task_id) -> files keyed on task_id
    whole = build_hashcat_command(job.id, task.id)
    for tmpl in ("control/hashes/hashfile_%d_%d.txt",
                 "control/outfiles/hc_cracked_%d_%d.txt",
                 "control/outfiles/hc_potfile_%d_%d.pot"):
        assert tmpl % (job.id, task.id) in whole

    # two chunks with distinct job_task_ids never share a file name
    c1 = build_hashcat_command(job.id, task.id, chunk={"skip": 0, "limit": 5},
                               job_task_id=101)
    c2 = build_hashcat_command(job.id, task.id, chunk={"skip": 5, "limit": 5},
                               job_task_id=202)
    assert ("control/outfiles/hc_cracked_%d_101.txt" % job.id) in c1
    assert ("control/outfiles/hc_cracked_%d_202.txt" % job.id) in c2
    assert ("control/hashes/hashfile_%d_101.txt" % job.id) in c1
    assert ("control/outfiles/hc_potfile_%d_202.pot" % job.id) in c2


# ---------------------------------------------------------------------------
# --hex-salt: emitted only for a hex_salt hashfile on a salted mode
# ---------------------------------------------------------------------------


def _build_hex(user, *, hex_salt, hash_type, ciphertext="abcd:cafe"):
    """Build a job whose hashfile carries the given hex_salt flag + hash mode and
    return its hashcat command (straight dict mode, no rule)."""
    hf = Hashfiles(name="hf", customer_id=1, owner_id=user.id, hex_salt=hex_salt)
    db.session.add(hf)
    db.session.commit()
    hsh = Hashes(sub_ciphertext="0" * 8, ciphertext=ciphertext, hash_type=hash_type, cracked=False)
    db.session.add(hsh)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=hsh.id, hashfile_id=hf.id))
    job = Jobs(name="j", status="Queued", hashfile_id=hf.id, customer_id=1, owner_id=user.id)
    db.session.add(job)
    wl = _wordlist(user)
    task = Tasks(name="t", hc_attackmode=0, owner_id=user.id,
                 wl_id=wl.id, rule_id=None, hc_mask=None, loopback=False)
    db.session.add(task)
    db.session.commit()
    return build_hashcat_command(job.id, task.id)


@pytest.mark.security
def test_hex_salt_emitted_for_salted_mode(app):
    user = _make_user()
    cmd = _build_hex(user, hex_salt=True, hash_type=10)     # md5($pass.$salt) -> salted
    assert " --hex-salt" in cmd
    assert " -m 10" in cmd


@pytest.mark.security
def test_hex_salt_omitted_when_flag_off(app):
    user = _make_user()
    cmd = _build_hex(user, hex_salt=False, hash_type=10)
    assert "--hex-salt" not in cmd


@pytest.mark.security
def test_hex_salt_omitted_for_unsalted_mode(app):
    """Flag on, but an unsalted mode (NTLM) has no salt -> hashcat would reject
    --hex-salt, so it must be suppressed."""
    user = _make_user()
    cmd = _build_hex(user, hex_salt=True, hash_type=1000, ciphertext="b" * 32)
    assert "--hex-salt" not in cmd


# ---------------------------------------------------------------------------
# Routes persist / clear Tasks.loopback
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_tasks_add_persists_loopback(app, client):
    user = _make_user()
    _login(client, user)
    wl = _wordlist(user, name="AddWL")

    resp = client.post("/tasks/add", data={
        "name": "loop-task",
        "hc_attackmode": "0",
        "wl_id": str(wl.id),
        "wl_id_2": str(wl.id),       # hidden select still submits a value in the browser
        "rule_id": "None",
        "loopback": "y",
        "submit": "Create",
    }, follow_redirects=False)
    assert resp.status_code in (301, 302)

    task = Tasks.query.filter_by(name="loop-task").first()
    assert task is not None and task.loopback is True


@pytest.mark.security
def test_tasks_add_without_checkbox_defaults_false(app, client):
    user = _make_user()
    _login(client, user)
    wl = _wordlist(user, name="AddWL2")

    resp = client.post("/tasks/add", data={
        "name": "no-loop-task",
        "hc_attackmode": "0",
        "wl_id": str(wl.id),
        "wl_id_2": str(wl.id),
        "rule_id": "None",
        "submit": "Create",
    }, follow_redirects=False)
    assert resp.status_code in (301, 302)

    task = Tasks.query.filter_by(name="no-loop-task").first()
    assert task is not None and task.loopback is False


@pytest.mark.security
def test_edit_to_mask_clears_loopback(app, client):
    user = _make_user()
    _login(client, user)
    wl = _wordlist(user, name="EditWL")
    # start as a dict task with loopback on
    task = Tasks(name="edit-task", hc_attackmode=0, owner_id=user.id,
                 wl_id=wl.id, rule_id=None, loopback=True)
    db.session.add(task)
    db.session.commit()
    task_id = task.id

    resp = client.post(f"/tasks/edit/{task_id}", data={
        "name": "edit-task",
        "hc_attackmode": "3",
        "wl_id": str(wl.id),
        "wl_id_2": str(wl.id),
        "rule_id": "None",
        "mask": "?d?d?d",
        "submit": "Update",
    }, follow_redirects=False)
    assert resp.status_code in (301, 302)

    refreshed = Tasks.query.get(task_id)
    assert refreshed.hc_attackmode == 3
    assert refreshed.loopback is False


# ---------------------------------------------------------------------------
# Tasks page (the real modal UI + info modal)
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_tasks_page_renders_loopback_modal_field_and_info_cell(app, client):
    """GET /tasks renders the loopback toggle in the add/edit modal and shows
    Loopback state in a dict+rule task's info modal — but not for other modes."""
    user = _make_user()
    _login(client, user)
    wl = _wordlist(user, name="PageWL")
    rule = _rule(user)
    # a dict+rule task with loopback ON ...
    db.session.add(Tasks(name="dictrule-task", hc_attackmode=0, owner_id=user.id,
                         wl_id=wl.id, rule_id=rule.id, loopback=True))
    # ... and a mask task (loopback is not applicable here)
    db.session.add(Tasks(name="mask-task", hc_attackmode=3, owner_id=user.id,
                         wl_id=None, rule_id=None, hc_mask="?d?d?d", loopback=False))
    db.session.commit()

    resp = client.get("/tasks")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)

    # add/edit modal field (shared macro renders it for both 'atk' and 'etk')
    assert 'name="loopback"' in html
    assert 'id="atk-fld-loopback"' in html
    assert 'id="etk-fld-loopback"' in html
    # edit prefill payload carries the saved flag
    assert "loopback:true" in html

    # info modal: the dict+rule task shows the Loopback cell as Enabled; the
    # mask task adds no Loopback cell, so the kv-label appears exactly once.
    assert html.count(">Loopback<") == 1
    assert "Enabled" in html
