"""Unit tests for hash file parsers in ``hashview.utils.utils``.

These tests pin parser behavior for the file formats the app supports:
- **pwdump**: filters out machine accounts (``trailing $``) AND a duplicate
  ``_history0``/bare ``_history`` row when the account's current-password
  row is also present (issue #412); ``_history1`` and up are always kept
- **shadow**: extracts username + crypt-style hash
- **NetNTLM (5500/5600)**: filters machine accounts, uppercases the
  username, lowercases the ciphertext parts
- **hash_only**: handles non-1000 hash types

The parsers commit rows to the DB via ``_import_chunk`` /
``import_hashfilehashes``, so we use an in-memory SQLite app from the unit
conftest.
"""

import pytest

from hashview.models import Hashes, HashfileHashes, Hashfiles, Users, db
from hashview.utils.utils import import_hashfilehashes


def _make_user_and_hashfile() -> int:
    user = Users(
        first_name="t",
        last_name="u",
        email_address="t@example.com",
        password="x" * 60,
        admin=True,
    )
    db.session.add(user)
    db.session.commit()
    hashfile = Hashfiles(
        name="t.txt",
        customer_id=1,
        owner_id=user.id,
    )
    db.session.add(hashfile)
    db.session.commit()
    return hashfile.id


def _decode_username(stored: str) -> str:
    # usernames are stored as plain UTF-8 text now (no more latin-1 hex)
    return stored


def _all_usernames(hashfile_id: int):
    return {
        _decode_username(hfh.username)
        for hfh in HashfileHashes.query.filter_by(hashfile_id=hashfile_id).all()
        if hfh.username
    }


@pytest.mark.security
def test_pwdump_filters_machine_accounts_and_history(app, tmp_path):
    """Lines ending in ``$`` (machine accounts) are always dropped. A
    ``_history0`` row is dropped only because its base account (``alice``) is
    also in the file (issue #412); ``_history1`` is a real, distinct password
    and is always kept."""
    hashfile_id = _make_user_and_hashfile()
    path = tmp_path / "pwdump.txt"
    path.write_text(
        "\n".join([
            # real user — should land
            "alice:1001:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::",
            # machine account — should be skipped
            "WIN10$:1002:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586d:::",
            # duplicate of alice's current password — should be skipped
            "alice_history0:1003:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586e:::",
            # a real, distinct prior password — should land
            "alice_history1:1004:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586f:::",
        ]) + "\n"
    )

    import_hashfilehashes(
        hashfile_id=hashfile_id,
        hashfile_path=str(path),
        file_type="pwdump",
        hash_type="1000",
    )

    usernames = _all_usernames(hashfile_id)
    assert usernames == {"alice", "alice_history1"}


@pytest.mark.security
def test_shadow_imports_username_and_hash(app, tmp_path):
    hashfile_id = _make_user_and_hashfile()
    path = tmp_path / "shadow"
    # username:$6$salt$hash:...
    path.write_text(
        "root:$6$rounds=5000$abc$ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ:18000:0:99999:7:::\n"
        "alice:$6$saltyy$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:18000:0:99999:7:::\n"
    )

    import_hashfilehashes(
        hashfile_id=hashfile_id,
        hashfile_path=str(path),
        file_type="shadow",
        hash_type="1800",
    )

    usernames = _all_usernames(hashfile_id)
    assert usernames == {"root", "alice"}


@pytest.mark.security
def test_netntlm_filters_machine_accounts_and_uppercases_username(app, tmp_path):
    """NetNTLMv1/v2 import should drop lines whose username ends in ``$``
    and store the username uppercased."""
    hashfile_id = _make_user_and_hashfile()
    path = tmp_path / "netntlm.txt"
    # Format: USER::DOMAIN:server_chal:nt_resp:lm_resp
    path.write_text(
        "alice::CORP:1122334455667788:"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:"
        "1122334455667788AABBCCDDEEFF1122334455667788AABBCCDD\n"
        "MACHINE$::CORP:1122334455667788:"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:"
        "1122334455667788AABBCCDDEEFF1122334455667788AABBCCDD\n"
    )

    import_hashfilehashes(
        hashfile_id=hashfile_id,
        hashfile_path=str(path),
        file_type="NetNTLM",
        hash_type="5500",
    )

    usernames = _all_usernames(hashfile_id)
    assert "ALICE" in usernames
    assert not any(u.endswith("$") for u in usernames)


@pytest.mark.security
def test_hash_only_non_1000_preserves_case(app, tmp_path):
    """For hash_type=0 (MD5), import should preserve the input as-is (no
    lowercasing — that's reserved for NTLM/SHA1)."""
    hashfile_id = _make_user_and_hashfile()
    path = tmp_path / "md5.txt"
    path.write_text("5F4DCC3B5AA765D61D8327DEB882CF99\n")  # md5("password")

    import_hashfilehashes(
        hashfile_id=hashfile_id,
        hashfile_path=str(path),
        file_type="hash_only",
        hash_type="0",
    )

    rows = (
        Hashes.query.join(HashfileHashes, Hashes.id == HashfileHashes.hash_id)
        .filter(HashfileHashes.hashfile_id == hashfile_id)
        .all()
    )
    assert len(rows) == 1
    assert rows[0].ciphertext == "5F4DCC3B5AA765D61D8327DEB882CF99"


@pytest.mark.security
def test_user_hash_ntlm_lowercases_ciphertext(app, tmp_path):
    """user_hash NTLM import must store the hash lowercased so it matches
    hashcat's lowercase crack output. The crack-upload lookup is
    ``sub_ciphertext == md5(ciphertext)`` and md5 is case-sensitive, so an
    uppercase-stored hash would never be recorded as recovered."""
    hashfile_id = _make_user_and_hashfile()
    path = tmp_path / "userhash.txt"
    # emoji username + UPPERCASE NTLM('password'); hashcat returns it lowercased
    path.write_text("\U0001f63a:8846F7EAEE8FB117AD06BDD830B7586C\n", encoding="utf-8")

    import_hashfilehashes(
        hashfile_id=hashfile_id,
        hashfile_path=str(path),
        file_type="user_hash",
        hash_type="1000",
    )

    row = Hashes.query.first()
    assert row.ciphertext == "8846f7eaee8fb117ad06bdd830b7586c"   # stored lowercased


@pytest.mark.security
def test_hash_only_ntlm_lowercases(app, tmp_path):
    """hash_type 1000 (NTLM) lower-cases on import (hashcat returns lowercase)."""
    hashfile_id = _make_user_and_hashfile()
    path = tmp_path / "ntlm.txt"
    path.write_text("8846F7EAEE8FB117AD06BDD830B7586C\n")

    import_hashfilehashes(
        hashfile_id=hashfile_id,
        hashfile_path=str(path),
        file_type="hash_only",
        hash_type="1000",
    )

    row = Hashes.query.first()
    assert row.ciphertext == "8846f7eaee8fb117ad06bdd830b7586c"


# ---------------------------------------------------------------------------
# batched import (#363)
# ---------------------------------------------------------------------------


def _count_import(hashfile_id, path, file_type, hash_type):
    """Run an import, returning (commits, statements, ok)."""
    from sqlalchemy import event

    statements = []

    def record(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement.split()[0].upper())

    commits = [0]
    real_commit = db.session.commit

    def counting_commit():
        commits[0] += 1
        return real_commit()

    event.listen(db.engine, "before_cursor_execute", record)
    db.session.commit = counting_commit
    try:
        ok = import_hashfilehashes(hashfile_id=hashfile_id, hashfile_path=str(path),
                                   file_type=file_type, hash_type=hash_type)
    finally:
        db.session.commit = real_commit
        event.remove(db.engine, "before_cursor_execute", record)
    return commits[0], statements, ok


def _md5_lines(n, prefix="u"):
    import hashlib
    return [hashlib.md5(f"{prefix}{i}".encode()).hexdigest() for i in range(n)]


@pytest.mark.security
def test_import_commits_once_per_chunk_not_once_per_row(app, tmp_path):
    """The #363 regression guard.

    Import used to issue one SELECT + INSERT + commit per new hash and another
    INSERT + commit per link row -- ~2N commits, each an InnoDB redo-log fsync,
    which is what made a large hashfile take minutes. Measured on this file
    before the change: 3,000 commits and 6,000 statements; after: 1 and 4.

    Asserted as "does not grow with row count" rather than as an exact number,
    so it cannot be satisfied by a rewrite that is merely different.
    """
    hashfile_id = _make_user_and_hashfile()
    uniq = _md5_lines(1000)
    path = tmp_path / "batched.txt"
    # 50% overlap: the second half repeats the first, the realistic case
    path.write_text("\n".join(uniq + uniq) + "\n")

    commits, statements, ok = _count_import(hashfile_id, path, "hash_only", "1000")
    assert ok is True
    # 2,000 lines fit one chunk, so this is a single transaction.
    assert commits == 1, f"expected one commit for one chunk, got {commits}"
    assert len(statements) < 20, f"per-row statements are back: {len(statements)}"
    # ...and the data is still exactly right.
    assert Hashes.query.count() == 1000
    assert HashfileHashes.query.filter_by(hashfile_id=hashfile_id).count() == 2000


@pytest.mark.security
def test_import_cost_scales_with_chunks_not_rows(app, tmp_path):
    """Doubling the rows at a fixed chunk size must not double the statements."""
    from hashview.utils import utils as utils_mod

    hashfile_id = _make_user_and_hashfile()
    original = utils_mod._IMPORT_CHUNK_SIZE
    utils_mod._IMPORT_CHUNK_SIZE = 100
    try:
        path = tmp_path / "a.txt"
        path.write_text("\n".join(_md5_lines(200, "a")) + "\n")
        commits_200, _, _ = _count_import(hashfile_id, path, "hash_only", "1000")

        path2 = tmp_path / "b.txt"
        path2.write_text("\n".join(_md5_lines(400, "b")) + "\n")
        commits_400, _, _ = _count_import(hashfile_id, path2, "hash_only", "1000")
    finally:
        utils_mod._IMPORT_CHUNK_SIZE = original

    assert commits_200 == 2      # 200 rows / 100 per chunk
    assert commits_400 == 4      # 400 rows / 100 per chunk, not 400 commits


@pytest.mark.security
def test_import_dedupes_duplicates_that_span_two_chunks(app, tmp_path):
    """Cross-chunk dedup no longer relies on read-your-writes from a per-row commit.

    Within a chunk duplicates collapse on (hash_type, sub_ciphertext) before the
    insert; across chunks the earlier chunk is already committed, so the lookup
    finds it. Both halves have to hold or a hash gets inserted twice.
    """
    from hashview.utils import utils as utils_mod

    hashfile_id = _make_user_and_hashfile()
    original = utils_mod._IMPORT_CHUNK_SIZE
    utils_mod._IMPORT_CHUNK_SIZE = 10
    try:
        uniq = _md5_lines(10, "dup")
        path = tmp_path / "spanning.txt"
        # 10 unique, then the same 10 again -> chunk 2 must find chunk 1's rows,
        # and a third copy inside chunk 2 must collapse within the chunk.
        path.write_text("\n".join(uniq + uniq + uniq) + "\n")
        _, _, ok = _count_import(hashfile_id, path, "hash_only", "1000")
    finally:
        utils_mod._IMPORT_CHUNK_SIZE = original

    assert ok is True
    assert Hashes.query.count() == 10
    assert HashfileHashes.query.filter_by(hashfile_id=hashfile_id).count() == 30


@pytest.mark.security
def test_import_returns_false_on_a_malformed_user_hash_line(app, tmp_path):
    """A user_hash line with no ':' aborts the import, as it did before."""
    hashfile_id = _make_user_and_hashfile()
    path = tmp_path / "bad.txt"
    path.write_text("alice:8846f7eaee8fb117ad06bdd830b7586c\nno-colon-here\n")

    _, _, ok = _count_import(hashfile_id, path, "user_hash", "1000")
    assert ok is False


@pytest.mark.security
def test_duplicate_hash_type_sub_ciphertext_is_rejected_by_the_database(app):
    """uq_hashes_sub_ciphertext_hash_type enforces what the dedup assumed.

    The import looks a hash up by this pair and inserts when absent, so without
    the constraint two concurrent imports of the same hash could both miss and
    both insert. Nothing enforced it before.
    """
    from sqlalchemy.exc import IntegrityError

    db.session.add(Hashes(hash_type=1000, sub_ciphertext="a" * 32,
                          ciphertext="one", cracked=0))
    db.session.commit()

    db.session.add(Hashes(hash_type=1000, sub_ciphertext="a" * 32,
                          ciphertext="two-different-ciphertext", cracked=0))
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()

    # The same sub_ciphertext under a *different* hash_type is still fine: an
    # NTLM hash and an MD5 hash can be the same 32 hex characters, which is
    # exactly why the constraint is on the pair and not on sub_ciphertext alone.
    db.session.add(Hashes(hash_type=0, sub_ciphertext="a" * 32,
                          ciphertext="one", cracked=0))
    db.session.commit()
    assert Hashes.query.filter_by(sub_ciphertext="a" * 32).count() == 2


@pytest.mark.security
def test_import_chunk_retries_once_after_a_concurrent_insert(app, tmp_path, monkeypatch):
    """A losing race is retried, not surfaced.

    With the constraint in place, a concurrent import inserting one of our
    hashes between our lookup and our insert makes the insert fail rather than
    silently duplicate. _import_chunk retries once; the retry's lookup finds
    the other importer's row.
    """
    from sqlalchemy.exc import IntegrityError

    from hashview.utils import utils as utils_mod

    hashfile_id = _make_user_and_hashfile()
    path = tmp_path / "raced.txt"
    path.write_text("\n".join(_md5_lines(5, "race")) + "\n")

    real_once = utils_mod._import_chunk_once
    calls = []

    def flaky(hf_id, rows):
        calls.append(len(rows))
        if len(calls) == 1:
            db.session.rollback()
            raise IntegrityError("simulated concurrent insert", None, Exception())
        return real_once(hf_id, rows)

    monkeypatch.setattr(utils_mod, "_import_chunk_once", flaky)
    assert utils_mod.import_hashfilehashes(
        hashfile_id=hashfile_id, hashfile_path=str(path),
        file_type="hash_only", hash_type="1000") is True

    assert len(calls) == 2, "the chunk should be attempted exactly twice"
    assert Hashes.query.count() == 5
    assert HashfileHashes.query.filter_by(hashfile_id=hashfile_id).count() == 5


@pytest.mark.security
def test_import_chunk_reraises_if_the_retry_also_conflicts(app, tmp_path, monkeypatch):
    """One retry, not an unbounded loop."""
    from sqlalchemy.exc import IntegrityError

    from hashview.utils import utils as utils_mod

    hashfile_id = _make_user_and_hashfile()
    path = tmp_path / "always.txt"
    path.write_text("\n".join(_md5_lines(2, "always")) + "\n")

    calls = []

    def always_conflict(hf_id, rows):
        calls.append(1)
        db.session.rollback()
        raise IntegrityError("persistent conflict", None, Exception())

    monkeypatch.setattr(utils_mod, "_import_chunk_once", always_conflict)
    with pytest.raises(IntegrityError):
        utils_mod.import_hashfilehashes(
            hashfile_id=hashfile_id, hashfile_path=str(path),
            file_type="hash_only", hash_type="1000")
    assert len(calls) == 2, "exactly one retry, then give up"
