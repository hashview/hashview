"""A hashfile with trailing blank lines must import, not 500.

Reported from a live v0.8.3-dev instance (04867a1): a NetNTLM upload whose file
ended in three empty lines returned HTTP 500 from the job wizard --

    File "hashview/utils/utils.py", line 1055, in _classify_hashfile_line
        line_list[3] = line_list[3].lower()
    IndexError: list index out of range

Two guards are supposed to stop that, and the interesting part is that the
FIRST one works:

  * ``_validate_hashfile`` strips each line and skips it when empty, so a file
    whose only flaw is trailing newlines passes validation and is accepted;
  * ``import_hashfilehashes`` then had its own guard, ``if len(line) == 0``,
    which is never true. Iterating a file yields the newline WITH the line, so a
    blank line arrives as ``'\\n'``. Only a zero-length string would match, and
    iteration never produces one.

So validation deliberately waved the lines through and the importer tripped over
exactly those lines, two statements below its own dead guard.

Every format is covered here rather than just the reported one, because the
blast radius differs per format and the quietest case is the worst: pwdump,
shadow, NetNTLM and kerberos raise IndexError (the 500), user_hash aborts the
whole file, and hash_only raises nothing at all -- it imports a row whose
ciphertext is the empty string, which then sits in the corpus joining dedup and
analytics with nothing to indicate it is junk.
"""
import pytest

from hashview.models import Hashes, HashfileHashes, Hashfiles, Users, db
from hashview.utils.utils import import_hashfilehashes

# One valid line per format, with the hash_type the UI would pass alongside it.
FORMATS = [
    ("hash_only", "1000", "8846f7eaee8fb117ad06bdd830b7586c"),
    ("user_hash", "1000", "alice:8846f7eaee8fb117ad06bdd830b7586c"),
    ("pwdump", "1000",
     "alice:1001:aad3b435b51404eeaad3b435b51404ee:"
     "8846f7eaee8fb117ad06bdd830b7586c:::"),
    ("shadow", "1800",
     "alice:$6$saltyy$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:18000:0:99999:7:::"),
    ("NetNTLM", "5600",
     "alice::CORP:1122334455667788:" + "a" * 32 + ":" + "b" * 64),
    ("kerberos", "13100",
     "$krb5tgs$23$*alice$CORP.LOCAL$cifs/host*$" + "a" * 32 + "$" + "b" * 64),
]

# The shapes a real editor or export produces. The reported file was the third.
TRAILERS = [
    pytest.param("\n", id="single-trailing-newline"),
    pytest.param("\n\n", id="one-blank-line"),
    pytest.param("\n\n\n\n", id="three-blank-lines-as-reported"),
    pytest.param("\n   \n\t\n\n", id="whitespace-only-lines"),
    pytest.param("\r\n\r\n", id="crlf-blank-lines"),
]


def _hashfile(email="blank@example.com"):
    user = Users(first_name="t", last_name="u", email_address=email,
                 password="x" * 60, admin=True)
    db.session.add(user)
    db.session.commit()
    hashfile = Hashfiles(name="t.txt", customer_id=1, owner_id=user.id)
    db.session.add(hashfile)
    db.session.commit()
    return hashfile.id


def _rows(hashfile_id):
    return (db.session.query(Hashes)
            .join(HashfileHashes, HashfileHashes.hash_id == Hashes.id)
            .filter(HashfileHashes.hashfile_id == hashfile_id).all())


@pytest.mark.parametrize("file_type, hash_type, line", FORMATS)
@pytest.mark.parametrize("trailer", TRAILERS)
def test_trailing_blank_lines_do_not_break_the_import(app, tmp_path, file_type,
                                                      hash_type, line, trailer):
    """The report, generalised: one good hash, then blank lines.

    Asserting the return value AND the row count matters. Returning False is the
    user_hash failure mode (the upload is refused rather than crashing), and a
    silent extra row is the hash_only one -- a pass/no-exception check would
    call both of those fine.
    """
    hashfile_id = _hashfile(f"blank-{file_type}-{len(trailer)}@example.com")
    path = tmp_path / "hashes.txt"
    path.write_text(line + trailer)

    ok = import_hashfilehashes(hashfile_id=hashfile_id, hashfile_path=str(path),
                               file_type=file_type, hash_type=hash_type)

    assert ok is not False, f"{file_type}: import refused a file of one hash + blank lines"
    rows = _rows(hashfile_id)
    assert len(rows) == 1, (
        f"{file_type}: expected exactly the one real hash, got {len(rows)}: "
        f"{[r.ciphertext for r in rows]}")
    assert rows[0].ciphertext.strip(), (
        f"{file_type}: imported a row with an empty ciphertext")


@pytest.mark.parametrize("file_type, hash_type, line", FORMATS)
def test_blank_lines_between_hashes_are_skipped_too(app, tmp_path, file_type,
                                                    hash_type, line):
    """Not only trailing. A blank line in the middle is the same defect and is
    what an operator gets from concatenating two exports."""
    hashfile_id = _hashfile(f"mid-{file_type}@example.com")
    path = tmp_path / "hashes.txt"
    path.write_text("\n" + line + "\n\n")

    ok = import_hashfilehashes(hashfile_id=hashfile_id, hashfile_path=str(path),
                               file_type=file_type, hash_type=hash_type)

    assert ok is not False
    assert len(_rows(hashfile_id)) == 1


@pytest.mark.parametrize("file_type, hash_type", [(f, h) for f, h, _ in FORMATS])
def test_a_file_of_only_blank_lines_imports_nothing(app, tmp_path, file_type,
                                                    hash_type):
    """The degenerate case. It must import zero rows rather than crash or
    manufacture one -- _validate_hashfile rejects this file up front ("contains
    no hashes"), so reaching the importer at all means something upstream let it
    past, and the importer should still not invent data."""
    hashfile_id = _hashfile(f"empty-{file_type}@example.com")
    path = tmp_path / "hashes.txt"
    path.write_text("\n\n   \n\t\n")

    import_hashfilehashes(hashfile_id=hashfile_id, hashfile_path=str(path),
                          file_type=file_type, hash_type=hash_type)

    assert _rows(hashfile_id) == []


def test_the_guard_matches_the_validators_rule(app, tmp_path):
    """The two layers must agree.

    The bug was not that either rule was wrong on its own -- it was that the
    validator skipped a line the importer then parsed. Anything validation
    accepts, import has to survive.
    """
    from hashview.utils.utils import validate_netntlm_hashfile

    good = "alice::CORP:1122334455667788:" + "a" * 32 + ":" + "b" * 64
    path = tmp_path / "netntlm.txt"
    path.write_text(good + "\n\n\n\n")

    assert validate_netntlm_hashfile(str(path), 5600) is False, (
        "validation no longer accepts this file, so the premise has changed")

    hashfile_id = _hashfile("parity@example.com")
    assert import_hashfilehashes(hashfile_id=hashfile_id, hashfile_path=str(path),
                                 file_type="NetNTLM", hash_type="5600") is not False
    assert len(_rows(hashfile_id)) == 1


def test_the_dead_guard_is_gone_from_the_source():
    """`len(line) == 0` on a line from file iteration is unreachable by
    construction, so it reads as a working guard while doing nothing. It was
    inverted (`len(line) > 0`) around a readlines() loop before #363 batched the
    import, and equally dead there."""
    import inspect
    import re

    from hashview.utils.utils import import_hashfilehashes as importer

    # Comments only, stripped: the fix's own comment quotes the old guard to
    # explain it, and a naive substring search would match that prose.
    code = "\n".join(re.sub(r"#.*$", "", line)
                     for line in inspect.getsource(importer).splitlines())

    assert "len(line) == 0" not in code, "the unreachable guard is back"
    assert "line.strip()" in code, "the blank-line guard is gone entirely"
