"""Machine-account / password-history filtering on import.

AD dumps carry two kinds of row that are not real user accounts:

- **machine accounts** — ``COMPUTER$``, whose password is a 120-char random
  secret that will never crack, and
- **password history** — ``alice_history0``, ``COMPUTER$_history1``, emitted by
  ``secretsdump.py -history``.

Both inflate a hashfile's account count and depress its reported crack rate,
and nothing filters at report time, so import is the only place to drop them.

Covers issues #409 (the ``user:hash`` format had no filter at all), #410 (the
pwdump filter was a case-sensitive substring test) and #411 (the NetNTLM filter
only looked for a trailing ``$``).
"""

import pytest

from hashview.models import Hashes, HashfileHashes, Hashfiles, Users, db
from hashview.utils.utils import import_hashfilehashes, is_machine_or_history_account

NT = "8846f7eaee8fb117ad06bdd830b7586c"
LM = "aad3b435b51404eeaad3b435b51404ee"


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
    hashfile = Hashfiles(name="t.txt", customer_id=1, owner_id=user.id)
    db.session.add(hashfile)
    db.session.commit()
    return hashfile.id


def _usernames(hashfile_id: int):
    return {
        row.username
        for row in HashfileHashes.query.filter_by(hashfile_id=hashfile_id).all()
        if row.username
    }


def _import(tmp_path, name, body, file_type, hash_type="1000"):
    hashfile_id = _make_user_and_hashfile()
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    import_hashfilehashes(
        hashfile_id=hashfile_id,
        hashfile_path=str(path),
        file_type=file_type,
        hash_type=hash_type,
    )
    return _usernames(hashfile_id)


# --- the shared predicate ---------------------------------------------------

@pytest.mark.security
@pytest.mark.parametrize("username", [
    "WIN10$",
    "CORP\\WIN10$",
    "WIN10$_history0",
    "WIN10$_HISTORY0",
    "alice_history0",
    "alice_History12",
    "alice_history",          # no index — some dumpers omit it
    "  WIN10$  ",             # surrounding whitespace must not defeat the check
])
def test_predicate_rejects(username):
    assert is_machine_or_history_account(username) is True


@pytest.mark.security
@pytest.mark.parametrize("username", [
    "alice",
    "CORP\\alice",
    "krbtgt",
    "bob_historyclub",        # anchored: '_history' mid-name is a real account
    "history_teacher",
    "al$ce",                  # '$' only counts at the end
    "",
    None,
])
def test_predicate_allows_real_accounts(username):
    assert is_machine_or_history_account(username) is False


# --- issue #409: user:hash had no filter at all ----------------------------

@pytest.mark.security
def test_user_hash_ntlm_filters_machine_accounts_and_history(app, tmp_path):
    """An NTDS dump cut down to ``user:nthash`` must get the same filtering as
    the pwdump form of the same data (issue #409)."""
    usernames = _import(tmp_path, "uh.txt", (
        f"alice:{NT}\n"
        f"WIN10$:{NT}\n"
        f"WIN10$_history0:{NT}\n"
        f"alice_history0:{NT}\n"
        f"CORP\\WIN10$_history1:{NT}\n"
    ), file_type="user_hash")

    assert usernames == {"alice"}


@pytest.mark.security
def test_user_hash_non_ntlm_keeps_dollar_usernames(app, tmp_path):
    """The filter is deliberately scoped to the NTLM family: ``user:hash`` is a
    generic format, and dropping a trailing-``$`` username out of, say, an MD5
    web-app dump would be silent data loss, not a fix."""
    usernames = _import(tmp_path, "md5.txt", (
        "alice$:5f4dcc3b5aa765d61d8327deb882cf99\n"
    ), file_type="user_hash", hash_type="0")

    assert usernames == {"alice$"}


@pytest.mark.security
def test_user_hash_filters_when_hash_type_is_an_int(app, tmp_path):
    """The API upload route is declared ``<int:hash_type>`` and passes the value
    straight through, so the filter has to survive an int hash_type -- the form
    path is the only one that hands it over as a string."""
    usernames = _import(tmp_path, "uh_int.txt", (
        f"alice:{NT}\n"
        f"WIN10$:{NT}\n"
    ), file_type="user_hash", hash_type=1000)

    assert usernames == {"alice"}


@pytest.mark.security
def test_hash_only_dcc2_filters_machine_accounts(app, tmp_path):
    """DCC2 is the one ``hash_only`` mode whose ciphertext carries a username
    (``$DCC2$<iter>#<user>#<hash>``), so it is the one that can carry an AD
    machine account. 2100 is UI-selectable, so this is reachable."""
    usernames = _import(tmp_path, "dcc2.txt", (
        "$DCC2$10240#alice#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "$DCC2$10240#win10$#bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "$DCC2$10240#alice_history0#cccccccccccccccccccccccccccccccc\n"
    ), file_type="hash_only", hash_type="2100")

    assert usernames == {"alice"}


# --- issue #410: pwdump filter was case-sensitive --------------------------

@pytest.mark.security
def test_pwdump_filters_uppercase_history(app, tmp_path):
    """``_HISTORY`` is the same record as ``_history`` (issue #410)."""
    usernames = _import(tmp_path, "pd.txt", (
        f"alice:1001:{LM}:{NT}:::\n"
        f"WIN10$_HISTORY0:1002:{LM}:{NT}:::\n"
        f"BOB_History1:1003:{LM}:{NT}:::\n"
    ), file_type="pwdump")

    assert usernames == {"alice"}


@pytest.mark.security
def test_pwdump_keeps_account_with_history_inside_the_name(app, tmp_path):
    """Anchoring the suffix fixes a pre-existing false positive: the old
    substring test dropped any account whose name merely contained
    ``_history``."""
    usernames = _import(tmp_path, "pd2.txt", (
        f"bob_historyclub:1001:{LM}:{NT}:::\n"
    ), file_type="pwdump")

    assert usernames == {"bob_historyclub"}


# --- issue #411: NetNTLM filter only looked for a trailing $ ---------------

@pytest.mark.security
def test_netntlm_filters_machine_account_history(app, tmp_path):
    """NetNTLM dropped ``MACHINE$`` but imported ``MACHINE$_history0``
    (issue #411)."""
    resp = "A" * 44
    chal = "1122334455667788"
    lm_resp = "1122334455667788AABBCCDDEEFF1122334455667788AABBCCDD"
    usernames = _import(tmp_path, "nn.txt", (
        f"alice::CORP:{chal}:{resp}:{lm_resp}\n"
        f"MACHINE$::CORP:{chal}:{resp}:{lm_resp}\n"
        f"MACHINE$_history0::CORP:{chal}:{resp}:{lm_resp}\n"
    ), file_type="NetNTLM", hash_type="5500")

    assert usernames == {"ALICE"}


# --- no orphan hash rows ---------------------------------------------------

@pytest.mark.security
def test_filtered_rows_do_not_create_hash_rows(app, tmp_path):
    """The filter must run *before* import_hash_only, or the ciphertext lands in
    `hashes` with no hashfile row pointing at it and still gets cracked.

    The unscoped `Hashes` query is deliberate: an orphaned row is by definition
    not reachable through a hashfile-scoped join, so narrowing this to a join
    would silently stop testing the thing it exists to test. Safe because the
    ``app`` fixture is function-scoped.
    """
    machine_nt = "8846f7eaee8fb117ad06bdd830b7586d"
    _import(tmp_path, "uh2.txt", (
        f"alice:{NT}\n"
        f"WIN10$:{machine_nt}\n"
    ), file_type="user_hash")

    ciphertexts = {row.ciphertext for row in Hashes.query.all()}
    assert NT in ciphertexts
    assert machine_nt not in ciphertexts
