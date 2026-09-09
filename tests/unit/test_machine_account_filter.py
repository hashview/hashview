"""Machine-account / password-history filtering on import.

AD dumps carry two kinds of row that are not real user accounts:

- **machine accounts** — ``COMPUTER$``, whose password is a 120-char random
  secret that will never crack. Filtered in every AD-fed format (pwdump,
  ``user_hash`` NTLM family, DCC2 excepted -- see below, NetNTLM).
- **duplicate password history** — ``secretsdump.py -history``'s first history
  row (``alice_history0``, or bare ``alice_history`` when the dumper omits the
  index) duplicates the account's own current-password hash. It is only
  dropped when that current-password row (``alice``) is also present in the
  same file (issue #412); older history rows (``alice_history1`` and up) are
  real, distinct passwords and are always kept, in every format.

Both inflate a hashfile's account count and depress its reported crack rate,
and nothing filters at report time, so import is the only place to drop them.

DCC2 (domain cached credentials) is excluded from the machine-account check:
it caches interactive logons for user accounts, not computer accounts, so a
trailing ``$`` there is never a machine account.

Covers issues #409 (the ``user:hash`` format had no filter at all), #410 (the
pwdump filter was a case-sensitive substring test) and #411 (the NetNTLM filter
only looked for a trailing ``$``).
"""

import pytest

from hashview.models import Hashes, HashfileHashes, Hashfiles, Users, db
from hashview.utils.utils import (
    history_zero_base_name,
    import_hashfilehashes,
    is_machine_account,
)

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


# --- the machine-account predicate (all AD-fed formats except DCC2) --------

@pytest.mark.security
@pytest.mark.parametrize("username", [
    "WIN10$",
    "CORP\\WIN10$",
    "  WIN10$  ",             # surrounding whitespace must not defeat the check
])
def test_machine_predicate_rejects(username):
    assert is_machine_account(username) is True


@pytest.mark.security
@pytest.mark.parametrize("username", [
    "alice",
    "CORP\\alice",
    "krbtgt",
    "alice_history0",         # history suffix alone is not a machine account
    "al$ce",                  # '$' only counts at the end
    "",
    None,
])
def test_machine_predicate_allows_real_accounts(username):
    assert is_machine_account(username) is False


# --- the history-zero-base-name helper --------------------------------------

@pytest.mark.security
@pytest.mark.parametrize("username,base", [
    ("alice_history0", "alice"),
    ("alice_history", "alice"),        # no index -- some dumpers omit it
    ("ALICE_HISTORY0", "ALICE"),       # case-insensitive
    ("MACHINE$_history0", "MACHINE$"),
    ("  alice_history0  ", "alice"),   # surrounding whitespace must not defeat the check
])
def test_history_zero_base_name_strips_suffix(username, base):
    assert history_zero_base_name(username) == base


@pytest.mark.security
@pytest.mark.parametrize("username", [
    "alice_history1",         # a real, distinct history row -- not index 0
    "alice_history12",
    "bob_historyclub",        # anchored: '_history' mid-name is a real account
    "alice",
    "",
    None,
])
def test_history_zero_base_name_returns_none_for_non_history_zero(username):
    assert history_zero_base_name(username) is None


# --- issue #409: user:hash had no filter at all ----------------------------

@pytest.mark.security
def test_user_hash_ntlm_filters_machine_accounts(app, tmp_path):
    """An NTDS dump cut down to ``user:nthash`` must get machine-account
    filtering like pwdump (issue #409)."""
    usernames = _import(tmp_path, "uh.txt", (
        f"alice:{NT}\n"
        f"WIN10$:{NT}\n"
    ), file_type="user_hash")

    assert usernames == {"alice"}


@pytest.mark.security
def test_user_hash_drops_history_zero_only_when_base_present(app, tmp_path):
    """issue #412: ``alice_history0`` duplicates ``alice``'s current-password
    hash, so it is dropped only because ``alice`` is also in the file.
    ``alice_history1`` is a real, distinct password and is always kept, and
    ``bob_history0`` is kept because ``bob`` never appears."""
    usernames = _import(tmp_path, "uh2.txt", (
        f"alice:{NT}\n"
        f"alice_history0:{NT}\n"
        f"alice_history1:{NT}\n"
        f"bob_history0:{NT}\n"
    ), file_type="user_hash")

    assert usernames == {"alice", "alice_history1", "bob_history0"}


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
def test_user_hash_non_ntlm_keeps_history_zero_even_with_base_present(app, tmp_path):
    """The history-zero check is scoped to AD-fed hash types, same as the
    machine-account check: a generic MD5 dump's ``alice_history0`` is an
    unrelated real username, not a secretsdump.py duplicate."""
    usernames = _import(tmp_path, "md5_hist.txt", (
        "alice:5f4dcc3b5aa765d61d8327deb882cf99\n"
        "alice_history0:5f4dcc3b5aa765d61d8327deb882cf99\n"
    ), file_type="user_hash", hash_type="0")

    assert usernames == {"alice", "alice_history0"}


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
def test_hash_only_dcc2_keeps_dollar_usernames(app, tmp_path):
    """DCC2 (domain cached credentials) caches interactive logons for user
    accounts, not computer accounts, so a trailing ``$`` in its username field
    is never an AD machine account -- no machine-account filtering here."""
    usernames = _import(tmp_path, "dcc2.txt", (
        "$DCC2$10240#alice#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "$DCC2$10240#win10$#bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
    ), file_type="hash_only", hash_type="2100")

    assert usernames == {"alice", "win10$"}


@pytest.mark.security
def test_hash_only_dcc2_drops_history_zero_only_when_base_present(app, tmp_path):
    """issue #412 applies to DCC2 the same as every other AD-fed format."""
    usernames = _import(tmp_path, "dcc2_hist.txt", (
        "$DCC2$10240#alice#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "$DCC2$10240#alice_history0#bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "$DCC2$10240#alice_history1#cccccccccccccccccccccccccccccccc\n"
        "$DCC2$10240#bob_history0#dddddddddddddddddddddddddddddddd\n"
    ), file_type="hash_only", hash_type="2100")

    assert usernames == {"alice", "alice_history1", "bob_history0"}


# --- issue #410: pwdump filter was case-sensitive --------------------------

@pytest.mark.security
def test_pwdump_filters_uppercase_machine_account(app, tmp_path):
    """A trailing ``$`` is filtered case-insensitively (issue #410)."""
    usernames = _import(tmp_path, "pd.txt", (
        f"alice:1001:{LM}:{NT}:::\n"
        f"WIN10$:1002:{LM}:{NT}:::\n"
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


@pytest.mark.security
def test_pwdump_drops_history_zero_only_when_base_present(app, tmp_path):
    """issue #412: ``alice_history0`` (or bare ``alice_history``) duplicates
    ``alice``'s current-password hash and is dropped only because ``alice``
    is also in the file. ``alice_history1`` and ``BOB_History0`` (no bare
    ``bob`` row) are kept -- the latter case-insensitively matched against
    ``present_usernames``, matching the case-insensitivity of issue #410."""
    usernames = _import(tmp_path, "pd3.txt", (
        f"alice:1001:{LM}:{NT}:::\n"
        f"alice_history0:1002:{LM}:{NT}:::\n"
        f"alice_history1:1003:{LM}:{NT}:::\n"
        f"BOB_History0:1004:{LM}:{NT}:::\n"
        f"carol_history:1005:{LM}:{NT}:::\n"
        f"CAROL:1006:{LM}:{NT}:::\n"
    ), file_type="pwdump")

    assert usernames == {"alice", "alice_history1", "BOB_History0", "CAROL"}


# --- issue #411: NetNTLM filter only looked for a trailing $ ---------------

@pytest.mark.security
def test_netntlm_filters_machine_account(app, tmp_path):
    """NetNTLM dropped ``MACHINE$`` (issue #411) -- every trailing-``$``
    username is filtered, not just the first one encountered."""
    resp = "A" * 44
    chal = "1122334455667788"
    lm_resp = "1122334455667788AABBCCDDEEFF1122334455667788AABBCCDD"
    usernames = _import(tmp_path, "nn.txt", (
        f"alice::CORP:{chal}:{resp}:{lm_resp}\n"
        f"MACHINE$::CORP:{chal}:{resp}:{lm_resp}\n"
        f"CORP\\WIN10$::CORP:{chal}:{resp}:{lm_resp}\n"
        f"bob::CORP:{chal}:{resp}:{lm_resp}\n"
    ), file_type="NetNTLM", hash_type="5500")

    assert usernames == {"ALICE", "BOB"}


@pytest.mark.security
def test_netntlm_drops_history_zero_only_when_base_present(app, tmp_path):
    """issue #412 applies to NetNTLM the same as every other AD-fed format,
    even though a real network capture carries no password history in
    practice."""
    resp = "A" * 44
    chal = "1122334455667788"
    lm_resp = "1122334455667788AABBCCDDEEFF1122334455667788AABBCCDD"
    usernames = _import(tmp_path, "nn2.txt", (
        f"alice::CORP:{chal}:{resp}:{lm_resp}\n"
        f"alice_history0::CORP:{chal}:{resp}:{lm_resp}\n"
        f"alice_history1::CORP:{chal}:{resp}:{lm_resp}\n"
        f"bob_history0::CORP:{chal}:{resp}:{lm_resp}\n"
    ), file_type="NetNTLM", hash_type="5500")

    assert usernames == {"ALICE", "ALICE_HISTORY1", "BOB_HISTORY0"}


# --- no orphan hash rows ---------------------------------------------------

@pytest.mark.security
def test_filtered_rows_do_not_create_hash_rows(app, tmp_path):
    """The filter must run *before* the row is buffered, or the ciphertext lands in
    `hashes` with no hashfile row pointing at it and still gets cracked.

    The unscoped `Hashes` query is deliberate: an orphaned row is by definition
    not reachable through a hashfile-scoped join, so narrowing this to a join
    would silently stop testing the thing it exists to test. Safe because the
    ``app`` fixture is function-scoped.
    """
    machine_nt = "8846f7eaee8fb117ad06bdd830b7586d"
    _import(tmp_path, "uh3.txt", (
        f"alice:{NT}\n"
        f"WIN10$:{machine_nt}\n"
    ), file_type="user_hash")

    ciphertexts = {row.ciphertext for row in Hashes.query.all()}
    assert NT in ciphertexts
    assert machine_nt not in ciphertexts
