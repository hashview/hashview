"""Property-based tests for hash file parsers.

Generated counterparts to tests/unit/test_hash_parsers.py: instead of pinning
single examples, these assert invariants over arbitrary usernames/hashes —
the parser must never import machine accounts (trailing $), never import
*_history entries, and never crash on weird-but-structurally-valid lines.

Hypothesis runs each test body many times inside ONE function-scoped ``app``
fixture instance, so DB state accumulates across examples. Every example
therefore creates its own user (unique email) + hashfile and scopes all
assertions to that hashfile_id — never to global table counts.
"""

import os
import tempfile
import uuid

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from hashview.models import Hashes, HashfileHashes, Hashfiles, Users, db
from hashview.utils.utils import import_hashfilehashes

# --- strategies -------------------------------------------------------------

HEX32 = st.text(alphabet="0123456789abcdefABCDEF", min_size=32, max_size=32)
USERNAME = st.text(
    alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd"), max_codepoint=0x7F),
    min_size=1,
    max_size=20,
)

# Shared settings: the unit-test ``app`` fixture is function-scoped but each
# example builds its own hashfile, so suppressing the fixture health check is
# safe here. deadline=None because the first example pays SQLite setup cost.
PROPERTY_SETTINGS = settings(
    max_examples=50,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)


# --- helpers ----------------------------------------------------------------

def _make_user_and_hashfile() -> int:
    """Copy of the helper in test_hash_parsers.py, with a unique email so
    repeated creation across Hypothesis examples doesn't violate the unique
    constraint on Users.email_address."""
    user = Users(
        first_name="t",
        last_name="u",
        email_address=f"{uuid.uuid4().hex}@example.com",
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


def _import_text(text: str, hashfile_id: int, file_type: str, hash_type: str):
    """Write ``text`` to a temp file and run the real parser on it."""
    fd, path = tempfile.mkstemp(suffix=".txt")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        return import_hashfilehashes(
            hashfile_id=hashfile_id,
            hashfile_path=path,
            file_type=file_type,
            hash_type=hash_type,
        )
    finally:
        os.unlink(path)


def _imported_rows(hashfile_id: int):
    return HashfileHashes.query.filter_by(hashfile_id=hashfile_id).all()


def _imported_ciphertexts(hashfile_id: int):
    return [
        row.ciphertext
        for row in Hashes.query.join(
            HashfileHashes, Hashes.id == HashfileHashes.hash_id
        )
        .filter(HashfileHashes.hashfile_id == hashfile_id)
        .all()
    ]


# --- invariant 1: pwdump machine accounts -----------------------------------

@pytest.mark.security
@PROPERTY_SETTINGS
@given(username=USERNAME, nt=HEX32)
def test_pwdump_machine_accounts_never_imported(app, username, nt):
    """Any username with a trailing ``$`` is a machine account and must never
    be imported, no matter what the rest of the line looks like. A control
    line with the bare username confirms the filter isn't dropping everything."""
    hashfile_id = _make_user_and_hashfile()
    text = (
        f"{username}$:1001:aad3b435b51404eeaad3b435b51404ee:{nt}:::\n"
        f"{username}:1002:aad3b435b51404eeaad3b435b51404ee:{nt}:::\n"
    )
    _import_text(text, hashfile_id, file_type="pwdump", hash_type="1000")

    usernames = {row.username for row in _imported_rows(hashfile_id)}
    assert f"{username}$" not in usernames, f"machine account {username}$ was imported"
    assert not any(u.endswith("$") for u in usernames)
    assert usernames == {username}


# --- invariant 2: pwdump *_history entries ----------------------------------

@pytest.mark.security
@PROPERTY_SETTINGS
@given(username=USERNAME, suffix=st.integers(min_value=0, max_value=99), nt=HEX32)
def test_pwdump_history_entries_never_imported(app, username, suffix, nt):
    """``*_history*`` entries are NTLM password-history records (the AD fix in
    the CHANGELOG) and must never be imported. The bare-username control line
    on the same file confirms the filter is selective."""
    hashfile_id = _make_user_and_hashfile()
    history_user = f"{username}_history{suffix}"
    text = (
        f"{history_user}:1001:aad3b435b51404eeaad3b435b51404ee:{nt}:::\n"
        f"{username}:1002:aad3b435b51404eeaad3b435b51404ee:{nt}:::\n"
    )
    _import_text(text, hashfile_id, file_type="pwdump", hash_type="1000")

    usernames = {row.username for row in _imported_rows(hashfile_id)}
    assert not any("_history" in u for u in usernames), (
        f"history entry {history_user} was imported"
    )
    assert usernames == {username}


# --- invariant 3: NetNTLM machine accounts + case normalisation -------------

# NetNTLM line: USER::DOMAIN:server_chal:nt_resp:lm_resp
# Username has no '$' (so it imports) and the parser uppercases it; the
# ciphertext fields 3/4/5 are lowercased while the domain (field 2) is left
# alone. Exclude usernames already ending in '$' so they don't get filtered.
NETNTLM_USER = st.text(
    alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd"), max_codepoint=0x7F),
    min_size=1,
    max_size=20,
).filter(lambda s: not s.endswith("$"))
HEX_RESP = st.text(alphabet="0123456789abcdefABCDEF", min_size=8, max_size=48)


HEX_CHAL = st.text(alphabet="0123456789abcdefABCDEF", min_size=16, max_size=16)


@pytest.mark.security
@PROPERTY_SETTINGS
@given(username=NETNTLM_USER, chal=HEX_CHAL, nt_resp=HEX_RESP, lm_resp=HEX_RESP)
def test_netntlm_machine_accounts_filtered_and_case_normalised(
    app, username, chal, nt_resp, lm_resp
):
    """Machine accounts (trailing ``$``) must be filtered; the plain username
    must be uppercased; challenge and response fields (parts 3/4/5) must be
    stored lowercased regardless of input case; domain (part 2) case is
    preserved as-is."""
    hashfile_id = _make_user_and_hashfile()
    domain = "CORP"
    real = f"{username}::{domain}:{chal}:{nt_resp}:{lm_resp}\n"
    machine = f"{username}$::{domain}:{chal}:{nt_resp}:{lm_resp}\n"
    _import_text(real + machine, hashfile_id, file_type="NetNTLM", hash_type="5500")

    usernames = {row.username for row in _imported_rows(hashfile_id)}
    # machine account dropped
    assert not any(u.endswith("$") for u in usernames)
    # real username imported, uppercased
    assert usernames == {username.upper()}

    # ciphertext fields lowercased (fields 3/4/5), domain (field 2) untouched
    for ct in _imported_ciphertexts(hashfile_id):
        parts = ct.split(":")
        assert parts[0] == username.upper()
        assert parts[2] == domain  # domain case-preserved
        assert parts[3] == chal.lower()
        assert parts[4] == nt_resp.lower()
        assert parts[5] == lm_resp.lower()


# --- invariant 4: shadow never raises on arbitrary usernames ----------------

# shadow line: username:$id$salt$hash:meta... — username has no ':'.
SHADOW_USER = st.text(
    alphabet=st.characters(
        min_codepoint=0x21, max_codepoint=0x7E, blacklist_characters=":"
    ),
    min_size=1,
    max_size=30,
)
CRYPT_TOKEN = st.text(
    alphabet="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./",
    min_size=1,
    max_size=16,
)
CRYPT_HASH = st.text(
    alphabet="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./",
    min_size=20,
    max_size=86,
)


@pytest.mark.security
@PROPERTY_SETTINGS
@given(username=SHADOW_USER, salt=CRYPT_TOKEN, crypt=CRYPT_HASH)
def test_shadow_never_raises_and_imports_username(app, username, salt, crypt):
    """The shadow parser must import the leading username and crypt hash for
    arbitrary printable non-colon usernames without raising."""
    hashfile_id = _make_user_and_hashfile()
    line = f"{username}:$6${salt}${crypt}:18000:0:99999:7:::\n"
    _import_text(line, hashfile_id, file_type="shadow", hash_type="1800")

    usernames = {row.username for row in _imported_rows(hashfile_id)}
    assert usernames == {username}

    ciphertexts = _imported_ciphertexts(hashfile_id)
    assert len(ciphertexts) == 1
    assert ciphertexts[0].startswith(f"$6${salt}$")


# --- invariant 5: hash_only non-1000 round-trips without mutation -----------

# hash types where the parser does NOT lowercase (i.e. not 300/1000/1731) and
# does not special-case ('2100'). Mixed-case hex digests must round-trip
# verbatim.
@pytest.mark.security
@PROPERTY_SETTINGS
@given(
    digest=st.text(alphabet="0123456789abcdefABCDEF", min_size=32, max_size=64),
    hash_type=st.sampled_from(["0", "100", "1400", "1700"]),
)
def test_hash_only_non_1000_round_trips_unmutated(app, digest, hash_type):
    """For non-NTLM/SHA1 hash types, hash_only import must store the exact
    input (case preserved, no mutation)."""
    hashfile_id = _make_user_and_hashfile()
    _import_text(digest + "\n", hashfile_id, file_type="hash_only", hash_type=hash_type)

    ciphertexts = _imported_ciphertexts(hashfile_id)
    assert digest in ciphertexts, f"{digest!r} not stored verbatim: {ciphertexts!r}"
