"""Unit tests for hash file parsers in ``hashview.utils.utils``.

These tests pin parser behavior for the file formats the app supports:
- **pwdump**: filters out machine accounts (``trailing $``) AND a duplicate
  ``_history0``/bare ``_history`` row when the account's current-password
  row is also present (issue #412); ``_history1`` and up are always kept
- **shadow**: extracts username + crypt-style hash
- **NetNTLM (5500/5600)**: filters machine accounts, uppercases the
  username, lowercases the ciphertext parts
- **hash_only**: handles non-1000 hash types

The parsers commit rows to the DB via ``import_hash_only`` /
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
# kerberos $krb5tgs$17/$18 — impacket's SPN field
# ---------------------------------------------------------------------------

_KRB_CK18 = "16ce51f6eba20c8ee534ff8a"
_KRB_ED = "57d07b23" * 8


def test_normalize_kerberos_hash_strips_only_the_aes_spn_field():
    from hashview.utils.utils import normalize_kerberos_hash

    spn = (f"$krb5tgs$18$svc_sql$CONTOSO.LOCAL"
           f"$*MSSQLSvc/sql01.contoso.local:1433*${_KRB_CK18}${_KRB_ED}")
    plain = f"$krb5tgs$18$svc_sql$CONTOSO.LOCAL${_KRB_CK18}${_KRB_ED}"

    assert normalize_kerberos_hash(spn, "19700") == plain
    # idempotent: a hash that never had an SPN is untouched
    assert normalize_kerberos_hash(plain, "19700") == plain
    # etype 17 too
    assert normalize_kerberos_hash(
        f"$krb5tgs$17$u$R$*http/web*$849e31b3db1c1f203fa20b85${_KRB_ED}", "19600"
    ) == f"$krb5tgs$17$u$R$849e31b3db1c1f203fa20b85${_KRB_ED}"


def test_normalize_kerberos_hash_preserves_principal_case_for_aes_etypes():
    """The principal is part of the AES Kerberos salt.

    Measured on hashcat 6.2.6: upper-casing the principal in its own 19700
    example hash drops recovery to 0/1, while upper-casing the realm still
    cracks 1/1 (hashcat normalises the realm itself). hashcat lower-cases the
    hex fields on output and leaves principal and realm verbatim, so that is
    the shape to store -- folding the principal produces a hash that is
    accepted, queued, and can never crack.
    """
    from hashview.utils.utils import normalize_kerberos_hash

    got = normalize_kerberos_hash(
        f"$krb5tgs$18$SQLSvc$CONTOSO.LOCAL$*MSSQLSvc/a.b:1433*"
        f"${_KRB_CK18.upper()}${_KRB_ED.upper()}", "19700")
    assert got == f"$krb5tgs$18$SQLSvc$CONTOSO.LOCAL${_KRB_CK18}${_KRB_ED}"

    # every principal-salted mode, not just TGS-REP
    for htype, tag, etype in (("19800", "krb5pa", "17"), ("19900", "krb5pa", "18"),
                              ("28800", "krb5db", "17"), ("28900", "krb5db", "18")):
        got = normalize_kerberos_hash(
            f"${tag}${etype}$MixedCase$CONTOSO.LOCAL${'A' * 104}", htype)
        assert got == f"${tag}${etype}$MixedCase$CONTOSO.LOCAL${'a' * 104}", htype


def test_normalize_kerberos_hash_folds_case_for_unsalted_rc4_etypes():
    """RC4 keys are MD4(password) with no salt, so case cannot matter there.

    Verified on hashcat: 13100 and 18200 still crack 1/1 with the principal and
    realm upper-cased. These keep the historical all-lower-case stored form,
    which is equally a round-trip fixed point and preserves de-duplication of
    the same hash pasted in different cases.
    """
    from hashview.utils.utils import normalize_kerberos_hash

    tgs23 = f"$krb5tgs$23$*USER$REALM$test/spn*${'A' * 32}${_KRB_ED.upper()}"
    assert normalize_kerberos_hash(tgs23, "13100") == tgs23.lower()
    asrep = f"$krb5asrep$23$USER@CONTOSO.LOCAL:{'A' * 32}${_KRB_ED.upper()}"
    assert normalize_kerberos_hash(asrep, "18200") == asrep.lower()


@pytest.mark.security
def test_kerberos_import_stores_the_shape_hashcat_echoes_back(app, tmp_path):
    """An SPN-bearing, mixed-case hash must be stored exactly as hashcat echoes it.

    hashcat drops the SPN, lower-cases the hex and preserves the principal, and
    a recovered hash is matched by an exact md5 of the stored ciphertext -- so
    any other stored shape leaves the crack unmatchable and silently discarded.

    The expected string below is not assumed, it is hashcat 6.2.6's own
    rendering. Confirmed two ways, because a mixed-case principal cannot be
    cracked on demand (the salt is wrong by construction) and so never reaches
    a normal outfile: ``--left`` and ``--show`` both re-encode through the same
    writer the crack path uses -- proven by feeding them upper-case hex and
    watching it come back folded -- and both echo ``SQLSvc``/``Contoso.Local``
    verbatim. Neither the agent nor the ingest route touches case in between
    (hashview/api/routes.py builds the lookup key straight from the reported
    line), so stored form == reported form == this string.
    """
    from hashview.utils.utils import get_md5_hash

    hashfile_id = _make_user_and_hashfile()
    path = tmp_path / "krb.txt"
    path.write_text(
        f"$krb5tgs$18$SQLSvc$CONTOSO.LOCAL"
        f"$*MSSQLSvc/sql01.contoso.local:1433*${_KRB_CK18.upper()}${_KRB_ED.upper()}\n"
    )

    import_hashfilehashes(
        hashfile_id=hashfile_id,
        hashfile_path=str(path),
        file_type="kerberos",
        hash_type="19700",
    )

    links = HashfileHashes.query.filter_by(hashfile_id=hashfile_id).all()
    assert len(links) == 1
    stored = Hashes.query.get(links[0].hash_id)

    echoed = f"$krb5tgs$18$SQLSvc$CONTOSO.LOCAL${_KRB_CK18}${_KRB_ED}"
    assert "*" not in stored.ciphertext
    assert stored.ciphertext == echoed
    # the principal's case survived -- this is what makes the hash crackable
    assert "SQLSvc" in stored.ciphertext
    # the agent-upload lookup keys off this md5; it has to match
    assert stored.sub_ciphertext == get_md5_hash(echoed)
    assert _all_usernames(hashfile_id) == {"SQLSvc"}
