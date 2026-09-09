"""Regression tests for Kerberos 19700 normalization and recovery.

This test module pins the fixed behavior for Kerberos 19700 import and recovery,
testing the invariant: stored ciphertext must be byte-identical to what hashcat
will echo, or recovery matching on md5(ciphertext) breaks.

The module models four test vectors from hashcat's 19700 example hash
(password 'hashcat') crossed against two assertions:

1. **A — import succeeds**: validate_kerberos_hashfile returns falsy and
   import_hashfilehashes creates exactly one Hashes row + one HashfileHashes row.
   The stored username must preserve its original case (critical for AES salt).

2. **B — recovery lands**: Feed the row's ciphertext to the recovery lookup
   (matching on sub_ciphertext=get_md5_hash(ciphertext)) and verify the MD5 key
   matches what hashcat would echo.

Vectors:
- V1: SPN absent, username lowercase
- V2: SPN absent, username mixed-case
- V3: SPN present, username lowercase
- V4: SPN present, username mixed-case

All four vectors now pass both assertions, confirming:
- D1 (SPN validation) is fixed: V3, V4 import succeeds
- D2 (case preservation) is fixed: V2 preserves username case in storage
- D3 (recovery matching) is fixed: stored ciphertext MD5 matches echoed form

The hashcat_echo() helper models hashcat's established behavior (verified 6.2.6-7.1.2):
- Strips SPN field from echo (Form 2 → Form 1)
- Lowercases hex fields (checksum, edata)
- Preserves username and realm case verbatim

That behavior is proven by tests/hashcat_interop/test_kerberos_aes_interop.py.
"""

import pytest

from hashview.models import Hashes, HashfileHashes, Hashfiles, Users, db
from hashview.utils.utils import (
    get_md5_hash,
    import_hashfilehashes,
    validate_kerberos_hashfile,
)

# --- Exact values from the brief (verified empirically) ---------------------

# From hashcat's 19700 example hash (password 'hashcat')
CHECKSUM = "16ce51f6eba20c8ee534ff8a"
EDATA = (
    "57d07b23643a516834795f0c010da8f549b7e65063e5a367ca9240f9b800adad"
    "1734df7e7d5dd8307e785de4f40aacf901df41aa6ce695f8619ec579c1fa57ee"
    "93661cf402aeef4e3a42e7e3477645d52c09dc72feade03512dffe0df517344f"
    "673c63532b790c242cc1d50f4b4b34976cb6e08ab325b3aefb2684262a5ee9fa"
    "acb14d059754f50553be5bfa5c4c51e833ff2b6ac02c6e5d4c4eb193e27d7dde3"
    "01bd1ddf480e5e282b8c27ef37b136c8f140b56de105b73adeb1de16232fa1ab5"
    "c9f6"
)
REALM = "synacktiv.local"
SPN = "srv_http/web.synacktiv.local"


def hashcat_echo(ciphertext: str) -> str:
    """Model hashcat's outfile-format 1,3 echo for Kerberos 19700.

    Hashcat (verified 6.2.6 through 7.1.2) performs the following
    transformations on the echoed line:
    1. Strips the SPN field (Form 2 → Form 1)
    2. Lowercases hex fields (checksum, edata)
    3. Preserves username and realm case verbatim

    The invariant this helper maintains is: stored ciphertext must be
    byte-identical to what hashcat will echo, or recovery (matching on
    md5(ciphertext)) breaks.

    This model is proven correct by tests/hashcat_interop/test_kerberos_aes_interop.py.
    """
    # Parse the form: $krb5tgs$18$user$realm[*spn*]$checksum$edata
    parts = ciphertext.split("$")
    # parts: ['', 'krb5tgs', '18', user, realm, [*spn* or checksum], checksum, edata]

    if len(parts) == 8 and parts[5].startswith("*"):
        # Form 2: $krb5tgs$18$user$realm$*spn*$checksum$edata
        # Strip the SPN field, lowercase the hex fields
        mode = parts[1]
        version = parts[2]
        user = parts[3]
        realm = parts[4]
        checksum = parts[6].lower()
        edata = parts[7].lower()
        return f"${mode}${version}${user}${realm}${checksum}${edata}"
    else:
        # Form 1: $krb5tgs$18$user$realm$checksum$edata
        # Just lowercase the hex fields
        if len(parts) == 7:
            mode = parts[1]
            version = parts[2]
            user = parts[3]
            realm = parts[4]
            checksum = parts[5].lower()
            edata = parts[6].lower()
            return f"${mode}${version}${user}${realm}${checksum}${edata}"
        else:
            # Unexpected format; return as-is (will likely fail tests)
            return ciphertext


def _make_user_and_hashfile():
    """Create a user and hashfile for testing."""
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
        name="kerberos_19700_test.txt",
        customer_id=1,
        owner_id=user.id,
    )
    db.session.add(hashfile)
    db.session.commit()
    return hashfile.id


# --- Test vectors -------------------------------------------------------

# V1: No SPN, lowercase username
V1_USERNAME = "srv_http"
V1_CIPHERTEXT = f"$krb5tgs$18${V1_USERNAME}${REALM}${CHECKSUM}${EDATA}"

# V2: No SPN, mixed-case username
V2_USERNAME = "Srv_HTTP"
V2_CIPHERTEXT = f"$krb5tgs$18${V2_USERNAME}${REALM}${CHECKSUM}${EDATA}"

# V3: With SPN, lowercase username
V3_USERNAME = "srv_http"
V3_CIPHERTEXT = (
    f"$krb5tgs$18${V3_USERNAME}${REALM}$*{SPN}*${CHECKSUM}${EDATA}"
)

# V4: With SPN, mixed-case username
V4_USERNAME = "Srv_HTTP"
V4_CIPHERTEXT = (
    f"$krb5tgs$18${V4_USERNAME}${REALM}$*{SPN}*${CHECKSUM}${EDATA}"
)


# --- Assertion A: Import succeeds ------------------------------------------

@pytest.mark.parametrize(
    "vector_name,username,ciphertext",
    [
        ("V1", V1_USERNAME, V1_CIPHERTEXT),
        ("V2", V2_USERNAME, V2_CIPHERTEXT),
        ("V3", V3_USERNAME, V3_CIPHERTEXT),
        ("V4", V4_USERNAME, V4_CIPHERTEXT),
    ],
)
def test_import_succeeds(app, tmp_path, vector_name, username, ciphertext):
    """Assertion A: validate_kerberos_hashfile passes and import creates rows.

    The stored username must preserve its original case.
    """
    hashfile_id = _make_user_and_hashfile()
    path = tmp_path / f"{vector_name}.txt"
    path.write_text(ciphertext + "\n")

    # Validate should pass (returns falsy, i.e., False or None)
    error = validate_kerberos_hashfile(str(path), "19700")
    assert not error, f"Validation failed: {error}"

    # Import should succeed
    result = import_hashfilehashes(
        hashfile_id=hashfile_id,
        hashfile_path=str(path),
        file_type="kerberos",
        hash_type="19700",
    )
    assert result is True, "Import returned False"

    # Should create exactly one Hashes row and one HashfileHashes row
    hashes = Hashes.query.all()
    hashfile_hashes = HashfileHashes.query.filter_by(hashfile_id=hashfile_id).all()

    assert len(hashes) == 1, f"Expected 1 Hashes row, got {len(hashes)}"
    assert len(hashfile_hashes) == 1, f"Expected 1 HashfileHashes row, got {len(hashfile_hashes)}"

    # The stored username must preserve its original case
    stored_username = hashfile_hashes[0].username
    assert (
        stored_username == username
    ), f"Username case not preserved: stored={stored_username}, input={username}"


# --- Assertion B: Recovery lands -------------------------------------------

@pytest.mark.parametrize(
    "vector_name,username,ciphertext",
    [
        ("V1", V1_USERNAME, V1_CIPHERTEXT),
        ("V2", V2_USERNAME, V2_CIPHERTEXT),
        ("V3", V3_USERNAME, V3_CIPHERTEXT),
        ("V4", V4_USERNAME, V4_CIPHERTEXT),
    ],
)
def test_recovery_lands(app, tmp_path, vector_name, username, ciphertext):
    """Assertion B: Verify MD5-based recovery lookup key invariant.

    This test models the MD5-based recovery lookup in the agent heartbeat path
    (hashview/api/routes.py found_uploads handler), which queries:
      Hashes.query.filter_by(..., sub_ciphertext=get_md5_hash(ciphertext), cracked='0')
    where ciphertext is what hashcat echoes from the cracked-password line.

    For V1 (lowercase username, no SPN): The test verifies the lookup key is stable
    across import→echo cycle (MD5 remains invariant). This pins the base invariant.

    For V2 (mixed-case username, no SPN): The test verifies that case preservation
    in storage is correct. The stored username preserves the original mixed case,
    so the MD5 key matches what hashcat would echo, confirming D2 is fixed.

    For V3/V4 (SPN form): The test verifies that the stored ciphertext has the SPN
    stripped (to match hashcat's echo). Computing the MD5 of the echoed ciphertext
    (with SPN stripped) matches the stored MD5, confirming D3 is fixed. This proves
    that recovery lookup will find the row when hashcat echoes the cracked line.

    All vectors now pass, confirming the stored ciphertext invariant holds for every
    case: it is byte-identical to what hashcat will echo, enabling recovery matching.
    """
    hashfile_id = _make_user_and_hashfile()
    path = tmp_path / f"{vector_name}.txt"
    path.write_text(ciphertext + "\n")

    # Validate and import
    error = validate_kerberos_hashfile(str(path), "19700")
    assert not error, f"Validation failed: {error}"

    result = import_hashfilehashes(
        hashfile_id=hashfile_id,
        hashfile_path=str(path),
        file_type="kerberos",
        hash_type="19700",
    )
    assert result is True, "Import returned False"

    # Get the stored row
    hashes = Hashes.query.all()
    assert len(hashes) == 1, f"Expected 1 Hashes row, got {len(hashes)}"
    stored_row = hashes[0]

    # Model what hashcat will echo for this ciphertext
    echoed_ciphertext = hashcat_echo(ciphertext)

    # The agent heartbeat recovery handler queries on sub_ciphertext=get_md5_hash(ciphertext),
    # where ciphertext is what hashcat echoes from the cracked-password line.
    # (The second recovery lookup at ~line 1967 lowercases the ciphertext before matching,
    # but it only serves modes 0, 100, 300, 900, 1000, 1400, 1731 per CRACKED_HASH_VERIFIERS,
    # so no Kerberos mode reaches that path; this test models the agent heartbeat path correctly.)

    # Verify that the stored sub_ciphertext can be found via the echoed ciphertext
    expected_sub_ciphertext = get_md5_hash(echoed_ciphertext)

    assert stored_row.sub_ciphertext == expected_sub_ciphertext, (
        f"Recovery lookup would fail: stored sub_ciphertext={stored_row.sub_ciphertext}, "
        f"echoed={echoed_ciphertext}, expected_sub_ciphertext={expected_sub_ciphertext}"
    )
