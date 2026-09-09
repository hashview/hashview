"""Unit tests for normalize_kerberos_hash function.

Tests the normalization logic for Kerberos hashes across all supported modes.
The invariant tested: stored ciphertext must be byte-identical to hashcat's echo.

Test vectors are based on established hashcat behavior (6.2.6 through 7.1.2):
- SPN field is stripped from echo
- Hex fields (checksum, edata) are lowercased
- Username and realm are preserved verbatim
"""

import pytest

from hashview.utils.utils import normalize_kerberos_hash


class TestNormalizeKerberos19600And19700:
    """Test 19600 and 19700 (krb5tgs etype 17/18) normalization."""

    @pytest.mark.parametrize("ciphertext,expected", [
        # Lowercase username
        ("$krb5tgs$18$srv_http$synacktiv.local$16ce51f6eba20c8ee534ff8a$57d07b23",
         "$krb5tgs$18$srv_http$synacktiv.local$16ce51f6eba20c8ee534ff8a$57d07b23"),
        # Mixed-case username and uppercase hex—case must be preserved, hex lowercased
        ("$krb5tgs$18$Srv_HTTP$SYNACKTIV.LOCAL$16CE51F6EBA20C8EE534FF8A$57D07B23",
         "$krb5tgs$18$Srv_HTTP$SYNACKTIV.LOCAL$16ce51f6eba20c8ee534ff8a$57d07b23"),
    ])
    def test_19700_no_spn(self, ciphertext, expected):
        """Form 1: no SPN. Case is preserved for user/realm; hex is lowercased."""
        result = normalize_kerberos_hash(ciphertext, "19700")
        assert result == expected

    def test_19700_no_spn_uppercase_hex(self):
        """Form 1: no SPN, uppercase hex fields."""
        ciphertext = "$krb5tgs$18$srv_http$synacktiv.local$16CE51F6EBA20C8EE534FF8A$57D07B23"
        result = normalize_kerberos_hash(ciphertext, "19700")
        # Hex should be lowercased, user and realm preserved
        expected = "$krb5tgs$18$srv_http$synacktiv.local$16ce51f6eba20c8ee534ff8a$57d07b23"
        assert result == expected

    def test_19700_with_spn_lowercase_username(self):
        """Form 2: with SPN, lowercase username—SPN stripped."""
        ciphertext = "$krb5tgs$18$srv_http$synacktiv.local$*srv_http/web.synacktiv.local*$16CE51F6EBA20C8EE534FF8A$57D07B23"
        result = normalize_kerberos_hash(ciphertext, "19700")
        # SPN stripped, hex lowercased, user/realm preserved
        expected = "$krb5tgs$18$srv_http$synacktiv.local$16ce51f6eba20c8ee534ff8a$57d07b23"
        assert result == expected

    def test_19700_with_spn_mixedcase_username(self):
        """Form 2: with SPN, mixed-case username—SPN stripped, case preserved."""
        ciphertext = "$krb5tgs$18$Srv_HTTP$SYNACKTIV.LOCAL$*srv_http/web.synacktiv.local*$16CE51F6EBA20C8EE534FF8A$57D07B23"
        result = normalize_kerberos_hash(ciphertext, "19700")
        # SPN stripped, hex lowercased, user/realm case preserved
        expected = "$krb5tgs$18$Srv_HTTP$SYNACKTIV.LOCAL$16ce51f6eba20c8ee534ff8a$57d07b23"
        assert result == expected

    @pytest.mark.parametrize("ciphertext,expected", [
        # No SPN, lowercase username
        ("$krb5tgs$17$srv_http$synacktiv.local$16ce51f6eba20c8ee534ff8a$57d07b23",
         "$krb5tgs$17$srv_http$synacktiv.local$16ce51f6eba20c8ee534ff8a$57d07b23"),
        # With SPN, mixed-case username—SPN stripped, case preserved
        ("$krb5tgs$17$Srv_HTTP$SYNACKTIV.LOCAL$*srv_http/web.synacktiv.local*$16CE51F6EBA20C8EE534FF8A$57D07B23",
         "$krb5tgs$17$Srv_HTTP$SYNACKTIV.LOCAL$16ce51f6eba20c8ee534ff8a$57d07b23"),
    ])
    def test_19600(self, ciphertext, expected):
        """19600 (etype 17): case is preserved for user/realm; SPN stripped; hex lowercased."""
        result = normalize_kerberos_hash(ciphertext, "19600")
        assert result == expected


class TestNormalizeKerberosAesSaltModes:
    """Test 19800, 19900, 28800, 28900 (krb5pa/krb5db etype 17/18) normalization.

    These modes lowercase only the trailing hex field; user/realm case preserved.
    """

    def test_19800_lowercase_hex_only(self):
        """19800: lowercase trailing hex, preserve user/realm."""
        ciphertext = "$krb5pa$17$SRV_HTTP$SYNACKTIV.LOCAL$57D07B23643A" + "0"*106
        result = normalize_kerberos_hash(ciphertext, "19800")
        # User and realm case preserved, hex field lowercased
        expected = "$krb5pa$17$SRV_HTTP$SYNACKTIV.LOCAL$" + "57d07b23643a" + "0"*106
        assert result == expected

    def test_19900_lowercase_hex_only(self):
        """19900: lowercase trailing hex, preserve user/realm."""
        ciphertext = "$krb5pa$18$SRV_HTTP$SYNACKTIV.LOCAL$57D07B23643A" + "0"*106
        result = normalize_kerberos_hash(ciphertext, "19900")
        expected = "$krb5pa$18$SRV_HTTP$SYNACKTIV.LOCAL$" + "57d07b23643a" + "0"*106
        assert result == expected

    def test_28800_lowercase_hex_only(self):
        """28800: lowercase trailing hex, preserve user/realm."""
        ciphertext = "$krb5db$17$SRV_HTTP$SYNACKTIV.LOCAL$57D07B23643A" + "0"*50
        result = normalize_kerberos_hash(ciphertext, "28800")
        expected = "$krb5db$17$SRV_HTTP$SYNACKTIV.LOCAL$" + "57d07b23643a" + "0"*50
        assert result == expected

    def test_28900_lowercase_hex_only(self):
        """28900: lowercase trailing hex, preserve user/realm."""
        ciphertext = "$krb5db$18$SRV_HTTP$SYNACKTIV.LOCAL$57D07B23643A" + "0"*50
        result = normalize_kerberos_hash(ciphertext, "28900")
        expected = "$krb5db$18$SRV_HTTP$SYNACKTIV.LOCAL$" + "57d07b23643a" + "0"*50
        assert result == expected


class TestNormalizeKerberosOtherModes:
    """Test 7500, 13100, 18200, 35300, 35400: keep existing behavior (lowercase)."""

    def test_7500_full_lowercase(self):
        """7500 (krb5pa RC4): existing behavior—lowercase entire hash."""
        ciphertext = "$krb5pa$23$USER$REALM$CHECKSUM$EDATA"
        result = normalize_kerberos_hash(ciphertext, "7500")
        assert result == ciphertext.lower()

    def test_13100_full_lowercase(self):
        """13100 (krb5tgs RC4): existing behavior—lowercase entire hash."""
        ciphertext = "$krb5tgs$23$*USER*REALM*$32HEX$EDATA"
        result = normalize_kerberos_hash(ciphertext, "13100")
        assert result == ciphertext.lower()

    def test_18200_full_lowercase(self):
        """18200 (krb5asrep RC4): existing behavior—lowercase entire hash."""
        ciphertext = "$krb5asrep$23$USER:32HEX$EDATA"
        result = normalize_kerberos_hash(ciphertext, "18200")
        assert result == ciphertext.lower()

    def test_35300_alias_13100_full_lowercase(self):
        """35300 (alias to 13100): existing behavior—lowercase entire hash."""
        ciphertext = "$krb5tgs$23$*USER*REALM*$32HEX$EDATA"
        result = normalize_kerberos_hash(ciphertext, "35300")
        assert result == ciphertext.lower()

    def test_35400_alias_18200_full_lowercase(self):
        """35400 (alias to 18200): existing behavior—lowercase entire hash."""
        ciphertext = "$krb5asrep$23$USER:32HEX$EDATA"
        result = normalize_kerberos_hash(ciphertext, "35400")
        assert result == ciphertext.lower()


class TestNormalizeKerberosMalformedInput:
    """Test malformed input handling—return unchanged."""

    def test_malformed_too_few_parts(self):
        """Malformed: fewer than 6 dollar-delimited parts."""
        ciphertext = "$krb5tgs$18$user"
        result = normalize_kerberos_hash(ciphertext, "19700")
        assert result == ciphertext

    def test_malformed_wrong_number_of_parts_19700(self):
        """Malformed: 19700 with wrong number of parts."""
        ciphertext = "$krb5tgs$18$user$realm$checksum"  # Only 6 parts, need 7 or 8
        result = normalize_kerberos_hash(ciphertext, "19700")
        assert result == ciphertext

    def test_malformed_spn_format(self):
        """Malformed: SPN-like field but no asterisks."""
        ciphertext = "$krb5tgs$18$user$realm$noasterisks$checksum$edata"
        result = normalize_kerberos_hash(ciphertext, "19700")
        # This has 8 parts but parts[5] doesn't start with *, so it's not Form 2
        # Return unchanged
        assert result == ciphertext

    def test_empty_string(self):
        """Malformed: empty string."""
        result = normalize_kerberos_hash("", "19700")
        assert result == ""

    def test_hash_type_as_int(self):
        """Edge case: hash_type as int (should be converted to string by alias lookup)."""
        ciphertext = "$krb5tgs$18$Srv_HTTP$SYNACKTIV.LOCAL$16CE51F6EBA20C8EE534FF8A$57D07B23"
        result = normalize_kerberos_hash(ciphertext, 19700)
        # Should still work because _KERBEROS_ALIAS.get(str(19700), ...) converts it
        expected = "$krb5tgs$18$Srv_HTTP$SYNACKTIV.LOCAL$16ce51f6eba20c8ee534ff8a$57d07b23"
        assert result == expected


class TestNormalizeKerberosEdgeCases:
    """Edge cases in formatting and field extraction."""

    def test_19700_long_edata(self):
        """19700 with very long edata field."""
        long_edata = "A" * 500
        ciphertext = f"$krb5tgs$18$user$realm$16CE51F6EBA20C8EE534FF8A${long_edata}"
        result = normalize_kerberos_hash(ciphertext, "19700")
        expected = f"$krb5tgs$18$user$realm$16ce51f6eba20c8ee534ff8a${long_edata.lower()}"
        assert result == expected

    def test_19700_hex_with_lowercase_and_uppercase_mixed(self):
        """Hex fields with mixed case."""
        ciphertext = "$krb5tgs$18$user$realm$16Ce51F6eBA20C8Ee534Ff8a$57d07B23643A516834795f0c"
        result = normalize_kerberos_hash(ciphertext, "19700")
        # All hex should be lowercased
        expected = "$krb5tgs$18$user$realm$16ce51f6eba20c8ee534ff8a$57d07b23643a516834795f0c"
        assert result == expected
