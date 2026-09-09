"""Unit tests for the hardened hashfile validators.

Contract: each validator returns an ERROR STRING for a malformed file and a
falsy value (False) when the file passes. Valid vectors are real hashcat
--example-hashes; malformed vectors exercise the new hex/length/structure
checks and the fixed robustness (blank lines, empty file, encoding, the
netntlm arity bug, sha512crypt rounds=, locked shadow accounts).
"""

import os
import tempfile

import pytest

from hashview.utils.utils import (
    hash_type_uses_salt,
    validate_hash_only_hashfile,
    validate_hex_salt,
    validate_kerberos_hashfile,
    validate_netntlm_hashfile,
    validate_pwdump_hashfile,
    validate_shadow_hashfile,
    validate_user_hash_hashfile,
)


def _run(fn, lines, *args):
    """Write lines to a temp file, run the validator, return its result."""
    fd, path = tempfile.mkstemp()
    try:
        with os.fdopen(fd, 'w') as f:
            f.write('\n'.join(lines) + '\n')
        return fn(path, *args)
    finally:
        os.remove(path)


def _ok(fn, lines, *args):
    res = _run(fn, lines, *args)
    assert res is False, "expected pass (False) but got: %r" % (res,)


def _bad(fn, lines, *args):
    res = _run(fn, lines, *args)
    assert isinstance(res, str) and res, "expected an error string but got: %r" % (res,)


# ---------------------------------------------------------------------------
# pwdump (NTLM 1000)
# ---------------------------------------------------------------------------

def test_pwdump_valid():
    _ok(validate_pwdump_hashfile, [
        'Administrator:500:aad3b435b51404eeaad3b435b51404ee:b4b9b02e6f09a9bd760f388b67351e2b:::',
        'jdoe:1001::b4b9b02e6f09a9bd760f388b67351e2b:::',                      # empty LM ok
        'CONTOSO\\svc_sql:1107:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::',
    ], '1000')


def test_pwdump_invalid():
    _bad(validate_pwdump_hashfile, ['Administrator:500:aad3b435b51404eeaad3b435b51404ee:b4b9b02e6f09a9bd760f388b67351e2:::'], '1000')  # NT 31 hex
    _bad(validate_pwdump_hashfile, ['u:500:aad3b435b51404eeaad3b435b51404ee:b4b9b02e6f09a9bd760f388b67351g2b:::'], '1000')             # NT non-hex
    _bad(validate_pwdump_hashfile, ['Administrator:500:aad3b435b51404eeaad3b435b51404ee:b4b9b02e6f09a9bd760f388b67351e2b'], '1000')    # missing :::
    _bad(validate_pwdump_hashfile, [':500::b4b9b02e6f09a9bd760f388b67351e2b:::'], '1000')                                              # empty username
    _bad(validate_pwdump_hashfile, ['u:500::b4b9b02e6f09a9bd760f388b67351e2b:::'], '500')                                              # unsupported hash type


# ---------------------------------------------------------------------------
# netntlm (5500/27000 v1, 5600/27100 v2) — incl. the arity-bug fix
# ---------------------------------------------------------------------------

_V1 = '::5V4T:ada06359242920a500000000000000000000000000000000:0556d5297b5daa70eaffde82ef99293a3f3bb59b7c9704ea:9c23f6c094853920'
_V2 = '0UL5G37JOI0SX::6VB1IS0KA74:ebe1afa18b7fbfa6:aab8bf8675658dd2a939458a1077ba08:010100000000000031c8aa092510945398b9f7b7dde1a9fb00000000f7876f2b04b700'


def test_netntlm_v1_v2_valid_two_arg():
    _ok(validate_netntlm_hashfile, [_V1], '5500')
    _ok(validate_netntlm_hashfile, [_V1], '27000')
    _ok(validate_netntlm_hashfile, [_V2], '5600')
    _ok(validate_netntlm_hashfile, [_V2], '27100')


def test_netntlm_one_arg_jobs_path():
    # jobs/routes.py calls with a single argument — must not TypeError, accepts v1 or v2
    _ok(validate_netntlm_hashfile, [_V1])
    _ok(validate_netntlm_hashfile, [_V2])


def test_netntlm_invalid():
    _bad(validate_netntlm_hashfile, ['::5V4T:ada06359242920a5:0556d5297b5daa70eaffde82ef99293a3f3bb59b7c9704ea:9c23f6c094853920'], '5500')  # LM resp 16 not 48
    _bad(validate_netntlm_hashfile, ['::5V4T:ada06359242920a500000000000000000000000000000000:0556d5297b5daa70eaffde82ef99293a3f3bb59b7c9704ea:9c23f6c09485392z'], '5500')  # non-hex challenge
    _bad(validate_netntlm_hashfile, ['::5V4T:ada06359242920a500000000000000000000000000000000:0556d5297b5daa70eaffde82ef99293a3f3bb59b7c9704ea'], '5500')  # only 5 fields
    _bad(validate_netntlm_hashfile, [_V2], '5500')   # v2 hash validated as v1 -> field4 wrong length


def test_netntlm_duplicate_detection():
    res = _run(validate_netntlm_hashfile, [_V1, _V1], '5500')
    assert isinstance(res, str) and 'duplicate' in res.lower()


# ---------------------------------------------------------------------------
# kerberos
# ---------------------------------------------------------------------------

# hashcat 6.2.6 --example-hashes, verbatim. Regenerate with:
#   hashcat -m <mode> --example-hashes --mach
_HASHCAT_EXAMPLES = {
    '7500':
        '$krb5pa$23$user$realm$salt$5cbb0c882a2b26956e81644edbdb746326f4f5f0e947144fb3095dffe4b4b03e854fc1d631323632303636373330383333353630',
    '13100':
        '$krb5tgs$23$*user$realm$test/spn*$b548e10f5694ae018d7ad63c257af7dc$35e8e45658860bc31a859b41a08989265f4ef8afd75652ab4d7a30ef151bf6350d879ae189a8cb769e01fa573c6315232b37e4bcad9105520640a781e5fd85c09615e78267e494f433f067cc6958200a82f70627ce0eebc2ac445729c2a8a0255dc3ede2c4973d2d93ac8c1a56b26444df300cb93045d05ff2326affaa3ae97f5cd866c14b78a459f0933a550e0b6507bf8af27c2391ef69fbdd649dd059a4b9ae2440edd96c82479645ccdb06bae0eead3b7f639178a90cf24d9a',
    '18200':
        '$krb5asrep$23$user@domain.com:3e156ada591263b8aab0965f5aebd837$007497cb51b6c8116d6407a782ea0e1c5402b17db7afa6b05a6d30ed164a9933c754d720e279c6c573679bd27128fe77e5fea1f72334c1193c8ff0b370fadc6368bf2d49bbfdba4c5dccab95e8c8ebfdc75f438a0797dbfb2f8a1a5f4c423f9bfc1fea483342a11bd56a216f4d5158ccc4b224b52894fadfba3957dfe4b6b8f5f9f9fe422811a314768673e0c924340b8ccb84775ce9defaa3baa0910b676ad0036d13032b0dd94e3b13903cc738a7b6d00b0b3c210d1f972a6c7cae9bd3c959acf7565be528fc179118f28c679f6deeee1456f0781eb8154e18e49cb27b64bf74cd7112a0ebae2102ac',
    '19600':
        '$krb5tgs$17$srv_http$synacktiv.local$849e31b3db1c1f203fa20b85$948690f5875125348286ad3346d27b43eaabc71896b620c16de7ddcdbd561628c650c508856a3f574261948b6db4b48332d30536e978046a423ad4368f9a69b4dc4642dab4e0d475d8299be718fd6f98ac85a771b457b2453e78c9411dfce572b19660fe7a5a8246d9b2a91ea2f14d1986ea0a77ecf9b8330bc8fd9ab540bcf46b74c5aa7005cfccd89ec05f66aeab30c6b2bf8595cf6c9a1b68ad885258850c4b1dd9265f270fb2af52fd76c16246df51ea67efc58a65c345686c84e43642febe908a',
    '19700':
        '$krb5tgs$18$srv_http$synacktiv.local$16ce51f6eba20c8ee534ff8a$57d07b23643a516834795f0c010da8f549b7e65063e5a367ca9240f9b800adad1734df7e7d5dd8307e785de4f40aacf901df41aa6ce695f8619ec579c1fa57ee93661cf402aeef4e3a42e7e3477645d52c09dc72feade03512dffe0df517344f673c63532b790c242cc1d50f4b4b34976cb6e08ab325b3aefb2684262a5ee9faacb14d059754f50553be5bfa5c4c51e833ff2b6ac02c6e5d4c4eb193e27d7dde301bd1ddf480e5e282b8c27ef37b136c8f140b56de105b73adeb1de16232fa1ab5c9f6',
    '19800':
        '$krb5pa$17$hashcat$HASHCATDOMAIN.COM$a17776abe5383236c58582f515843e029ecbff43706d177651b7b6cdb2713b17597ddb35b1c9c470c281589fd1d51cca125414d19e40e333',
    '19900':
        '$krb5pa$18$hashcat$HASHCATDOMAIN.COM$96c289009b05181bfd32062962740b1b1ce5f74eb12e0266cde74e81094661addab08c0c1a178882c91a0ed89ae4e0e68d2820b9cce69770',
    '28800':
        '$krb5db$17$test$TEST.LOCAL$1c41586d6c060071e08186ee214e725e',
    '28900':
        '$krb5db$18$test$TEST.LOCAL$266b5a53a6d663c3f69174f3309acada8e467c097c7973699f86286a6cf1a6c7',
}


@pytest.mark.parametrize("htype", sorted(_HASHCAT_EXAMPLES))
def test_kerberos_hashcat_example_hashes_validate(htype):
    """hashcat's own canonical example must always pass its validator.

    A floor, not a safety net: these patterns were originally calibrated FROM
    the examples, so every one of them passed even while real impacket output
    was being rejected. It is the mode-specific tests below that carry the
    weight.
    """
    _ok(validate_kerberos_hashfile, [_HASHCAT_EXAMPLES[htype]], htype)


# Structurally valid synthetic vectors, with the field lengths hashcat actually
# requires (swept one character at a time against hashcat 6.2.6, not copied
# from the examples): 7500 tail exactly 104, 13100/18200 checksum 32 + edata2
# >= 64, 19600/19700 checksum 24 + edata2 >= 64, 19800/19900 tail 104-112,
# 28800 tail 32, 28900 tail 64.
_ED = 'ab' * 64                     # 128 hex, comfortably over the 64 floor
_KRB = {
    '7500':  '$krb5pa$23$user$realm$salt$' + 'a' * 104,
    '13100': '$krb5tgs$23$*user$realm$test/spn*$' + 'b' * 32 + '$' + _ED,
    '18200': '$krb5asrep$23$user@domain.com:' + 'c' * 32 + '$' + _ED,
    '19600': '$krb5tgs$17$srv_http$synacktiv.local$' + 'd' * 24 + '$' + _ED,
    '19700': '$krb5tgs$18$srv_http$synacktiv.local$' + 'e' * 24 + '$' + _ED,
    '19800': '$krb5pa$17$hashcat$HASHCATDOMAIN.COM$' + 'a' * 112,
    '19900': '$krb5pa$18$hashcat$HASHCATDOMAIN.COM$' + 'b' * 112,
    '28800': '$krb5db$17$test$TEST.LOCAL$' + 'a' * 32,
    '28900': '$krb5db$18$test$TEST.LOCAL$' + 'b' * 64,
}


@pytest.mark.parametrize("htype,vec", list(_KRB.items()))
def test_kerberos_valid(htype, vec):
    _ok(validate_kerberos_hashfile, [vec], htype)


def test_kerberos_aliases_35300_35400():
    _ok(validate_kerberos_hashfile, [_KRB['13100']], '35300')   # NT variant of 13100
    _ok(validate_kerberos_hashfile, [_KRB['18200']], '35400')   # NT variant of 18200


def test_kerberos_invalid():
    _bad(validate_kerberos_hashfile, [_KRB['13100']], '7500')                              # wrong prefix for type
    _bad(validate_kerberos_hashfile, ['$krb5pa$99$user$realm$salt$' + 'a' * 104], '7500')  # wrong etype
    _bad(validate_kerberos_hashfile, ['$krb5tgs$17$u$r$' + 'd' * 24 + '$xyz'], '19600')    # non-hex edata
    _bad(validate_kerberos_hashfile, [_KRB['7500']], '99999')                              # unsupported type


# --- field lengths, swept against hashcat rather than assumed ---------------
#
# These were all `[0-9a-fA-F]+`, so any hex length passed hashview and the
# paste succeeded; the hash then failed on the agent with "No hashes loaded",
# where the user has no way to connect it to what they typed.


@pytest.mark.parametrize("htype,prefix,length", [
    ('7500',  '$krb5pa$23$user$realm$salt$', 104),
    ('28800', '$krb5db$17$test$TEST.LOCAL$', 32),
    ('28900', '$krb5db$18$test$TEST.LOCAL$', 64),
])
def test_kerberos_fixed_length_tails_are_exact(htype, prefix, length):
    """hashcat accepts exactly one tail length for these three modes."""
    _ok(validate_kerberos_hashfile, [prefix + 'a' * length], htype)
    for delta in (-2, -1, 1, 2):
        _bad(validate_kerberos_hashfile, [prefix + 'a' * (length + delta)], htype)


@pytest.mark.parametrize("htype,prefix", [
    ('19800', '$krb5pa$17$hashcat$HASHCATDOMAIN.COM$'),
    ('19900', '$krb5pa$18$hashcat$HASHCATDOMAIN.COM$'),
])
def test_kerberos_pa_enc_timestamp_window_is_104_to_112(htype, prefix):
    """The one place hashview was TIGHTER than hashcat.

    The blob is confounder(16) + a DER-encoded PA-ENC-TS-ENC whose length
    varies with the optional microseconds field + HMAC(12), so the accepted
    window is 104-112 hex inclusive -- measured by sweeping 80..140. Requiring
    exactly 112 rejected real 104-hex hashes outright.
    """
    for n in range(104, 113):
        _ok(validate_kerberos_hashfile, [prefix + 'a' * n], htype)
    for n in (102, 103, 113, 114):
        _bad(validate_kerberos_hashfile, [prefix + 'a' * n], htype)


@pytest.mark.parametrize("htype,vec_prefix,checksum_len", [
    ('13100', '$krb5tgs$23$*user$realm$spn*$', 32),
    ('18200', '$krb5asrep$23$user@dom.com:', 32),
    ('19600', '$krb5tgs$17$u$REALM$', 24),
    ('19700', '$krb5tgs$18$u$REALM$', 24),
])
def test_kerberos_edata2_floor_is_64_hex(htype, vec_prefix, checksum_len):
    """A truncated paste is caught here instead of on the agent."""
    head = vec_prefix + 'a' * checksum_len + '$'
    _ok(validate_kerberos_hashfile, [head + 'b' * 64], htype)
    _ok(validate_kerberos_hashfile, [head + 'b' * 65], htype)      # odd lengths are fine
    for n in (32, 62, 63):
        _bad(validate_kerberos_hashfile, [head + 'b' * n], htype)


# --- shapes real tools emit ------------------------------------------------


def test_kerberos_asrep_etype_field_is_optional():
    """Rubeus and John emit $krb5asrep$user@REALM:... with no `23$`.

    hashcat accepts it and echoes it back byte-identical (checked with --left),
    so there is no stored-form mismatch to worry about -- it can simply be
    accepted.
    """
    _ok(validate_kerberos_hashfile,
        ['$krb5asrep$user@dom.com:' + 'c' * 32 + '$' + _ED], '18200')
    _ok(validate_kerberos_hashfile,
        ['$krb5asrep$23$user@dom.com:' + 'c' * 32 + '$' + _ED], '18200')
    # A machine-account principal carries a literal '$'; the pre-existing
    # pattern allowed that and making the etype optional must not break it.
    _ok(validate_kerberos_hashfile,
        ['$krb5asrep$COMPUTER$@dom.com:' + 'c' * 32 + '$' + _ED], '18200')
    # A machine account is `<name>$`, so a computer named `18` arrives as
    # `18$@REALM` -- indistinguishable from an etype to a naive guard, and
    # hashcat loads it. Regression guard for exactly that false reject.
    for digits in ('18', '9', '123'):
        _ok(validate_kerberos_hashfile,
            [f'$krb5asrep$23${digits}$@dom.com:' + 'c' * 32 + '$' + _ED], '18200')
        _ok(validate_kerberos_hashfile,
            [f'$krb5asrep${digits}$@dom.com:' + 'c' * 32 + '$' + _ED], '18200')
    # ...but a wrong etype is still a mode/hash mismatch worth catching, even
    # though hashcat itself shrugs and accepts it. Without the lookahead the
    # optional-etype group turns `[^:]+` into a wildcard that swallows `17$`.
    for bad_etype in ('17', '18', '999'):
        _bad(validate_kerberos_hashfile,
             [f'$krb5asrep${bad_etype}$user@dom.com:' + 'c' * 32 + '$' + _ED], '18200')


def test_kerberos_tgs_rc4_rejects_a_nested_star():
    """`\*.+\*` let a '*' inside the triple through; hashcat rejects it."""
    _bad(validate_kerberos_hashfile,
         ['$krb5tgs$23$*us*er$realm$spn*$' + 'b' * 32 + '$' + _ED], '13100')
    _ok(validate_kerberos_hashfile,
        ['$krb5tgs$23$*user$realm$spn*$' + 'b' * 32 + '$' + _ED], '13100')


def test_kerberos_tgs_rc4_bare_and_john_shapes_stay_rejected():
    """A deliberate, documented divergence from hashcat.

    hashcat also loads `$krb5tgs$23$<ck>$<edata>` and John's
    `$krb5tgs$<spn>:<ck>$<edata>`, and both round-trip verbatim -- but neither
    carries a principal where the importer looks for one
    (``line.split('$')[3]``), so accepting them would file a hex blob as the
    username. No roasting tool in common use emits either shape, so they stay
    rejected until the importer can parse them.
    """
    _bad(validate_kerberos_hashfile,
         ['$krb5tgs$23$' + 'b' * 32 + '$' + _ED], '13100')
    _bad(validate_kerberos_hashfile,
         ['$krb5tgs$test/spn:' + 'b' * 32 + '$' + _ED], '13100')

# ---------------------------------------------------------------------------
# shadow (500/1500/1800/3200)
# ---------------------------------------------------------------------------

def test_shadow_valid_bare_and_line():
    _ok(validate_shadow_hashfile, ['$1$38652870$DUjsu4TTlTsOe/xxZ05uf/'], '500')
    _ok(validate_shadow_hashfile, ['root:$1$38652870$DUjsu4TTlTsOe/xxZ05uf/:18000:0:99999:7:::'], '500')
    _ok(validate_shadow_hashfile, ['24leDr0hHfb3A'], '1500')
    _ok(validate_shadow_hashfile, ['user:24leDr0hHfb3A:18000::::::'], '1500')
    _ok(validate_shadow_hashfile, ['$6$72820166$U4DVzpcYxgw7MVVDGGvB2/H5lRistD5.Ah4upwENR5UtffLR4X4SxSzfREv8z6wVl0jRFX40/KnYVvK4829kD1'], '1800')
    _ok(validate_shadow_hashfile, ['root:$6$rounds=5000$72820166$U4DVzpcYxgw7MVVDGGvB2/H5lRistD5.Ah4upwENR5UtffLR4X4SxSzfREv8z6wVl0jRFX40/KnYVvK4829kD1:1::::::'], '1800')  # rounds=
    _ok(validate_shadow_hashfile, ['$2a$05$MBCzKhG1KhezLh.0LRa0Kuw12nLJtpHy6DIaU.JAnqJUDYspHC.Ou'], '3200')


def test_shadow_invalid_and_locked():
    _bad(validate_shadow_hashfile, ['$6$salt$tooShortDigest'], '1800')                 # 86-char digest required
    _bad(validate_shadow_hashfile, ['daemon:*:18000:0:99999:7:::'], '1800')            # locked account
    _bad(validate_shadow_hashfile, ['bin:!:18000::::::'], '1800')                      # locked
    _bad(validate_shadow_hashfile, ['nobody::18000::::::'], '1800')                    # empty/passwordless
    _bad(validate_shadow_hashfile, ['$1$38652870$DUjsu4TTlTsOe/xxZ05uf/'], '9999')     # unsupported shadow type


# ---------------------------------------------------------------------------
# hash_only (data-driven table)
# ---------------------------------------------------------------------------

_HO_VALID = {
    '0':     '8743b52063cd84097a65d1633f5c74f5',
    '100':   'b89eaac7e61417341b710b727768294d0e6a277b',
    '1000':  '32ed87bdb5fdc5e9cba88547376818d4',
    '122':   '86586886b8bd3c379d2e176243a7225e6aae969d293fe9a9',
    '1700':  '82a9dda829eb7f8ffe9fbe49e45d47d2dad9664fbb7adf72492e3c81ebd3e29134d9bc12212bf83c6840f10e8246b9db54a4859b7ccd0123d86e5872c1e5082f',
    '10':    '3d83c8e717ff0e7ecfe187f088d69954:343141',
    '1410':  '5bb7456f43e3610363f68ad6de82b8b96f3fc9ad24e9d1f1f8d8bd89638db7c0:12480864321',
    '22':    'nKjiFErqK7TPcZdFZsZMNWPtw4Pv8n:26506173',
    '2400':  'dRRVnUmUHXOTt9nk',
    '2100':  '$DCC2$10240#6848#e2829c8af2232fa53797e2f0e35e4626',
    '500':   '$1$38652870$DUjsu4TTlTsOe/xxZ05uf/',
    '7000':  'AK1FCIhM0IUIQVFJgcDFwLCMi7GppdwtRzMyDpFOFxdpH8=',
    '8100':  '1130725275da09ca13254957f2314a639818d44c37ef6d558',
    '10100': '583e6f51e52ba296:2:4:47356410265714355482333327356688',
    '9400':  '$office$*2007*20*128*16*18410007331073848057180885845227*944c70a5ee6e5ab2a6a86ff54b5f621a*e6650f1f2630c27fd8fc0f5e56e2e01f99784b9f',
    '9600':  '$office$*2013*100000*256*16*67805436882475302087847656644837*0c392d3b9ca889656d1e615c54f9f3c9*612b79e33b96322c3253fc8a0f314463cd76bc4efe1352f7efffca0f374f7e4b',
}


@pytest.mark.parametrize("htype,vec", list(_HO_VALID.items()))
def test_hash_only_valid(htype, vec):
    _ok(validate_hash_only_hashfile, [vec], htype)


def test_hash_only_invalid():
    _bad(validate_hash_only_hashfile, ['8743b52063cd84097a65d1633f5c74fZ'], '0')      # non-hex
    _bad(validate_hash_only_hashfile, ['8743b52063cd84097a65d1633f5c74f'], '0')        # 31 chars
    _bad(validate_hash_only_hashfile, ['dRRVnUmUHXOTt9nkXX'], '2400')                  # 18 not 16 (old bug accepted 18)
    _bad(validate_hash_only_hashfile, ['86586886b8bd3c379d2e176243a7225e6aae969d293fe9a9XX'], '122')  # 50 not 48 (old bug wanted 50)
    _bad(validate_hash_only_hashfile, ['nKjiFErqK7TPcZdFZsZMNWPtw4Pv8n'], '22')        # Juniper missing :salt (old bug treated 22 as 32-hex)
    _bad(validate_hash_only_hashfile, ['$6$salt$short'], '1800')                       # bad sha512crypt
    _bad(validate_hash_only_hashfile, ['8743b52063cd84097a65d1633f5c74f5'], '10')      # md5+salt needs :salt


def test_hash_only_pkzip_accepts_both_tags():
    # hashcat's --identify maps BOTH the legacy '$pkzip$' and the '$pkzip2$' tag
    # to the PKZIP modes (its example hash uses '$pkzip2$'), so accept either for
    # every PKZIP mode. (Previously the rule was '$pkzip2$'-only, rejecting valid
    # '$pkzip$' hashes.)
    pkzip = ('$pkzip$8*1*1*0*0*19*9635*93c0ece4f264048e2af711ba68e132833ad76f985a8a2a9658'
             '*$/pkzip$')
    pkzip2 = '$pkzip2$3*1*1*0*0*24*3e2c*3ef8*0619e9d17ff3f994*$/pkzip2$'
    for htype in ('17200', '17210', '17220', '17225', '17230'):
        _ok(validate_hash_only_hashfile, [pkzip], htype)
        _ok(validate_hash_only_hashfile, [pkzip2], htype)
    _bad(validate_hash_only_hashfile, ['$notpkzip$1*2*3'], '17225')   # other magic still rejected


def test_hash_only_unknown_type_is_lenient():
    # a type not in the table is accepted (cannot be safely constrained)
    _ok(validate_hash_only_hashfile, ['anything-goes-here'], '31500')


# ---------------------------------------------------------------------------
# shared robustness
# ---------------------------------------------------------------------------

def test_blank_lines_skipped():
    _ok(validate_hash_only_hashfile, ['8743b52063cd84097a65d1633f5c74f5', '', '   ', '\t'], '0')


def test_empty_file_rejected():
    _bad(validate_hash_only_hashfile, [''], '0')
    _bad(validate_pwdump_hashfile, ['', '   '], '1000')


def test_non_utf8_bytes_do_not_crash():
    fd, path = tempfile.mkstemp()
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(b'8743b52063cd84097a65d1633f5c74f5\n\xff\xfe\x00garbage\n')
        res = validate_hash_only_hashfile(path, '0')   # decode must not raise
        assert isinstance(res, str)                     # the garbage line is rejected, not a 500
    finally:
        os.remove(path)


def test_utf8_bom_on_line1_is_accepted():
    # a leading UTF-8 BOM (Windows editors) must NOT reject the first hash
    fd, path = tempfile.mkstemp()
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(b'\xef\xbb\xbf8743b52063cd84097a65d1633f5c74f5\n')
        assert validate_hash_only_hashfile(path, '0') is False
    finally:
        os.remove(path)


def test_user_hash_accepts_two_args_and_validates():
    # API call site passes (path, hash_type); jobs call site passes (path)
    _ok(validate_user_hash_hashfile, ['alice:5f4dcc3b5aa765d61d8327deb882cf99'], '1000')
    _ok(validate_user_hash_hashfile, ['alice:5f4dcc3b5aa765d61d8327deb882cf99'])
    _bad(validate_user_hash_hashfile, ['no-colon-here'], '1000')


# ---------------------------------------------------------------------------
# newly-added modes: kerberos $krb5db$ (28800/28900), shadow crypt (7400/12400/15100)
# ---------------------------------------------------------------------------

def test_kerberos_krb5db_modes():
    _ok(validate_kerberos_hashfile, ['$krb5db$17$test$TEST.LOCAL$1c41586d6c060071e08186ee214e725e'], '28800')
    _ok(validate_kerberos_hashfile, ['$krb5db$18$test$TEST.LOCAL$266b5a53a6d663c3f69174f3309acada8e467c097c7973699f86286a6cf1a6c7'], '28900')
    _bad(validate_kerberos_hashfile, ['$krb5db$18$test$TEST.LOCAL$1c41586d6c060071e08186ee214e725e'], '28800')  # etype 18 under 28800
    _bad(validate_kerberos_hashfile, ['$krb5db$17$test$TEST.LOCAL$zz41586d6c060071e08186ee214e725e'], '28800')  # non-hex tail


def test_shadow_new_crypt_modes():
    _ok(validate_shadow_hashfile, ['$5$7777657035274252$XftMj84MW.New1/ViLY5V4CM4Y7EBvfETaZsCW9vcJ8'], '7400')
    _ok(validate_shadow_hashfile, ['user:$5$7777657035274252$XftMj84MW.New1/ViLY5V4CM4Y7EBvfETaZsCW9vcJ8:18000::::::'], '7400')
    _ok(validate_shadow_hashfile, ['_GW..8841inaTltazRsQ'], '12400')
    _ok(validate_shadow_hashfile, ['$sha1$20000$75552156$HhYMDdaEHiK3eMIzTldOFPnw.s2Q'], '15100')
    _bad(validate_shadow_hashfile, ['$5$saltsalt$tooshortdigest'], '7400')           # sha256crypt digest must be 43
    _bad(validate_shadow_hashfile, ['_GW..8841inaTltazRs'], '12400')                  # bsdicrypt must be 20 chars total


# ---------------------------------------------------------------------------
# hash_only now covers the full hashcat mode set via the auto-derived table
# ---------------------------------------------------------------------------

def test_hash_only_luks_large_hash_accepted():
    # LUKS hashes embed the keyslot and are hundreds of KB — must not be
    # rejected by the per-line length cap (regression: cap was 50,000).
    luks = '$luks$1$' + ('a' * 200000)
    _ok(validate_hash_only_hashfile, [luks], '29511')


def test_hash_only_bcrypt_wrapped_modes_accept_2b():
    # bcrypt-wrapped KDFs: $2b$/$2y$/$2x$ tags must be accepted, not only $2a$
    for mode in ('25600', '25800', '28400'):
        _ok(validate_hash_only_hashfile, ['$2b$05$/VT2Xs2dMd8GJKfrXhjYP.DkTjOVrY12yDN7/6I8ZV0q/1lEohLru'], mode)
        _ok(validate_hash_only_hashfile, ['$2a$05$/VT2Xs2dMd8GJKfrXhjYP.DkTjOVrY12yDN7/6I8ZV0q/1lEohLru'], mode)
        _bad(validate_hash_only_hashfile, ['$1$notbcrypt$abc'], mode)


def test_hash_only_auto_table_modes():
    # raw hex (mode 1400 SHA2-256), hash:salt (mode 12 PostgreSQL), $-prefix (mode 11600 7-zip)
    _ok(validate_hash_only_hashfile, ['127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935'], '1400')
    _bad(validate_hash_only_hashfile, ['127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba9'], '1400')   # short
    _ok(validate_hash_only_hashfile, ['a6343a68d964ca596d9752250d54bb8a:postgres'], '12')
    _bad(validate_hash_only_hashfile, ['a6343a68d964ca596d9752250d54bb8a'], '12')      # missing :salt
    _ok(validate_hash_only_hashfile, ['$7z$0$19$0$salt$8$deadbeef$1234'], '11600')
    _bad(validate_hash_only_hashfile, ['notsevenzip'], '11600')                        # wrong prefix


# ---------------------------------------------------------------------------
# form choices (data module)
# ---------------------------------------------------------------------------

def test_form_choices_complete_and_lm_excluded():
    from hashview.utils.hashcat_modes import (
        HASH_TYPE_CHOICES,
        KERBEROS_HASH_TYPE_CHOICES,
        NETNTLM_HASH_TYPE_CHOICES,
        SHADOW_HASH_TYPE_CHOICES,
    )

    def vals(choices):
        return [v for v, _ in choices if v]

    ht = vals(HASH_TYPE_CHOICES)
    assert '1000' in ht and '0' in ht and '22000' in ht        # broad coverage
    assert '3000' not in ht                                     # LM excluded
    # sequential (ascending by mode number)
    nums = [int(v) for v in ht]
    assert nums == sorted(nums)
    # the categorized selects are the right kinds, sequential, LM-free
    assert vals(KERBEROS_HASH_TYPE_CHOICES) == ['7500', '13100', '18200', '19600', '19700', '19800', '19900', '28800', '28900']
    assert vals(NETNTLM_HASH_TYPE_CHOICES) == ['5500', '5600', '27000', '27100']
    assert vals(SHADOW_HASH_TYPE_CHOICES) == ['500', '1500', '1800', '3200', '7400', '12400', '15100']


# ---------------------------------------------------------------------------
# --hex-salt (hash_type_uses_salt + validate_hex_salt)
# ---------------------------------------------------------------------------

def test_hash_type_uses_salt():
    # generic colon-delimited salted modes -> True
    for salted in ('10', '20', '110', '1410', '1710', '11', '2811', '1100'):
        assert hash_type_uses_salt(salted) is True, salted
    # an auto-derived hexsalt mode -> True
    assert hash_type_uses_salt('3100') is True
    # unsalted raw modes -> False
    for plain in ('0', '100', '1000', '1700', '900'):
        assert hash_type_uses_salt(plain) is False, plain
    # fixed-structure multi-field colon modes are excluded
    for excluded in ('22', '10100', '14000'):
        assert hash_type_uses_salt(excluded) is False, excluded
    # accepts int too (str-normalised internally)
    assert hash_type_uses_salt(10) is True


def test_validate_hex_salt_hash_only():
    md5 = 'a' * 32
    # valid hex salt after the first colon
    _ok(validate_hex_salt, [md5 + ':deadbeef', md5 + ':0123456789abcdef'], 'hash_only', '10')
    # salt with non-hex characters
    _bad(validate_hex_salt, [md5 + ':xyz123'], 'hash_only', '10')
    # no salt at all (no colon)
    _bad(validate_hex_salt, [md5], 'hash_only', '10')
    # colon present but empty salt
    _bad(validate_hex_salt, [md5 + ':'], 'hash_only', '10')


def test_validate_hex_salt_user_hash():
    md5 = 'b' * 32
    # user:hash:salt -> salt after the 2nd colon
    _ok(validate_hex_salt, ['alice:' + md5 + ':cafe', 'bob:' + md5 + ':00ff'], 'user_hash', '10')
    # non-hex salt
    _bad(validate_hex_salt, ['alice:' + md5 + ':nothex'], 'user_hash', '10')
    # only user:hash, no salt field
    _bad(validate_hex_salt, ['alice:' + md5], 'user_hash', '10')


def test_validate_hex_salt_noop_for_unsalted_mode():
    # unsalted mode -> nothing to validate, returns False even with junk "salts"
    ntlm = 'c' * 32
    _ok(validate_hex_salt, [ntlm, ntlm + ':whatever'], 'hash_only', '1000')
