"""A stored hash must be spelled the way hashcat will spell it back.

An agent's recovered hash is matched to its row by an exact md5 of the stored
ciphertext (``hashview/api/routes.py``), so the stored form has to be a fixed
point of hashcat's own encoder. It was not, for almost every mode:

  * hashcat parses hex case-INSENSITIVELY -- one parser, ``hex_convert()`` in
    src/convert.c, ``(c & 15) + (c >> 6) * 9``, which folds 'A' and 'a' to the
    same nibble -- so an upper-case paste is accepted and cracked;
  * it re-emits through ``u8_to_hex``/``u32_to_hex``/``u64_to_hex``, whose table
    is the literal ``'0'..'9','a'..'f'``, so it reports the hash in LOWER case.

Hashview folded the case of four modes (300, 1000, 1731 and DCC2). Everything
else -- MD5, SHA1, SHA256, MSSQL 2000/2005, NetNTLM, hundreds more -- was stored
exactly as typed, so a hash pasted in upper case was cracked and then silently
failed to match: cracked=0 for ever, password never reaching the
``(DYNAMIC) All Recovered Passwords`` wordlist, hash re-attacked by every later
job. That is #444's failure mode reached by a different route.

A blanket ``.lower()`` is not the fix, and this file pins why not. Three groups
of modes would be corrupted by one:

  * nine emit UPPER case (``snprintf("%08X")`` or an explicit ``uppercase()``);
  * fourteen carry ``OPTS_TYPE_HASH_COPY`` and echo the line byte for byte;
  * a text salt is echoed verbatim, so folding it changes the hash -- the same
    trap ``normalize_kerberos_hash`` exists to avoid for the AES etypes;
  * and a free-text field can hold a hex-looking value: 'deadbeef' is a
    plausible account name, and hashcat hands a Kerberos principal back
    untouched, so those modes are absent from the table entirely.

Every vector below is hashcat 6.2.6's own canonical output, taken from
``hashcat -m <mode> <file> --left``, which prints exactly what the outfile,
potfile and ``--show`` print. The table under test was derived the same way; the
opt-in test at the bottom re-derives it against a live binary.
"""
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from hashview.utils.hashcat_modes import HASH_CASE_RULES
from hashview.utils.utils import (
    _classify_hashfile_line,
    get_md5_hash,
    normalize_hash_case,
)

VECTORS = json.loads(
    (Path(__file__).parent / 'data' / 'hashcat_canonical_forms.json').read_text())

# hashcat's OPTS_TYPE_HASH_COPY: module_hash_encode is
# `snprintf(line_buf, line_size, "%s", hash_info->orighash)`, so whatever case
# you hand it comes back. Folding any of these is always wrong.
HASH_COPY_MODES = {
    '501', '7100', '10600', '10700', '10900', '11300', '11400', '11900',
    '12000', '12001', '12100', '12700', '15200', '16400',
}

# Emit upper case: snprintf("%08X"/"%02X"), or an explicit uppercase().
UPPERCASE_MODES = {'3100', '7401', '7700', '7701', '7800', '7801', '8500',
                   '12300', '15500'}


# One hex field, matching the importer's own definition: delimiter-bounded and
# at least 8 characters, so it cannot latch onto part of a base64 blob.
HEX_FIELD = re.compile(r'(?<![A-Za-z0-9+/=])[0-9a-fA-F]{8,}(?![A-Za-z0-9+/=])')


def _recase(text, span, how):
    """Re-spell only the span the rule claims, leaving the structure intact --
    upper-casing a '0x' tag or a '$krb5tgs$' signature would just make a hash
    hashcat refuses, which proves nothing."""
    if span == 'fields':
        return HEX_FIELD.sub(lambda m: how(m.group(0)), text)
    if span in ('all', 'line'):
        start, end = 0, len(text)
    elif span[0] == 'after':
        start, end = len(span[1]), len(text)
    elif span[0] == 'head':
        start, end = 0, text.find(span[1])
    else:                                     # ('tail', sep)
        start, end = text.rfind(span[1]) + 1, len(text)
    return text[:start] + how(text[start:end]) + text[end:]


# --- the reported bug --------------------------------------------------------

def test_an_uppercase_paste_lands_on_the_form_hashcat_will_report():
    """The whole point. Mode 132 is the one the report came in on; NTLM (1000)
    is the one this was first hit with."""
    mssql_upper = '0x010045083578BF13A6E30CA29C40E540813772754D54A5FFD325'
    assert normalize_hash_case(mssql_upper, '132') == mssql_upper.lower()

    ntlm_upper = '8846F7EAEE8FB117AD06BDD830B7586C'
    assert normalize_hash_case(ntlm_upper, '1000') == ntlm_upper.lower()


def test_the_md5_lookup_now_matches_whatever_case_was_pasted():
    """The failure was never visible as a wrong string -- it was visible as a
    lookup that found nothing. Pin the lookup key, not the spelling."""
    digest = '5F4DCC3B5AA765D61D8327DEB882CF99'
    keys = {get_md5_hash(normalize_hash_case(spelling, '0'))
            for spelling in (digest, digest.lower(), digest.swapcase())}
    assert len(keys) == 1


@pytest.mark.parametrize('mode', sorted(VECTORS))
def test_every_spelling_of_every_covered_mode_folds_onto_hashcats_form(mode):
    """The table, against hashcat's own output for all 3 spellings of each hash.

    This is the regression test: before the fix `normalize_hash_case` did not
    exist and every one of these modes but four stored the hash as typed.
    """
    canon, span = VECTORS[mode]['canon'], HASH_CASE_RULES[mode][0]
    span = span if isinstance(span, str) else tuple(span)
    for how in (str.lower, str.upper, str.swapcase):
        assert normalize_hash_case(_recase(canon, span, how), mode) == canon


# --- the three groups a blanket .lower() would corrupt -----------------------

@pytest.mark.parametrize('mode', sorted(HASH_COPY_MODES))
def test_hash_copy_modes_are_not_in_the_table(mode):
    """hashcat echoes these verbatim, so there is no case to normalise to and
    any rule at all is a wrong one."""
    assert mode not in HASH_CASE_RULES


@pytest.mark.parametrize('mode', sorted(UPPERCASE_MODES & set(VECTORS)))
def test_the_uppercase_modes_fold_upward(mode):
    """A lower-case paste of an Oracle/SAP/RACF/JKS hash has to be raised, not
    left alone -- these are the modes a blanket .lower() would newly break."""
    span, case = HASH_CASE_RULES[mode]
    span = span if isinstance(span, str) else tuple(span)
    assert case == 'upper'
    canon = VECTORS[mode]['canon']
    assert normalize_hash_case(_recase(canon, span, str.lower), mode) == canon
    assert any(c.isupper() for c in canon)


def test_a_text_salt_is_never_folded():
    """hashcat memcpy's a text salt straight back out (generic_salt_encode with
    no ST_HEX/ST_BASE64 flag), so folding it changes the hash. Only the digest
    ahead of the colon may move."""
    salted = 'A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6:SaltyMcSaltFace'
    assert normalize_hash_case(salted, '10') == (
        'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6:SaltyMcSaltFace')


def test_kerberos_principal_salted_modes_keep_their_case():
    """19600/19700/19800/19900/28800/28900 salt the key with REALM + principal.
    They are handled by normalize_kerberos_hash on their own file_type, and must
    not pick up a rule here that would fold the principal."""
    for mode in ('19600', '19700', '19800', '19900', '28800', '28900'):
        rule = HASH_CASE_RULES.get(mode)
        if rule is None:
            continue
        assert rule[0] != 'line', f'mode {mode} would have its principal folded'


# --- lines that do not have the shape the rule was derived for ---------------

def test_an_unknown_mode_is_returned_untouched():
    assert normalize_hash_case('DeadBeef', '999999') == 'DeadBeef'


def test_a_line_that_does_not_fit_the_rule_is_returned_untouched():
    """A truncated hash, or a file of something else uploaded under a mode that
    happens to have a rule, must come through unchanged rather than be folded on
    a guess -- the importer still has to store what was uploaded."""
    assert normalize_hash_case('not-a-hash-at-all', '1000') == 'not-a-hash-at-all'
    assert normalize_hash_case('8846F7EAEE8FB117AD06BDD830B7586Z', '1000') == (
        '8846F7EAEE8FB117AD06BDD830B7586Z')
    assert normalize_hash_case('NOTHEX:salt', '10') == 'NOTHEX:salt'
    assert normalize_hash_case('nocolonhere', '10') == 'nocolonhere'


def test_a_fixed_marker_rule_matches_its_marker_rather_than_counting_characters():
    """An MSSQL hash pasted without its '0x' is hex from the first character, so
    a rule that folded 'from offset 2' regardless would leave the first two
    digits upper-case -- half a hash, and a fixed point of nothing."""
    body = '010045083578BF13A6E30CA29C40E540813772754D54A5FFD325'
    assert normalize_hash_case('0x' + body, '132') == '0x' + body.lower()
    assert normalize_hash_case(body, '132') == body


# --- the importer actually uses it -------------------------------------------

def test_hash_only_import_normalises_a_mode_it_never_used_to():
    sha1_upper = 'B6589FC6AB0DC82CF12099D1C2D40AB994E8410C'
    ciphertext, hash_type, username = _classify_hashfile_line(
        sha1_upper + '\n', 'hash_only', '100', set())
    assert (ciphertext, hash_type, username) == (sha1_upper.lower(), '100', None)


def test_user_hash_import_stores_the_hash_alone_not_the_whole_line():
    """#445: the 300/1731 branch lower-cased the whole 'user:hash' line and
    stored THAT as the ciphertext, username included, so the hash could never
    match a crack no matter what case it was in."""
    line = 'alice:FCF7C1B8749CF99D88E5F34271D636178FB5D130\n'
    ciphertext, _, username = _classify_hashfile_line(line, 'user_hash', '300', set())
    assert ciphertext == 'fcf7c1b8749cf99d88e5f34271d636178fb5d130'
    assert username == 'alice'


def test_dcc2_keeps_its_uppercase_tag():
    """hashcat lower-cases the iteration count, username and digest but re-emits
    '$DCC2$' upper-cased, which is why this one is not table-driven."""
    line = '$DCC2$10240#Alice#A1B2C3D4E5F60718293A4B5C6D7E8F90\n'
    ciphertext, _, username = _classify_hashfile_line(line, 'hash_only', '2100', set())
    assert ciphertext == '$DCC2$10240#alice#a1b2c3d4e5f60718293a4b5c6d7e8f90'
    assert username == 'alice'


# --- the authority check -----------------------------------------------------

@pytest.mark.hashcat_matrix
def test_the_table_reproduces_hashcats_own_answer(tmp_path):
    """Everything above pins what the table does. This pins that what it does is
    what hashcat does, which is the only definition that matters.

    One test rather than one per mode on purpose: it shells out three times for
    every covered mode, and as ~650 parametrised cases it would be ~650 skip
    lines in a CI run that has no hashcat. Skipped without a binary; set
    HASHCAT_BIN to point at one.
    """
    binary = os.environ.get('HASHCAT_BIN') or shutil.which('hashcat')
    if not binary:
        pytest.skip('needs hashcat')

    path, pot = tmp_path / 'h.txt', tmp_path / 'h.pot'
    mismatches = []
    for mode in sorted(VECTORS, key=int):
        canon, span = VECTORS[mode]['canon'], HASH_CASE_RULES[mode][0]
        span = span if isinstance(span, str) else tuple(span)
        for how in (str.lower, str.upper, str.swapcase):
            spelling = _recase(canon, span, how)
            path.write_text(spelling + '\n')
            if pot.exists():
                pot.unlink()
            proc = subprocess.run(
                [binary, '-m', mode, str(path), '--left', '--potfile-path',
                 str(pot), '--quiet'], capture_output=True, timeout=60)
            lines = [out for out in proc.stdout.decode('utf-8', 'replace').splitlines()
                     if out.strip()]
            if not lines:
                continue                   # hashcat refused this spelling
            stored = normalize_hash_case(spelling, mode)
            if stored != lines[-1]:
                mismatches.append(
                    f'{mode}: hashview stores {stored[:60]!r}, '
                    f'hashcat prints {lines[-1][:60]!r}')

    assert not mismatches, (
        'these would be stored in a form hashcat never reports, so their cracks '
        'could not be matched:\n  ' + '\n  '.join(mismatches[:20]))
