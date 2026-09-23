"""A hashfile must match the hash type the operator picked (MSSQL / Sybase).

Reported: a user uploaded two hashfiles of modes 1731 and 132 and swapped the
types between them. Nothing objected. The job was built, queued, dispatched, and
only then did hashcat refuse to load the file -- by which point the failure is a
line in an agent log rather than a red box on the upload form.

131, 132 and 1731 are the same product (MSSQL 2000, 2005, 2012/2014), which is
exactly why they get confused, and 131/132 share the ``0x0100`` tag so LENGTH is
the only thing separating them. None of the three had a validation rule of any
kind: ``validate_hash_only_hashfile`` looks in the curated table, then the
auto-derived one, then gives up and accepts the line. The auto-generator could
not cover them because its ``('hex', N)`` spec needs the whole string to be hex
and the leading ``0x`` breaks that, while its prefix specs were written for
``$name$`` style tags.

Every constant below came out of ``hashcat --example-hashes`` and every
acceptance boundary was probed against the real binary rather than derived from
the format documentation -- including the two that are not obvious:

  * the ``0x`` is mandatory AND lowercase: ``0X0100...`` and a bare ``0100...``
    are both refused;
  * the hex digits after the tag are case-INsensitive.

Getting that backwards in either direction is a false rejection of a legitimate
upload, which is worse than the bug being fixed: a user with a valid file and no
way to submit it.
"""
import subprocess

import pytest

from hashview.utils.utils import _HASH_ONLY_RULES, validate_hash_only_hashfile

# hashcat v6.2.6 --example-hashes. Shapes:
#   131  0x0100 +  8 hex salt +  80 hex ->  94
#   132  0x0100 +  8 hex salt +  40 hex ->  54
#   1731 0x0200 +  8 hex salt + 128 hex -> 142
#   8000 0xc007 + 16 hex salt +  64 hex ->  86
EXAMPLES = {
    '131': '0x0100778883860000000000000000000000000000000000000000'
           'eda3604e067a06f2732b05b9cb90b8a710996939',
    '132': '0x010045083578bf13a6e30ca29c40e540813772754d54a5ffd325',
    '1731': '0x02003788006711b2e74e7d8cb4be96b1d187c962c5591a02d5a6ae81b3a4a094'
            'b26b7877958b26733e45016d929a756ed30d0a5ee65d3ce1970f9b7bf946e705c'
            '595f07625b1',
    '8000': '0xc0071808773188715731b69bd4e310b4129913aaf657356c5bdf3c46f249ed42'
            '477b5c74af6eaac4d15a',
}
MSSQL_FAMILY = ('131', '132', '1731')


def _write(tmp_path, text, name='hashes.txt'):
    path = tmp_path / name
    path.write_text(text if text.endswith('\n') else text + '\n')
    return str(path)


# --- the reported bug --------------------------------------------------------

@pytest.mark.parametrize('declared', MSSQL_FAMILY)
@pytest.mark.parametrize('actual', MSSQL_FAMILY)
def test_a_hashfile_must_match_the_type_it_was_uploaded_as(app, tmp_path, actual,
                                                           declared):
    """The whole 3x3 matrix, because the diagonal is the only part that should
    pass and a rule that accepted everything would satisfy any single case."""
    path = _write(tmp_path, EXAMPLES[actual])

    result = validate_hash_only_hashfile(path, declared)

    if actual == declared:
        assert result is False, (
            f'a genuine mode-{actual} hash was rejected as mode {declared}: {result}')
    else:
        assert isinstance(result, str), (
            f'a mode-{actual} hash was accepted as mode {declared} -- hashcat '
            'will refuse to load this file after the job is already queued')
        assert 'line 1' in result


def test_131_and_132_are_told_apart_by_length_alone():
    """They share the 0x0100 tag, so a prefix-only rule would pass both. This is
    the specific pair the reporter mixed up."""
    assert EXAMPLES['131'][:6] == EXAMPLES['132'][:6] == '0x0100'
    assert len(EXAMPLES['131']) != len(EXAMPLES['132'])
    assert _HASH_ONLY_RULES['131'][0].match(EXAMPLES['132']) is None
    assert _HASH_ONLY_RULES['132'][0].match(EXAMPLES['131']) is None


# --- the boundaries, as hashcat actually draws them --------------------------

@pytest.mark.parametrize('mode', sorted(EXAMPLES))
def test_the_0x_tag_is_required_and_lowercase(mode):
    """Probed against the binary. A rule that accepted '0X...' or a bare hex
    body would pass a file hashcat then refuses."""
    body = EXAMPLES[mode][2:]
    rule = _HASH_ONLY_RULES[mode][0]

    assert rule.match(EXAMPLES[mode]) is not None
    assert rule.match(body) is None, "accepted a hash with no '0x' tag"
    assert rule.match('0X' + body) is None, "accepted an uppercase '0X' tag"


@pytest.mark.parametrize('mode', sorted(EXAMPLES))
def test_the_hex_digits_are_case_insensitive(mode):
    """The other direction, and the one that costs a user their upload if the
    rule is too tight: hashcat accepts uppercase digits after the tag."""
    example = EXAMPLES[mode]
    tag, digits = example[:6], example[6:]
    assert _HASH_ONLY_RULES[mode][0].match(tag + digits.upper()) is not None, (
        'uppercase hex is valid to hashcat and must not be rejected here')


@pytest.mark.parametrize('mode', sorted(EXAMPLES))
def test_the_length_is_exact(mode):
    """One char either side of the real length must fail, or the rule is really
    only checking the prefix."""
    example = EXAMPLES[mode]
    rule = _HASH_ONLY_RULES[mode][0]
    assert rule.match(example + 'ab') is None, 'accepted an over-long hash'
    assert rule.match(example[:-2]) is None, 'accepted a truncated hash'


@pytest.mark.parametrize('mode', sorted(EXAMPLES))
def test_the_error_names_the_expected_shape(app, tmp_path, mode):
    """A rejection has to tell the operator what the file should have looked
    like; "line 3 is invalid" sends them back to guessing between three modes
    of the same product."""
    other = '132' if mode != '132' else '1731'
    path = _write(tmp_path, EXAMPLES[other])

    result = validate_hash_only_hashfile(path, mode)

    assert isinstance(result, str)
    assert str(len(EXAMPLES[mode])) in result or EXAMPLES[mode][:6] in result, (
        f'the message does not describe the expected shape: {result}')


def test_a_file_where_only_some_lines_are_wrong_is_still_rejected(app, tmp_path):
    """Partial contamination is the realistic shape of this mistake -- two
    exports concatenated, not a wholesale swap."""
    path = _write(tmp_path, EXAMPLES['132'] + '\n' + EXAMPLES['1731'])

    result = validate_hash_only_hashfile(path, '132')

    assert isinstance(result, str)
    assert 'line 2' in result


# --- the rules agree with the binary, not with my reading of the docs --------

@pytest.mark.hashcat_matrix
@pytest.mark.parametrize('declared', sorted(EXAMPLES))
@pytest.mark.parametrize('actual', sorted(EXAMPLES))
def test_the_rules_reproduce_hashcats_own_verdict(app, tmp_path, actual, declared):
    """The authority check. Skipped without HASHCAT_BIN.

    Everything above pins what the regexes do. This pins that what they do is
    what hashcat does -- the only definition of "valid" that matters, since the
    entire point is to refuse files hashcat would refuse and accept the ones it
    would take.
    """
    import os
    import shutil

    binary = os.environ.get('HASHCAT_BIN') or shutil.which('hashcat')
    if not binary:
        pytest.skip('needs hashcat')

    path = _write(tmp_path, EXAMPLES[actual])
    proc = subprocess.run(
        [binary, '-m', declared, path, '--quiet', '--potfile-disable',
         '-a', '3', '?d', '--runtime', '1'],
        capture_output=True, text=True, timeout=120)
    blob = (proc.stdout + proc.stderr).lower()
    hashcat_loaded = not any(marker in blob for marker in (
        'separator', 'line-length', 'token', 'signature', 'no hashes loaded'))

    hashview_accepts = validate_hash_only_hashfile(path, declared) is False

    assert hashview_accepts == hashcat_loaded, (
        f'mode-{actual} hash declared as {declared}: hashview '
        f'{"accepts" if hashview_accepts else "rejects"} but hashcat '
        f'{"loads" if hashcat_loaded else "refuses"} it')
