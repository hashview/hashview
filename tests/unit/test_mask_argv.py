"""The Hashcat-mask task field can hold more than a mask.

The field is free-form and unvalidated, and the UI has no input for a custom
charset, so operators write the whole invocation into it:

    ?1?1?1?1?1 -1 ?u?l?d

build_hashcat_command used to pass that as ONE argv element, so hashcat received
a single giant mask and refused it with "Custom-charset 1 is undefined."
(reproduced against hashcat 6.2.6).

Splitting on every space would swap one bug for another: a literal space is a
valid mask character -- `hashcat -a 3 --stdout '?d ?d'` emits "1 0", "0 0", ...
-- and that works today only because the field arrives as a single element. So
the split is at option boundaries only, and these tests pin both halves of that.
"""

import itertools

import pytest

from hashview.utils.utils import mask_argv, split_mask_field

#############################################
# The split itself
#############################################

@pytest.mark.parametrize("mask,expected", [
    # the reported failure: mask first, charset after
    ('?1?1?1?1?1 -1 ?u?l?d', ['?1?1?1?1?1', '-1', '?u?l?d']),
    # hashcat's own documented order: options first, mask last
    ('-1 ?u?l?d ?1?1?1?1?1', ['-1', '?u?l?d', '?1?1?1?1?1']),
    # several custom charsets
    ('?1?1 -1 ab -2 cd ?2?2', ['?1?1', '-1', 'ab', '-2', 'cd', '?2?2']),
    # long-form option
    ('?1?1 --custom-charset1 abc', ['?1?1', '--custom-charset1', 'abc']),
])
def test_option_bearing_masks_are_split(mask, expected):
    assert mask_argv(mask) == expected


@pytest.mark.parametrize("mask", [
    '?a?a?a?a?a?a?a?a',     # the plain case, and what production actually holds
    '?l?l?l?l?l?l?l',
    '?d ?d',                # LITERAL SPACE -- valid hashcat, works today
    '?u?l?l?l ?d?d?d?d',    # "Word 1234"
    '?l?l-?d?d',            # a dash inside a token is not an option
    'Summer?d?d?d?d',       # literal prefix
])
def test_masks_without_options_stay_one_argument(mask):
    """The regression guard. A plain space-split would break every one of these."""
    assert mask_argv(mask) == [mask]


def test_empty_and_none_pass_through_unchanged():
    """Purely a split: an absent mask is not silently dropped or rewritten, so
    nothing about the rest of the command moves with this change."""
    assert mask_argv('') == ['']
    assert mask_argv(None) == [None]


def test_split_preserves_every_token():
    """Nothing is lost or reordered -- the concatenation round-trips."""
    mask = '?1?1?1 -1 ?u?l?d -2 ?s ?2'
    assert ' '.join(' '.join(mask_argv(mask)).split()) == ' '.join(mask.split())


#############################################
# Through build_hashcat_command (modes 3, 6, 7)
#############################################

from hashview.models import (  # noqa: E402
    Hashes,
    HashfileHashes,
    Jobs,
    Tasks,
    Users,
    Wordlists,
    db,
)
from hashview.utils.utils import build_hashcat_command  # noqa: E402

_SEQ = itertools.count()


def _job_and_task(attackmode, mask, wl_id=None):
    user = Users(first_name="A", last_name="D",
                 email_address=f"m{next(_SEQ)}@e.com",
                 password="x" * 60, admin=True)
    db.session.add(user)
    db.session.commit()
    hsh = Hashes(sub_ciphertext=f"{next(_SEQ):08d}", ciphertext="abcd",
                 hash_type=0, cracked=False)
    db.session.add(hsh)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=hsh.id, hashfile_id=1))
    job = Jobs(name="j", status="Queued", hashfile_id=1, customer_id=1, owner_id=user.id)
    db.session.add(job)
    task = Tasks(name="t", hc_attackmode=attackmode, owner_id=user.id,
                 wl_id=wl_id, hc_mask=mask)
    db.session.add(task)
    db.session.commit()
    return build_hashcat_command(job.id, task.id)


def _chunked(attackmode, submask, wl_id=None):
    """Same, but the mask arrives as a CHUNK sub-mask."""
    user = Users(first_name="A", last_name="D",
                 email_address=f"c{next(_SEQ)}@e.com",
                 password="x" * 60, admin=True)
    db.session.add(user)
    db.session.commit()
    hsh = Hashes(sub_ciphertext=f"{next(_SEQ):08d}", ciphertext="beef",
                 hash_type=0, cracked=False)
    db.session.add(hsh)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=hsh.id, hashfile_id=1))
    job = Jobs(name="j2", status="Queued", hashfile_id=1, customer_id=1, owner_id=user.id)
    db.session.add(job)
    task = Tasks(name="t2", hc_attackmode=attackmode, owner_id=user.id,
                 wl_id=wl_id, hc_mask='?a?a?a?a')
    db.session.add(task)
    db.session.commit()
    return build_hashcat_command(job.id, task.id, chunk={'mask': submask},
                                 job_task_id=99)


def _wordlist():
    """A real wordlist row, so ordering assertions have a token to look for."""
    wl = Wordlists(name="wl-sent", owner_id=1, type="static",
                   path="/x/control/wordlists/deadbeef.gz", size=1, checksum="c" * 64)
    db.session.add(wl)
    db.session.commit()
    return wl


def test_mask_mode_emits_the_charset_as_separate_arguments(app):
    """The reported bug: hashcat answered 'Custom-charset 1 is undefined.'
    because all three tokens arrived as one argv element."""
    argv = _job_and_task(3, '?1?1?1?1?1 -1 ?u?l?d')

    assert '?1?1?1?1?1 -1 ?u?l?d' not in argv, "still one giant element"
    i = argv.index('?1?1?1?1?1')
    assert argv[i:i + 3] == ['?1?1?1?1?1', '-1', '?u?l?d']


@pytest.mark.parametrize("attackmode", [3, 6, 7])
def test_every_mask_bearing_mode_splits(app, attackmode):
    """Mask mode and both hybrids all pass the mask through; none may regress."""
    argv = _job_and_task(attackmode, '?1?1 -1 ab', wl_id=None)
    assert '-1' in argv and 'ab' in argv
    assert argv[argv.index('-1') - 1] == '?1?1'


def test_hybrid_7_keeps_the_wordlist_after_the_mask(app):
    """Mode 7 is mask-then-wordlist. The split must not push the wordlist ahead
    of the mask -- that would silently turn it into mode 6 semantics (wordlist
    first), producing different candidates.

    A REAL wordlist is seeded on purpose: with wl_id=None the path is '' and the
    ordering assertion cannot see a swap at all.
    """
    wl = Wordlists(name="wl", owner_id=1, type="static",
                   path="/x/control/wordlists/deadbeef.gz", size=1, checksum="c" * 64)
    db.session.add(wl)
    db.session.commit()

    argv = _job_and_task(7, '?1?1 -1 ab', wl_id=wl.id)

    wl_token = next(t for t in argv if t and 'deadbeef' in t)
    assert argv.index('?1?1') < argv.index(wl_token), (
        f"wordlist must follow the mask in mode 7: {argv}")
    assert argv.index('?1?1') < argv.index('-1') < argv.index(wl_token)


def test_plain_mask_command_is_unchanged(app):
    """Nothing moves for the masks production actually holds."""
    argv = _job_and_task(3, '?a?a?a?a?a?a?a?a')
    assert argv[-1] == '?a?a?a?a?a?a?a?a'
    assert argv.count('?a?a?a?a?a?a?a?a') == 1


def test_literal_space_mask_survives_as_one_argument(app):
    """The regression this fix had to avoid: '?d ?d' is a valid mask meaning
    digit-space-digit, and it only works while it stays a single argv element."""
    argv = _job_and_task(3, '?u?l?l?l ?d?d?d?d')
    assert '?u?l?l?l ?d?d?d?d' in argv


# ---------------------------------------------------------- split_mask_field

def test_split_identifies_a_dash_leading_mask_as_the_mask():
    """The bug: '-?d?d?d' is a MASK that happens to start with '-', not an
    option. hashcat has no option '-?'."""
    assert split_mask_field('-?d?d?d') == (['-?d?d?d'], 0)


def test_split_leaves_the_options_first_form_unidentifiable():
    """'-1 ?u?l?d ?1?1' -- is '?u?l?d' the charset value or the mask? It is
    ambiguous by construction, so no mask index and no sentinel."""
    parts, index = split_mask_field('-1 ?u?l?d ?1?1?1?1?1')
    assert parts == ['-1', '?u?l?d', '?1?1?1?1?1']
    assert index == -1


def test_split_hoists_a_charset_off_a_dash_leading_mask():
    parts, index = split_mask_field('-?d?d -1 abc')
    assert parts == ['-?d?d', '-1', 'abc']
    assert index == 0          # so the caller can hoist parts[1:] ahead of '--'


def test_split_preserves_a_leading_space_in_the_mask():
    """?s (and so ?a) begins with a literal space, so a chunk sub-mask can start
    with one. Joining the tokens back together would silently eat it."""
    parts, index = split_mask_field(' -?d?d --increment')
    assert parts[0] == ' -?d?d'
    assert index == 0


def test_first_token_is_mask_overrides_the_option_heuristic():
    """A chunk of '?aabc' is '-abc' -- second character is a letter, so the
    free-form heuristic reads it as an option. The chunker knows better."""
    assert split_mask_field('-abc?d')[1] == -1                       # free-form
    assert split_mask_field('-abc?d', first_token_is_mask=True) == (['-abc?d'], 0)


@pytest.mark.parametrize("field", [
    '?1?1?1?1?1 -1 ?u?l?d', '-1 ?u?l?d ?1?1?1?1?1', '?1?1 -1 ab -2 cd ?2?2',
    '?1?1 --custom-charset1 abc', '?a?a?a?a', '?d ?d', '?u?l?l?l ?d?d?d?d',
    '?l?l-?d?d', '', None,
])
def test_mask_argv_is_the_parts_half_of_split_mask_field(field):
    """The wrapper must not drift from the function it wraps."""
    assert mask_argv(field) == split_mask_field(field)[0]


# ------------------------------------------------- the '--' sentinel in argv

@pytest.mark.parametrize("mode", [3, 6, 7])
def test_dash_leading_mask_emits_the_sentinel(app, mode):
    wl = _wordlist() if mode in (6, 7) else None
    argv = _job_and_task(mode, '-?d?d?d', wl_id=(wl.id if wl else None))

    assert argv.count('--') == 1
    sentinel = argv.index('--')
    target = next(i for i, t in enumerate(argv) if t and t.startswith('control/hashes/'))
    assert sentinel < target, f"sentinel must precede the positionals: {argv}"
    # everything after the sentinel is a positional: the only '-'-leading token
    # there is the mask itself, which is the entire point of the sentinel
    after = argv[sentinel + 1:]
    assert '-?d?d?d' in after
    assert [t for t in after if t.startswith('-')] == ['-?d?d?d']


def test_sentinel_is_paired_with_status_json(app):
    """An un-upgraded agent appends --status-json AFTER the sentinel, where it is
    not honoured; emitting it here keeps mode 3 reporting status on old agents."""
    argv = _job_and_task(3, '-?d?d?d')
    assert argv.index('--status-json') == argv.index('--') - 1


def test_plain_mask_emits_no_sentinel(app):
    """Conditional emission is the whole compatibility story: every command that
    does not need '--' keeps a byte-identical argv."""
    assert '--' not in _job_and_task(3, '?a?a?a?a?a?a?a?a')
    assert '--' not in _job_and_task(3, '?1?1?1?1?1 -1 ?u?l?d')
    assert '--' not in _job_and_task(3, '?u?l?l?l ?d?d?d?d')


def test_space_leading_mask_emits_no_sentinel(app):
    """A leading space is a valid literal and works today; do not disturb it."""
    argv = _job_and_task(3, ' ?d?d?d')
    assert '--' not in argv
    assert ' ?d?d?d' in argv


def test_dash_leading_chunk_submask_emits_the_sentinel(app):
    """The reported case: chunking ?a expands the leading position over all 95
    characters, one of which is '-'."""
    argv = _chunked(3, '-?a?a?a')
    assert argv.count('--') == 1
    assert argv[-1] == '-?a?a?a'
    assert '--skip' not in argv and '--limit' not in argv


def test_mode_7_keeps_the_wordlist_after_the_mask(app):
    """hashcat's mode 7 signature is <hashfile> <mask> <wordlist>; the sentinel
    must not reorder it."""
    wl = _wordlist()
    argv = _job_and_task(7, '-?d?d', wl_id=wl.id)
    wl_token = next(t for t in argv if t and 'deadbeef' in t)
    assert argv.index('-?d?d') < argv.index(wl_token)
    assert argv.index('--') < argv.index('-?d?d')
