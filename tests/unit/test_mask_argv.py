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

import pytest

from hashview.utils.utils import mask_argv

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


def _job_and_task(attackmode, mask, wl_id=None):
    user = Users(first_name="A", last_name="D", email_address="m@e.com",
                 password="x" * 60, admin=True)
    db.session.add(user)
    db.session.commit()
    hsh = Hashes(sub_ciphertext="0" * 8, ciphertext="abcd", hash_type=0, cracked=False)
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
