"""Unit tests for the pure chunk planner (hashview.utils.chunking).

These never touch the DB — the planner takes plain numbers — so they pin the
splitting math, the mask expansion (including '?' escaping), the dynamic-wordlist
exclusion, and the whole-task fallbacks.
"""


from hashview.utils.chunking import (
    _expand_mask,
    is_chunkable,
    mask_keyspace,
    parse_mask,
    plan_chunks,
)

# --- is_chunkable ----------------------------------------------------------

def test_is_chunkable_true_for_static_supported_modes():
    assert is_chunkable(0, wl_id=5, wl_id_2=None, dynamic_wl_ids={9})
    assert is_chunkable(3, wl_id=None, wl_id_2=None, dynamic_wl_ids={9})


def test_is_chunkable_false_when_wordlist_is_dynamic():
    assert not is_chunkable(0, wl_id=9, wl_id_2=None, dynamic_wl_ids={9})
    # combinator second wordlist dynamic also disqualifies
    assert not is_chunkable(1, wl_id=5, wl_id_2=9, dynamic_wl_ids={9})


def test_is_chunkable_false_for_unsupported_mode():
    assert not is_chunkable(2, wl_id=5, wl_id_2=None, dynamic_wl_ids=set())


# --- mask parsing / keyspace ----------------------------------------------

def test_mask_keyspace_builtins():
    assert mask_keyspace('?d?d') == 100
    assert mask_keyspace('?l?l?l') == 26 ** 3
    assert mask_keyspace('a?d') == 10          # literal 'a' contributes 1
    assert mask_keyspace('?a') == 95


def test_parse_mask_rejects_custom_and_byte_charsets():
    assert parse_mask('?1?l') is None          # custom charset
    assert parse_mask('?b?b') is None          # raw bytes
    assert parse_mask('?') is None             # dangling '?'
    assert mask_keyspace('?1') is None


def test_parse_mask_handles_escaped_question_literal():
    # '??' is a literal '?', not a charset
    assert parse_mask('??' '?d') == [('lit', '?'), ('set', 'd')]
    assert mask_keyspace('??' '?d') == 10


# --- plan_chunks: fallbacks ------------------------------------------------

def test_plan_whole_when_no_benchmark():
    assert plan_chunks(0, wordlist_size=10**9, rule_count=1,
                       slowest_speed=None) == [{}]


def test_plan_whole_when_attack_small_relative_to_speed():
    # 1000 words, no rules, fast agent -> one chunk would finish instantly
    assert plan_chunks(0, wordlist_size=1000, rule_count=0,
                       slowest_speed=10**9, target_seconds=3600) == [{}]


# --- plan_chunks: wordlist modes ------------------------------------------

def _assert_tiles_wordlist(specs, size):
    """skip/limit specs must tile [0, size) contiguously with no gap/overlap."""
    assert len(specs) >= 2
    skip = 0
    for spec in specs:
        assert spec['skip'] == skip
        assert spec['limit'] >= 1
        skip += spec['limit']
    assert skip == size                      # exact coverage, no overshoot


def test_plan_wordlist_with_rules_splits_and_tiles():
    size = 1_000_000
    # per_word = rule_count (100); target_candidates = 60 * 1000 = 60000;
    # words_per_chunk = 600 -> ~1667 chunks, capped at max_chunks.
    specs = plan_chunks(0, wordlist_size=size, rule_count=100,
                        slowest_speed=1000, target_seconds=60, max_chunks=50)
    assert all('skip' in s and 'limit' in s for s in specs)
    assert len(specs) <= 50
    _assert_tiles_wordlist(specs, size)


def test_plan_wordlist_chunk_count_scales_with_speed():
    size = 1_000_000
    slow = plan_chunks(0, wordlist_size=size, rule_count=10,
                       slowest_speed=1000, target_seconds=10, max_chunks=10_000)
    fast = plan_chunks(0, wordlist_size=size, rule_count=10,
                       slowest_speed=100_000, target_seconds=10, max_chunks=10_000)
    # a faster slowest-agent => bigger chunks => fewer of them
    assert len(fast) < len(slow)


def test_plan_combinator_uses_second_wordlist_as_amplifier():
    # left list 1e6 words, right list 1e6 -> 1e12 candidates; target 1e6 -> ~1e6
    # chunks, capped. Confirms wordlist2_size drives the split.
    specs = plan_chunks(1, wordlist_size=1_000_000, wordlist2_size=1_000_000,
                        slowest_speed=1000, target_seconds=1000, max_chunks=200)
    assert len(specs) >= 2
    _assert_tiles_wordlist(specs, 1_000_000)


# --- plan_chunks: mask modes ----------------------------------------------

def test_plan_mask_expands_into_submasks():
    # ?d?d?d?d = 10000 candidates; target 100 -> ~100 chunks -> expand 2 leading
    # ?d positions (10*10 = 100 submasks), each '<dd>?d?d'.
    specs = plan_chunks(3, mask='?d?d?d?d', slowest_speed=1, target_seconds=100)
    masks = [s['mask'] for s in specs]
    assert len(masks) == 100
    assert all(m.endswith('?d?d') for m in masks)
    assert '00?d?d' in masks and '99?d?d' in masks
    # every emitted sub-mask is itself a valid (parseable) mask
    assert all(parse_mask(m) is not None for m in masks)


def test_plan_mask_whole_when_small():
    assert plan_chunks(3, mask='?d?d', slowest_speed=1, target_seconds=3600) == [{}]


def test_plan_mask_unsplittable_charset_runs_whole():
    # ?b can't be expanded into literals -> whole task even though it's huge
    assert plan_chunks(3, mask='?b?b?b?b', slowest_speed=1, target_seconds=1) == [{}]


def test_plan_mask_escapes_question_literal_in_prefix():
    # Expanding ?s includes the literal '?' character, which must be emitted as
    # '??' so the generated sub-mask stays valid.
    specs = plan_chunks(3, mask='?s?s', slowest_speed=1, target_seconds=1,
                        max_chunks=100)
    masks = [s['mask'] for s in specs]
    assert any(m.startswith('??') for m in masks), masks
    assert all(parse_mask(m) is not None for m in masks)


def test_plan_mask_respects_max_chunks():
    specs = plan_chunks(3, mask='?a?a?a?a?a', slowest_speed=1, target_seconds=1,
                        max_chunks=95)
    # one ?a position = 95 expansions; two would be 9025 > max -> stop at one
    assert len(specs) == 95


def test_plan_mask_mode7_includes_wordlist_factor():
    # mask alone (?d?d=100) <= target, but x wordlist (10000) exceeds it -> splits
    whole = plan_chunks(7, mask='?d?d', wordlist_size=1,
                        slowest_speed=1, target_seconds=100)
    split = plan_chunks(7, mask='?d?d', wordlist_size=10_000,
                        slowest_speed=1, target_seconds=100)
    assert whole == [{}]
    assert len(split) >= 2


# --- plan_chunks: hybrid mode 6 (wordlist + mask) --------------------------

def test_plan_mode6_hybrid_uses_mask_as_amplifier():
    """Mode 6 multiplies each word by the mask keyspace when sizing chunks.

    With a ?d?d (=100) mask the per-word candidate count is 100x, so the same
    wordlist that runs whole without a mask splits into word-range chunks.
    """
    with_mask = plan_chunks(6, wordlist_size=1000, mask='?d?d',
                            slowest_speed=1000, target_seconds=1)
    no_mask = plan_chunks(6, wordlist_size=1000, mask=None,
                          slowest_speed=1000, target_seconds=1)
    assert len(with_mask) >= 2
    assert all('skip' in s and 'limit' in s for s in with_mask)  # word-range chunks
    assert no_mask == [{}]                                       # amplifier=1 -> whole


# --- plan_chunks: whole-task fallbacks (guard branches) --------------------

def test_plan_wordlist_whole_when_size_missing():
    # A wordlist-mode task with no/zero wordlist size can't be tiled.
    assert plan_chunks(0, wordlist_size=0, rule_count=5,
                       slowest_speed=1, target_seconds=1) == [{}]


def test_plan_mask_whole_when_mask_missing():
    # A mask-mode task with no mask string can't be expanded.
    assert plan_chunks(3, mask=None, slowest_speed=1, target_seconds=1) == [{}]


def test_plan_whole_for_unsupported_attackmode():
    # An attackmode that's neither a wordlist nor a mask mode runs whole.
    assert plan_chunks(99, wordlist_size=10**9, slowest_speed=1,
                       target_seconds=1) == [{}]


def test_plan_mask_whole_when_max_chunks_below_first_charset():
    # max_chunks (5) is smaller than the first charset (?d=10), so even one
    # position can't be expanded within the cap -> run whole.
    assert plan_chunks(3, mask='?d?d?d?d', slowest_speed=1, target_seconds=1,
                       max_chunks=5) == [{}]


# --- plan_chunks: mask expansion with literals -----------------------------

def test_plan_mask_expands_with_leading_literal():
    # A literal segment ahead of the expanded charset is carried into every
    # sub-mask (exercises the 'lit' branch while building prefixes).
    specs = plan_chunks(3, mask='a?d?d?d', slowest_speed=1, target_seconds=1,
                        max_chunks=100)
    assert len(specs) >= 2
    assert all(s['mask'].startswith('a') for s in specs)


def test_expand_mask_returns_none_for_all_literal_mask():
    # No charset positions -> nothing to split.
    assert _expand_mask('abcd', desired_chunks=4, max_chunks=100) is None


def test_expand_mask_returns_none_for_unparseable_mask():
    # A custom-charset mask (?1) doesn't parse -> can't be expanded.
    assert _expand_mask('?1?l', desired_chunks=4, max_chunks=100) is None
