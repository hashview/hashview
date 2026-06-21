"""Pure-Python task chunk planner for distributed hashcat cracking.

A "chunk" is a slice of a Task's attack that one agent runs. Chunks are sized so
that one chunk takes roughly ``target_seconds`` on the SLOWEST benchmarked agent,
which lets weak and strong agents each pull an appropriate share of the work
(faster agents simply drain more chunks from the queue).

No hashcat is invoked on the server. We never need to reproduce hashcat's internal
keyspace integer because we split along dimensions we *can* count in Python:

* Wordlist base-loop modes (0 straight, 1 combinator, 6 hybrid wordlist+mask):
  the base loop is the (left) wordlist and hashcat ``--skip``/``--limit`` are word
  offsets whose count equals the wordlist line count (already stored on
  ``Wordlists.size``). A chunk is a ``[skip, limit)`` word range.

* Mask base-loop modes (3 mask, 7 hybrid mask+wordlist): the base loop is the
  mask. We split by expanding the leading mask position(s) into literal
  characters, producing one sub-mask per combination (each its own chunk). No
  ``--skip``/``--limit`` is needed.

Tasks that use a dynamic wordlist are never chunked (decided by the caller via
:func:`is_chunkable`): their content is regenerated per run / non-stationary, so
offsets would not line up across agents.

This module is intentionally dependency-free (no DB, no Flask) so it is trivially
unit-testable; callers resolve wordlist sizes / rule counts / dynamic-wordlist ids
from the DB and pass them in as plain numbers.
"""

# Built-in hashcat mask charsets -> the literal characters they expand to.
MASK_CHARSETS = {
    'l': 'abcdefghijklmnopqrstuvwxyz',
    'u': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    'd': '0123456789',
    's': ' !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~',
    'h': '0123456789abcdef',
    'H': '0123456789ABCDEF',
}
# ?a is the union of ?l ?u ?d ?s (95 printable ASCII).
MASK_CHARSETS['a'] = (
    MASK_CHARSETS['l'] + MASK_CHARSETS['u'] + MASK_CHARSETS['d'] + MASK_CHARSETS['s']
)

# Charsets we are willing to expand a leading mask position over. ?b (raw bytes
# 0x00-0xff) and custom ?1-?4 charsets are deliberately excluded -> a mask using
# them is treated as unsplittable and runs whole.
_EXPANDABLE = frozenset(MASK_CHARSETS)

# Safety cap: never produce more than this many chunks for a single task.
DEFAULT_MAX_CHUNKS = 1000

WORDLIST_MODES = (0, 1, 6)
MASK_MODES = (3, 7)


def is_chunkable(attackmode, wl_id, wl_id_2, dynamic_wl_ids):
    """True if a task may be split into chunks.

    ``dynamic_wl_ids`` is the set of Wordlists.id whose type is 'dynamic'. A task
    that references one (as its wordlist or combinator second wordlist) is never
    chunked.
    """
    if attackmode not in WORDLIST_MODES + MASK_MODES:
        return False
    dynamic = dynamic_wl_ids or set()
    if wl_id in dynamic or wl_id_2 in dynamic:
        return False
    return True


def _escape_mask_literal(ch):
    """Escape a literal character for a hashcat mask (only '?' is special)."""
    return '??' if ch == '?' else ch


def parse_mask(mask):
    """Parse a hashcat mask into a list of tokens.

    Each token is ``('set', letter)`` for a built-in charset position or
    ``('lit', char)`` for a fixed literal. Returns ``None`` if the mask contains
    something we can't reason about (a custom ``?1``-``?4`` charset, ``?b``, or a
    dangling ``?``), so the caller falls back to running the task whole.
    """
    tokens = []
    i = 0
    n = len(mask)
    while i < n:
        c = mask[i]
        if c == '?':
            if i + 1 >= n:
                return None  # dangling '?'
            nxt = mask[i + 1]
            if nxt == '?':
                tokens.append(('lit', '?'))
            elif nxt in _EXPANDABLE:
                tokens.append(('set', nxt))
            else:
                return None  # ?b or custom ?1-?4 -> not safely expandable
            i += 2
        else:
            tokens.append(('lit', c))
            i += 1
    return tokens


def _serialize_mask(tokens):
    """Re-emit a token list as a hashcat mask string."""
    out = []
    for kind, val in tokens:
        if kind == 'set':
            out.append('?' + val)
        else:
            out.append(_escape_mask_literal(val))
    return ''.join(out)


def mask_keyspace(mask):
    """Total candidate count of a mask, or None if it can't be computed."""
    tokens = parse_mask(mask)
    if tokens is None:
        return None
    total = 1
    for kind, val in tokens:
        if kind == 'set':
            total *= len(MASK_CHARSETS[val])
    return total


def _expand_mask(mask, desired_chunks, max_chunks):
    """Split ``mask`` into sub-masks by expanding leading charset position(s).

    Returns a list of >= 2 sub-mask strings, or ``None`` to signal "don't split".
    """
    tokens = parse_mask(mask)
    if tokens is None:
        return None
    set_indices = [idx for idx, (k, _) in enumerate(tokens) if k == 'set']
    if not set_indices:
        return None  # all-literal mask: nothing to split

    # Grow the expanded prefix until the product of its charset sizes reaches
    # desired_chunks, without exceeding max_chunks.
    product = 1
    cut = None           # expand tokens[:cut]
    last_ok_cut = None   # largest prefix whose product stays <= max_chunks
    for idx in set_indices:
        size = len(MASK_CHARSETS[tokens[idx][1]])
        if product * size > max_chunks:
            break
        product *= size
        last_ok_cut = idx + 1
        if product >= desired_chunks:
            cut = idx + 1
            break
    if cut is None:
        cut = last_ok_cut
    if cut is None:
        return None  # even the first charset position exceeds max_chunks

    prefix_tokens = tokens[:cut]
    suffix = _serialize_mask(tokens[cut:])

    prefixes = ['']
    for kind, val in prefix_tokens:
        if kind == 'lit':
            esc = _escape_mask_literal(val)
            prefixes = [p + esc for p in prefixes]
        else:  # 'set'
            chars = MASK_CHARSETS[val]
            prefixes = [p + _escape_mask_literal(ch) for p in prefixes for ch in chars]

    submasks = [p + suffix for p in prefixes]
    if len(submasks) < 2:
        return None
    return submasks


def plan_chunks(attackmode, *, wordlist_size=None, wordlist2_size=None,
                rule_count=0, mask=None, slowest_speed=None,
                target_seconds=3600, max_chunks=DEFAULT_MAX_CHUNKS):
    """Plan chunks for one task.

    Returns a list of chunk-spec dicts:
      * ``{'skip': int, 'limit': int}`` -> a wordlist word-range chunk
      * ``{'mask': str}``               -> a mask sub-attack chunk
    A return of ``[{}]`` (single empty spec) means "do not chunk; run whole".

    ``slowest_speed`` is the smallest agent benchmark (hashes/sec) for the job's
    hash type; ``None``/0 means no benchmark yet -> run whole (benchmark-first
    dispatch backfills the data for next time).
    """
    whole = [{}]
    if not slowest_speed or slowest_speed <= 0 or target_seconds <= 0:
        return whole
    # Candidate guesses one chunk should cover to take ~target_seconds.
    target_candidates = target_seconds * slowest_speed

    if attackmode in WORDLIST_MODES:
        if not wordlist_size or wordlist_size <= 0:
            return whole
        if attackmode == 0:
            per_word = max(1, rule_count or 0)        # rules amplify each word
        elif attackmode == 1:
            per_word = max(1, wordlist2_size or 0)     # each left word x right list
        elif attackmode == 6:
            per_word = max(1, mask_keyspace(mask) or 1) if mask else 1
        else:
            per_word = 1
        words_per_chunk = max(1, int(target_candidates // per_word))
        num_chunks = (wordlist_size + words_per_chunk - 1) // words_per_chunk
        if num_chunks > max_chunks:
            num_chunks = max_chunks
            words_per_chunk = (wordlist_size + num_chunks - 1) // num_chunks
        if num_chunks <= 1:
            return whole
        specs = []
        skip = 0
        while skip < wordlist_size:
            limit = min(words_per_chunk, wordlist_size - skip)
            specs.append({'skip': skip, 'limit': limit})
            skip += limit
        return specs if len(specs) > 1 else whole

    if attackmode in MASK_MODES:
        if not mask:
            return whole
        mk = mask_keyspace(mask)
        if mk is None:
            return whole
        total = mk
        if attackmode == 7:
            total *= max(1, wordlist_size or 1)        # mask base loop x wordlist
        if total <= target_candidates:
            return whole
        desired = (total + target_candidates - 1) // target_candidates
        desired = min(desired, max_chunks)
        submasks = _expand_mask(mask, desired, max_chunks)
        if not submasks or len(submasks) < 2:
            return whole
        return [{'mask': m} for m in submasks]

    return whole
