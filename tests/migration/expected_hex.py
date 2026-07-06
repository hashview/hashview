"""Single source of truth for the legacy-hex seed cases.

Each entry maps the value AS SEEDED on main (a hex string, the legacy storage
format for usernames/plaintext) to the value EXPECTED after the dev app's
``decode_legacy_hex_if_needed`` backfill runs. The seed SQL (seed_main.sql) and
the verifier (test_migration_e2e.py) both consume this so they cannot drift.
"""

# The ``_decode_hex_column`` max_len/overflow guard IS reachable: a non-UTF-8
# value decodes to ``$HEX[<hex>]`` -- 6 chars LONGER than the stored hex -- so a
# 252-char hex of non-UTF-8 bytes (fits in VARCHAR(256)) would decode to a
# 258-char marker that exceeds the column, and the backfill leaves it hex-
# encoded rather than overflow. ``u_overflow`` exercises this end-to-end; the
# unit test ``test_backfill_leaves_oversized_hex_untouched`` covers it too.
_OVERFLOW_HEX = "ff" * 126   # 252 chars stored; $HEX[...] form is 258 > 256

# marker -> (seeded_hex_value, expected_after_backfill)
USERNAME_CASES = {
    "u_ascii":     ("41646d696e", "Admin"),          # ASCII hex -> text
    "u_utf8":      ("c3a9",       "é"),          # 'é' UTF-8 -> text
    "u_nonutf8":   ("ff01",       "$HEX[ff01]"),      # invalid UTF-8 -> $HEX[...]
    "u_plaintext": ("already-text", "already-text"),  # not valid hex -> untouched
    "u_overflow":  (_OVERFLOW_HEX, _OVERFLOW_HEX),    # decoded $HEX[...] > 256 -> left hex
}

PLAINTEXT_CASES = {
    "p_ascii":    ("70617373", "pass"),               # 'pass'
    "p_utf8":     ("f09f9880", "\U0001f600"),          # 😀 emoji (4-byte) -> text
    "p_nonutf8":  ("ff",       "$HEX[ff]"),            # invalid UTF-8 -> $HEX[...]
}
