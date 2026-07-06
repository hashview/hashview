"""Single source of truth for the legacy-hex seed cases.

Each entry maps the value AS SEEDED on main (a hex string, the legacy storage
format for usernames/plaintext) to the value EXPECTED after the dev app's
``decode_legacy_hex_if_needed`` backfill runs. The seed SQL (seed_main.sql) and
the verifier (test_migration_e2e.py) both consume this so they cannot drift.
"""

# marker -> (seeded_hex_value, expected_after_backfill)
USERNAME_CASES = {
    "u_ascii":     ("41646d696e", "Admin"),          # ASCII hex -> text
    "u_utf8":      ("c3a9",       "é"),          # 'é' UTF-8 -> text
    "u_nonutf8":   ("ff01",       "$HEX[ff01]"),      # invalid UTF-8 -> $HEX[...]
    "u_plaintext": ("already-text", "already-text"),  # not valid hex -> untouched
}

# For the overflow guard: a hex string whose decoded UTF-8 form is > 256 chars
# stays hex-encoded (column is VARCHAR(256)). 260 'A's = 520 hex chars.
_OVERFLOW_HEX = "41" * 260
PLAINTEXT_CASES = {
    "p_ascii":    ("70617373", "pass"),               # 'pass'
    "p_utf8":     ("f09f9880", "\U0001f600"),          # 😀 emoji (4-byte) -> text
    "p_nonutf8":  ("ff",       "$HEX[ff]"),            # invalid UTF-8 -> $HEX[...]
    "p_overflow": (_OVERFLOW_HEX, _OVERFLOW_HEX),      # decoded > 256 -> left hex
}
