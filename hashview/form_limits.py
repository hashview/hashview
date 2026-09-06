"""Resolution of the MAX_FORM_MEMORY_SIZE config key (issue #314).

Kept in its own dependency-free module rather than inline in ``config.py``
because ``hashview.config`` reads ``hashview/config.conf`` at import time and
raises ``KeyError`` when that file is absent, which makes it unimportable from
the test suite. Nothing here imports Flask, Werkzeug or any Hashview module, so
it is safe to import from anywhere.
"""

# Flask/Werkzeug's own built-in default for max_form_memory_size
# (werkzeug.wrappers.Request.max_form_memory_size). Used when the config key is
# absent or unparseable, so an untouched config.conf behaves exactly as before.
FLASK_DEFAULT_FORM_MEMORY_SIZE = 500_000

# Lower bound we refuse to go below. Werkzeug enforces max_form_memory_size in
# two places, and only one of them exempts file uploads:
#
#   * werkzeug/formparser.py accumulates a per-part ``field_size``, but only for
#     ``Field`` events -- it stays ``None`` for ``File`` events, so uploaded
#     files stream to disk uncounted. That is the limit this config key is
#     meant to expose.
#
#   * werkzeug/sansio/multipart.py (MultipartDecoder.receive_data) raises
#     RequestEntityTooLarge when a single read chunk would push the decode
#     buffer past the cap. That check does *not* distinguish files from fields,
#     and MultiPartParser reads in ``buffer_size`` chunks, default 64 KiB.
#
# The chunk check compares ``len(buffer) + len(data)`` against the cap, so
# below 64 KiB a file upload fails as soon as the body outgrows the cap -- a
# 1000-byte cap rejects a 10KB hash file, which is exactly the "upload the
# hashes as a file instead" workaround the 413 handler recommends. At or above
# 64 KiB no single read can ever exceed the cap, so uploads of any file size
# parse cleanly. Hence the clamp rather than honouring a smaller value.
MIN_FORM_MEMORY_SIZE = 64 * 1024  # 65536


def resolve_max_form_memory_size(raw, default=FLASK_DEFAULT_FORM_MEMORY_SIZE):
    """Coerce a raw config.conf value into a usable MAX_FORM_MEMORY_SIZE.

    ``raw`` is whatever ConfigParser returned (always a string, or ``None`` when
    the key is absent). Unset or unparseable values fall back to ``default`` --
    a typo in config.conf should not take the app down at import time. Values
    below :data:`MIN_FORM_MEMORY_SIZE` are clamped up to it; see the constant's
    comment for why.
    """
    if raw is None:
        return default

    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return default

    return max(value, MIN_FORM_MEMORY_SIZE)
