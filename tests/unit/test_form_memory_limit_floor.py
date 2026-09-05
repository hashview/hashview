"""Tests for the MAX_FORM_MEMORY_SIZE floor (issue #314 review follow-up).

Werkzeug enforces ``max_form_memory_size`` in *two* places, and only one of
them exempts file uploads:

1. ``werkzeug/formparser.py`` accumulates ``field_size`` per part, but only for
   ``Field`` events -- ``field_size`` is left at ``None`` for ``File`` events,
   so uploaded files stream to disk uncounted. This is the limit the config key
   is *meant* to expose.

2. ``werkzeug/sansio/multipart.py`` (``MultipartDecoder.receive_data``) raises
   ``RequestEntityTooLarge`` when a single read chunk would push the decode
   buffer past the cap. This one does *not* distinguish files from fields, and
   the parser reads in ``buffer_size`` chunks (default ``64 * 1024``).

Consequence: setting the cap below 64KiB breaks *all* multipart file uploads,
including the "upload the hashes as a file instead" workaround the 413 handler
tells operators to use. These tests pin the floor that prevents that.
"""

import io

import pytest
from flask import Flask, request

from hashview.form_limits import (
    FLASK_DEFAULT_FORM_MEMORY_SIZE,
    MIN_FORM_MEMORY_SIZE,
    resolve_max_form_memory_size,
)


# ---------------------------------------------------------------------------
# The floor constant must match Werkzeug's real multipart read-chunk size.
# ---------------------------------------------------------------------------
def test_floor_matches_werkzeug_multipart_read_buffer():
    """MIN_FORM_MEMORY_SIZE must equal the parser's ``buffer_size`` default.

    If Werkzeug ever changes that default, this fails loudly rather than
    letting the floor silently become wrong.
    """
    import inspect

    from werkzeug.formparser import MultiPartParser

    default = inspect.signature(MultiPartParser).parameters["buffer_size"].default
    assert MIN_FORM_MEMORY_SIZE == default


def test_flask_default_constant_matches_werkzeug():
    from werkzeug.wrappers import Request

    assert FLASK_DEFAULT_FORM_MEMORY_SIZE == Request.max_form_memory_size


# ---------------------------------------------------------------------------
# resolve_max_form_memory_size()
# ---------------------------------------------------------------------------
def test_absent_key_resolves_to_flask_default():
    assert resolve_max_form_memory_size(None) == FLASK_DEFAULT_FORM_MEMORY_SIZE


@pytest.mark.parametrize("raw", ["16", "1000", "65535", 16, 0])
def test_values_below_the_floor_are_clamped_up(raw):
    """A deployer lowering this to "tighten security" must not silently lose
    every file upload."""
    assert resolve_max_form_memory_size(raw) == MIN_FORM_MEMORY_SIZE


@pytest.mark.parametrize("raw", ["65536", "500000", "2000000", 2_000_000])
def test_values_at_or_above_the_floor_are_preserved(raw):
    assert resolve_max_form_memory_size(raw) == int(raw)


def test_configparser_string_is_coerced_to_int():
    """ConfigParser hands back strings; Flask needs an int."""
    resolved = resolve_max_form_memory_size("750000")
    assert resolved == 750000
    assert isinstance(resolved, int)


@pytest.mark.parametrize("raw", ["", "   ", "not-a-number", "12.5"])
def test_unparseable_values_fall_back_to_the_default(raw):
    """A typo in config.conf must not take the whole app down at import time."""
    assert resolve_max_form_memory_size(raw) == FLASK_DEFAULT_FORM_MEMORY_SIZE


def test_negative_value_is_clamped_not_treated_as_unlimited():
    assert resolve_max_form_memory_size("-1") == MIN_FORM_MEMORY_SIZE


# ---------------------------------------------------------------------------
# The behaviour the floor exists to protect: file uploads still work.
# ---------------------------------------------------------------------------
def _upload_probe_client(cap):
    """Minimal Flask app that just parses a multipart upload, so this exercises
    Werkzeug's parser directly rather than any Hashview route."""
    app = Flask(__name__)
    app.config["MAX_FORM_MEMORY_SIZE"] = cap

    @app.post("/upload")
    def _upload():
        return {"size": len(request.files["file"].read())}

    return app.test_client()


@pytest.mark.parametrize("size", [10_000, 200_000, 5_000_000])
def test_file_upload_succeeds_at_the_floor(size):
    """At MIN_FORM_MEMORY_SIZE, a multipart file upload of any size parses --
    files are not counted against the per-field cap."""
    resp = _upload_probe_client(MIN_FORM_MEMORY_SIZE).post(
        "/upload",
        data={"file": (io.BytesIO(b"A" * size), "hashes.txt")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    assert resp.get_json()["size"] == size


@pytest.mark.parametrize(
    ("cap", "size"),
    [
        (MIN_FORM_MEMORY_SIZE - 1, 200_000),
        (1000, 10_000),
        (16, 5_000),
    ],
)
def test_file_upload_breaks_below_the_floor(cap, size):
    """The regression this floor prevents.

    The multipart chunk check compares ``len(buffer) + len(data)`` against the
    cap, and each read is at most ``buffer_size`` (64KiB) -- so below the floor
    a file upload fails once the body outgrows the cap, no matter that the
    bytes belong to a *file* part. At or above the floor no single chunk can
    ever exceed the cap, which is why clamping to 64KiB makes uploads safe at
    any file size.
    """
    resp = _upload_probe_client(cap).post(
        "/upload",
        data={"file": (io.BytesIO(b"A" * size), "hashes.txt")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 413


def test_pasted_field_is_still_capped_at_the_floor():
    """Clamping up must not defeat the point of the setting: a pasted textarea
    larger than the cap is still rejected."""
    app = Flask(__name__)
    app.config["MAX_FORM_MEMORY_SIZE"] = MIN_FORM_MEMORY_SIZE

    @app.post("/paste")
    def _paste():
        return {"len": len(request.form["hashes"])}

    client = app.test_client()

    ok = client.post("/paste", data={"hashes": "A" * (MIN_FORM_MEMORY_SIZE - 100)})
    assert ok.status_code == 200

    too_big = client.post("/paste", data={"hashes": "A" * (MIN_FORM_MEMORY_SIZE + 100)})
    assert too_big.status_code == 413
