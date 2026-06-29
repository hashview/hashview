"""File-encoding behaviour of wordlist ingestion.

Wordlist ingestion (``ingest_static_wordlist_file`` — shared by the UI upload,
the API upload, and the drop-folder import) is deliberately *byte-oriented*: it
never decodes text. It counts lines by counting ``\\n`` (0x0A) bytes and stores
the content gzip-compressed verbatim. These tests pin that contract across the
encodings a real wordlist arrives in (UTF-8, UTF-8-with-BOM, Latin-1, UTF-16,
CRLF) and for hashcat's ``$HEX[...]`` candidate format.

Two surfaces are exercised:
  - ``ingest_static_wordlist_file`` (and the UI route) accept arbitrary bytes,
    including NUL-containing UTF-16, and round-trip them unchanged;
  - the drop-folder gate ``looks_like_text_or_gz`` rejects NUL bytes, so a
    UTF-16 list that uploads fine via the UI is refused by the drop folder
    unless it is gzipped. That asymmetry is intentional and asserted here.

Pattern mirrors test_wordlist_gzip_storage.py: run inside the ``app`` fixture's
context and clean any .gz the ingest drops into the real control/wordlists dir.
"""

import gzip
import io
import os
from pathlib import Path

import pytest

from hashview.models import Users, Wordlists, db
from hashview.utils.utils import (
    get_filehash,
    get_linecount,
    ingest_static_wordlist_file,
    is_gzip,
)
from hashview.utils.wordlist_import import looks_like_text_or_gz

REPO_ROOT = Path(__file__).resolve().parents[2]
WORDLISTS_DIR = REPO_ROOT / "hashview" / "control" / "wordlists"
TMP_DIR = REPO_ROOT / "hashview" / "control" / "tmp"

# UTF-8 BOM and a sampling of hashcat $HEX[] candidate lines. The $HEX[...] is
# stored as the literal ASCII text hashcat reads back — hashview does NOT decode
# the hex, so even hex that would decode to a newline/NUL stays one text line.
UTF8_BOM = b"\xef\xbb\xbf"
HEX_LINES = (
    b"password\n"
    b"$HEX[68656c6c6f]\n"        # "hello"
    b"$HEX[70c3a4737377c3b67264]\n"  # "pässwörd" bytes
    b"$HEX[000a09]\n"            # NUL/LF/TAB *as literal hex text*, not real bytes
    b"$HEX[]\n"                  # degenerate empty-hex line
    b"letmein\n"
)


@pytest.fixture(autouse=True)
def _clean_control_dirs():
    """Remove any files these tests create under the real control dirs."""
    def snap(d):
        return set(os.listdir(d)) if d.exists() else set()
    before_wl, before_tmp = snap(WORDLISTS_DIR), snap(TMP_DIR)
    yield
    for d, before in ((WORDLISTS_DIR, before_wl), (TMP_DIR, before_tmp)):
        if not d.exists():
            continue
        for name in set(os.listdir(d)) - before:
            try:
                os.remove(d / name)
            except OSError:
                pass


def _make_user():
    u = Users(first_name="E", last_name="N", email_address="enc@e.com",
              password="x" * 60, admin=True)
    db.session.add(u)
    db.session.commit()
    return u


def _login(client, user):
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True


def _ingest(content, tmp_path, name="enc"):
    """Write ``content`` bytes to a temp file and ingest it; return the row."""
    src = tmp_path / "upload.bin"
    src.write_bytes(content)
    return ingest_static_wordlist_file(str(src), _make_user().id, name), src


def _stored_bytes(wl):
    """The decompressed bytes hashview stored for this wordlist."""
    with gzip.open(wl.path, "rb") as f:
        return f.read()


# ---------------------------------------------------------------------------
# ingest: encodings round-trip verbatim, lines counted by '\n' byte
# ---------------------------------------------------------------------------

def test_ingest_utf8_multibyte_roundtrips(app, tmp_path):
    content = "café\nnaïve\n🔑emoji\nüber\n".encode()
    wl, src = _ingest(content, tmp_path, "utf8")
    assert _stored_bytes(wl) == content                 # verbatim
    assert wl.size == content.count(b"\n") + 1 == 5
    assert wl.size == get_linecount(str(src))
    assert wl.checksum == get_filehash(wl.path)


def test_ingest_utf8_bom_is_preserved_not_stripped(app, tmp_path):
    # The BOM is part of the file's bytes; ingest must not silently strip it
    # (doing so would change the first candidate hashcat tries).
    content = UTF8_BOM + b"password\n123456\n"
    wl, _ = _ingest(content, tmp_path, "bom")
    stored = _stored_bytes(wl)
    assert stored == content
    assert stored.startswith(UTF8_BOM)
    assert wl.size == 3                                  # 2 newlines + 1


def test_ingest_latin1_high_bytes_preserved(app, tmp_path):
    # 0x80-0xFF bytes are not valid UTF-8 here; ingest is byte-oriented so they
    # survive unchanged rather than raising a decode error.
    content = "café\nrésumé\n".encode("latin-1")
    assert b"\xe9" in content                            # é in latin-1
    wl, _ = _ingest(content, tmp_path, "latin1")
    assert _stored_bytes(wl) == content
    assert wl.size == 3


def test_ingest_crlf_counted_by_newline_byte(app, tmp_path):
    # Windows CRLF: line count follows the '\n' byte (the '\r' rides along in
    # the stored bytes and is preserved verbatim).
    content = b"alpha\r\nbravo\r\ncharlie\r\n"
    wl, src = _ingest(content, tmp_path, "crlf")
    assert _stored_bytes(wl) == content                  # \r kept
    assert wl.size == content.count(b"\n") + 1 == 4
    assert wl.size == get_linecount(str(src))


def test_ingest_no_trailing_newline_line_count(app, tmp_path):
    # get_linecount semantics are (count of '\n') + 1, so a file with no
    # trailing newline still counts its last line.
    content = b"one\ntwo\nthree"
    wl, _ = _ingest(content, tmp_path, "notrail")
    assert wl.size == 3


def test_ingest_utf16le_accepted_and_roundtrips(app, tmp_path):
    # UTF-16 is full of NUL bytes. The UI/API ingest has no binary gate, so it
    # accepts the list and stores it byte-for-byte. For ASCII text the number
    # of 0x0A bytes equals the number of newlines, so the count is sane.
    content = "alpha\nbravo\ncharlie\n".encode("utf-16-le")  # incl. no BOM
    assert b"\x00" in content
    wl, src = _ingest(content, tmp_path, "utf16")
    assert _stored_bytes(wl) == content
    assert wl.size == get_linecount(str(src))
    assert wl.size == 4                                  # 3 LF bytes + 1


# ---------------------------------------------------------------------------
# ingest: hashcat $HEX[...] candidate format
# ---------------------------------------------------------------------------

def test_ingest_hashcat_hex_format_roundtrips_verbatim(app, tmp_path):
    # hashview must not interpret $HEX[...]; it stores the literal text so
    # hashcat receives and decodes it. Each $HEX[...] is one ordinary line.
    wl, src = _ingest(HEX_LINES, tmp_path, "hex")
    stored = _stored_bytes(wl)
    assert stored == HEX_LINES                           # literal, not decoded
    assert b"$HEX[68656c6c6f]" in stored
    assert b"$HEX[]" in stored
    assert wl.size == HEX_LINES.count(b"\n") + 1 == 7
    assert wl.size == get_linecount(str(src))


def test_ingest_hex_line_with_encoded_newline_is_not_expanded(app, tmp_path):
    # $HEX[610a62] would *decode* to "a\nb" (an embedded newline), but the "0a"
    # here is the literal ASCII chars '0','a' — hashview never expands it. So
    # the only real newline byte is the line terminator: had the hex been
    # decoded, the stored bytes would contain a second 0x0A and size would be 3.
    content = b"$HEX[610a62]\n"
    wl, _ = _ingest(content, tmp_path, "hexnl")
    stored = _stored_bytes(wl)
    assert stored == content
    assert stored.count(b"\n") == 1                       # hex added no newline
    assert wl.size == content.count(b"\n") + 1 == 2       # get_linecount semantics


def test_ingest_hex_format_gzip_upload_roundtrips(app, tmp_path):
    # A gzipped $HEX[] list is decompressed, counted, re-compressed at -9; the
    # decoded content must still be the original literal text.
    gz = tmp_path / "hex.gz"
    with gzip.open(str(gz), "wb", compresslevel=1) as f:
        f.write(HEX_LINES)
    wl = ingest_static_wordlist_file(str(gz), _make_user().id, "HexGz")
    assert _stored_bytes(wl) == HEX_LINES
    assert wl.size == HEX_LINES.count(b"\n") + 1


# ---------------------------------------------------------------------------
# drop-folder gate: looks_like_text_or_gz (NUL-byte heuristic)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("content", [
    pytest.param(b"password\n123456\n", id="utf8"),
    pytest.param(UTF8_BOM + b"password\n", id="utf8-bom"),
    pytest.param("café\nrésumé\n".encode("latin-1"), id="latin1"),
    pytest.param(HEX_LINES, id="hashcat-hex"),
])
def test_looks_like_text_accepts_text_encodings(tmp_path, content):
    p = tmp_path / "wl"
    p.write_bytes(content)
    assert looks_like_text_or_gz(str(p)) is True


def test_looks_like_text_rejects_utf16_due_to_nul(tmp_path):
    # The drop-folder importer rejects UTF-16 (NUL bytes) as "binary", even
    # though the UI/API ingest would accept the very same bytes.
    p = tmp_path / "wl"
    p.write_bytes("alpha\nbravo\n".encode("utf-16-le"))
    assert looks_like_text_or_gz(str(p)) is False


def test_looks_like_text_accepts_gzipped_utf16(tmp_path):
    # Gzipping a UTF-16 list gets it past the gate: is_gzip wins before the
    # NUL-byte check, and the ingest then round-trips it.
    p = tmp_path / "wl.gz"
    with gzip.open(str(p), "wb") as f:
        f.write("alpha\nbravo\n".encode("utf-16-le"))
    assert looks_like_text_or_gz(str(p)) is True


# ---------------------------------------------------------------------------
# UI route end-to-end: a couple of encodings through POST /wordlists/add
# ---------------------------------------------------------------------------

def test_ui_upload_hashcat_hex_roundtrips(app, client):
    user = _make_user()
    _login(client, user)
    resp = client.post(
        "/wordlists/add",
        data={"name": "HexUI", "wordlist": (io.BytesIO(HEX_LINES), "hex.txt"),
              "submit": "upload"},
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    assert resp.status_code in (302, 200)
    wl = Wordlists.query.filter_by(name="HexUI").first()
    assert wl is not None and is_gzip(wl.path)
    with gzip.open(wl.path, "rb") as f:
        assert f.read() == HEX_LINES
    assert wl.size == HEX_LINES.count(b"\n") + 1


def test_ui_upload_utf8_bom_roundtrips(app, client):
    user = _make_user()
    _login(client, user)
    content = UTF8_BOM + b"password\nhunter2\n"
    resp = client.post(
        "/wordlists/add",
        data={"name": "BomUI", "wordlist": (io.BytesIO(content), "bom.txt"),
              "submit": "upload"},
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    assert resp.status_code in (302, 200)
    wl = Wordlists.query.filter_by(name="BomUI").first()
    assert wl is not None
    with gzip.open(wl.path, "rb") as f:
        assert f.read() == content                       # BOM preserved
