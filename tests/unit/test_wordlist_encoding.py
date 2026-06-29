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
import hashlib
import io
import os
import time
from pathlib import Path

import pytest

from hashview.models import Users, Wordlists, db
from hashview.utils import wordlist_import as wli
from hashview.utils.audit import configure_audit_logging
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

# Cookie domain must match the unit conftest's SERVER_NAME or Werkzeug won't
# send the cookie (matches test_wordlist_gzip_storage.py).
COOKIE_DOMAIN = "localhost.test"

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

# Shared encoding samples for the parametrized round-trip tests.
ENCODINGS = [
    pytest.param("café\nnaïve\n🔑emoji\n".encode(), id="utf8-multibyte"),
    pytest.param("alpha\nbravo\ncharlie\n".encode("utf-16-le"), id="utf16le"),
    pytest.param(HEX_LINES, id="hashcat-hex"),
    pytest.param("café\nrésumé\n".encode("latin-1"), id="latin1"),
    pytest.param(UTF8_BOM + b"password\nhunter2\n", id="utf8-bom"),
]


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


def _make_user(api_key=None):
    u = Users(first_name="E", last_name="N", email_address="enc@e.com",
              password="x" * 60, admin=True, api_key=api_key)
    db.session.add(u)
    db.session.commit()
    return u


def _login(client, user):
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True


def _auth(client, api_key):
    """Authenticate the API client by uuid cookie (matches the API upload route)."""
    client.set_cookie("uuid", api_key, domain=COOKIE_DOMAIN)


@pytest.fixture()
def drop(app, tmp_path, monkeypatch):
    """Isolated drop folder for run_import; also redirect audit logging into tmp
    so the import's audit events never touch the repo's real logs dir."""
    app.config["HASHVIEW_LOGS_DIR"] = str(tmp_path / "audit_logs")
    configure_audit_logging(app)
    d = tmp_path / "wordlists_import"
    d.mkdir()
    monkeypatch.setattr(wli, "import_dir", lambda app: str(d))
    return d


def _seed_drop(drop_dir, filename, content):
    """Drop a file into the import folder and age its mtime past the quiescence
    guard so run_import will process it."""
    src = drop_dir / filename
    src.write_bytes(content)
    past = time.time() - (wli.QUIESCE_SECONDS + 60)
    os.utime(src, (past, past))
    return src


def _write(tmp_path, content, name="upload.bin"):
    """Write bytes to a temp file and return its path."""
    src = tmp_path / name
    src.write_bytes(content)
    return src


def _ingest(content, tmp_path, name="enc"):
    """Write ``content`` bytes to a temp file and ingest it; return the row."""
    src = _write(tmp_path, content)
    return ingest_static_wordlist_file(str(src), _make_user().id, name), src


def _store_static(content, tmp_path, owner_id, name="DL"):
    """Ingest ``content`` and persist the static Wordlists row (for download tests)."""
    src = _write(tmp_path, content, name="src.bin")
    wl = ingest_static_wordlist_file(str(src), owner_id, name)
    db.session.add(wl)
    db.session.commit()
    return wl


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


# ---------------------------------------------------------------------------
# API upload route end-to-end: POST /v1/wordlists/add/<name> (raw bytes body)
# ---------------------------------------------------------------------------

def test_api_upload_utf16_accepted_and_roundtrips(app, client):
    # The API body is read as raw bytes, so a NUL-containing UTF-16 list is
    # accepted (no binary gate on this path) and stored verbatim.
    _make_user(api_key="enc-utf16")
    _auth(client, "enc-utf16")
    content = "alpha\nbravo\ncharlie\n".encode("utf-16-le")
    resp = client.post("/v1/wordlists/add/ApiUtf16", data=content,
                       content_type="application/octet-stream")
    body = resp.get_json()
    assert body["status"] == 200
    wl = Wordlists.query.get(body["wordlist_id"])
    assert is_gzip(wl.path)
    with gzip.open(wl.path, "rb") as f:
        assert f.read() == content
    assert wl.size == content.count(b"\n") + 1 == 4


def test_api_upload_hashcat_hex_roundtrips(app, client):
    _make_user(api_key="enc-hex")
    _auth(client, "enc-hex")
    resp = client.post("/v1/wordlists/add/ApiHex", data=HEX_LINES,
                       content_type="text/plain")
    body = resp.get_json()
    assert body["status"] == 200
    wl = Wordlists.query.get(body["wordlist_id"])
    with gzip.open(wl.path, "rb") as f:
        assert f.read() == HEX_LINES                      # literal, not decoded
    assert wl.size == HEX_LINES.count(b"\n") + 1


def test_api_upload_utf8_bom_preserved(app, client):
    _make_user(api_key="enc-bom")
    _auth(client, "enc-bom")
    content = UTF8_BOM + b"p\xc3\xa4ssw\xc3\xb6rd\n"      # "pässwörd\n" utf-8 + BOM
    resp = client.post("/v1/wordlists/add/ApiBom", data=content,
                       content_type="application/octet-stream")
    body = resp.get_json()
    assert body["status"] == 200
    wl = Wordlists.query.get(body["wordlist_id"])
    with gzip.open(wl.path, "rb") as f:
        assert f.read() == content                        # BOM not stripped


# ---------------------------------------------------------------------------
# ingest edge cases (degenerate inputs + binary the UI/API accept)
# ---------------------------------------------------------------------------

def test_ingest_empty_file(app, tmp_path):
    # An empty wordlist stores empty bytes; get_linecount's (count + 1) reports 1.
    wl, _ = _ingest(b"", tmp_path, "empty")
    assert _stored_bytes(wl) == b""
    assert wl.size == 1


def test_ingest_only_newlines(app, tmp_path):
    # Blank lines are real lines under the '\n'-count semantics.
    content = b"\n\n\n"
    wl, _ = _ingest(content, tmp_path, "blanks")
    assert _stored_bytes(wl) == content
    assert wl.size == 4                                    # 3 newlines + 1


def test_ingest_bom_only_file(app, tmp_path):
    # A file that is just a BOM (no newline) is one line and round-trips.
    wl, _ = _ingest(UTF8_BOM, tmp_path, "bomonly")
    assert _stored_bytes(wl) == UTF8_BOM
    assert wl.size == 1


def test_ingest_binary_with_nul_accepted_by_ingest(app, tmp_path):
    # The UI/API ingest has no binary gate: NUL-containing bytes that the
    # drop-folder importer would reject are accepted here and round-trip.
    content = b"word1\n\x00\x01\x02binary\x00\nword3\n"
    assert not looks_like_text_or_gz(str(_write(tmp_path, content)))  # drop-folder would refuse
    wl, _ = _ingest(content, tmp_path, "binary")
    assert _stored_bytes(wl) == content
    assert wl.size == content.count(b"\n") + 1


def test_ingest_mixed_lf_and_crlf(app, tmp_path):
    # Mixed line endings: only '\n' bytes are counted; bytes are kept verbatim.
    content = b"unix\nwindows\r\nunix2\n"
    wl, _ = _ingest(content, tmp_path, "mixed")
    assert _stored_bytes(wl) == content
    assert wl.size == content.count(b"\n") + 1 == 4


# ---------------------------------------------------------------------------
# drop-folder import end-to-end: run_import per encoding (the NUL asymmetry)
# ---------------------------------------------------------------------------

def test_import_utf8_bom_succeeds(app, drop):
    user = _make_user()
    content = UTF8_BOM + b"password\nhunter2\n"
    _seed_drop(drop, "bom.txt", content)
    summary = wli.run_import(app, ["bom.txt"], user.id)
    assert summary["imported"] == ["bom.txt"]
    wl = Wordlists.query.filter_by(name="bom").first()
    assert wl is not None and is_gzip(wl.path)
    with gzip.open(wl.path, "rb") as f:
        assert f.read() == content


def test_import_utf16_rejected_to_failed(app, drop):
    # UTF-16 (NUL bytes) is refused by the drop-folder gate and parked as .failed
    # -- the same bytes upload fine via the UI/API (see the ingest/API tests).
    user = _make_user()
    _seed_drop(drop, "utf16.txt", "alpha\nbravo\n".encode("utf-16-le"))
    summary = wli.run_import(app, ["utf16.txt"], user.id)
    assert summary["failed"] == ["utf16.txt"]
    assert Wordlists.query.filter_by(name="utf16").first() is None
    assert (drop / "utf16.txt.failed").exists()


def test_import_gzipped_utf16_succeeds(app, drop):
    # Gzipping the UTF-16 list gets it past the gate (is_gzip wins) and the
    # ingest round-trips the original bytes.
    user = _make_user()
    raw = "alpha\nbravo\ncharlie\n".encode("utf-16-le")
    buf = drop / "utf16.gz"
    with gzip.open(str(buf), "wb") as f:
        f.write(raw)
    past = time.time() - (wli.QUIESCE_SECONDS + 60)
    os.utime(buf, (past, past))
    summary = wli.run_import(app, ["utf16.gz"], user.id)
    assert summary["imported"] == ["utf16.gz"]
    wl = Wordlists.query.filter_by(name="utf16").first()
    assert wl is not None and is_gzip(wl.path)
    with gzip.open(wl.path, "rb") as f:
        assert f.read() == raw


# ---------------------------------------------------------------------------
# download round-trip per encoding: bytes reach the agent / browser intact
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("content", ENCODINGS)
def test_agent_download_serves_encoding_verbatim(app, client, tmp_path, content):
    # GET /v1/wordlists/<id> (agent sync) serves the stored .gz verbatim; the
    # agent verifies sha256(body) against the catalog checksum, so the bytes --
    # whatever the encoding -- must survive the round-trip exactly.
    user = _make_user(api_key="dl-agent")
    _auth(client, "dl-agent")
    wl = _store_static(content, tmp_path, user.id)
    resp = client.get(f"/v1/wordlists/{wl.id}")
    assert resp.status_code == 200
    body = resp.data
    assert body[:2] == b"\x1f\x8b"                        # gzip on the wire
    assert hashlib.sha256(body).hexdigest() == wl.checksum   # agent integrity check
    assert gzip.decompress(body) == content               # original bytes recovered


@pytest.mark.parametrize("content", ENCODINGS)
def test_ui_download_attachment_roundtrips(app, client, tmp_path, content):
    # GET /wordlists/download/<id> serves the static list as a .gz attachment;
    # decompressing the response yields the original bytes for every encoding.
    user = _make_user()
    _login(client, user)
    wl = _store_static(content, tmp_path, user.id)
    resp = client.get(f"/wordlists/download/{wl.id}")
    assert resp.status_code == 200
    assert resp.headers["Content-Disposition"].startswith("attachment")
    assert gzip.decompress(resp.data) == content


# ---------------------------------------------------------------------------
# AJAX upload path (X-Requested-With: fetch -> JSON) per encoding
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("content", ENCODINGS)
def test_ui_ajax_upload_encoding_json_ok(app, client, content):
    user = _make_user()
    _login(client, user)
    resp = client.post(
        "/wordlists/add",
        data={"name": "AjaxEnc", "wordlist": (io.BytesIO(content), "wl.txt"),
              "submit": "upload"},
        content_type="multipart/form-data",
        headers={"X-Requested-With": "fetch"},
    )
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"
    wl = Wordlists.query.filter_by(name="AjaxEnc").first()
    assert wl is not None and is_gzip(wl.path)
    with gzip.open(wl.path, "rb") as f:
        assert f.read() == content


# ---------------------------------------------------------------------------
# API route: remaining text encodings + gzip body of multibyte UTF-8
# ---------------------------------------------------------------------------

def test_api_upload_utf8_multibyte_roundtrips(app, client):
    _make_user(api_key="enc-mb")
    _auth(client, "enc-mb")
    content = "café\nnaïve\n🔑emoji\nüber\n".encode()
    resp = client.post("/v1/wordlists/add/ApiMB", data=content, content_type="text/plain")
    body = resp.get_json()
    assert body["status"] == 200
    wl = Wordlists.query.get(body["wordlist_id"])
    assert wl.size == content.count(b"\n") + 1
    with gzip.open(wl.path, "rb") as f:
        assert f.read() == content


def test_api_upload_latin1_roundtrips(app, client):
    _make_user(api_key="enc-l1")
    _auth(client, "enc-l1")
    content = "café\nrésumé\n".encode("latin-1")
    resp = client.post("/v1/wordlists/add/ApiL1", data=content,
                       content_type="application/octet-stream")
    body = resp.get_json()
    assert body["status"] == 200
    wl = Wordlists.query.get(body["wordlist_id"])
    with gzip.open(wl.path, "rb") as f:
        assert f.read() == content


def test_api_upload_gzip_of_multibyte_roundtrips(app, client):
    # A gzipped multibyte-UTF-8 body is decompressed, counted, re-compressed at
    # -9; the stored content must still decode to the original bytes.
    _make_user(api_key="enc-gzmb")
    _auth(client, "enc-gzmb")
    content = "café\nnaïve\n🔑emoji\n".encode()
    resp = client.post("/v1/wordlists/add/ApiGzMB", data=gzip.compress(content),
                       content_type="application/octet-stream")
    body = resp.get_json()
    assert body["status"] == 200
    wl = Wordlists.query.get(body["wordlist_id"])
    with gzip.open(wl.path, "rb") as f:
        assert f.read() == content
