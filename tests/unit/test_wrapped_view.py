"""Unit tests for the /wrapped year-in-review page and its math.

Seeds cracked Hashes across three users in the calendar year Wrapped reports on
(the current year until go-live) and asserts both that the page renders and that
the corrected statistics are accurate:
  - the year window includes Dec 31 (datetime bounds, not 'YYYY-12-31'),
  - rank-based "top N%" percentile (best = small N),
  - NetNTLMv2 count is v2-only (not v1+v2),
  - out-of-year recoveries are excluded.

Uses the in-memory SQLite app from tests/unit/conftest.py.
"""

from datetime import datetime

from hashview.models import Hashes, Users, db
from hashview.utils.clock import utcnow


def _login(client, user):
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["_fresh"] = True


def _user(first, last, email):
    u = Users(first_name=first, last_name=last, email_address=email,
              password="x" * 60, admin=True)
    db.session.add(u)
    db.session.commit()
    return u


_CT = [0]


def _hash(hash_type, plaintext, recovered_by, when):
    _CT[0] += 1
    h = Hashes(sub_ciphertext="%08x" % _CT[0], ciphertext="c%d" % _CT[0],
               hash_type=hash_type, cracked=True, plaintext=plaintext,
               recovered_at=when, recovered_by=recovered_by)
    db.session.add(h)
    db.session.commit()
    return h


LONG_TOKEN = "LONGEST_CATCH_OF_THE_WHOLE_YEAR"   # 31 chars, unique
OUT_TOKEN = "OUTOFRANGE_SHOULD_NOT_SHOW"


def _seed(uid1, uid2, uid3, year):
    mid = datetime(year, 6, 1, 12, 0)
    dec31 = datetime(year, 12, 31, 23, 59)       # must be counted (datetime bounds)
    out = datetime(year - 1, 6, 1, 12, 0)        # previous year -> excluded

    # current user (uid1): 4 NTLM (incl. the longest + the Dec-31 boundary),
    # 3 NetNTLMv1, 2 NetNTLMv2  -> 9 total in-year
    _hash(1000, LONG_TOKEN, uid1, mid)
    _hash(1000, "password1", uid1, mid)
    _hash(1000, "summer", uid1, mid)
    _hash(1000, "winter", uid1, dec31)
    for i in range(3):
        _hash(5500, "v1_%d" % i, uid1, mid)
    for i in range(2):
        _hash(5600, "v2_%d" % i, uid1, mid)
    _hash(1000, OUT_TOKEN, uid1, out)            # out of range

    # uid2: 2 NTLM, uid3: 1 NTLM
    _hash(1000, "u2a", uid2, mid)
    _hash(1000, "u2b", uid2, mid)
    _hash(1000, "u3a", uid3, mid)


def test_wrapped_renders_with_accurate_math(app, client):
    year = utcnow().year
    u1 = _user("Jane", "Mercer", "j.mercer@example.com")
    u2 = _user("Rick", "Vance", "r.vance@example.com")
    u3 = _user("Sam", "Okafor", "s.okafor@example.com")
    _login(client, u1)
    _seed(u1.id, u2.id, u3.id, year)

    resp = client.get("/wrapped")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)

    for bad in ("Internal Server Error", "Traceback", "UndefinedError"):
        assert bad not in html

    # intro / handle
    assert "WRAPPED" in html and str(year) in html
    assert "j.mercer" in html                     # first-initial.last handle

    # total: u1 has 9 (4 NTLM incl Dec-31 + 3 v1 + 2 v2); ranks #1 of 3 -> top 33%
    assert "<b>9</b> passwords" in html           # Dec-31 boundary counted
    assert "<b>top 33%</b>" in html               # rank-based percentile (best=small)
    assert ">#1<" in html                         # finale Global rank tile

    # per-type counts
    assert "<b>4</b> NTLM hashes" in html
    assert "<b>3</b> NetNTLMv1 hashes" in html
    assert "<b>2</b> NetNTLMv2 hashes" in html    # v2-only, NOT v1+v2 (=5)

    # longest pool + range exclusion
    assert LONG_TOKEN in html
    assert OUT_TOKEN not in html


def test_wrapped_hex_plaintext_decoded_for_length(app, client):
    """$HEX[..] plaintexts are hex-decoded before length ranking + display, so
    the wrapper length never inflates the ranking."""
    year = utcnow().year
    u = _user("Hex", "Decoder", "h.decoder@example.com")
    _login(client, u)
    token = "DECODED_LONGEST_VALUE"               # 21 real chars
    hexpw = "$HEX[" + token.encode().hex() + "]"   # ~47-char wrapper on the wire
    _hash(1000, hexpw, u.id, datetime(year, 5, 5, 10, 0))
    _hash(1000, "shorter", u.id, datetime(year, 5, 5, 11, 0))

    html = client.get("/wrapped").get_data(as_text=True)
    assert token in html                 # decoded plaintext is shown
    assert hexpw in html                 # the raw $HEX[..] wrapper is also shown
    assert "21 characters" in html       # length is the decoded length, not the wrapper


def test_wrapped_single_user_no_zero_division(app, client):
    """Regression: only the current user has data -> no ZeroDivisionError, and
    a lone cracker is 'top 100%' (rank 1 of 1)."""
    year = utcnow().year
    u1 = _user("Solo", "Cracker", "solo@example.com")
    _login(client, u1)
    _hash(1000, "onlyone", u1.id, datetime(year, 3, 3, 9, 0))

    resp = client.get("/wrapped")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "<b>1</b> passwords" in html
    assert "<b>top 100%</b>" in html
