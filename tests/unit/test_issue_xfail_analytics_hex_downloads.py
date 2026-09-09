"""Strict-xfail regression tests for issues #469 and #470.

Both routes carry a comment claiming they decode ``$HEX[...]``-wrapped values
the way the main /analytics dashboard query does (via ``decode_hex_plain``,
hashview/utils/utils.py), but the code beneath each comment is a no-op:

- fig9 shared-password/hash download (hashview/analytics/routes.py ~705):
  ``# Decode possible hex‑encoded usernames`` followed by
  ``decoded = entry`` in both the try and except branch.
- fig8 username==password download (hashview/analytics/routes.py ~774):
  ``# Decode password`` followed by ``password = entry[0]``, a bare
  assignment.

Each test asserts the CORRECT (decoded) behavior and is
``@pytest.mark.xfail(strict=True)``, so it XFAILs today and turns into a hard
XPASS failure the moment the no-op is replaced with a real
``decode_hex_plain`` call -- the signal to drop the marker.
"""

import pytest

from hashview.models import Customers, Hashes, HashfileHashes, Hashfiles, db
from tests.unit.helpers import login, make_admin


def _seed_customer_hashfile():
    cust = Customers(name="HexCo")
    db.session.add(cust)
    db.session.commit()
    hf = Hashfiles(name="dump", customer_id=cust.id, owner_id=1, runtime=0)
    db.session.add(hf)
    db.session.commit()
    return cust.id, hf.id


@pytest.mark.xfail(
    strict=True,
    reason=(
        "issue #469: fig9 download's 'Decode possible hex-encoded usernames' "
        "comment (hashview/analytics/routes.py ~705) is a no-op -- "
        "decoded = entry in both try/except branches -- so a $HEX[...]-wrapped "
        "username is exported still hex-wrapped instead of decoded."
    ),
)
def test_fig9_download_decodes_hex_username(app, client):
    admin = make_admin()
    login(client, admin)
    customer_id, hashfile_id = _seed_customer_hashfile()

    # One Hashes row referenced by two HashfileHashes rows so it qualifies for
    # fig9's "shared hash" grouping (group_by hash_id having count() > 1).
    h = Hashes(sub_ciphertext="0" * 8, ciphertext="aaa", hash_type=1000,
               cracked=True, plaintext="pw")
    db.session.add(h)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hashfile_id,
                                  username="$HEX[4a6f686e]"))  # "John"
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hashfile_id,
                                  username="alice"))
    db.session.commit()

    resp = client.get(
        f"/analytics/download/fig9?customer_id={customer_id}&hashfile_id={hashfile_id}")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)

    assert "$HEX[" not in body, (
        "expected the hex-wrapped username to be decoded, but it was exported raw")
    assert "John" in body


@pytest.mark.xfail(
    strict=True,
    reason=(
        "issue #470: fig8 download's 'Decode password' comment "
        "(hashview/analytics/routes.py ~774) is a no-op -- "
        "password = entry[0] is a bare assignment -- so a $HEX[...]-wrapped "
        "recovered plaintext never matches its (decoded) username and is "
        "silently excluded from the username==password export."
    ),
)
def test_fig8_download_decodes_hex_password_before_matching(app, client):
    admin = make_admin()
    login(client, admin)
    customer_id, hashfile_id = _seed_customer_hashfile()

    # username == plaintext once decoded ("alice" -> hex 616c696365)
    h = Hashes(sub_ciphertext="0" * 8, ciphertext="aaa", hash_type=1000,
               cracked=True, plaintext="$HEX[616c696365]")
    db.session.add(h)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hashfile_id,
                                  username="alice"))
    db.session.commit()

    resp = client.get(
        f"/analytics/download/fig8?customer_id={customer_id}&hashfile_id={hashfile_id}")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)

    assert "alice" in body, (
        "expected the hex-wrapped password to be decoded and matched against "
        "the username, but it was excluded from the export")
