"""Unit test for ``/agents/download`` tarball layout.

Verifies the produced tarball expands to ``./hashview-agent/`` (no
``install/`` wrapper). This locks in the v0.8.2 layout change introduced
at commit ``34cdd15``.
"""

import tarfile

import pytest

from hashview.models import Users, db


@pytest.mark.security
def test_agents_download_tarball_starts_at_hashview_agent(app, client, tmp_path):
    """The ``.tgz`` returned by ``/agents/download`` should NOT have a
    leading ``install/`` directory. Exercises real tarfile implementation."""
    # Build an admin user and a logged-in session.
    admin = Users(
        first_name="A",
        last_name="D",
        email_address="admin@example.com",
        password="x" * 60,
        admin=True,
    )
    db.session.add(admin)
    db.session.commit()

    # Log the admin in
    with client.session_transaction() as sess:
        sess["_user_id"] = str(admin.id)
        sess["_fresh"] = True

    # Make the request
    resp = client.get("/agents/download", follow_redirects=False)
    assert resp.status_code == 200, f"expected 200, got {resp.status_code}"
    body = resp.data
    assert body[:2] == b"\x1f\x8b", "Response is not a gzip stream"

    # Write the bytes to disk and inspect the entries
    out = tmp_path / "agent.tgz"
    out.write_bytes(body)

    with tarfile.open(out, "r:gz") as tf:
        names = tf.getnames()
    assert names, "tarball is empty"
    assert all(not n.startswith("install/") for n in names), (
        f"Tarball still has install/ prefix: {names[:5]}"
    )
    assert any(n.startswith("hashview-agent/") or n == "hashview-agent" for n in names), (
        f"Tarball does not start at hashview-agent/: {names[:5]}"
    )
