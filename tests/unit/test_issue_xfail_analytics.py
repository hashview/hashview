"""xfail tests documenting open analytics GitHub issues.

Each test asserts the DESIRED behavior and is marked xfail (strict=False) so it
records as XFAIL while the issue is open and flips to XPASS once fixed. They are
written to be collectible and to run as XFAIL/XPASS (never ERROR).

Issues covered:
- #92: "Top 10 users who share the same password" — the Shared Passwords card
  groups shared plaintexts but is UNCAPPED (hashview/analytics/routes.py ~334-338,
  rendered in templates/analytics.html.j2 ~514-541). The issue asks for a Top-10
  ranking.
- #50: "Record and display instacrack rate in analytics" — instacrack is computed
  at upload time (hashview/api/routes.py, hashview/jobs/routes.py) but the rate is
  never persisted on Hashfiles (models.py ~197-205) nor surfaced on /analytics.
"""

import re

import pytest

from hashview.models import Customers, Hashes, HashfileHashes, Hashfiles, db
from tests.unit.helpers import login, make_admin


def _seed_shared_groups(n_groups):
    """Seed `n_groups` distinct shared-password groups under one customer/hashfile.

    Each group is a unique plaintext shared by exactly two usernames (so every
    group qualifies as "shared", i.e. used by >1 account). Returns the customer id.
    """
    cust = Customers(name="SharedCo")
    db.session.add(cust)
    db.session.commit()
    hf = Hashfiles(name="dump", customer_id=cust.id, owner_id=1, runtime=0)
    db.session.add(hf)
    db.session.commit()

    for g in range(n_groups):
        plaintext = f"SharedPw{g}!"
        for member in range(2):
            ct = f"ct{g}_{member}"
            h = Hashes(sub_ciphertext="0" * 8, ciphertext=ct, hash_type=1000,
                       cracked=True, plaintext=plaintext)
            db.session.add(h)
            db.session.commit()
            db.session.add(HashfileHashes(hash_id=h.id, hashfile_id=hf.id,
                                          username=f"user{g}_{member}"))
    db.session.commit()
    return cust.id


def _count_shared_groups(html):
    """Count rendered shared-password groups.

    The template renders one POST form per group:
        <form method="POST" action="/analytics/download/shared" ...>
    so counting those occurrences gives the number of rendered groups.
    """
    return len(re.findall(r'action="/analytics/download/shared"', html))


# --------------------------------------------------------------------------- #
# Issue #92: shared-password grouping should be a Top-10 ranking, not uncapped #
# --------------------------------------------------------------------------- #

@pytest.mark.xfail(reason="issue #92: shared-password grouping is uncapped; "
                          "should be ranked Top 10", strict=False)
def test_shared_passwords_ranking_capped_at_top_10(app, client):
    admin = make_admin()
    login(client, admin)
    customer_id = _seed_shared_groups(15)

    resp = client.get(f"/analytics?customer_id={customer_id}")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)

    rendered = _count_shared_groups(html)
    assert rendered > 0, "expected shared-password groups to be rendered"
    assert rendered <= 10, (
        f"shared-password groups should be capped at Top 10, got {rendered}")


def test_shared_password_grouping_present_and_ranked(app, client):
    """The shared-password grouping/section is present in the response.

    This portion (the section exists at all) is already true today, so it is NOT
    marked xfail — it documents the baseline the #92 ranking builds on.
    """
    admin = make_admin()
    login(client, admin)
    customer_id = _seed_shared_groups(12)

    resp = client.get(f"/analytics?customer_id={customer_id}")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)

    assert "Shared Passwords" in html
    assert _count_shared_groups(html) > 0


# --------------------------------------------------------------------------- #
# Issue #50: record + display instacrack rate in analytics                    #
# --------------------------------------------------------------------------- #

@pytest.mark.xfail(reason="issue #50: Hashfiles has no persisted instacrack-rate "
                          "column", strict=False)
def test_hashfile_model_has_instacrack_field(app):
    # A plausibly-named persisted column for the instacrack rate should exist on
    # the Hashfiles model. None of these exist today (models.py ~197-205).
    candidates = [
        "instacrack_rate",
        "instacrack",
        "insta_crack_rate",
        "instacracked",
        "instacrack_percent",
        "instacrack_count",
    ]
    assert any(hasattr(Hashfiles, name) for name in candidates), (
        "Hashfiles should persist an instacrack-rate field; "
        f"none of {candidates} found")


@pytest.mark.xfail(reason="issue #50: instacrack rate is not displayed on the "
                          "analytics page", strict=False)
def test_analytics_page_displays_instacrack_rate(app, client):
    admin = make_admin()
    login(client, admin)
    customer_id = _seed_shared_groups(2)

    resp = client.get(f"/analytics?customer_id={customer_id}")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)

    assert "instacrack" in html.lower(), (
        "analytics page should display the instacrack rate")
