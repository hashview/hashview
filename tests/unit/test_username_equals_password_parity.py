"""The username==password card and its fig8 export must answer the same question.

Issue #388. The card compared ``_local_part(username).lower()`` against the
decoded plaintext; the export compared ``username.split('\\\\')[1]`` against the
raw ``plaintext`` column, case-sensitively. Four independent ways to disagree,
every one of them dropping accounts from the file that the card had just
counted -- and the file is the artefact that goes into a client report, so the
card says "12 accounts use their username as a password" and the attachment
lists eight of them with nothing to explain the gap.

The bug is not really the comparison, it is that there were two of them. So the
tests below are mostly PARITY tests: same corpus, same scope, card and file must
produce the same accounts. A test that only asserted the export's behaviour
would pass just as happily against a second implementation that agreed today and
drifted next month.
"""
from datetime import datetime

import pytest

from hashview.analytics.routes import (
    _local_part,
    _recovered_corpus,
    _username_is_password,
)
from hashview.models import Customers, Hashes, HashfileHashes, Hashfiles, db
from hashview.utils.utils import get_md5_hash
from tests.unit.helpers import login, make_admin

# (username, stored plaintext, is a username==password account?)
#
# The first two are the issue's own repro. The rest are the divergences it did
# not name, each of which dropped an account from the file on its own.
SHAPES = [
    ("CORP\\eve", "eve", True),                 # exact match, single domain
    ("CORP\\Frank", "frank", True),             # case differs -- same credential
    ("A\\B\\user", "user", True),               # split('\\')[1] compared 'B'
    ("kerb*gina", "gina", True),                # '*' form, single segment
    ("A*B*hugo", "hugo", True),                 # split('*')[1] compared 'B'
    ("CORP\\ines", "$HEX[696e6573]", True),     # plaintext stored hex-encoded
    ("bare", "bare", True),                     # no domain at all
    ("CORP\\zed", "notzed", False),             # a plain non-match
    ("CORP\\kim", "", False),                   # blank password is not a match
]


def _account(hashfile, username, plaintext, index):
    hash_row = Hashes(sub_ciphertext=get_md5_hash(f"ct{index}"), ciphertext=f"ct{index}",
                      hash_type=1000, cracked=True, plaintext=plaintext,
                      recovered_at=datetime(2024, 1, 2))
    db.session.add(hash_row)
    db.session.commit()
    db.session.add(HashfileHashes(hash_id=hash_row.id, hashfile_id=hashfile.id,
                                  username=username))
    db.session.commit()
    return hash_row


def _scope(admin, accounts, name="Parity"):
    customer = Customers(name=name)
    db.session.add(customer)
    db.session.commit()
    hashfile = Hashfiles(name=f"hf-{name}", customer_id=customer.id, owner_id=admin.id)
    db.session.add(hashfile)
    db.session.commit()
    for index, (username, plaintext) in enumerate(accounts):
        _account(hashfile, username, plaintext, index)
    return customer, hashfile


def _card(customer_id, hashfile_id=None):
    """What the card counts, computed the way the card computes it."""
    return sorted(_local_part(username)
                  for plaintext, username in _recovered_corpus(customer_id, hashfile_id)
                  if _username_is_password(username, plaintext))


def _served(client, customer_id, hashfile_id=None):
    url = f"/analytics/download/fig8?customer_id={customer_id}"
    if hashfile_id is not None:
        url += f"&hashfile_id={hashfile_id}"
    body = client.get(url).get_data(as_text=True)
    return [line for line in body.splitlines() if line.strip()]


# --- the predicate ------------------------------------------------------------

@pytest.mark.parametrize("username, plaintext, expected", [
    ("CORP\\eve", "eve", True),
    ("CORP\\Frank", "frank", True),         # the card's case-insensitive rule
    ("CORP\\frank", "FRANK", True),         # and the other direction
    ("A\\B\\user", "user", True),           # last component, not the second
    ("A*B*hugo", "hugo", True),
    ("bare", "bare", True),
    ("CORP\\zed", "notzed", False),
    ("CORP\\eve", "", False),               # a blank password matches nothing
    ("CORP\\eve", None, False),
    ("", "eve", False),                     # an unnamed row identifies no account
    (None, "eve", False),
])
def test_the_predicate(username, plaintext, expected):
    assert _username_is_password(username, plaintext) is expected


# --- parity, which is the actual point ----------------------------------------

def test_the_card_and_the_file_list_the_same_accounts(app, client):
    admin = make_admin(email="parity@example.com")
    login(client, admin)
    customer, _hf = _scope(admin, [(u, p) for u, p, _ in SHAPES])

    assert _served(client, customer.id) == _card(customer.id) != []


@pytest.mark.parametrize("username, plaintext, is_match", SHAPES)
def test_each_shape_is_treated_the_same_on_both_sides(app, client, username, plaintext,
                                                      is_match):
    """One shape at a time, so a failure names the divergence that came back."""
    admin = make_admin(email=f"shape{abs(hash(username))}@example.com")
    login(client, admin)
    customer, _hf = _scope(admin, [(username, plaintext)], name=f"S{abs(hash(username))}")

    served = _served(client, customer.id)
    assert served == _card(customer.id)
    assert served == ([_local_part(username)] if is_match else [])


def test_the_file_has_one_line_per_account_not_per_name(app, client):
    """The card's badge counts ACCOUNTS.

    Two people can both be 'eve' in different domains. De-duplicating the file
    by name would drop one of them and put the count disagreement straight back
    -- the same class of bug, arrived at from the other direction.
    """
    admin = make_admin(email="dupe@example.com")
    login(client, admin)
    customer, _hf = _scope(admin, [("CORP\\eve", "eve"), ("OTHER\\eve", "EVE")])

    served = _served(client, customer.id)
    assert served == ["eve", "eve"]
    assert len(served) == len(_card(customer.id)) == 2


def test_one_account_in_two_hashfiles_is_listed_once(app, client):
    """The other direction: the Hashes -> HashfileHashes join is one-to-many, so
    a single account whose hash lives in two hashfiles must not be counted (or
    exported) twice."""
    admin = make_admin(email="twofiles@example.com")
    login(client, admin)
    customer = Customers(name="TwoFiles")
    db.session.add(customer)
    db.session.commit()
    first = Hashfiles(name="hf-a", customer_id=customer.id, owner_id=admin.id)
    second = Hashfiles(name="hf-b", customer_id=customer.id, owner_id=admin.id)
    db.session.add_all([first, second])
    db.session.commit()
    hash_row = Hashes(sub_ciphertext=get_md5_hash("shared"), ciphertext="shared",
                      hash_type=1000, cracked=True, plaintext="omar",
                      recovered_at=datetime(2024, 1, 2))
    db.session.add(hash_row)
    db.session.commit()
    for hashfile in (first, second):
        db.session.add(HashfileHashes(hash_id=hash_row.id, hashfile_id=hashfile.id,
                                      username="CORP\\omar"))
    db.session.commit()

    assert _served(client, customer.id) == ["omar"] == _card(customer.id)


def test_the_export_is_still_scoped(app, client):
    """Parity must not have been bought by widening the export's scope."""
    admin = make_admin(email="scoped@example.com")
    login(client, admin)
    customer = Customers(name="Scoped")
    db.session.add(customer)
    db.session.commit()
    first = Hashfiles(name="hf-one", customer_id=customer.id, owner_id=admin.id)
    second = Hashfiles(name="hf-two", customer_id=customer.id, owner_id=admin.id)
    db.session.add_all([first, second])
    db.session.commit()
    _account(first, "CORP\\pia", "pia", 90)
    _account(second, "CORP\\quinn", "quinn", 91)

    assert _served(client, customer.id, first.id) == ["pia"]
    assert _served(client, customer.id, second.id) == ["quinn"]
    assert _served(client, customer.id) == ["pia", "quinn"]


def test_both_sides_read_the_same_corpus_helper(app):
    """A behavioural parity suite cannot see a second implementation that agrees
    today, so this pins the structural property: one corpus builder, one
    predicate, both used by both readers."""
    import inspect

    from hashview.analytics import routes

    for source in (inspect.getsource(routes.analytics_download_fig8),
                   inspect.getsource(routes.get_analytics)):
        assert "_recovered_corpus(" in source
        assert "_username_is_password(" in source
