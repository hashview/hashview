"""Tests for combine_hashfiles() helper.

Tests all 13 required cases for combining multiple hashfiles into one.
"""

import re

from sqlalchemy.exc import SQLAlchemyError

from hashview.models import Hashes, HashfileHashes, Hashfiles, db
from hashview.utils import utils as utils_mod
from hashview.utils.utils import combine_hashfiles
from tests.unit.helpers import make_admin, make_customer


def _make_hashfile(customer_id, owner_id, name="test_hf", hex_salt=False):
    """Create a Hashfiles row."""
    hf = Hashfiles(name=name, customer_id=customer_id, owner_id=owner_id,
                   hex_salt=hex_salt)
    db.session.add(hf)
    db.session.commit()
    return hf


def _make_hash(ciphertext, hash_type=1000, cracked=False):
    """Create a Hashes row (e.g., NTLM)."""
    h = Hashes(sub_ciphertext=ciphertext[:32], ciphertext=ciphertext,
               hash_type=hash_type, cracked=cracked)
    db.session.add(h)
    db.session.commit()
    return h


def _link_hash(hashfile_id, hash_id, username=None):
    """Create a HashfileHashes link."""
    hfh = HashfileHashes(hashfile_id=hashfile_id, hash_id=hash_id,
                         username=username)
    db.session.add(hfh)
    db.session.commit()
    return hfh


# ============================================================================
# Test Cases
# ============================================================================

def test_combine_two_disjoint_hashfiles(app):
    """Case 1: Two files with disjoint hashes → union in combined file."""
    with app.app_context():
        cust = make_customer()
        admin = make_admin()

        # Create two hashfiles with different hashes
        hf1 = _make_hashfile(cust.id, admin.id, name="hf1")
        hf2 = _make_hashfile(cust.id, admin.id, name="hf2")

        h1 = _make_hash("a" * 32)
        h2 = _make_hash("b" * 32)

        _link_hash(hf1.id, h1.id)
        _link_hash(hf2.id, h2.id)

        # Combine
        combined, err = combine_hashfiles([hf1.id, hf2.id],
                                         customer_id=cust.id, owner_id=admin.id)

        assert err is None
        assert combined is not None
        assert combined.id is not None

        # Combined should have both hashes
        links = HashfileHashes.query.filter_by(hashfile_id=combined.id).all()
        assert len(links) == 2
        hash_ids = {link.hash_id for link in links}
        assert hash_ids == {h1.id, h2.id}

        # Sources are untouched
        assert HashfileHashes.query.filter_by(hashfile_id=hf1.id).count() == 1
        assert HashfileHashes.query.filter_by(hashfile_id=hf2.id).count() == 1


def test_combine_shared_hash_dedup(app):
    """Case 2: Two files sharing a hash → appears once in combined."""
    with app.app_context():
        cust = make_customer()
        admin = make_admin()

        hf1 = _make_hashfile(cust.id, admin.id, name="hf1")
        hf2 = _make_hashfile(cust.id, admin.id, name="hf2")

        # Both files reference the same hash
        h_shared = _make_hash("c" * 32)
        _link_hash(hf1.id, h_shared.id)
        _link_hash(hf2.id, h_shared.id)

        combined, err = combine_hashfiles([hf1.id, hf2.id],
                                         customer_id=cust.id, owner_id=admin.id)

        assert err is None
        assert combined is not None

        # Combined should have the hash exactly once
        links = HashfileHashes.query.filter_by(hashfile_id=combined.id).all()
        assert len(links) == 1
        assert links[0].hash_id == h_shared.id


def test_combine_same_hash_different_usernames(app):
    """Case 3: Same hash_id with different usernames → both rows kept."""
    with app.app_context():
        cust = make_customer()
        admin = make_admin()

        hf1 = _make_hashfile(cust.id, admin.id, name="hf1")
        hf2 = _make_hashfile(cust.id, admin.id, name="hf2")

        h = _make_hash("d" * 32)
        # Same hash, different usernames
        _link_hash(hf1.id, h.id, username="user1")
        _link_hash(hf2.id, h.id, username="user2")

        combined, err = combine_hashfiles([hf1.id, hf2.id],
                                         customer_id=cust.id, owner_id=admin.id)

        assert err is None
        assert combined is not None

        links = HashfileHashes.query.filter_by(hashfile_id=combined.id).all()
        assert len(links) == 2
        usernames = {link.username for link in links}
        assert usernames == {"user1", "user2"}


def test_combine_null_usernames_deduped(app):
    """Case 4: Rows with username=None are deduped."""
    with app.app_context():
        cust = make_customer()
        admin = make_admin()

        hf1 = _make_hashfile(cust.id, admin.id, name="hf1")
        hf2 = _make_hashfile(cust.id, admin.id, name="hf2")

        h = _make_hash("e" * 32)
        # Same hash, both with username=None
        _link_hash(hf1.id, h.id, username=None)
        _link_hash(hf2.id, h.id, username=None)

        combined, err = combine_hashfiles([hf1.id, hf2.id],
                                         customer_id=cust.id, owner_id=admin.id)

        assert err is None

        links = HashfileHashes.query.filter_by(hashfile_id=combined.id).all()
        # Should appear exactly once despite two sources having it
        assert len(links) == 1
        assert links[0].username is None


def test_combine_different_hash_types_rejected(app):
    """Case 5: Different hash types → error, no new row."""
    with app.app_context():
        cust = make_customer()
        admin = make_admin()

        hf1 = _make_hashfile(cust.id, admin.id, name="hf1")
        hf2 = _make_hashfile(cust.id, admin.id, name="hf2")

        # NTLM (1000)
        h1 = _make_hash("f" * 32, hash_type=1000)
        # MD5 (0)
        h2 = _make_hash("g" * 32, hash_type=0)

        _link_hash(hf1.id, h1.id)
        _link_hash(hf2.id, h2.id)

        before_count = Hashfiles.query.count()

        combined, err = combine_hashfiles([hf1.id, hf2.id],
                                         customer_id=cust.id, owner_id=admin.id)

        assert combined is None
        assert err is not None
        assert "hash type" in err.lower()
        assert Hashfiles.query.count() == before_count  # No new row created


def test_combine_different_hex_salt_rejected(app):
    """Case 6: Differing hex_salt → error, no new row."""
    with app.app_context():
        cust = make_customer()
        admin = make_admin()

        hf1 = _make_hashfile(cust.id, admin.id, name="hf1", hex_salt=True)
        hf2 = _make_hashfile(cust.id, admin.id, name="hf2", hex_salt=False)

        h1 = _make_hash("h" * 32, hash_type=1000)
        h2 = _make_hash("i" * 32, hash_type=1000)

        _link_hash(hf1.id, h1.id)
        _link_hash(hf2.id, h2.id)

        before_count = Hashfiles.query.count()

        combined, err = combine_hashfiles([hf1.id, hf2.id],
                                         customer_id=cust.id, owner_id=admin.id)

        assert combined is None
        assert err is not None
        assert "hex-salt" in err.lower()
        assert Hashfiles.query.count() == before_count


def test_combine_all_hex_salt_true(app):
    """Case 7: All sources hex_salt=True → combined has hex_salt=True."""
    with app.app_context():
        cust = make_customer()
        admin = make_admin()

        hf1 = _make_hashfile(cust.id, admin.id, name="hf1", hex_salt=True)
        hf2 = _make_hashfile(cust.id, admin.id, name="hf2", hex_salt=True)

        h1 = _make_hash("j" * 32, hash_type=1000)
        h2 = _make_hash("k" * 32, hash_type=1000)

        _link_hash(hf1.id, h1.id)
        _link_hash(hf2.id, h2.id)

        combined, err = combine_hashfiles([hf1.id, hf2.id],
                                         customer_id=cust.id, owner_id=admin.id)

        assert err is None
        assert combined is not None
        assert combined.hex_salt is True


def test_combine_another_customer_rejected(app):
    """Case 8: Hashfile belongs to another customer → error, no new row."""
    with app.app_context():
        cust1 = make_customer(name="Customer 1")
        cust2 = make_customer(name="Customer 2")
        admin = make_admin()

        hf1 = _make_hashfile(cust1.id, admin.id, name="hf1")
        hf2 = _make_hashfile(cust2.id, admin.id, name="hf2")

        h1 = _make_hash("l" * 32, hash_type=1000)
        h2 = _make_hash("m" * 32, hash_type=1000)

        _link_hash(hf1.id, h1.id)
        _link_hash(hf2.id, h2.id)

        before_count = Hashfiles.query.count()

        # Try to combine with cust1's credentials
        combined, err = combine_hashfiles([hf1.id, hf2.id],
                                         customer_id=cust1.id, owner_id=admin.id)

        assert combined is None
        assert err == "Invalid hashfile selection."
        assert Hashfiles.query.count() == before_count


def test_combine_nonexistent_hashfile_id(app):
    """Case 9: Nonexistent hashfile id → same error, no new row."""
    with app.app_context():
        cust = make_customer()
        admin = make_admin()

        hf1 = _make_hashfile(cust.id, admin.id, name="hf1")
        h1 = _make_hash("n" * 32, hash_type=1000)
        _link_hash(hf1.id, h1.id)

        before_count = Hashfiles.query.count()

        # Use a non-existent id
        combined, err = combine_hashfiles([hf1.id, 99999],
                                         customer_id=cust.id, owner_id=admin.id)

        assert combined is None
        assert err == "Invalid hashfile selection."
        assert Hashfiles.query.count() == before_count


def test_combine_fewer_than_two_ids(app):
    """Case 10: Fewer than two ids → error, no new row."""
    with app.app_context():
        cust = make_customer()
        admin = make_admin()

        hf1 = _make_hashfile(cust.id, admin.id, name="hf1")
        h1 = _make_hash("o" * 32, hash_type=1000)
        _link_hash(hf1.id, h1.id)

        before_count = Hashfiles.query.count()

        # Only one id
        combined, err = combine_hashfiles([hf1.id],
                                         customer_id=cust.id, owner_id=admin.id)

        assert combined is None
        assert err is not None
        assert "at least two" in err.lower()
        assert Hashfiles.query.count() == before_count

        # Zero ids
        combined, err = combine_hashfiles([],
                                         customer_id=cust.id, owner_id=admin.id)

        assert combined is None
        assert err is not None
        assert "at least two" in err.lower()


def test_combine_empty_source_hashfile(app):
    """Case 11: Source with zero hashes → error, no new row."""
    with app.app_context():
        cust = make_customer()
        admin = make_admin()

        hf1 = _make_hashfile(cust.id, admin.id, name="hf1")
        hf2 = _make_hashfile(cust.id, admin.id, name="hf2_empty")

        h1 = _make_hash("p" * 32, hash_type=1000)
        _link_hash(hf1.id, h1.id)
        # hf2 has no links

        before_count = Hashfiles.query.count()

        combined, err = combine_hashfiles([hf1.id, hf2.id],
                                         customer_id=cust.id, owner_id=admin.id)

        assert combined is None
        assert err is not None
        assert "has no hashes" in err.lower()
        assert "hf2_empty" in err
        assert Hashfiles.query.count() == before_count


def test_combine_generated_name_format(app):
    """Case 12: Generated name matches ^combined-\\d{8}-\\d{6}$."""
    with app.app_context():
        cust = make_customer()
        admin = make_admin()

        hf1 = _make_hashfile(cust.id, admin.id, name="hf1")
        hf2 = _make_hashfile(cust.id, admin.id, name="hf2")

        h1 = _make_hash("q" * 32, hash_type=1000)
        h2 = _make_hash("r" * 32, hash_type=1000)

        _link_hash(hf1.id, h1.id)
        _link_hash(hf2.id, h2.id)

        combined, err = combine_hashfiles([hf1.id, hf2.id],
                                         customer_id=cust.id, owner_id=admin.id)

        assert err is None
        assert combined is not None
        pattern = r"^combined-\d{8}-\d{6}$"
        assert re.match(pattern, combined.name)


def test_combine_first_seen_order_preserved(app):
    """Case 13: First-seen order respects source id order, not global link id."""
    with app.app_context():
        cust = make_customer()
        admin = make_admin()

        hf1 = _make_hashfile(cust.id, admin.id, name='hf1')
        hf2 = _make_hashfile(cust.id, admin.id, name='hf2')
        hf3 = _make_hashfile(cust.id, admin.id, name='hf3')

        # Create hashes
        h1 = _make_hash('s' * 32, hash_type=1000)
        h2 = _make_hash('t' * 32, hash_type=1000)
        h3 = _make_hash('u' * 32, hash_type=1000)
        h4 = _make_hash('v' * 32, hash_type=1000)

        # Create hf2's links FIRST (lower ids in database)
        _link_hash(hf2.id, h3.id)
        _link_hash(hf3.id, h4.id)
        # Then create hf1's links (higher ids in database)
        _link_hash(hf1.id, h1.id)
        _link_hash(hf1.id, h2.id)

        # Combine in source order: hf1, hf2, hf3
        # Despite hf2/hf3 links having lower db ids, output should follow
        # source order (hf1, then hf2, then hf3)
        combined, err = combine_hashfiles([hf1.id, hf2.id, hf3.id],
                                         customer_id=cust.id, owner_id=admin.id)

        assert err is None
        assert combined is not None

        links = (HashfileHashes.query.filter_by(hashfile_id=combined.id)
                 .order_by(HashfileHashes.id).all())
        hash_ids = [link.hash_id for link in links]
        # Should follow source order, NOT global link id order
        assert hash_ids == [h1.id, h2.id, h3.id, h4.id]

        # Reverse order test: combine([hf3.id, hf1.id, hf2.id], ...)
        # should produce h4, h1, h2, h3
        combined2, err2 = combine_hashfiles([hf3.id, hf1.id, hf2.id],
                                          customer_id=cust.id, owner_id=admin.id)

        assert err2 is None
        assert combined2 is not None

        links2 = (HashfileHashes.query.filter_by(hashfile_id=combined2.id)
                  .order_by(HashfileHashes.id).all())
        hash_ids2 = [link.hash_id for link in links2]
        assert hash_ids2 == [h4.id, h1.id, h2.id, h3.id]


def test_source_whose_first_link_is_dangling_is_rejected(app):
    """A source whose FIRST link points at a missing Hashes row is rejected.

    Only the representative (first) link's hash type is validated, the same
    way hashfile_hash_type()/build_hashcat_command derive a file's type. A
    dangling link at position 2+ of a source is not detected here and is
    copied into the combined file unchanged.
    """
    with app.app_context():
        cust = make_customer()
        admin = make_admin()

        hf1 = _make_hashfile(cust.id, admin.id, name='hf1')
        hf2 = _make_hashfile(cust.id, admin.id, name='hf2')

        h1 = _make_hash('w' * 32, hash_type=1000)
        _link_hash(hf1.id, h1.id)

        # Create a link to a non-existent hash_id
        _link_hash(hf2.id, 99999)

        before_count = Hashfiles.query.count()

        combined, err = combine_hashfiles([hf1.id, hf2.id],
                                         customer_id=cust.id, owner_id=admin.id)

        assert combined is None
        assert err is not None
        assert 'resolvable hash type' in err.lower()
        assert Hashfiles.query.count() == before_count


def test_combine_customer_id_and_owner_id_inherited(app):
    """Combined row inherits customer_id and owner_id from arguments."""
    with app.app_context():
        cust = make_customer()
        admin = make_admin()

        hf1 = _make_hashfile(cust.id, admin.id, name='hf1')
        hf2 = _make_hashfile(cust.id, admin.id, name='hf2')

        h1 = _make_hash('x' * 32, hash_type=1000)
        h2 = _make_hash('y' * 32, hash_type=1000)

        _link_hash(hf1.id, h1.id)
        _link_hash(hf2.id, h2.id)

        combined, err = combine_hashfiles([hf1.id, hf2.id],
                                         customer_id=cust.id, owner_id=admin.id)

        assert err is None
        assert combined is not None
        assert combined.customer_id == cust.id
        assert combined.owner_id == admin.id


def test_combine_non_int_id_rejected(app):
    """Non-integer hashfile id (e.g. 'abc') → rejected."""
    with app.app_context():
        cust = make_customer()
        admin = make_admin()

        hf1 = _make_hashfile(cust.id, admin.id, name='hf1')
        h1 = _make_hash('z' * 32, hash_type=1000)
        _link_hash(hf1.id, h1.id)

        before_count = Hashfiles.query.count()

        combined, err = combine_hashfiles([hf1.id, 'abc'],
                                         customer_id=cust.id, owner_id=admin.id)

        assert combined is None
        assert err == 'Invalid hashfile selection.'
        assert Hashfiles.query.count() == before_count


def test_combine_commit_failure_is_a_refusal_not_a_500(app, monkeypatch):
    """A SQLAlchemyError on the final commit is turned into the (None, error)
    refusal contract, and the half-built combined row is rolled back."""
    with app.app_context():
        cust = make_customer()
        admin = make_admin()

        hf1 = _make_hashfile(cust.id, admin.id, name='hf1')
        hf2 = _make_hashfile(cust.id, admin.id, name='hf2')
        h1 = _make_hash('ab' * 16, hash_type=1000)
        h2 = _make_hash('cd' * 16, hash_type=1000)
        _link_hash(hf1.id, h1.id)
        _link_hash(hf2.id, h2.id)

        before_count = Hashfiles.query.count()

        def boom():
            raise SQLAlchemyError('simulated commit failure')

        monkeypatch.setattr(db.session, 'commit', boom)
        combined, err = combine_hashfiles([hf1.id, hf2.id],
                                         customer_id=cust.id, owner_id=admin.id)
        monkeypatch.undo()

        assert combined is None
        assert err == 'Could not combine those hashfiles.'
        assert Hashfiles.query.count() == before_count
        assert Hashfiles.query.filter(Hashfiles.name.like('combined-%')).count() == 0


def test_combine_chunked_insert_preserves_order_and_dedup(app, monkeypatch):
    """Rows are inserted per _IMPORT_CHUNK_SIZE inside one transaction. Shrink
    the chunk size so a small fixture crosses several chunk boundaries and
    check first-seen order and dedup survive the chunking."""
    with app.app_context():
        cust = make_customer()
        admin = make_admin()

        hf1 = _make_hashfile(cust.id, admin.id, name='hf1')
        hf2 = _make_hashfile(cust.id, admin.id, name='hf2')

        hashes = [_make_hash(f'{i:032x}', hash_type=1000) for i in range(7)]
        # hf1: h0..h4 ; hf2: h3..h6 (h3, h4 overlap)
        for h in hashes[:5]:
            _link_hash(hf1.id, h.id)
        for h in hashes[3:]:
            _link_hash(hf2.id, h.id)

        monkeypatch.setattr(utils_mod, '_IMPORT_CHUNK_SIZE', 2)
        combined, err = combine_hashfiles([hf1.id, hf2.id],
                                         customer_id=cust.id, owner_id=admin.id)

        assert err is None
        links = (HashfileHashes.query.filter_by(hashfile_id=combined.id)
                 .order_by(HashfileHashes.id).all())
        assert [link.hash_id for link in links] == [h.id for h in hashes]


def test_combine_hash_with_null_and_named_usernames(app):
    """Same hash_id with username=None and username='alice' → both kept."""
    with app.app_context():
        cust = make_customer()
        admin = make_admin()

        hf1 = _make_hashfile(cust.id, admin.id, name='hf1')
        hf2 = _make_hashfile(cust.id, admin.id, name='hf2')

        h = _make_hash('aa' * 16, hash_type=1000)
        # Same hash, one with null username, one with named
        _link_hash(hf1.id, h.id, username=None)
        _link_hash(hf2.id, h.id, username='alice')

        combined, err = combine_hashfiles([hf1.id, hf2.id],
                                         customer_id=cust.id, owner_id=admin.id)

        assert err is None
        assert combined is not None

        links = HashfileHashes.query.filter_by(hashfile_id=combined.id).all()
        assert len(links) == 2
        usernames = {link.username for link in links}
        assert usernames == {None, 'alice'}
