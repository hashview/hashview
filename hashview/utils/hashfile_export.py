"""Hashfile export formatting shared by the web download and the /v1 API (#368).

Both ``hashfiles.hashfiles_download`` (session auth) and
``v1_api_export_hashfile`` (API-key auth) render through
``iter_hashfile_export``, so the UI and the API cannot drift apart on what a
format contains.
"""
from hashview.models import Hashes, HashfileHashes, db

# Download/export formats offered by the hashfile download modal and the API:
#   - hashes : every hash (ciphertext only)
#   - all    : uncracked -> hash, cracked -> hash:plain
#   - cracked: cracked only, as hash:plain
#   - plains : cracked only, plaintext only
HASHFILE_EXPORT_FORMATS = ('hashes', 'all', 'cracked', 'plains')


def iter_hashfile_export(hashfile_id, fmt):
    """Yield one export line (without a newline) per relevant hash.

    Plaintexts are emitted as stored: valid UTF-8 as text, anything else as
    hashcat's ``$HEX[...]`` marker (see ``bytes_to_text``), so ``cracked``
    output is directly usable as a hashcat potfile.

    Each hash is emitted once, even when several accounts in the hashfile share
    it (one ``Hashes`` row, several ``HashfileHashes`` links). That is why this
    is an ``IN`` semi-join rather than a join: the legacy ``Query.all()`` the
    web export used to call de-duplicated a joined entity query, but
    ``yield_per`` does not, so a join would repeat shared hashes.

    Rows are streamed with ``yield_per`` so a large hashfile is not fully
    materialized in memory. The caller must validate ``fmt`` first; an unknown
    format yields nothing.
    """
    hash_ids = db.session.query(HashfileHashes.hash_id) \
        .filter(HashfileHashes.hashfile_id == hashfile_id)
    rows = db.session.query(Hashes) \
        .filter(Hashes.id.in_(hash_ids)) \
        .yield_per(1000)
    for h in rows:
        cracked = bool(h.cracked)
        plaintext = h.plaintext or ''
        if fmt == 'hashes':
            yield h.ciphertext
        elif fmt == 'all':
            yield h.ciphertext + ':' + plaintext if cracked else h.ciphertext
        elif fmt == 'cracked' and cracked:
            yield h.ciphertext + ':' + plaintext
        elif fmt == 'plains' and cracked:
            yield plaintext
