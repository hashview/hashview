"""/v1 hash routes: search, and importing externally cracked hashes.

Carved out of routes.py per issue #441; pure code motion.
"""
import os
import secrets
from datetime import datetime

from flask import (
    current_app,
    jsonify,
    redirect,
    request,
)

# The blueprint and the shared helpers now live in hashview/api/_shared.py
# (issue #441). They are imported INTO this module's namespace rather than used
# through it, so every reference here -- and every test that monkeypatches e.g.
# hashview.api.routes.is_authorized -- keeps resolving exactly as before.
from hashview.api._shared import (  # noqa: F401
    _ENCODER_DENYLIST,
    AlchemyEncoder,
    _error,
    agentAuthorized,
    alchemy_to_native,
    api,
    is_authorized,
    update_heartbeat,
    userAuthorized,
    versionCheck,
)
from hashview.models import (
    Hashes,
    HashfileHashes,
    Users,
    db,
)
from hashview.utils.utils import (
    get_cracked_hash_verifier,
    get_md5_hash,
    process_recovered_hash_notifications,
    remove_file,
    text_from_field,
)


# Search
@api.route('/v1/search', methods=['POST'])
def v1_api_search():
    if not is_authorized(user=True, agent=False, request=request):
        return redirect("/v1/not_authorized")
    
    # silent=True: an empty/invalid body returns None (-> JSON "Invalid Search")
    # rather than Flask's HTML 400 page (issue #213).
    search_json = request.get_json(silent=True)
    if not search_json:
        return jsonify({'status': 500, 'type': 'message', 'msg': 'Invalid Search'})

    not_found = {'status': 200, 'type': 'message', 'msg': 'Search complete. No Results Found.'}

    # Provide exactly one of hash / plaintext / username (checked in that order).

    # By exact ciphertext -> the single recovered hash (back-compatible object shape).
    if search_json.get('hash'):
        ciphertext = search_json['hash']
        cracked_hash = Hashes.query.filter_by(cracked=True, ciphertext=ciphertext).first()
        if not cracked_hash:
            return jsonify(not_found)
        return jsonify({'status': 200, 'type': 'message', 'msg': {
            'hash_type': cracked_hash.hash_type,
            'hash': ciphertext,
            'plaintext': cracked_hash.plaintext,
        }})

    # By recovered plaintext -> every cracked hash with that plaintext (a list).
    if search_json.get('plaintext'):
        matches = Hashes.query.filter_by(cracked=True, plaintext=search_json['plaintext']).all()
        if not matches:
            return jsonify(not_found)
        return jsonify({'status': 200, 'type': 'message', 'msg': [
            {'hash_type': h.hash_type, 'hash': h.ciphertext, 'plaintext': h.plaintext}
            for h in matches
        ]})

    # By username -> the associated hash(es), with plaintext when recovered (a list).
    if search_json.get('username'):
        username = search_json['username']
        rows = (db.session.query(Hashes)
                .join(HashfileHashes, Hashes.id == HashfileHashes.hash_id)
                .filter(HashfileHashes.username == username)
                .all())
        seen = set()
        results = []
        for h in rows:
            if h.id in seen:  # a username can map to the same hash across hashfiles
                continue
            seen.add(h.id)
            results.append({
                'username': username,
                'hash_type': h.hash_type,
                'hash': h.ciphertext,
                'plaintext': h.plaintext if h.cracked else None,
            })
        if not results:
            return jsonify(not_found)
        return jsonify({'status': 200, 'type': 'message', 'msg': results})

    return jsonify({'status': 500, 'type': 'message', 'msg': 'Invalid Search'})


@api.route('/v1/hashes/import/<int:hash_type>', methods=['POST'])
def v1_api_hashes_import(hash_type):
    if not is_authorized(user=True, agent=False, request=request):
        return redirect("/v1/not_authorized")

    # Verify-only model: only accept a submitted plaintext for a hash type the
    # server can LOCALLY recompute. get_cracked_hash_verifier returns None for
    # anything unsupported (incl. LM 3000), which we reject up front.
    verifier = get_cracked_hash_verifier(hash_type)
    if verifier is None:
        return jsonify({'status': 403, 'type': 'message', 'msg': 'Unsupported Hashtype'})

    # Expect raw plain‑text body (Content‑Type: text/plain)
    raw_content = request.get_data(as_text=True)
    if not raw_content:
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': 'Missing cracked content in request body'
        })

    # Resolve user from api_key cookie
    user_uuid = request.cookies.get('uuid')
    user = Users.query.filter_by(api_key=user_uuid).first()
    if not user:
        return jsonify({
            'status': 403,
            'type': 'Error',
            'msg': 'User not found'
        })

    # Generate a random filename for storage
    random_name = secrets.token_hex(8) + '.txt'
    file_path = os.path.abspath(os.path.join(current_app.root_path, 'control/tmp', random_name))

    # Save the raw content to disk
    try:
        with open(file_path, 'w') as f:
            f.write(raw_content)
    except Exception:
        current_app.logger.exception('API: failed to write file')
        return jsonify({
            'status': 500,
            'type': 'Error',
            'msg': 'Failed to write file.'
        })


    # import contents from file. The import is atomic: all verified records are
    # mutated in the session and committed ONCE after the loop completes. Any
    # verification failure rolls back so nothing from this request persists.
    try:
        try:
            with open(file_path, encoding='utf-8', errors='surrogateescape') as f:
                for line in f:
                    line = line.rstrip('\r\n')
                    if not line:
                        continue
                    parts = line.split(':')
                    ciphertext = parts[0]
                    # everything after the first ':' is the plaintext (it may itself contain ':')
                    plaintext = ':'.join(parts[1:])

                    # Recompute the digest from the submitted plaintext (plus any salt
                    # embedded in the ciphertext) and compare case-insensitively.
                    # Never trust unverified plaintext.
                    if verifier(plaintext, ciphertext):
                        # valid hash:plaintext. Hashfile imports store hex hashes
                        # lowercased and key sub_ciphertext off the lowercased value,
                        # so look up on ciphertext.lower() to actually hit the record.
                        record = Hashes.query.filter_by(hash_type=hash_type, sub_ciphertext=get_md5_hash(ciphertext.lower()), cracked='0').first()
                        if record:
                            # Mutate in the session; commit happens once after the loop.
                            record.plaintext = text_from_field(plaintext)
                            record.cracked = 1
                            record.recovered_at = datetime.today()
                            record.recovered_by = user.id
                    else:
                        # A single bad line invalidates the whole request; roll back
                        # any pending changes so nothing persists.
                        db.session.rollback()
                        return jsonify({
                            'status': 500,
                            'type': 'Error',
                            'msg': f'Plaintext for hash {ciphertext}, was found to be invalid.'
                        })

            # All lines verified. Commit the whole batch atomically.
            try:
                db.session.commit()
            except Exception:
                current_app.logger.exception('API: failed to import cracked hashes')
                db.session.rollback()
                return jsonify({
                    'status': 500,
                    'type': 'Error',
                    'msg': 'Failed to import cracked hash.'
                })
        except Exception:
            current_app.logger.exception('API: failed to open/parse uploaded file')
            db.session.rollback()
            return jsonify({
                'status': 500,
                'type': 'Error',
                'msg': 'Failed to open file.'
            })
    finally:
        remove_file(file_path)

    # Send per-hash "recovered" notifications (email/push/slack) for any now-cracked watched hash.
    process_recovered_hash_notifications()

    message = {
        'status': 200,
        'type': 'message',
        'msg': 'OK'
    }
    return jsonify(message)
