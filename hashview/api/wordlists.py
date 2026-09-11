"""/v1 wordlist routes: list, download, upload.

Carved out of routes.py per issue #441; pure code motion.
"""
import os
import secrets

from flask import (
    current_app,
    jsonify,
    redirect,
    request,
    send_from_directory,
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
    Users,
    Wordlists,
    db,
)
from hashview.utils.audit import log_event
from hashview.utils.utils import (
    compress_to_gz,
    ingest_static_wordlist_file,
    remove_file,
    resolve_control_file,
    send_generated_file,
    update_dynamic_wordlist,
)


# Provide wordlist info (really should be plural)
@api.route('/v1/wordlists', methods=['GET'])
def v1_api_get_wordlist():
    if not is_authorized(user=True, agent=True, request=request):
        return redirect("/v1/not_authorized")

    update_heartbeat(request.cookies.get('uuid'))
    wordlists = Wordlists.query.all()
    message = {
        'status': 200,
        'wordlists': alchemy_to_native(wordlists)
    }
    return jsonify(message)


# serve a wordlist
@api.route('/v1/wordlists/<int:wordlist_id>', methods=['GET'])
def v1_api_get_wordlist_download(wordlist_id):
    if not is_authorized(user=True, agent=True, request=request):
        return redirect("/v1/not_authorized")

    update_heartbeat(request.cookies.get('uuid'))
    wordlist = Wordlists.query.get(wordlist_id)
    if wordlist is None:
        return jsonify({'status': 404, 'type': 'Error', 'msg': 'Wordlist not found'}), 404

    wordlists_dir = os.path.join(current_app.root_path, 'control/wordlists')
    tmp_dir = os.path.join(current_app.root_path, 'control/tmp')

    if wordlist.type == 'static':
        # Static lists are stored compressed at rest: serve the .gz directly. The
        # stored bytes are stable, so the agent's sha256(.gz) matches the DB
        # checksum. Resolve by basename against the wordlists dir rather than
        # trusting a possibly-relative wordlist.path against the CWD (legacy rows
        # can hold a relative path). When the row outlives its file -- e.g. a
        # wordlist stranded by an upgrade -- return a clear JSON 404 instead of
        # send_from_directory's bare HTML page, so the agent logs an actionable
        # body and the operator knows to re-upload. (Mirrors /v1/rules/<id>.)
        wordlist_name = os.path.basename(wordlist.path or '')
        if resolve_control_file(wordlist.path, 'wordlists') is None:
            # Log it here too: without this the only evidence an agent is
            # re-asking for a dead file every sync lives in that agent's log,
            # on another host.
            current_app.logger.warning(
                'Wordlist %s has no file on disk (path=%s); serving 404 to the '
                'caller. Restore or delete it from the Wordlists page (#383).',
                wordlist.id, wordlist.path)
            return jsonify({'status': 404, 'type': 'Error',
                            'msg': 'Wordlist file missing on disk: ' + (wordlist_name or '(no path)')}), 404
        return send_from_directory(wordlists_dir, wordlist_name, mimetype='application/octet-stream')

    # Dynamic lists are regenerated from the DB on demand and served gzipped.
    # Generate into a per-request unique temp file (never the shared
    # wordlist.path); the DB row metadata is deliberately left untouched
    # (dest_path is set).
    tmp_txt = os.path.join(tmp_dir, secrets.token_hex(8) + '.txt')
    update_dynamic_wordlist(wordlist_id, dest_path=tmp_txt)

    # Compress the plaintext into control/tmp and serve that. No shell; pure-
    # Python streamed gzip -9. Both temp files live under control/tmp and are
    # cleaned up: the .txt now, the .gz after the response is streamed.
    tmp_gz = os.path.join(tmp_dir, secrets.token_hex(8) + '.gz')
    compress_to_gz(tmp_txt, tmp_gz, 9)
    remove_file(tmp_txt)
    return send_generated_file(
        tmp_dir, os.path.basename(tmp_gz), mimetype='application/octet-stream')


# Create new wordlist
@api.route('/v1/wordlists/add/<wordlist_name>', methods=['POST'])
def v1_api_add_wordlist(wordlist_name):
    # Authorization check. This is a user-upload action — it resolves the
    # caller to a Users row by api_key — so it's user-only. The agent never
    # POSTs here (it only GETs wordlists), so requiring a user
    # credential refuses agent uuids cleanly instead of letting them through to
    # a "User not found" 403.
    if not is_authorized(user=True, agent=False, request=request):
        return redirect("/v1/not_authorized")

    # Read the body as BYTES (not as_text) so an uploaded gzip wordlist isn't
    # corrupted by text decoding. The body may be plain text or a gzip file.
    raw_content = request.get_data()
    if not raw_content:
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': 'Missing wordlist content in request body'
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

    # Write the raw body to a control/tmp temp, then ingest it into
    # compressed-at-rest storage (handles plain text or gzip; validates gzip).
    tmp_path = os.path.abspath(os.path.join(current_app.root_path, 'control/tmp', secrets.token_hex(8)))
    try:
        with open(tmp_path, 'wb') as f:
            f.write(raw_content)
        wordlist_entry = ingest_static_wordlist_file(tmp_path, user.id, wordlist_name)
    except Exception:
        current_app.logger.exception('API /v1/wordlists: failed to process wordlist')
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': 'Failed to process wordlist (not valid text or gzip?).'
        })
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

    db.session.add(wordlist_entry)
    db.session.commit()

    log_event('wordlist.create', actor=(user.email_address, user.id),
              target=f'wordlist:{wordlist_entry.id} {wordlist_entry.name!r}')
    message = {
        'status': 200,
        'type': 'message',
        'msg': 'Wordlist added',
        'wordlist_id': wordlist_entry.id
    }
    return jsonify(message)
