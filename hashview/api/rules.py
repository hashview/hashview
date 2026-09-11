"""/v1 rule routes: list, download, upload, delete.

Carved out of routes.py per issue #441; pure code motion.
"""
import os
import secrets

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
    Rules,
    Tasks,
    Users,
    db,
)
from hashview.utils.audit import log_event
from hashview.utils.utils import (
    compress_to_gz,
    decompress_gz,
    get_filehash,
    get_linecount,
    is_gzip,
    remove_rule_file,
    resolve_control_file,
    send_generated_file,
)


@api.route('/v1/rules', methods=['GET'])
def v1_api_get_rules():
    if not is_authorized(user=True, agent=True, request=request):
        return redirect("/v1/not_authorized")

    update_heartbeat(request.cookies.get('uuid'))
    rules = Rules.query.all()
    message = {
        'status': 200,
        'rules': alchemy_to_native(rules)
    }
    return jsonify(message)


# serve a rules file
@api.route('/v1/rules/<int:rules_id>', methods=['GET'])
def v1_api_get_rules_download(rules_id):
    if not is_authorized(user=True, agent=True, request=request):
        return redirect("/v1/not_authorized")

    update_heartbeat(request.cookies.get('uuid'))
    rules = Rules.query.get(rules_id)
    if rules is None:
        return jsonify({'status': 404, 'type': 'Error', 'msg': 'Rule not found'}), 404

    # Rules are stored plaintext at rest; compress into control/tmp and serve
    # that. No shell; pure-Python streamed gzip -9 (same pattern as the
    # dynamic-wordlist download above). The random tmp name avoids predictable
    # paths and collisions between concurrent downloads.
    tmp_dir = os.path.join(current_app.root_path, 'control/tmp')
    src_path = resolve_control_file(rules.path, 'rules')
    if src_path is None:
        # Log it here too: without this the only evidence an agent is re-asking
        # for a dead file every sync lives in that agent's log, on another host.
        current_app.logger.warning(
            'Rule %s has no file on disk (path=%s); serving 404 to the caller. '
            'Restore or delete it from the Rules page (issue #383).',
            rules.id, rules.path)
        return jsonify({'status': 404, 'type': 'Error', 'msg': 'Rule file missing on disk'}), 404

    tmp_gz = os.path.join(tmp_dir, secrets.token_hex(8) + '.gz')
    compress_to_gz(src_path, tmp_gz, 9)
    return send_generated_file(
        tmp_dir, os.path.basename(tmp_gz), mimetype='application/octet-stream')


# Delete a rule
@api.route('/v1/rules/<int:rules_id>', methods=['DELETE'])
def v1_api_delete_rule(rules_id):
    """Delete a rule row. Owner or admin only, and never while a task uses it.

    Mirrors the web UI's rules_delete guard for guard: a rule referenced by any
    task cannot be deleted, because Tasks.rule_id has no foreign key and the
    orphaned reference would make those tasks unrunnable. Tasks.rule_id is the
    only reference to check -- j_rule and k_rule are hashcat's inline -j/-k rule
    strings, not rows in this table.

    The rule's file under control/rules goes too, via the same helper the web UI
    uses, so the two paths cannot drift (#397).
    """
    if not is_authorized(user=True, agent=False, request=request):
        return redirect("/v1/not_authorized")

    uuid = request.cookies.get('uuid')
    user = Users.query.filter_by(api_key=uuid).first()
    # Both refusals below carry a real HTTP 403, where the sibling deletes
    # (jobs, hashfiles, task groups) answer 200 with status 403 in the body.
    # That is deliberate: this endpoint exists for API-only tooling (#397), the
    # repo's own spec for the issue asserts a 403 status code, and the envelope
    # still reports 403 either way -- so a client reading the body sees no
    # change and a client reading the status code stops being told "OK" when it
    # was refused. The endpoint already answers a real 404 and a real 409.
    if not user:
        return jsonify({
            'status': 403,
            'type': 'Error',
            'msg': 'User not found'
        }), 403

    rule = Rules.query.get(rules_id)
    if rule is None:
        return jsonify({'status': 404, 'type': 'Error', 'msg': 'Rule not found'}), 404

    if not (user.admin or rule.owner_id == user.id):
        return jsonify({
            'status': 403,
            'type': 'Error',
            'msg': 'You do not have rights to delete this rule'
        }), 403

    # Checked before the delete, not repaired after: a task pointing at a
    # missing rule builds a hashcat command with no rule file.
    if Tasks.query.filter_by(rule_id=rule.id).first():
        return jsonify({
            'status': 409,
            'type': 'Error',
            'msg': 'Rule is currently used in a task and can not be deleted'
        }), 409

    # Path captured before the row goes; the row is removed first so a failed
    # unlink only orphans a file (see remove_rule_file).
    rule_path = rule.path
    rule_target = f'rule:{rule.id} {rule.name!r}'
    try:
        db.session.delete(rule)
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception('API /v1/rules: failed to delete rule')
        return jsonify({
            'status': 500,
            'type': 'Error',
            'msg': 'Failed to delete rule.'
        })

    log_event('rule.delete', actor=(user.email_address, user.id), target=rule_target)
    remove_rule_file(rule_path)
    return jsonify({
        'status': 200,
        'type': 'message',
        'msg': 'Rule deleted',
        'rule_id': rules_id
    })


# Create new rule
@api.route('/v1/rules/add/<rule_name>', methods=['POST'])
def v1_api_add_rule(rule_name):
    # User-upload action (resolves the caller to a Users row by api_key), so
    # it's user-only — the agent only GETs rules, it never POSTs here.
    if not is_authorized(user=True, agent=False, request=request):
        return redirect("/v1/not_authorized")

    # Read the body as BYTES (not as_text) so an uploaded gzip rule file isn't
    # corrupted by text decoding. The body may be plain text or a gzip file.
    raw_content = request.get_data()
    if not raw_content:
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': 'Missing rule content in request body'
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

    # Unlike wordlists, rules are stored PLAINTEXT at rest (control/rules/),
    # so a gzip body is decompressed before landing. The <hex>.txt naming
    # matches the web UI's save_file() convention.
    tmp_path = os.path.abspath(os.path.join(current_app.root_path, 'control/tmp', secrets.token_hex(8)))
    final_path = os.path.join(current_app.root_path, 'control/rules', secrets.token_hex(8) + '.txt')
    try:
        with open(tmp_path, 'wb') as f:
            f.write(raw_content)
        if is_gzip(tmp_path):
            # Raises on a malformed gzip stream, which doubles as validation
            decompress_gz(tmp_path, final_path)
        else:
            os.rename(tmp_path, final_path)
    except Exception:
        current_app.logger.exception('API /v1/rules: failed to process rule')
        if os.path.exists(final_path):
            os.remove(final_path)
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': 'Failed to process rule (not valid text or gzip?).'
        })
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

    # Same metadata helpers as the web UI upload (rules_add): size/checksum
    # are computed over the plaintext file.
    rule = Rules(
        name=rule_name,
        owner_id=user.id,
        path=final_path,
        size=get_linecount(final_path),
        checksum=get_filehash(final_path)
    )
    db.session.add(rule)
    db.session.commit()

    log_event('rule.create', actor=(user.email_address, user.id),
              target=f'rule:{rule.id} {rule.name!r}')
    message = {
        'status': 200,
        'type': 'message',
        'msg': 'Rule added',
        'rule_id': rule.id
    }
    return jsonify(message)
