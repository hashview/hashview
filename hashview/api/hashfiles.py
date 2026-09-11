"""/v1 hashfile routes: upload, download uncracked, delete, and lookups by hash type.

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
from sqlalchemy import case, exists, func

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
    Customers,
    Hashes,
    HashfileHashes,
    Hashfiles,
    HashNotifications,
    Jobs,
    Users,
    db,
)
from hashview.utils.audit import log_event
from hashview.utils.utils import (
    import_hashfilehashes,
    send_generated_file,
    validate_hash_only_hashfile,
    validate_kerberos_hashfile,
    validate_netntlm_hashfile,
    validate_pwdump_hashfile,
    validate_shadow_hashfile,
    validate_user_hash_hashfile,
)


# Upload a large hashfile
@api.route('/v1/hashfiles/upload/<int:customer_id>/<int:file_format>/<int:hash_type>/<hashfile_name>', methods=['POST'])
def v1_api_post_hashfile_upload(customer_id, file_format, hash_type, hashfile_name):
    if not is_authorized(user=True, agent=False, request=request):
        return redirect("/v1/not_authorized")
    
    customers = Customers.query.get(customer_id)
    if not customers:
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': 'Invalid customer ID'
        })

    # file_format:
    # 0 = pwdump
    # 1 = NetNTLM
    # 2 = kerberos
    # 3 = shadow
    # 4 = user:hash
    # 5 = hash_only

    # Expect raw plain‑text body (Content‑Type: text/plain)
    raw_content = request.get_data(as_text=True)
    if not raw_content:
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': 'Missing hashfile content in request body'
        })

    if file_format not in [0,1,2,3,4,5]:
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': 'Invalid file format. Valid formats are 0=pwdump, 1=NetNTLM, 2=kerberos, 3=shadow, 4=user:hash, 5=hash_only'
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
    file_path = os.path.abspath(os.path.join(current_app.root_path, 'control/tmp/', random_name))

    # Save the raw content to disk
    try:
        with open(file_path, 'w') as f:
            f.write(raw_content)
        f.close()
    except Exception:
        current_app.logger.exception('API: failed to write hashfile')
        return jsonify({
            'status': 500,
            'type': 'Error',
            'msg': 'Failed to write hashfile.'
        })

    # import contents from file
    try:
        current_app.logger.debug('API: validating hashfile %s of format %s for hashtype %s',
                                 file_path, file_format, hash_type)
        if file_format == 0:
            has_problem = validate_pwdump_hashfile(file_path, str(hash_type))
        elif file_format == 1:
            has_problem = validate_netntlm_hashfile(file_path, str(hash_type))
        elif file_format == 2:
            has_problem = validate_kerberos_hashfile(file_path, str(hash_type)) 
        elif file_format == 3:
            has_problem = validate_shadow_hashfile(file_path, str(hash_type))
        elif file_format == 4:
            has_problem = validate_user_hash_hashfile(file_path, str(hash_type))
        elif file_format == 5:
            has_problem = validate_hash_only_hashfile(file_path, str(hash_type)) 
        else:
            has_problem = 'Invalid File Format'

        if has_problem:
            return jsonify({
                'status': 500,
                'type': 'Error',
                'msg': f'Invalid Hash: {has_problem}'
            })            
 
        else:
            hashfile = Hashfiles(name=hashfile_name, customer_id=customer_id, owner_id=user.id)
            db.session.add(hashfile)

            db.session.commit()

            # Parse Hashfile
            if file_format == 0:
                file_format = 'pwdump'
            elif file_format == 1:
                file_format = 'NetNTLM'
            elif file_format == 2:
                file_format = 'kerberos'
            elif file_format == 3:
                file_format = 'shadow'
            elif file_format == 4:
                file_format = 'user_hash'
            elif file_format == 5:
                file_format = 'hash_only'
            if not import_hashfilehashes(   hashfile_id=hashfile.id,
                                            hashfile_path=file_path,
                                            file_type=file_format,
                                            hash_type=hash_type
                                            ):
                return jsonify({
                    'status': 500,
                    'type': 'Error',
                    'msg': 'Something went wrong. Check the filetype / hashtype and try again.'
                })                  

            hashfile_hashes_cnt = db.session.query(HashfileHashes).filter_by(hashfile_id=hashfile.id).count()
            if hashfile_hashes_cnt == 0:
                db.session.delete(hashfile)
                db.session.commit()
                return jsonify({
                    'status': 500,
                    'type': 'Error',
                    'msg': 'No valid hashes found in the hashfile. Hashfile not added.'
                })   

            cracked_hashfiles_hashes_cnt = db.session.query(Hashes).join(HashfileHashes, Hashes.id == HashfileHashes.hash_id).filter(Hashes.cracked == '1').filter(HashfileHashes.hashfile_id==hashfile.id).count()

            log_event('hashfile.create', actor=(user.email_address, user.id),
                      target=f'hashfile:{hashfile.id} {hashfile.name!r}',
                      detail=f'hashes={hashfile_hashes_cnt} instacracked={cracked_hashfiles_hashes_cnt}')
            # Return the insta crack result
            return jsonify({
                'status': 200,
                'type': 'message',
                'msg': 'Hashfile added',
                'hashfile_id': hashfile.id,
                'hash_count': hashfile_hashes_cnt,
                'instacracked': cracked_hashfiles_hashes_cnt
            })

    except Exception:
        current_app.logger.exception('API: hash import failed')
        return jsonify({
            'status': 500,
            'type': 'Error',
            'msg': 'Hash import Failed.'
        })


# generate and serve hashfile
@api.route('/v1/hashfiles/<int:hashfile_id>', methods=['GET'])
def v1_api_get_hashfile(hashfile_id):
    if not is_authorized(user=True, agent=True, request=request):
        return redirect("/v1/not_authorized")

    update_heartbeat(request.cookies.get('uuid'))
    random_hex = secrets.token_hex(8)
    # Build the path from current_app.root_path (like the sibling routes) so it does
    # not depend on the current working directory (issue #227).
    tmp_dir = os.path.join(current_app.root_path, 'control/tmp')
    file_path = os.path.join(tmp_dir, random_hex)

    # Left join to get the uncracked ciphertext hashes. Stream rows with yield_per and
    # a context manager so a large hashfile isn't fully materialized in memory.
    dbresults = db.session.query(Hashes, HashfileHashes) \
        .outerjoin(HashfileHashes, Hashes.id == HashfileHashes.hash_id) \
        .filter(Hashes.cracked == '0') \
        .filter(HashfileHashes.hashfile_id == hashfile_id) \
        .yield_per(1000)
    with open(file_path, 'w') as file_object:
        for result in dbresults:
            file_object.write(result[0].ciphertext + '\n')

    return send_generated_file(tmp_dir, random_hex)


@api.route('/v1/hashfiles/<int:hashfile_id>', methods=['DELETE'])
def v1_api_delete_hashfile(hashfile_id):
    if not is_authorized(user=True, agent=False, request=request):
        return redirect("/v1/not_authorized")

    uuid = request.cookies.get('uuid')
    user = Users.query.filter_by(api_key=uuid).first()
    if not user:
        return jsonify({
            'status': 403,
            'type': 'Error',
            'msg': 'User not found'
        })

    hashfile = Hashfiles.query.get(hashfile_id)
    if hashfile is None:
        return jsonify({'status': 404, 'type': 'Error', 'msg': 'Hashfile not found'}), 404

    if not (user.admin or hashfile.owner_id == user.id):
        return jsonify({
            'status': 403,
            'type': 'Error',
            'msg': 'You do not have rights to delete this hashfile'
        })

    # Refuse while the hashfile is still assigned to a job — the web UI does the
    # same (hashfiles_delete) and does NOT cascade job deletion from a hashfile.
    if Jobs.query.filter_by(hashfile_id=hashfile_id).first():
        return jsonify({
            'status': 409,
            'type': 'Error',
            'msg': 'Hashfile is currently associated with a job'
        }), 409

    # Mirror the web UI's hashfiles_delete cascade, atomically: the hashfile-hash
    # links, the hashfile, then any uncracked hashes / notifications it orphans.
    hashfile_target = f'hashfile:{hashfile.id} {hashfile.name!r}'
    try:
        HashfileHashes.query.filter_by(hashfile_id=hashfile.id).delete(synchronize_session=False)
        db.session.delete(hashfile)
        Hashes.query.filter(Hashes.cracked == 0).filter(
            ~exists().where(HashfileHashes.hash_id == Hashes.id)
        ).delete(synchronize_session=False)
        HashNotifications.query.filter(
            ~exists().where(Hashes.id == HashNotifications.hash_id)
        ).delete(synchronize_session=False)
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception('API /v1/hashfiles: failed to delete hashfile')
        return jsonify({
            'status': 500,
            'type': 'Error',
            'msg': 'Failed to delete hashfile.'
        })

    log_event('hashfile.delete', actor=(user.email_address, user.id), target=hashfile_target)
    return jsonify({
        'status': 200,
        'type': 'message',
        'msg': 'Hashfile deleted',
        'hashfile_id': hashfile_id
    })


# List hashfiles containing at least one hash of the given hash type.
# No collision with /v1/hashfiles/<int:hashfile_id>: the static 'hash_type/'
# segment wins over the int converter in Flask routing.
@api.route('/v1/hashfiles/hash_type/<int:hash_type>', methods=['GET'])
def v1_api_get_hashfiles_by_hash_type(hash_type):
    if not is_authorized(user=True, agent=False, request=request):
        return redirect("/v1/not_authorized")

    uuid = request.cookies.get('uuid')
    user = Users.query.filter_by(api_key=uuid).first()
    if not user:
        return jsonify({
            'status': 403,
            'type': 'Error',
            'msg': 'User not found'
        })

    # hash_type lives on Hashes (per-hash), not on Hashfiles: a file can hold
    # mixed types, so match via the HashfileHashes junction and scope the
    # counts to THIS hash_type within each file.
    #
    # One grouped query, not one per hashfile (issue #228). The previous form
    # took a DISTINCT list of hashfile ids and then, for each, ran an ORM
    # Hashfiles.query.get() plus two separate COUNTs -- three round trips per
    # matching file. Joining from Hashfiles and grouping does the same work in
    # a single statement.
    #
    # Joining FROM Hashfiles also subsumes the old `if hashfile is None:
    # continue` guard: a HashfileHashes row pointing at a deleted hashfile has
    # no row to join to, so it drops out instead of needing a lookup to
    # discover it is an orphan.
    rows = db.session.query(
            Hashfiles.id,
            Hashfiles.name,
            Hashfiles.customer_id,
            Hashfiles.owner_id,
            Hashfiles.uploaded_at,
            func.count(Hashes.id),
            func.coalesce(func.sum(case((Hashes.cracked == True, 1), else_=0)), 0),  # noqa: E712
        ) \
        .join(HashfileHashes, HashfileHashes.hashfile_id == Hashfiles.id) \
        .join(Hashes, Hashes.id == HashfileHashes.hash_id) \
        .filter(Hashes.hash_type == hash_type) \
        .group_by(Hashfiles.id) \
        .order_by(Hashfiles.id) \
        .all()

    results = []
    for (hashfile_id, name, customer_id, owner_id,
         uploaded_at, total, cracked) in rows:
        results.append({
            'id': hashfile_id,
            'name': name,
            'customer_id': customer_id,
            'owner_id': owner_id,
            'uploaded_at': uploaded_at.isoformat() if uploaded_at else None,
            'hash_type': hash_type,
            'total_hashes': int(total or 0),
            'cracked_hashes': int(cracked or 0),
        })

    # Structured list (not AlchemyEncoder) because the count fields are
    # derived, not model columns. An empty list with status 200 is the valid
    # "no hashfiles of this type" answer.
    message = {
        'status': 200,
        'type': 'message',
        'hashfiles': results
    }
    return jsonify(message)


# Get Hashtype
@api.route('/v1/getHashType/<int:hashfile_id>', methods=['GET'])
def v1_api_getHashType(hashfile_id):
    if not is_authorized(user=True, agent=True, request=request):
        return redirect("/v1/not_authorized")
    
    update_heartbeat(request.cookies.get('uuid'))
    hashfile_hash = HashfileHashes.query.filter_by(hashfile_id = hashfile_id).first()
    if not hashfile_hash:
        return jsonify({
            'status': 404,
            'type': 'Error',
            'msg': 'Hashfile not found'
        }), 404
    hash = Hashes.query.get(hashfile_hash.hash_id)
    if not hash:
        return jsonify({
            'status': 404,
            'type': 'Error',
            'msg': 'Hash not found'
        }), 404

    message = {
        'status': 200,
        'type': 'message',
        'msg': 'OK',
        'hash_type': hash.hash_type
    }
    return jsonify(message)
