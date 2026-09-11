"""/v1 customer routes: list, create, and a customer's hashfiles.

Carved out of routes.py per issue #441; pure code motion.
"""

from flask import (
    current_app,
    jsonify,
    redirect,
    request,
)
from sqlalchemy import case, func

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
    Users,
    db,
)
from hashview.utils.audit import log_event


@api.route('/v1/customers', methods=['GET'])
def v1_api_get_customers():
    if not is_authorized(user=True, agent=True, request=request):
        return redirect("/v1/not_authorized")

    update_heartbeat(request.cookies.get('uuid'))
    customers = Customers.query.all()
    message = {
        'status': 200,
        'users': alchemy_to_native(customers)
    }
    return jsonify(message)


@api.route('/v1/customers/add', methods=['POST'])
def v1_api_add_customer():
    # Authorization check
    if not is_authorized(user=True, agent=False, request=request):
        return redirect("/v1/not_authorized")

    # Expect JSON body (silent=True so an empty/invalid body returns None
    # instead of raising a 400 HTML page that callers can't parse as JSON)
    customer_data = request.get_json(silent=True)
    if not customer_data:
        return jsonify({
            'status': 400,
            'type': 'Error',
            'msg': 'Missing customer data in request body'
        })

    try:
        # Create DB entry (Customers only has id + name)
        customer_entry = Customers(
            name=customer_data.get('name')
        )
        db.session.add(customer_entry)
        db.session.commit()

        log_event('customer.create', target=f'customer:{customer_entry.id} {customer_entry.name!r}')
        message = {
            'status': 200,
            'type': 'message',
            'msg': 'Customer added',
            'customer_id': customer_entry.id
        }
        return jsonify(message)
    except Exception:
        current_app.logger.exception('API /v1/customers: failed to add customer')
        return jsonify({
            'status': 500,
            'type': 'Error',
            'msg': 'Failed to add customer.'
        })


# List every hashfile belonging to a customer (issue #346). Nested under the
# customer to mirror the web UI's per-customer view; unlike the by-hash-type
# route above, counts are NOT scoped to a single type -- total/cracked cover all
# hashes in the file and hash_type is the file's representative mode (min type,
# matching hashfiles_list()). An unknown customer is a valid empty result
# (status 200, hashfiles: []), not a 404 -- same contract as the by-hash-type
# route.
@api.route('/v1/customers/<int:customer_id>/hashfiles', methods=['GET'])
def v1_api_get_customer_hashfiles(customer_id):
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

    results = []
    for hashfile in Hashfiles.query.filter_by(customer_id=customer_id).all():
        agg = db.session.query(
            func.count(Hashes.id),
            func.coalesce(func.sum(case((Hashes.cracked == True, 1), else_=0)), 0),
            func.min(Hashes.hash_type),
        ).join(HashfileHashes, Hashes.id == HashfileHashes.hash_id) \
         .filter(HashfileHashes.hashfile_id == hashfile.id).first()
        results.append({
            'id': hashfile.id,
            'name': hashfile.name,
            'customer_id': hashfile.customer_id,
            'owner_id': hashfile.owner_id,
            'uploaded_at': hashfile.uploaded_at.isoformat() if hashfile.uploaded_at else None,
            'hash_type': agg[2],
            'total_hashes': int(agg[0] or 0),
            'cracked_hashes': int(agg[1] or 0),
        })

    return jsonify({
        'status': 200,
        'type': 'message',
        'hashfiles': results
    })
