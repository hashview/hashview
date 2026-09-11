"""Shared plumbing for the /v1 API blueprint.

The `api` Blueprint lives here rather than in routes.py so every
hashview/api/<resource>.py module can register on it without importing its
siblings. Alongside it sit the pieces every resource module needs: the
serializer with its secret denylist, the authorization gate, the agent
heartbeat stamp, and the error envelope.

Split out of routes.py, which had grown past 2,600 lines and ~38 handlers
(issue #441). Pure code motion -- nothing here changed behaviour on the way
across.
"""
import json

from flask import Blueprint, request
from packaging import version
from sqlalchemy import func
from sqlalchemy.ext.declarative import DeclarativeMeta

import hashview
from hashview.models import Agents, Users, db

api = Blueprint('api', __name__)

#
# Yeah, i know its bad and should be converted to a legit REST API.
# This code should be considered tempoary as we work over the port.
# Ideally this will get replaced (along with the agent code) some time later
#

# Column names that must NEVER be serialized to an API/agent response,
# regardless of which model is being dumped — secrets + credential material.
# (/v1/admin/settings is reachable by any authorized user OR agent, so a stored
# secret would otherwise leak to every agent.)
_ENCODER_DENYLIST = frozenset({
    'password', 'api_key',
    'azure_client_secret', 'slack_bot_token',
})

class AlchemyEncoder(json.JSONEncoder):

    def default(self, obj):
        if isinstance(obj.__class__, DeclarativeMeta):
            # an SQLAlchemy class
            fields = {}
            for field in [x for x in dir(obj)
                          if not x.startswith('_')
                          and x != 'metadata'
                          and x not in _ENCODER_DENYLIST]:
                data = obj.__getattribute__(field)
                try:
                    json.dumps(data) # this will fail on non-encodable values, like other classes
                    fields[field] = data
                except TypeError:
                    fields[field] = None
            # a json-encodable dict
            return fields

        return json.JSONEncoder.default(self, obj)

def alchemy_to_native(obj):
    """Serialize SQLAlchemy row(s) to native Python (list/dict) using the same
    field selection as AlchemyEncoder, so jsonify encodes the response body
    exactly once. This replaces the `json.dumps(rows, cls=AlchemyEncoder)`
    inside `jsonify({...})` pattern, which nested a JSON-encoded string in the
    response and forced clients to double-parse (issue #229). None passes
    through (-> JSON null)."""
    if isinstance(obj, list | tuple):
        return [alchemy_to_native(item) for item in obj]
    if isinstance(obj.__class__, DeclarativeMeta):
        return AlchemyEncoder().default(obj)
    return obj

def is_authorized(user, agent, request):
    # Honor the caller's user/agent flags so each route enforces its own
    # privilege boundary: a user-only route (user=True, agent=False) must
    # reject agent credentials, and an agent-only route (user=False,
    # agent=True) must reject user credentials. Previously this ignored both
    # flags and returned True for ANY valid user OR agent, letting agents hit
    # user-only routes and users hit agent-only routes.
    uuid = request.cookies.get('uuid')
    # Reject an absent/empty credential outright. Without this, a request with
    # no 'uuid' cookie passes None to userAuthorized()/agentAuthorized(), which
    # run filter_by(api_key=None)/filter_by(uuid=None) -> "WHERE col IS NULL".
    # api_key is nullable and is NOT set at user creation (only via
    # /profile/generate_api_key), so a NULL match would impersonate any
    # key-less user. (The old `if request.cookies` check was defeated by sending
    # any unrelated cookie with no uuid.)
    if not uuid:
        return False
    if user and userAuthorized(uuid):
        return True
    if agent and agentAuthorized(uuid):
        return True
    return False

def userAuthorized(uuid):
    user = Users.query.filter_by(api_key=uuid).first()
    if user:
        return True
    return False

def agentAuthorized(uuid):
    agent = Agents.query.filter_by(uuid=uuid).first()
    if agent:
        if agent.status == 'Online' or agent.status == 'Working' or agent.status == 'Idle' or agent.status == 'Authorized':
            return True
    return False

def update_heartbeat(uuid):
    agent = Agents.query.filter_by(uuid=uuid).first()
    if agent:
        agent.src_ip = request.remote_addr
        # Stamp with the DATABASE's clock (func.now()) rather than a Python datetime.
        # The heartbeat writer and the dashboard renderer can run in different process
        # timezones (e.g. UTC vs the host's local time); using the single DB clock for
        # both the write and the online/offline cutoff makes the comparison
        # timezone-independent and stops live agents from being shown as offline.
        agent.last_checkin = func.now()
        db.session.commit()

def versionCheck(agent_version):
    if agent_version:
        if version.parse(agent_version) < version.parse(hashview.__version__):
            return False
        return True
    else:
        return False

def _error(status, msg):
    """The house {status, type, msg} envelope for a refusal.

    Returned as HTTP 200 with the code in the body, which is what this endpoint
    has always done and what 35 other validation failures in this file do. Real
    HTTP codes appear elsewhere in /v1 only for 404 and 409.
    """
    return {'status': status, 'type': 'Error', 'msg': msg}
