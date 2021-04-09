from flask import Blueprint, jsonify, redirect, request, send_from_directory
from hashview.models import TaskQueues, Agents, JobTasks, Tasks, Wordlists, Rules
from hashview import db
import time
import os

api = Blueprint('api', __name__)

#
# Yeah, i know its bad and should be converted to a legit REST API. 
# This code should be considered tempoary as we work over the port.
# Ideally this will get replaced (along with the agent code) some time later
#


def update_heartbeat(uuid):
    agent = Agents.query.filter_by(uuid=uuid).first()
    if agent:
        agent.src_ip = request.remote_addr
        agent.last_checkin = time.strftime('%Y-%m-%d %H:%M:%S')
        db.session.commit()

@api.route('/v1/not_authorized', methods=['GET', 'POST'])
def api_unauthorized():
    message = {
        'status': 200,
        'type': 'Error',
        'msg': 'Your agent is not authorized to work with this cluster.'
    }
    return jsonify(message)

@api.route('/v1/queue', methods=['GET'])
def api_queue():
    # TO DO CHECK IF AUTHORIZED
    queue = TaskQueues.query.filter_by(status = 'Queued').first()
    if queue:
        message = {
            # TODO
            'status': 200,
            'msg': 'todo'
        }
    else:
        message = {
            'status': 200,
            'type': 'Error',
            'msg': 'There are no items on the queue to process'
        }
    return jsonify(message)

@api.route('/v1/agents/<uuid>/heartbeat', methods=['POST'])
def api_heartbeat(uuid):
    # Get agent from db
    agent = Agents.query.filter_by(uuid=uuid).first()
    if not agent:
        # no agent found, time to add it to our db
        new_agent = Agents( name = uuid,
                        src_ip = request.remote_addr,
                        uuid = uuid,
                        status = 'Pending',
                        last_checkin = time.strftime('%Y-%m-%d %H:%M:%S'))
        db.session.add(new_agent)
        db.session.commit()
        message = {
            'status': 200,
            'type': 'message',
            'msg': 'Go Away'
        }
        return jsonify(message)

    else:
        if agent.status == 'Authorized':
            # I believe 302 redirects from HTTP posts are not RFC compliant :/
            return redirect("/v1/agents/"+uuid+"/authorize")
        elif agent.status == 'Pending':
            # Agent exists, but has not ben activated. Update heartbeet and turn agent away
            update_heartbeat(uuid)
            message = {
                'status': 200,
                'type': 'message',
                'msg': 'Go Away'
            }
            return jsonify(message)
        elif agent.status == 'Syncing':
            update_heartbeat(uuid)
            message = {
                'status': 200,
                'type': 'message',
                'msg': 'OK'
            }
            return jsonify(message)
        else:
            agent_data = request.json
            # Check authorization cookies
            # if agent_status == working parse output
            # if agent_status == 'Idle'
            if agent_data['agent_status'] == 'Idle':
                already_assigned_task = JobTasks.query.filter_by(agent_id = agent.id).first()
                if already_assigned_task != None:
                    print(str(already_assigned_task.agent_id))
                    print(str(already_assigned_task.id))
                    print(str(already_assigned_task))
                    message = {
                        'status': 200,
                        'type': 'message',
                        'msg': 'START',
                        'task_id': already_assigned_task.task_id
                    }
                    return jsonify(message)
                else:
                    # Get first unassigned jobtask and 'assign' it to this agent
                    job_task_entry = JobTasks.query.filter_by(status = 'Queued').first()
                    job_task_entry.agent_id = agent.id
                    db.session.commit()
                    message = {
                        'status': 200,
                        'type': 'message',
                        'msg': 'START',
                        'task_id': job_task_entry.task_id
                    }
                    return jsonify(message)
            else:
                update_heartbeat(uuid)
                message = {
                    'status': 200,
                    'type': 'message',
                    'msg': 'OK'
                }
                return jsonify(message)

# Method required POST since we're 302 redirected from a HTTP/POST heartbeat
@api.route('/v1/agents/<uuid>/authorize', methods=['GET', 'POST'])
def api_authorize(uuid):

    agent = Agents.query.filter_by(uuid=uuid).first()
    if agent:
        update_heartbeat(uuid)
        if agent.status == 'Authorized':
            agent.status = 'Online'
            db.session.commit()
            message = {
                'status': 200,
                'type': 'message',
                'msg': 'Authorized'
            }
            return jsonify(message)
        else:
            message = {
                'status': 200,
                'type': 'message',
                'msg': 'Not Authorized'
            }
            return jsonify(message)
    else:
        message = {
            'status': 200,
            'type': 'message',
            'msg': 'Not Authorized'
        }
        return jsonify(message)

from sqlalchemy.ext.declarative import DeclarativeMeta
import json

class AlchemyEncoder(json.JSONEncoder):

    def default(self, obj):
        if isinstance(obj.__class__, DeclarativeMeta):
            # an SQLAlchemy class
            fields = {}
            for field in [x for x in dir(obj) if not x.startswith('_') and x != 'metadata']:
                data = obj.__getattribute__(field)
                try:
                    json.dumps(data) # this will fail on non-encodable values, like other classes
                    fields[field] = data
                except TypeError:
                    fields[field] = None
            # a json-encodable dict
            return fields

        return json.JSONEncoder.default(self, obj)

# Provide wordlist info (really should be plural)
@api.route('/v1/wordlist', methods=['GET'])
def api_wordlist():
    # TODO
    # Redirect if not authorized
    wordlists = Wordlists.query.all()
    message = {
        'wordlists': json.dumps(wordlists, cls=AlchemyEncoder)
    }
    return jsonify(message)

# serve a wordlist
@api.route('/v1/wordlist/<int:id>', methods=['GET'])
def api_wordlist_download(id):
    # Redirect if not authorized
    # TODO
    wordlist = Wordlists.query.get(id)
    wordlist_name = wordlist.path.split('/')[-1]
    cmd = "gzip -9 -k -c hashview/control/wordlists/" + wordlist_name + " > hashview/control/tmp/" + wordlist_name + ".gz"

    # What command injection?!
    # TODO
    os.system(cmd)
    return send_from_directory('control/tmp', wordlist_name + '.gz', mimetype = 'application/octet-stream')

# Provide rules info (really should be plural)
@api.route('/v1/rules', methods=['GET'])
def api_rules():
    # TODO
    # Redirect if not authorized
    rules = Rules.query.all()
    message = {
        'rules': json.dumps(rules, cls=AlchemyEncoder)
    }
    return jsonify(message)

# serve a rules file
@api.route('/v1/rules/<int:id>', methods=['GET'])
def api_rules_download(id):
    # Redirect if not authorized
    # TODO
    rules = Rules.query.get(id)
    rules_name = rules.path.split('/')[-1]
    cmd = "gzip -9 -k -c hashview/control/rules/" + rules_name + " > hashview/control/tmp/" + rules_name + ".gz"

    # What command injection?!
    # TODO
    os.system(cmd)
    return send_from_directory('control/tmp', rules_name + '.gz', mimetype = 'application/octet-stream')
