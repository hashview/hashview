from flask import Blueprint, jsonify, redirect, request, send_from_directory
from hashview.models import TaskQueues, Agents, JobTasks, Tasks, Wordlists, Rules, Jobs, Hashes, HashfileHashes
from hashview import db
import time
import os

api = Blueprint('api', __name__)

#
# Yeah, i know its bad and should be converted to a legit REST API. 
# This code should be considered tempoary as we work over the port.
# Ideally this will get replaced (along with the agent code) some time later
#
def agentAuthorized(uuid):
    agent = Agents.query.filter_by(uuid=uuid).first()
    if agent.status == 'Online':
        return True
    return False

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
def api_get_queue():
    if not agentAuthorized(request.cookies.get('agent_uuid')):
        return redirect("/v1/agents/"+uuid+"/authorize") 

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

# force or restart a queue item
# used when agent goes offline and comes back online
# without a running hashcat cmd while task still assigned to them
@api.route('/v1/queue/<int:id>', methods=['GET'])
def api_get_queue_assignment(id):
    if not agentAuthorized(request.cookies.get('agent_uuid')):
        return redirect("/v1/agents/"+uuid+"/authorize") 

    update_heartbeat(request.cookies.get('agent_uuid'))

    # Get agent id from UUID
    agent = Agents.query.filter_by(uuid=request.cookies.get('agent_uuid')).first()
    if agent:
        # we really dont need to filter by both id and agent_id :/
        assigned_task = JobTasks.query.filter_by(id=id, agent_id=agent.id).first()
        # yeah why keep our response consistant like we did with wordlists and rules :smh:
        return json.dumps(assigned_task, cls=AlchemyEncoder)
    else:
        message = {
            'status': 200,
            'type': 'message',
            'msg': 'Missing UUID'
        }
        return jsonify(message)

# Provide task info 
@api.route('/v1/task/<int:id>', methods=['GET'])
def api_get_task(id):
    if not agentAuthorized(request.cookies.get('agent_uuid')):
        return redirect("/v1/agents/"+uuid+"/authorize")

    update_heartbeat(request.cookies.get('agent_uuid'))
    task = Tasks.query.get(id)
    # yeah why keep our response consistant like we did with wordlists and rules :smh:
    return json.dumps(task, cls=AlchemyEncoder)


# Provide jobtask info 
@api.route('/v1/jobtask/<int:id>', methods=['GET'])
def api_get_jobtask(id):
    if not agentAuthorized(request.cookies.get('agent_uuid')):
        return redirect("/v1/agents/"+uuid+"/authorize")

    update_heartbeat(request.cookies.get('agent_uuid'))
    jobtask = JobTasks.query.filter_by(task_id=id).first()
    # yeah why keep our response consistant like we did with wordlists and rules :smh:
    return json.dumps(jobtask, cls=AlchemyEncoder)


# update status of jobtask
# TODO
# We dont really need the id here since we're pulling the jobtask.id from the json being posted
# might make sense to move this to something like /v1/queue/jobtask/status
@api.route('/v1/jobtask/<int:id>/status', methods=['POST'])
def api_set_queue_jobtask_status(id):
    if not agentAuthorized(request.cookies.get('agent_uuid')):
        return redirect("/v1/agents/"+uuid+"/authorize") 

    update_heartbeat(request.cookies.get('agent_uuid'))

    # TODO
    # Do we really care at this point that an agent exists for this?
    # Get agent id from UUID
    agent = Agents.query.filter_by(uuid=request.cookies.get('agent_uuid')).first()
    if agent:
        status_json = request.get_json()

        # TODO
        # Change the key from taskqueue_id to jobtask_id
        jobtasks = JobTasks.query.get(status_json['jobtask_id'])
        jobtasks.status = status_json['status']
        db.session.commit()

        # Update Jobs
        # TODO
        # Change the key from taskqueue_id to jobtask_id
        # Shouldn't we be changing the job stats to match the jobtask status?
        # Add started at time
        job = Jobs.query.get(jobtasks.job_id)
        if job.status == 'Queued':
            job.status = 'Running'
            job.started_at = time.strftime('%Y-%m-%d %H:%M:%S')
            db.session.commit()

        # TODO
        # This is such a janky way of doing this. Instead of having the agent tell us its done, we're just assuming
        # That if no other tasks are active we must be done
        done = True
        jobtasks = JobTasks.query.all()
        for jobtask in jobtasks:
            if jobtask.status == 'Queued' or jobtask.status == 'Running' or jobtask.status == 'Importing':
                done = False
        
        # Send email if completed
        # TODO
        if job.notify_completed == True and done == True:
            print('send completed email notification')
        
        # TODO
        # Add ended_at time
        if done:
            job.status = 'Completed'
            db.session.commit()

            # TODO
            # Calculate time difference in hashfile and update it
            diff = time.strftime('%Y-%m-%d %H:%M:%S') - job.started_at
            print('diff in time: ' + str(diff))

            #TODO
            # mark all jobtasks as completed
   
        message = {
            'status': 200,
            'type': 'message',
            'msg': 'OK'
        }
        return jsonify(message)
    else:
        message = {
            'status': 200,
            'type': 'message',
            'msg': 'Missing UUID'
        }
        return jsonify(message)

@api.route('/v1/agents/<uuid>/heartbeat', methods=['POST'])
def api_set_agent_heartbeat(uuid):
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
                    message = {
                        'status': 200,
                        'type': 'message',
                        'msg': 'START',
                        'task_id': already_assigned_task.id
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
def api_get_wordlist():
    if not agentAuthorized(request.cookies.get('agent_uuid')):
        return redirect("/v1/agents/"+uuid+"/authorize")

    update_heartbeat(request.cookies.get('agent_uuid'))
    wordlists = Wordlists.query.all()
    message = {
        'wordlists': json.dumps(wordlists, cls=AlchemyEncoder)
    }
    return jsonify(message)

# serve a wordlist
@api.route('/v1/wordlist/<int:id>', methods=['GET'])
def api_get_wordlist_download(id):
    if not agentAuthorized(request.cookies.get('agent_uuid')):
        return redirect("/v1/agents/"+uuid+"/authorize") 

    update_heartbeat(request.cookies.get('agent_uuid'))
    wordlist = Wordlists.query.get(id)
    wordlist_name = wordlist.path.split('/')[-1]
    cmd = "gzip -9 -k -c hashview/control/wordlists/" + wordlist_name + " > hashview/control/tmp/" + wordlist_name + ".gz"

    # What command injection?!
    # TODO
    os.system(cmd)
    return send_from_directory('control/tmp', wordlist_name + '.gz', mimetype = 'application/octet-stream')

# Provide rules info (really should be plural)
@api.route('/v1/rules', methods=['GET'])
def api_get_rules():
    if not agentAuthorized(request.cookies.get('agent_uuid')):
        return redirect("/v1/agents/"+uuid+"/authorize") 

    update_heartbeat(request.cookies.get('agent_uuid'))
    rules = Rules.query.all()
    message = {
        'rules': json.dumps(rules, cls=AlchemyEncoder)
    }
    return jsonify(message)

# serve a rules file
@api.route('/v1/rules/<int:id>', methods=['GET'])
def api_get_rules_download(id):
    if not agentAuthorized(request.cookies.get('agent_uuid')):
        return redirect("/v1/agents/"+uuid+"/authorize") 

    update_heartbeat(request.cookies.get('agent_uuid'))
    rules = Rules.query.get(id)
    rules_name = rules.path.split('/')[-1]
    cmd = "gzip -9 -k -c hashview/control/rules/" + rules_name + " > hashview/control/tmp/" + rules_name + ".gz"

    # What command injection?!
    # TODO
    os.system(cmd)
    return send_from_directory('control/tmp', rules_name + '.gz', mimetype = 'application/octet-stream')

# Provide job info 
@api.route('/v1/job/<int:id>', methods=['GET'])
def api_get_job(id):
    if not agentAuthorized(request.cookies.get('agent_uuid')):
        return redirect("/v1/agents/"+uuid+"/authorize")

    update_heartbeat(request.cookies.get('agent_uuid'))
    job = Jobs.query.get(id)
    # yeah why keep our response consistant like we did with wordlists and rules :smh:
    return json.dumps(job, cls=AlchemyEncoder)

# generate and serve hashfile
# TODO 
# Instead of this being a subset under a jobtask, just make this '/v1/hashfile/<int:id>
@api.route('/v1/jobtask/<int:jobtask_id>/hashfile/<int:hashfile_id>', methods=['GET'])
def api_get_hashfile(jobtask_id, hashfile_id):
    if not agentAuthorized(request.cookies.get('agent_uuid')):
        return redirect("/v1/agents/"+uuid+"/authorize")

    update_heartbeat(request.cookies.get('agent_uuid'))
    
    # we need the jobtask info to make the hashfile path
    jobtask = JobTasks.query.get(jobtask_id)

    hash_file = 'control/hashes/hashfile_' + str(jobtask.job_id) + '_' + str(jobtask.task_id) + '.txt'
    file_object = open('hashview/' + hash_file, 'w')

    # do a left join select to get our ciphertext hashes 
    dbresults = db.session.query(Hashes, HashfileHashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '0').filter(HashfileHashes.hashfile_id==hashfile_id).all()
    for result in dbresults:
        file_object.write(result[0].ciphertext + '\n')
        #print(result[0].ciphertext)
    file_object.close()

    return send_from_directory('control/hashes/', hash_file.split('/')[-1])

    