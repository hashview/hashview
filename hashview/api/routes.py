from flask import Blueprint, jsonify, redirect, request, send_from_directory, current_app, url_for
from hashview.models import Agents, JobTasks, Tasks, Wordlists, Rules, Jobs, Hashes, HashfileHashes, Users, HashNotifications
from hashview.utils.utils import save_file, get_md5_hash, update_dynamic_wordlist, update_job_task_status, send_email, send_pushover
from hashview import db
from sqlalchemy.ext.declarative import DeclarativeMeta
import time
import os
import json
import codecs
import secrets

api = Blueprint('api', __name__)

#
# Yeah, i know its bad and should be converted to a legit REST API. 
# This code should be considered tempoary as we work over the port.
# Ideally this will get replaced (along with the agent code) some time later
#

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

def agentAuthorized(uuid):
    agent = Agents.query.filter_by(uuid=uuid).first()
    if agent.status == 'Online' or agent.status == 'Working' or agent.status == 'Idle' or agent.status == 'Authorized':
        return True
    return False

def updateHeartbeat(uuid):
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

# force or restart a queue item
# used when agent goes offline and comes back online
# without a running hashcat cmd while task still assigned to them
@api.route('/v1/queue/<int:id>', methods=['GET'])
def api_get_queue_assignment(id):
    if not agentAuthorized(request.cookies.get('agent_uuid')):
        return redirect("/v1/not_authorized") 

    updateHeartbeat(request.cookies.get('agent_uuid'))

    # Get agent id from UUID
    agent = Agents.query.filter_by(uuid=request.cookies.get('agent_uuid')).first()
    if agent:
        # we really dont need to filter by both id and agent_id :/
        assigned_task = JobTasks.query.filter_by(agent_id=agent.id).first()

        # yeah why keep our response consistant like we did with wordlists and rules :smh:
        return json.dumps(assigned_task, cls=AlchemyEncoder)
    else:
        message = {
            'status': 200,
            'type': 'message',
            'msg': 'Missing UUID'
        }
        return jsonify(message)

# TODO
# isnt this the same thing as /v1/queue/<id>/status? Why do we have both
@api.route('/v1/queue/<int:id>/status', methods=['POST'])
def api_set_queue_assignment_status(id):
    if not agentAuthorized(request.cookies.get('agent_uuid')):
        return redirect("/v1/not_authorized") 

    status_json = request.get_json()
    updateHeartbeat(request.cookies.get('agent_uuid'))
    update_job_task_status(jobtask_id = id, status= status_json['status'])

    message = {
        'status': 200,
        'type': 'message',
        'msg': 'OK'
    }
    return jsonify(message)

# Provide task info 
@api.route('/v1/task/<int:id>', methods=['GET'])
def api_get_task(id):
    if not agentAuthorized(request.cookies.get('agent_uuid')):
        return redirect("/v1/not_authorized")

    updateHeartbeat(request.cookies.get('agent_uuid'))
    task = Tasks.query.get(id)
    # yeah why keep our response consistant like we did with wordlists and rules :smh:
    return json.dumps(task, cls=AlchemyEncoder)


# Provide jobtask info 
@api.route('/v1/jobtask/<int:id>', methods=['GET'])
def api_get_jobtask(id):
    if not agentAuthorized(request.cookies.get('agent_uuid')):
        return redirect("/v1/not_authorized")

    updateHeartbeat(request.cookies.get('agent_uuid'))
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
        return redirect("/v1/not_authorized") 

    status_json = request.get_json()
    updateHeartbeat(request.cookies.get('agent_uuid'))
    update_job_task_status(jobtask_id = id, status = status_json['status'])

    message = {
        'status': 200,
        'type': 'message',
        'msg': 'OK'
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
        updateHeartbeat(uuid)
        if agent.status == 'Authorized':
            # I believe 302 redirects from HTTP posts are not RFC compliant :/
            return redirect("/v1/agents/"+uuid+"/authorize")
        elif agent.status == 'Pending':
            # Agent exists, but has not ben activated. Update heartbeet and turn agent away
            updateHeartbeat(uuid)
            message = {
                'status': 200,
                'type': 'message',
                'msg': 'Go Away'
            }
            return jsonify(message)
        elif agent.status == 'Syncing':
            updateHeartbeat(uuid)
            message = {
                'status': 200,
                'type': 'message',
                'msg': 'OK'
            }
            return jsonify(message)
        else:
            agent_data = request.json

            # Check authorization cookies
            if agent_data['agent_status'] == 'Working':
                # Parse hc_status data
                jobtask_id = agent_data['agent_task']
                jobtask= JobTasks.query.get(jobtask_id)
                agent.status = agent_data['agent_status']

                if agent_data['hc_status']:
                    agent.hc_status = agent_data['agent_status']
                    hc_status = str(agent_data['hc_status']).replace("\'", "\"")             
                    json_response = json.loads(hc_status)
                    agent.benchmark = json_response['Speed # *']
                    agent.hc_status = str(agent_data['hc_status']).replace("\'", "\"")                       

                db.session.commit()

                if not jobtask or jobtask.status == 'Canceled':
                    message = {
                        'status': 200,
                        'type': 'message',
                        'msg': 'Canceled',
                    }
                    return jsonify(message)

            # if agent_status == 'Idle'
            if agent_data['agent_status'] == 'Idle':
                # Clear hc_status if we're idle
                agent.hc_status = ""
                db.session.commit()
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
                    if job_task_entry:
                        job_task_entry.agent_id = agent.id
                        job_task_entry.status = 'Running'
                        db.session.commit()
                        message = {
                            'status': 200,
                            'type': 'message',
                            'msg': 'START',
                            'task_id': job_task_entry.id
                        }
                        return jsonify(message)
                    else:
                        agent.status = 'Idle'
                        db.session.commit()
                        message = {
                            'status': 200,
                            'type': 'message',
                            'msg': 'OK'
                        }
                        return jsonify(message)
            else:
                updateHeartbeat(uuid)
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
        updateHeartbeat(uuid)
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

# Provide wordlist info (really should be plural)
@api.route('/v1/wordlist', methods=['GET'])
def api_get_wordlist():
    if not agentAuthorized(request.cookies.get('agent_uuid')):
        return redirect("/v1/not_authorized")

    updateHeartbeat(request.cookies.get('agent_uuid'))
    wordlists = Wordlists.query.all()
    message = {
        'wordlists': json.dumps(wordlists, cls=AlchemyEncoder)
    }
    return jsonify(message)

# serve a wordlist
@api.route('/v1/wordlist/<int:wordlist_id>', methods=['GET'])
def api_get_wordlist_download(wordlist_id):
    if not agentAuthorized(request.cookies.get('agent_uuid')):
        return redirect("/v1/not_authorized") 

    updateHeartbeat(request.cookies.get('agent_uuid'))
    wordlist = Wordlists.query.get(wordlist_id)
    wordlist_name = wordlist.path.split('/')[-1]
    cmd = "gzip -9 -k -c hashview/control/wordlists/" + wordlist_name + " > hashview/control/tmp/" + wordlist_name + ".gz"

    # What command injection?!
    # TODO
    os.system(cmd)
    return send_from_directory('control/tmp', wordlist_name + '.gz', mimetype = 'application/octet-stream')

# Update Dynamic Wordlist
@api.route('/v1/updateWordlist/<int:wordlist_id>', methods=['GET'])
def api_get_update_wordlist(wordlist_id):
    update_dynamic_wordlist(wordlist_id)
    message = {
        'status': 200,
        'type': 'message',
        'msg': 'OK'
    }
    return jsonify(message)

# Provide rules info (really should be plural)
@api.route('/v1/rules', methods=['GET'])
def api_get_rules():
    if not agentAuthorized(request.cookies.get('agent_uuid')):
        return redirect("/v1/not_authorized") 

    updateHeartbeat(request.cookies.get('agent_uuid'))
    rules = Rules.query.all()
    message = {
        'rules': json.dumps(rules, cls=AlchemyEncoder)
    }
    return jsonify(message)

# serve a rules file
@api.route('/v1/rules/<int:id>', methods=['GET'])
def api_get_rules_download(id):
    if not agentAuthorized(request.cookies.get('agent_uuid')):
        return redirect("/v1/not_authorized") 

    updateHeartbeat(request.cookies.get('agent_uuid'))
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
        return redirect("/v1/not_authorized")

    updateHeartbeat(request.cookies.get('agent_uuid'))
    job = Jobs.query.get(id)
    # yeah why keep our response consistant like we did with wordlists and rules :smh:
    return json.dumps(job, cls=AlchemyEncoder)

# generate and serve hashfile
# TODO 
# Instead of this being a subset under a jobtask, just make this '/v1/hashfile/<int:id>
@api.route('/v1/jobtask/<int:jobtask_id>/hashfile/<int:hashfile_id>', methods=['GET'])
def api_get_hashfile(jobtask_id, hashfile_id):
    if not agentAuthorized(request.cookies.get('agent_uuid')):
        return redirect("/v1/not_authorized")

    updateHeartbeat(request.cookies.get('agent_uuid'))
    
    # we need the jobtask info to make the hashfile path
    jobtask = JobTasks.query.get(jobtask_id)

    hash_file = 'control/hashes/hashfile_' + str(jobtask.job_id) + '_' + str(jobtask.task_id) + '.txt'
    file_object = open('hashview/' + hash_file, 'w')

    # do a left join select to get our ciphertext hashes 
    dbresults = db.session.query(Hashes, HashfileHashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '0').filter(HashfileHashes.hashfile_id==hashfile_id).all()
    for result in dbresults:
        file_object.write(result[0].ciphertext + '\n')
    file_object.close()

    return send_from_directory('control/hashes/', hash_file.split('/')[-1])

@api.route('/v1/jobtask/<int:jobtask_id>/crackfile/upload', methods=['POST'])
def api_put_jobtask_crackfile_upload(jobtask_id):
    if not agentAuthorized(request.cookies.get('agent_uuid')):
        return redirect("/v1/not_authorized")

    updateHeartbeat(request.cookies.get('agent_uuid'))

    # save to file    
    crackfile_path = os.path.join(current_app.root_path, save_file('control/tmp', request.files['file']))

    # parse file

    # Get hashtype
    jobtask = JobTasks.query.get(jobtask_id)
    job = Jobs.query.get(jobtask.job_id)
    hashfilehashes = HashfileHashes.query.filter_by(hashfile_id = job.hashfile_id).first()
    tmphash = Hashes.query.get(hashfilehashes.hash_id)
    hashtype = tmphash.hash_type
    
    # Because the contents of the crack file will be different depending on the hashtype, we'll need to
    # Parse based on what the original hashes were
    file_object = open(crackfile_path, 'r')
    lines = file_object.readlines()

    decode_hex = codecs.getdecoder("hex_codec")

    for entry in lines:
        if hashtype == 1000 or hashtype == 13100 or hashtype == 19200 or hashtype == 19600 or hashtype == 19700 or hashtype == 19800 or hashtype == 19900:
            ciphertext = entry.split(':')[0]
            encoded_plaintext = entry.split(':')[1]
            plaintext = bytes.fromhex(encoded_plaintext.rstrip())
        if hashtype == 5600 or hashtype == 5500:
            print('Entry: '+str(entry))
            ciphertext = entry.split(':')[0] + ":" + entry.split(':')[1].upper() + ":" + entry.split(':')[2].upper() + ":" + entry.split(':')[3].upper() + ":" + entry.split(':')[4].upper() + ":" + entry.split(':')[5].upper()
            ciphertext = ciphertext.lower()
            encoded_plaintext = entry.split(':')[6] # does it make sense to do -1 instead
            plaintext = bytes.fromhex(encoded_plaintext.rstrip())
        #if hashtype == 13100 or hashtype == 19200 or hashtype == 19600 or hashtype == 19700 or hashtype == 19800 or hashtype == 19900:

        # Does doing an import with multiple 'where' clauses make sense here, maybe we just stick with sub_ciphertext only since that _should_ be unique
        record = Hashes.query.filter_by(hash_type=hashtype, sub_ciphertext=get_md5_hash(ciphertext), cracked='0').first()
        if record:
            try:
                record.plaintext = plaintext.decode('UTF-8')
                record.cracked = 1
                db.session.commit()
            except:
                print('Attempted to import non UTF-8 character: ' + str(encoded_plaintext))


    # delete file
    os.remove(crackfile_path)

    # Send Hash Completion Notifications
    hash_notifications = HashNotifications.query.all()
    for hash_notification in hash_notifications:
        user = Users.query.get(hash_notification.owner_id)
        message = "Congratulations, a hash has been recovered!: \n\n"
        
        # Check if hash is cracked
        hash = Hashes.query.get(hash_notification.hash_id)
        if hash.cracked:

            message += 'You can check the results using the following link: ' + "\n"
            message += url_for('searches.searches_list', hash_id=hash.id, _external=True)
            if hash_notification.method == 'email':
                send_email(user, 'Hashview User Hash Recovered!', message)
            elif hash_notification.method == 'push':
                if user.pushover_key and user.pushover_id:
                    send_pushover(user, 'Message from Hashview', message)
            else:
                send_email(user, 'Hashview: Missing Pushover Key', 'Hello, you were due to recieve a pushover notification, but because your account was not provisioned with an pushover ID and Key, one could not be set. Please log into hashview and set these options under Manage->Profile.')
            db.session.delete(hash_notification)
            db.session.commit()

    message = {
        'status': 200,
        'type': 'message',
        'msg': 'OK'
    }
    return jsonify(message)

@api.route('/v1/agents/<int:uuid>/stats', methods=['POST'])
def api_set_stats(uuid):
    if not agentAuthorized(request.cookies.get('agent_uuid')):
        return redirect("/v1/not_authorized") 

    agent = Agents.query.filter_by(uuid=uuid).first()
    
    if (request.cookies.get('cpu_count')):
        agent.cpu_count = request.cookies.get('cpu_count')
    
    if (request.cookies.get('gpu_count')):
        agent.gpu_count = request.cookies.get('gpu_count')

    if (request.cookies.get('bechmark')):
        agent.benchmark = request.cookies.get('benchmark')
    
    db.session.commit()

    message = {
        'status': 200,
        'type': 'message',
        'msg': 'OK'
    }
    return jsonify(message)


#####
# v2 api functions, V1 will be removed at some point
@api.route('/v2/agents/heartbeat', methods=['POST'])
def v2_api_set_agent_heartbeat():
    # Get uuid
    uuid = request.cookies.get('uuid')

    # Get agent from db
    agent = Agents.query.filter_by(uuid=uuid).first()
    if not agent:
        # no agent found, time to add it to our db
        new_agent = Agents( name = request.cookies.get('name'),
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
        updateHeartbeat(uuid)
        if agent.status == 'Pending':
            # Agent exists, but has not ben activated. Update heartbeet and turn agent away
            updateHeartbeat(uuid)
            message = {
                'status': 200,
                'type': 'message',
                'msg': 'Go Away'
            }
            return jsonify(message)            
        else: 
            # check if job_task
            agent_data = request.get_json()

            # Check authorization cookies
            if agent_data['agent_status'] == 'Working':
                agent.status = 'Working'
                # Check to see if task was canceled
                jobtask = JobTasks.query.filter_by(agent_id = agent.id).first()
                if not jobtask or jobtask.status == 'Canceled':
                    message = {
                        'status': 200,
                        'type': 'message',
                        'msg': 'Canceled',
                    }
                    return jsonify(message)

                if agent_data['hc_status']:
                    agent.hc_status = agent_data['agent_status']
                    hc_status = str(agent_data['hc_status']).replace("\'", "\"")             
                    json_response = json.loads(hc_status)
                    agent.benchmark = json_response['Speed #']
                    agent.hc_status = str(agent_data['hc_status']).replace("\'", "\"")                       

                db.session.commit()                

            if agent_data['agent_status'] == 'Idle':
                # Clear hc_status if we're idle
                agent.status = "Idle"
                agent.hc_status = ""
                db.session.commit()
                already_assigned_task = JobTasks.query.filter_by(agent_id = agent.id).first()
                if already_assigned_task != None:
                    message = {
                        'status': 200,
                        'type': 'message',
                        'msg': 'START',
                        'job_task_id': already_assigned_task.id
                    }
                    return jsonify(message)
                else:
                    # Get first unassigned jobtask and 'assign' it to this agent
                    job_task_entry = JobTasks.query.filter_by(status = 'Queued').first()
                    if job_task_entry:
                        job_task_entry.agent_id = agent.id
                        job_task_entry.status = 'Running'
                        db.session.commit()
                        message = {
                            'status': 200,
                            'type': 'message',
                            'msg': 'START',
                            'job_task_id': job_task_entry.id
                        }
                        return jsonify(message)
                updateHeartbeat(uuid)
                message = {
                    'status': 200,
                    'type': 'message',
                    'msg': 'OK'
                }
                return jsonify(message)
            else:
                updateHeartbeat(uuid)
                message = {
                    'status': 200,
                    'type': 'message',
                    'msg': 'OK'
                }
                return jsonify(message)

@api.route('/v2/rules', methods=['GET'])
def v2_api_get_rules():
    if not agentAuthorized(request.cookies.get('uuid')):
        return redirect("/v1/not_authorized") 

    updateHeartbeat(request.cookies.get('uuid'))
    rules = Rules.query.all()
    message = {
        'rules': json.dumps(rules, cls=AlchemyEncoder)
    }
    return jsonify(message)

# serve a rules file
@api.route('/v2/rules/<int:rules_id>', methods=['GET'])
def v2_api_get_rules_download(rules_id):
    if not agentAuthorized(request.cookies.get('uuid')):
        return redirect("/v1/not_authorized") 

    updateHeartbeat(request.cookies.get('uuid'))
    rules = Rules.query.get(rules_id)
    rules_name = rules.path.split('/')[-1]
    cmd = "gzip -9 -k -c hashview/control/rules/" + rules_name + " > hashview/control/tmp/" + rules_name + ".gz"

    # What command injection?!
    # TODO
    os.system(cmd)
    return send_from_directory('control/tmp', rules_name + '.gz', mimetype = 'application/octet-stream')    

# Provide wordlist info (really should be plural)
@api.route('/v2/wordlists', methods=['GET'])
def v2_api_get_wordlist():
    if not agentAuthorized(request.cookies.get('uuid')):
        return redirect("/v1/not_authorized") 

    updateHeartbeat(request.cookies.get('uuid'))
    wordlists = Wordlists.query.all()
    message = {
        'wordlists': json.dumps(wordlists, cls=AlchemyEncoder)
    }
    return jsonify(message)

# serve a wordlist
@api.route('/v2/wordlists/<int:wordlist_id>', methods=['GET'])
def v2_api_get_wordlist_download(wordlist_id):
    if not agentAuthorized(request.cookies.get('uuid')):
        return redirect("/v1/not_authorized") 

    updateHeartbeat(request.cookies.get('uuid'))
    wordlist = Wordlists.query.get(wordlist_id)
    wordlist_name = wordlist.path.split('/')[-1]
    cmd = "gzip -9 -k -c hashview/control/wordlists/" + wordlist_name + " > hashview/control/tmp/" + wordlist_name + ".gz"

    # What command injection?!
    # TODO
    os.system(cmd)
    return send_from_directory('control/tmp', wordlist_name + '.gz', mimetype = 'application/octet-stream')

# Update Dynamic Wordlist
@api.route('/v2/updateWordlist/<int:wordlist_id>', methods=['GET'])
def v2_api_get_update_wordlist(wordlist_id):
    if not agentAuthorized(request.cookies.get('uuid')):
        return redirect("/v1/not_authorized") 

    updateHeartbeat(request.cookies.get('uuid'))
    update_dynamic_wordlist(wordlist_id)
    message = {
        'status': 200,
        'type': 'message',
        'msg': 'OK'
    }
    return jsonify(message)    

# force or restart a queue item
# used when agent goes offline and comes back online
# without a running hashcat cmd while task still assigned to them
@api.route('/v2/jobTasks/<int:job_task_id>', methods=['GET'])
def v2_api_get_queue_assignment(job_task_id):
    if not agentAuthorized(request.cookies.get('uuid')):
        return redirect("/v1/not_authorized") 

    updateHeartbeat(request.cookies.get('uuid'))

    # Get agent id from UUID
    agent = Agents.query.filter_by(uuid=request.cookies.get('uuid')).first()
    job_task = JobTasks.query.filter_by(agent_id=agent.id).first()

    message = {
        'job_task': json.dumps(job_task, cls=AlchemyEncoder)
    }
    return jsonify(message)

# Provide job info 
@api.route('/v2/jobs/<int:job_id>', methods=['GET'])
def v2_api_get_job(job_id):
    if not agentAuthorized(request.cookies.get('uuid')):
        return redirect("/v1/not_authorized") 

    updateHeartbeat(request.cookies.get('uuid'))
    job = Jobs.query.get(job_id)

    message = {
        'job': json.dumps(job, cls=AlchemyEncoder)
    }
    return jsonify(message)

# Provide task info 
@api.route('/v2/tasks/<int:task_id>', methods=['GET'])
def v2_api_get_task(task_id):
    if not agentAuthorized(request.cookies.get('uuid')):
        return redirect("/v1/not_authorized") 

    updateHeartbeat(request.cookies.get('uuid'))

    task = Tasks.query.get(task_id)

    message = {
        'task': json.dumps(task, cls=AlchemyEncoder)
    }
    return jsonify(message)

# generate and serve hashfile
@api.route('/v2/hashfiles/<int:hashfile_id>', methods=['GET'])
def v2_api_get_hashfile(hashfile_id):
    if not agentAuthorized(request.cookies.get('uuid')):
        return redirect("/v1/not_authorized") 

    updateHeartbeat(request.cookies.get('uuid'))
    
    # we need the jobtask info to make the hashfile path
    #jobtask = JobTasks.query.get(jobtask_id)

    #hash_file = 'control/hashes/hashfile_' + str(jobtask.job_id) + '_' + str(jobtask.task_id) + '.txt'
    random_hex = secrets.token_hex(8)
    file_object = open('hashview/control/tmp/' + random_hex, 'w')

    # do a left join select to get our ciphertext hashes 
    dbresults = db.session.query(Hashes, HashfileHashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '0').filter(HashfileHashes.hashfile_id==hashfile_id).all()
    for result in dbresults:
        file_object.write(result[0].ciphertext + '\n')
    file_object.close()

    return send_from_directory('control/tmp/', random_hex)

# Upload Cracked Hashes
@api.route('/v2/uploadCrackFile/<int:hash_type>', methods=['POST'])
def v2_api_put_jobtask_crackfile_upload(hash_type):
    if not agentAuthorized(request.cookies.get('uuid')):
        return redirect("/v1/not_authorized") 

    updateHeartbeat(request.cookies.get('uuid'))

    # save to file    
    file_contents = request.get_json()

    #crackfile_path = os.path.join(current_app.root_path, save_file('control/tmp', file_contents['file']))

    hashtype = hash_type
    
    # Because the contents of the crack file will be different depending on the hashtype, we'll need to
    # Parse based on what the original hashes were
    #file_object = open(crackfile_path, 'r')
    #lines = file_object.readlines()
    #lines = file_contents['file'].readlines()

    decode_hex = codecs.getdecoder("hex_codec")

    #for entry in lines:
    for entry in file_contents['file'].split('\n'):
        if ':' in entry:
            if hashtype == 1000 or hashtype == 1800 or hashtype == 2100 or hashtype == 13100 or hashtype == 19200 or hashtype == 19600 or hashtype == 19700 or hashtype == 19800 or hashtype == 19900:
                ciphertext = entry.split(':')[0]
                encoded_plaintext = entry.split(':')[1]
                plaintext = bytes.fromhex(encoded_plaintext.rstrip())
            if hashtype == 5600 or hashtype == 5500:
                print('Entry: '+str(entry))
                ciphertext = entry.split(':')[0] + ":" + entry.split(':')[1].upper() + ":" + entry.split(':')[2].upper() + ":" + entry.split(':')[3].upper() + ":" + entry.split(':')[4].upper() + ":" + entry.split(':')[5].upper()
                ciphertext = ciphertext.lower()
                encoded_plaintext = entry.split(':')[6] # does it make sense to do -1 instead
                plaintext = bytes.fromhex(encoded_plaintext.rstrip())
            #if hashtype == 13100 or hashtype == 19200 or hashtype == 19600 or hashtype == 19700 or hashtype == 19800 or hashtype == 19900:

            # Does doing an import with multiple 'where' clauses make sense here, maybe we just stick with sub_ciphertext only since that _should_ be unique
            record = Hashes.query.filter_by(hash_type=hashtype, sub_ciphertext=get_md5_hash(ciphertext), cracked='0').first()
            if record:
                try:
                    record.plaintext = plaintext.decode('UTF-8')
                    record.cracked = 1
                    db.session.commit()
                except:
                    print('Attempted to import non UTF-8 character: ' + str(encoded_plaintext))


    # delete file
    #os.remove(crackfile_path)

    # Send Hash Completion Notifications
    hash_notifications = HashNotifications.query.all()
    for hash_notification in hash_notifications:
        user = Users.query.get(hash_notification.owner_id)
        message = "Congratulations, a hash has been recovered!: \n\n"
        
        # Check if hash is cracked
        hash = Hashes.query.get(hash_notification.hash_id)
        if hash.cracked:

            message += 'You can check the results using the following link: ' + "\n"
            message += url_for('searches.searches_list', hash_id=hash.id, _external=True)
            if hash_notification.method == 'email':
                send_email(user, 'Hashview User Hash Recovered!', message)
            elif hash_notification.method == 'push':
                if user.pushover_key and user.pushover_id:
                    send_pushover(user, 'Message from Hashview', message)
            else:
                send_email(user, 'Hashview: Missing Pushover Key', 'Hello, you were due to recieve a pushover notification, but because your account was not provisioned with an pushover ID and Key, one could not be set. Please log into hashview and set these options under Manage->Profile.')
            db.session.delete(hash_notification)
            db.session.commit()

    message = {
        'status': 200,
        'type': 'message',
        'msg': 'OK'
    }
    return jsonify(message)

# Get Hashtype
@api.route('/v2/getHashType/<int:hashfile_id>', methods=['GET'])
def v2_api_getHashType(hashfile_id):
    if not agentAuthorized(request.cookies.get('uuid')):
        return redirect("/v1/not_authorized") 

    updateHeartbeat(request.cookies.get('uuid'))
    hashfile_hash = HashfileHashes.query.filter_by(hashfile_id = hashfile_id).first()
    hash = Hashes.query.get(hashfile_hash.hash_id)

    message = {
        'status': 200,
        'type': 'message',
        'msg': 'OK',
        'hash_type': hash.hash_type
    }
    return jsonify(message)

# Update JobTask status
@api.route('/v2/jobtask/status', methods=['POST'])
def v2_api_set_queue_jobtask_status():
    if not agentAuthorized(request.cookies.get('uuid')):
        return redirect("/v1/not_authorized") 

    updateHeartbeat(request.cookies.get('uuid'))

    status_json = request.get_json()
    update_job_task_status(jobtask_id = status_json['job_task_id'], status = status_json['task_status'])

    message = {
        'status': 200,
        'type': 'message',
        'msg': 'OK'
    }
    return jsonify(message)