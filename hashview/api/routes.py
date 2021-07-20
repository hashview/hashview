from flask import Blueprint, jsonify, redirect, request, send_from_directory, current_app
import sqlalchemy
from hashview.models import HashNotifications, TaskQueues, Agents, JobTasks, Tasks, Wordlists, Rules, Jobs, Hashes, HashfileHashes, JobNotifications, Users, Hashfiles
from hashview.utils.utils import save_file, get_md5_hash, send_email, update_dynamic_wordlist, send_pushover
from hashview import db
from sqlalchemy.ext.declarative import DeclarativeMeta
import time
import os
import json
import codecs
from datetime import datetime

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
    if agent.status == 'Online':
        return True
    return False

def updateHeartbeat(uuid):
    agent = Agents.query.filter_by(uuid=uuid).first()
    if agent:
        agent.src_ip = request.remote_addr
        agent.last_checkin = time.strftime('%Y-%m-%d %H:%M:%S')
        db.session.commit()

def updateJobTaskStatus(jobtask_id, status):

    jobtask = JobTasks.query.get(jobtask_id)
    jobtask.status = status
    if status == 'Completed':
        jobtask.agent_id = None
    db.session.commit()

    # Update Jobs
    # TODO
    # Shouldn't we be changing the job stats to match the jobtask status?
    # Add started at time
    job = Jobs.query.get(jobtask.job_id)
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
    
    if done:
        job.status = 'Completed'
        job.ended_at = time.strftime('%Y-%m-%d %H:%M:%S')
        db.session.commit()

        start_time = datetime.strptime(str(job.started_at), '%Y-%m-%d %H:%M:%S')
        end_time = datetime.strptime(str(job.ended_at), '%Y-%m-%d %H:%M:%S')
        durration = (abs(end_time - start_time).seconds) # So dumb you cant conver this to minutes, only resolution is seconds or days :(

        hashfile = Hashfiles.query.get(job.hashfile_id)
        hashfile.runtime += durration
        db.session.commit()

        # TODO
        # mark all jobtasks as completed
        job_notifications = JobNotifications.query.filter_by(job_id = job.id)
        
        for job_notification in job_notifications:
            user = Users.query.get(job_notification.owner_id)
            cracked_cnt = db.session.query(Hashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '1').filter(HashfileHashes.hashfile_id==job.hashfile_id).count()
            uncracked_cnt = db.session.query(Hashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '0').filter(HashfileHashes.hashfile_id==job.hashfile_id).count()
            if job_notification.method == 'email':
                send_email(user, 'Hashview Job: "' + job.name + '" Has Completed!', 'Your job has completed. It ran for a total of ' + str(durration) + ' seconds and resulted in a total of ' + str(cracked_cnt) + ' out of ' + str(cracked_cnt+uncracked_cnt) + ' hashes being recovered!')
            elif job_notification.method == 'push':
                if user.pushover_key and user.pushover_id:
                    send_pushover(user, 'Message from Hashview', 'Hashview Job: "' + job.name + '" Has Completed!')
                else:
                    send_email(user, 'Hashview: Missing Pushover Key', 'Hello, you were due to recieve a pushover notification, but because your account was not provisioned with an pushover ID and Key, one could not be set. Please log into hashview and set these options under Manage->Profile.')
            db.session.delete(job_notification)
            db.session.commit()
        
        # Send Hash Completion Notifications
        hash_notifications = HashNotifications.query.all()
        for hash_notification in hash_notifications:
            user = Users.query.get(hash_notification.owner_id)
            message = "Congratulations, the following users's hashes have been recovered: \n\n"
            
            # There's probably a way to do this in one query but im lazy
            cracked_hashes = db.session.query(Hashes, HashfileHashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '1').filter(HashfileHashes.hashfile_id==job.hashfile_id).all()
            for cracked_hash in cracked_hashes:
                if cracked_hash[0].id == hash_notification.hash_id:
                    message += cracked_hash[1].username + "\n"
                    if hash_notification.method == 'email':
                        send_email(user, 'Hashview User Hash Recovered!', message)
                    elif hash_notification.method == 'push':
                        if user.pushover_key and user.pushover_id:
                            send_pushover(user, 'Message from Hashview', message)
                    else:
                        send_email(user, 'Hashview: Missing Pushover Key', 'Hello, you were due to recieve a pushover notification, but because your account was not provisioned with an pushover ID and Key, one could not be set. Please log into hashview and set these options under Manage->Profile.')
            db.session.delete(hash_notification)
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

    updateHeartbeat(request.cookies.get('agent_uuid'))

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

# TODO
# isnt this the same thing as /v1/queue/<id>/status? Why do we have both
@api.route('/v1/queue/<int:id>/status', methods=['POST'])
def api_set_queue_assignment_status(id):
    if not agentAuthorized(request.cookies.get('agent_uuid')):
        return redirect("/v1/agents/"+uuid+"/authorize") 

    status_json = request.get_json()
    updateHeartbeat(request.cookies.get('agent_uuid'))
    updateJobTaskStatus(jobtask_id = id, status= status_json['status'])

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
        return redirect("/v1/agents/"+uuid+"/authorize")

    updateHeartbeat(request.cookies.get('agent_uuid'))
    task = Tasks.query.get(id)
    # yeah why keep our response consistant like we did with wordlists and rules :smh:
    return json.dumps(task, cls=AlchemyEncoder)


# Provide jobtask info 
@api.route('/v1/jobtask/<int:id>', methods=['GET'])
def api_get_jobtask(id):
    if not agentAuthorized(request.cookies.get('agent_uuid')):
        return redirect("/v1/agents/"+uuid+"/authorize")

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
        return redirect("/v1/agents/"+uuid+"/authorize") 

    status_json = request.get_json()
    updateHeartbeat(request.cookies.get('agent_uuid'))
    updateJobTaskStatus(jobtask_id = id, status= status_json['status'])

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
                if not jobtask or jobtask.status == 'Canceled':
                    message = {
                        'status': 200,
                        'type': 'message',
                        'msg': 'Canceled',
                    }
                    return jsonify(message)

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
                    if job_task_entry:
                        job_task_entry.agent_id = agent.id
                        db.session.commit()
                        message = {
                            'status': 200,
                            'type': 'message',
                            'msg': 'START',
                            'task_id': job_task_entry.id
                        }
                        return jsonify(message)
                    else:
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
        return redirect("/v1/agents/"+uuid+"/authorize")

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
        return redirect("/v1/agents/"+uuid+"/authorize") 

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
        return redirect("/v1/agents/"+uuid+"/authorize") 

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
        return redirect("/v1/agents/"+uuid+"/authorize") 

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
        return redirect("/v1/agents/"+uuid+"/authorize")

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
        return redirect("/v1/agents/"+uuid+"/authorize")

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
        return redirect("/v1/agents/"+uuid+"/authorize")

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
        #if hashtype == 13100 or hashtype == 19200 or hashtype == 19600 or hashtype == 19700 or hashtype == 19800 or hashtype == 19900:

        # Does doing an import with multiple 'where' clauses make sense here, maybe we just stick with sub_ciphertext only since that _should_ be unique
        record = Hashes.query.filter_by(hash_type=hashtype, sub_ciphertext=get_md5_hash(ciphertext), cracked='0').first()
        if record:
            record.plaintext = plaintext.decode('UTF-8')
            record.cracked = 1
            db.session.commit()


    # delete file
    os.remove(crackfile_path)

    message = {
        'status': 200,
        'type': 'message',
        'msg': 'OK'
    }
    return jsonify(message)