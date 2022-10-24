from agent.http import http
from agent.config import Config
import json


def heartbeat(agent_status, hc_status):
    message = {
        'agent_status': agent_status,
        'hc_status': hc_status,
    }

    response = http.post('/v1/agents/heartbeat', json.loads(json.dumps(message)))
    decoded_response = json.loads(response)
    if decoded_response['type'] == 'message' and decoded_response['status'] == 200:
        return decoded_response
    elif decoded_response['type'] == 'message' and decoded_response['status'] == 426:
        print('Our agent version is older than the servers. You need to upgrade your agent before continuing.')
        exit()
    else:
        print('we got an unexpected response type')
        print(str(decoded_response['type']))

def rules_list():
    response =  http.get('/v1/rules')
    if(json.loads(response)['status'] == 426):
        print('[ERROR] Our agent version is older than the servers. You need to upgrade your agent before continuing.')
        exit()
    else:
        decoded_response = json.loads(response)['rules']
        return decoded_response

def get_rules_file(rules_id):
    return http.get('/v1/rules/' + str(rules_id))

def getWordlists():
    response =  http.get('/v1/wordlists')
    if(json.loads(response)['status'] == 426):
        print('[ERROR] Our agent version is older than the servers. You need to upgrade your agent before continuing.')
        exit()
    else:    
        decoded_response = json.loads(response)['wordlists']
        return decoded_response

def get_wordlists_file(wordlist_id):
    return http.get('/v1/wordlists/' + str(wordlist_id))

def jobTasks(job_task_id):
    response = http.get('/v1/jobTasks/' + str(job_task_id))
    if(json.loads(response)['status'] == 426):
        print('[ERROR] Our agent version is older than the servers. You need to upgrade your agent before continuing.')
        exit()
    else:    
        decoded_response = json.loads(json.loads(response)['job_task'])
        return decoded_response

def jobs(job_id):
    response = http.get('/v1/jobs/' + str(job_id))
    if(json.loads(response)['status'] == 426):
        print('[ERROR] Our agent version is older than the servers. You need to upgrade your agent before continuing.')
        exit()
    else:    
        decoded_response = json.loads(json.loads(response)['job'])
        return decoded_response

def tasks(task_id):
    response = http.get('/v1/tasks/' + str(task_id))
    if(json.loads(response)['status'] == 426):
        print('[ERROR] Our agent version is older than the servers. You need to upgrade your agent before continuing.')
        exit()
    else:    
        decoded_response = json.loads(json.loads(response)['task'])
        return decoded_response

def updateDynamicWordlists(wordlist_id):
    response = http.get('/v1/updateWordlist/' + str(wordlist_id))
    decoded_response = json.loads(response)
    if decoded_response['type'] == 'message' and decoded_response['status'] == 200:
        return decoded_response
    elif decoded_response['type'] == 'message' and decoded_response['status'] == 426:
        print('Our agent version is older than the servers. You need to upgrade your agent before continuing.')
        exit()
    else:
        print('we got an unexpected response type')
        print(str(decoded_response['type']))    

def get_hashfile(hashfile_id):
    return http.get('/v1/hashfiles/' + str(hashfile_id))

def uploadCrackFile(file_path, hash_type):
    with open(file_path, 'r') as file:
    # we use jobtask to determin hashtype server side. 
        response =  http.post('/v1/uploadCrackFile/' + str(hash_type), data={'file': file.read()})
        decoded_response = json.loads(response)
        if decoded_response['type'] == 'message' and decoded_response['status'] == 200:
            return decoded_response
        elif decoded_response['type'] == 'message' and decoded_response['status'] == 426:
            print('Our agent version is older than the servers. You need to upgrade your agent before continuing.')
            exit()
        else:
            print('we got an unexpected response type')
            print(str(decoded_response['type']))

def getHashType(hashfile_id):
    response = http.get('/v1/getHashType/' + str(hashfile_id))
    decoded_response = json.loads(response)
    if decoded_response['type'] == 'message' and decoded_response['status'] == 200:
        return decoded_response
    elif decoded_response['type'] == 'message' and decoded_response['status'] == 426:
        print('Our agent version is older than the servers. You need to upgrade your agent before continuing.')
        exit()
    else:
        print('we got an unexpected response type')
        print(str(decoded_response['type']))

def updateJobTask(job_task_id, task_status):
    message = {
        'task_status': task_status,
        'job_task_id': job_task_id
    }

    try:
        response = http.post('/v1/jobtask/status', json.loads(json.dumps(message)))
        decoded_response = json.loads(response)
        if decoded_response['type'] == 'message' and decoded_response['status'] == 200:
            return decoded_response
        elif decoded_response['type'] == 'message' and decoded_response['status'] == 426:
            print('Our agent version is older than the servers. You need to upgrade your agent before continuing.')
            exit()

        with suppress(TypeError):
            # suppress NoneType error, so the status can be completed even if it fails.
            print("Program returned None.")
    except Exception as e:
        print(e)
        return
