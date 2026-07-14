import json
import logging

from agent.http import http

LOG = logging.getLogger('hashview-agent')

_UPGRADE_MSG = ('Our agent version is older than the servers. You need to '
                'upgrade your agent before continuing.')


def _load(response, endpoint):
    """Parse an HTTP-layer response into JSON, guarding the failure modes that
    used to surface as opaque TypeErrors.

    Returns the decoded object, or None when the server sent no body (the HTTP
    layer returns None on a non-200 / connection failure, e.g. mid-reboot) or a
    non-JSON body. When the decoded body carries the in-band status==426 upgrade
    signal, exit -- the agent is too old to keep talking to this server.
    """
    if response is None:
        LOG.warning('%s: no response from server (non-200 or connection failure).', endpoint)
        return None
    try:
        decoded = json.loads(response)
    except (TypeError, ValueError) as err:
        LOG.warning('%s: could not parse server response (%s).', endpoint, err)
        return None
    if isinstance(decoded, dict) and decoded.get('status') == 426:
        print('[ERROR] ' + _UPGRADE_MSG)
        exit()
    return decoded


def _extract(response, endpoint, key):
    """Pull a single payload key out of a decoded response.

    Guards a missing key / wrong shape -- e.g. an authorized-but-Error reply that
    the server returns as HTTP 200 with an {'type':'Error',...} body and no data
    key. Returns the value, or None.
    """
    decoded = _load(response, endpoint)
    if decoded is None:
        return None
    if not isinstance(decoded, dict) or key not in decoded:
        LOG.warning('%s: unexpected response shape (missing %r).', endpoint, key)
        return None
    return decoded[key]


def heartbeat(agent_status, hc_status):
    message = {
        'agent_status': agent_status,
        'hc_status': hc_status,
    }

    response = http.post('/v1/agents/heartbeat', json.loads(json.dumps(message)))
    decoded_response = _load(response, 'heartbeat')
    if decoded_response is None:
        # response is None (server returned a non-200, e.g. it was mid-reboot) or
        # not JSON. Treat this beat as a no-op: keep the current work and retry on
        # the next cycle instead of crashing the agent loop.
        return {'type': 'message', 'status': 200, 'msg': None}
    if decoded_response.get('type') == 'message' and decoded_response.get('status') == 200:
        return decoded_response
    LOG.warning('heartbeat: unexpected response type %s.', decoded_response.get('type'))

def report_benchmark(benchmark_results):
    message = {
        'benchmark_results': benchmark_results,
    }

    response = http.post('/v1/agents/benchmark', json.loads(json.dumps(message)))
    decoded_response = _load(response, 'report_benchmark')
    if decoded_response is None:
        return None
    if decoded_response.get('type') == 'message' and decoded_response.get('status') == 200:
        return decoded_response
    LOG.warning('report_benchmark: unexpected response type %s.', decoded_response.get('type'))
    return decoded_response

def server_settings():
    response = http.get('/v1/admin/settings')
    return _extract(response, 'server_settings', 'settings')

def rules_list():
    response = http.get('/v1/rules')
    return _extract(response, 'rules_list', 'rules')

def get_rules_file(rules_id):
    return http.get('/v1/rules/' + str(rules_id))

def getWordlists():
    response = http.get('/v1/wordlists')
    return _extract(response, 'getWordlists', 'wordlists')

def get_wordlists_file(wordlist_id):
    return http.get('/v1/wordlists/' + str(wordlist_id))

def jobTasks(job_task_id):
    response = http.get('/v1/jobTasks/' + str(job_task_id))
    return _extract(response, 'jobTasks', 'job_task')

def jobs(job_id):
    response = http.get('/v1/jobs/' + str(job_id))
    return _extract(response, 'jobs', 'job')

def tasks(task_id):
    response = http.get('/v1/tasks/' + str(task_id))
    return _extract(response, 'tasks', 'task')

def updateDynamicWordlists(wordlist_id):
    response = http.get('/v1/updateWordlist/' + str(wordlist_id))
    decoded_response = _load(response, 'updateDynamicWordlists')
    if decoded_response is None:
        return None
    if decoded_response.get('type') == 'message' and decoded_response.get('status') == 200:
        return decoded_response
    LOG.warning('updateDynamicWordlists: unexpected response type %s.', decoded_response.get('type'))

def get_hashfile(hashfile_id):
    return http.get('/v1/hashfiles/' + str(hashfile_id))

def uploadCrackFile(file_path, job_task_id):
    # The crack file is hashcat's outfile (hash:hex_plain). For NetNTLM/Kerberos
    # the hash portion embeds a username that can carry arbitrary non-UTF-8 bytes,
    # so decode tolerantly (errors='replace') instead of crashing the whole upload
    # on one stray byte and silently dropping every recovered crack in the file.
    with open(file_path, encoding='utf-8', errors='replace') as file:
    # we use jobtask to determin hashtype server side.
        #response =  http.post('/v1/uploadCrackFile/' + str(task_id) + "/" + str(hash_type), data={'file': file.read()})
        response = http.post('/v1/uploadCrackFile/' + str(job_task_id), data = {'file': file.read()})
        decoded_response = _load(response, 'uploadCrackFile')
        if decoded_response is None:
            return None
        if decoded_response.get('type') == 'message' and decoded_response.get('status') == 200:
            return decoded_response
        LOG.warning('uploadCrackFile: unexpected response type %s.', decoded_response.get('type'))

def getHashType(hashfile_id):
    response = http.get('/v1/getHashType/' + str(hashfile_id))
    decoded_response = _load(response, 'getHashType')
    if decoded_response is None:
        return None
    if decoded_response.get('type') == 'message' and decoded_response.get('status') == 200:
        return decoded_response
    LOG.warning('getHashType: unexpected response type %s.', decoded_response.get('type'))

def updateJobTask(job_task_id, task_status):
    message = {
        'task_status': task_status,
        'job_task_id': job_task_id
    }

    response = http.post('/v1/jobtask/status', json.loads(json.dumps(message)))
    decoded_response = _load(response, 'updateJobTask')
    if decoded_response is None:
        return None
    if decoded_response.get('type') == 'message' and decoded_response.get('status') == 200:
        return decoded_response
    LOG.warning('updateJobTask: unexpected response type %s / status %s.',
                decoded_response.get('type'), decoded_response.get('status'))
    return decoded_response

def sendError(error_message):
    message = {
            'error': error_message
    }
    response = http.post('/v1/error', json.loads(json.dumps(message)))
    decoded_response = _load(response, 'sendError')
    if decoded_response is None:
        return None
    if decoded_response.get('type') == 'message' and decoded_response.get('status') == 200:
        return decoded_response
    LOG.warning('sendError: unexpected response type %s / status %s.',
                decoded_response.get('type'), decoded_response.get('status'))
    return decoded_response
