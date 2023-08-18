import requests
import json
from agent.config import Config
# to supress SSL Error messages
import urllib3
import builtins
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from requests.packages.urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

import agent

retries = Retry(total=100, backoff_factor=1)
adapter = HTTPAdapter(max_retries=retries)
http = requests.Session()
http.mount("https://", adapter)
http.mount("http://", adapter)

def get(url):
    path = ''
    if Config.USE_SSL == 'True':
        path += 'https://'
    else:
        path += 'http://'

    version = agent.__version__

    cookie = {
        'uuid': Config.UUID,
        'name': Config.NAME,
        'agent_version': version
    }

    path += Config.HASHVIEW_SERVER + ':' + Config.HASHVIEW_PORT + url

    if builtins.state == 'debug':
        print('[DEBUG] http.py->GET: (path)' + path)
        print('[DEBUG] http.py->GET: (cookie)' + str(cookie))

    response = http.get(path, verify=False, cookies=cookie)
    if response.status_code == 200:
        return response.content
    else:
        print('[!] HTTP POST (response): Got an unexpected return code:' + str(response.status_code))

def post(url, data):
    path = ''
    if Config.USE_SSL == 'True':
        path += 'https://'
    else:
        path += 'http://'

    version = agent.__version__

    path += Config.HASHVIEW_SERVER + ':' + Config.HASHVIEW_PORT + url
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    cookie = {
        'uuid': Config.UUID,
        'name': Config.NAME,
        'agent_version': version
    }

    if builtins.state == 'debug':
        print('[DEBUG] http.py->POST: (path): ' + str(path))
        print('[DEBUG] http.py->POST: (data)' + str(data))
        print('[DEBUG] http.py->POST: (cookie)' + str(cookie))

    # put in try/catch statement for timeouts etc.
    response = http.post(path, data=json.dumps(data), verify=False, cookies=cookie, headers=headers)
    if response.status_code == 200:
        return response.text
    else:
        print('[!] HTTP POST (response): Got an unexpected return code:' + str(response.status_code))
