import requests
import json
from agent.config import Config
# to supress SSL Error messages
import urllib3
import builtins
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from requests.packages.urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

# Retry transient failures so a brief server outage (restart/redeploy) is ridden
# out rather than surfacing as an error. allowed_methods=None retries POST too,
# not just idempotent GETs: the agent's POSTs (heartbeat, crack upload, jobtask
# status) are all safe to repeat, and WITHOUT this a RemoteDisconnected during a
# restart kills the in-flight monitor loop and orphans the running hashcat instead
# of resuming. status_forcelist rides out the server coming back as a not-yet-ready
# gateway; raise_on_status=False lets a final non-200 return normally (callers
# already handle that) instead of raising after the retries are spent.
retries = Retry(
    total=100,
    backoff_factor=1,
    allowed_methods=None,
    status_forcelist=(502, 503, 504),
    raise_on_status=False,
)
adapter = HTTPAdapter(max_retries=retries)
http = requests.Session()
http.mount("https://", adapter)
http.mount("http://", adapter)


def _scheme():
    """Return 'https://' when the configured use_ssl is truthy, else 'http://'.

    Tolerant of how use_ssl gets written: the setup prompt is '[y/N]' and stores
    the raw answer ('y'/'yes'/'True'), so accept any of them (case-insensitive)
    rather than only the exact string 'True'. Otherwise a 'y' answer talks plain
    HTTP to a TLS port and the server resets the connection (the agent then never
    registers)."""
    return 'https://' if str(Config.USE_SSL).strip().lower() in (
        'true', 't', 'yes', 'y', '1', 'on') else 'http://'


def get(url):
    path = _scheme()

    with open('VERSION.TXT', 'r') as f:
        version = f.readline().strip('\n')

    cookie = {
        'uuid': Config.UUID,
        'name': Config.NAME,
        'agent_version': version
    }

    path += Config.HASHVIEW_SERVER + ':' + Config.HASHVIEW_PORT + url

    if builtins.state == 'debug':
        print('[DEBUG] http.py->GET: ' + path)
        print('[DEBUG] http.py->GET: ' + str(cookie))

    response = http.get(path, verify=False, cookies=cookie)
    if response.status_code == 200:
        return response.content
    else:
        print('[!] HTTP POST (response): Got an unexpected return code:' + str(response.status_code))

def post(url, data):
    path = _scheme()

    with open('VERSION.TXT', 'r') as f:
        version = f.readline().strip('\n')

    path += Config.HASHVIEW_SERVER + ':' + Config.HASHVIEW_PORT + url
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    cookie = {
        'uuid': Config.UUID,
        'name': Config.NAME,
        'agent_version': version
    }

    if builtins.state == 'debug':
        print('[DEBUG] http.py->POST: ' + str(path))
        print('[DEBUG] http.py->POST: ' + str(data))
        print('[DEBUG] http.py->POST: ' + str(cookie))

    # put in try/catch statement for timeouts etc.
    response = http.post(path, data=json.dumps(data), verify=False, cookies=cookie, headers=headers)
    if response.status_code == 200:
        return response.text
    else:
        print('[!] HTTP POST (response): Got an unexpected return code:' + str(response.status_code))