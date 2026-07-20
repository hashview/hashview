import argparse
import os
import socket
import uuid
import json
import secrets
import hashlib
import sys
import psutil
import re
import signal
import builtins
import time
import subprocess
import shlex
import gzip
import shutil
from contextlib import suppress
from threading import Thread
from datetime import datetime, timedelta


parser = argparse.ArgumentParser()
parser.add_argument("--debug", action="store_true", help="increase output verbosity")
args = parser.parse_args()

# Build Config

# ----------------------------------------------
# Manifest management (JSON based)
# ----------------------------------------------
class Manifest:
    """
    Simple JSON‑based manifest manager.
    Keeps the manifest data in memory and writes to disk only when
    `save()` is called.
    """
    def __init__(self, path):
        self.path = path
        self.data = {}
        self._load()

    def _load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path, "r") as f:
                    self.data = json.load(f)
            except Exception:
                # Corrupt or empty file – start fresh
                self.data = {}
        else:
            self.data = {}

    def save(self):
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w") as f:
            json.dump(self.data, f, indent=2, sort_keys=True)

# Global manifest instances
rules_manifest = Manifest("control/rules_manifest.json")
wordlists_manifest = Manifest("control/wordlists_manifest.json")
if not os.path.exists('agent/config.conf'):

    # Time to ask some questions
    print('\nInitial setup detected. Hashview Agent will now prompt you to setup the config fild ./agent/config/config.conf.\n')
    server = input('Enter IP address or FQDN of the hashview server: ')
    while len(server) == 0:
        print('Error: Value must be an IP address or FQDN. Can not be blank: ')
        server = input("Enter IP address or FQDN of the hashview server: ")
    port = input('Enter the port of the hashview server: ')
    while len(port) == 0:
        print('Error: You must provide a port. By default Hashview Server runs on 8443: ')
        port = input("Enter the port of the hashview server: ")
    use_tls = input('Does the Hashview server use SSL/TLS? [y/N]:')
    if use_tls == 'y' or use_tls == 'Y':
        use_tls = True
    else:
        use_tls = False

    hostname = socket.gethostname()
    name = input('Enter the name of this Hashview Agent [Hit Enter for: ' + hostname + ']: ')
    if len(name) == 0:
        name = hostname
    
    # Generate UUID
    agent_uuid = uuid.uuid4()

    hashcat_path = input('Enter the path to a local install of hashcat: ')
    while not os.path.exists(hashcat_path):
        print("Error: File not found.")
        hashcat_path = input('Enter the path to a local install of hashcat: ')    


    # Write config file
    config = open("agent/config.conf", "w")
    config.write("[HASHVIEW]\n")
    config.write("server = " + str(server) + "\n")
    config.write("port = " + str(port) + "\n")
    config.write("use_ssl = " + str(use_tls) + "\n\n")

    config.write("[AGENT]\n")
    config.write("name = " + str(name) + "\n")
    config.write("uuid = " + str(agent_uuid) + "\n")
    config.write("HC_BIN_PATH = " + str(hashcat_path) + "\n")

    config.close()

from agent.api import api


def _handle_subprocess_error(error):
    if error:
        print(error)
        if b'hashfile is empty or corrupt' not in error:
            if b'Terminated' in error:
                sys.exit()
            else:
                api.sendError(error.decode('utf-8', errors='replace'))
                os.kill(os.getpid(), signal.SIGINT)


def run_command(command):
    """Run a subprocess without invoking a shell (CWE-78)."""
    try:
        if isinstance(command, (list, tuple)):
            argv = list(command)
        else:
            argv = shlex.split(command)
        cmd = subprocess.Popen(argv, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = cmd.communicate()
        _handle_subprocess_error(error)
        return output
    except OSError as e:
        print("inside exception", e)
        api.sendError(str(e))
        os.kill(os.getpid(), signal.SIGINT)


def _gunzip_file(gz_path):
    """Decompress a .gz file in place, returning the output path."""
    out_path = gz_path[:-3] if gz_path.endswith('.gz') else gz_path + '.out'
    with gzip.open(gz_path, 'rb') as gz_file:
        with open(out_path, 'wb') as out_file:
            shutil.copyfileobj(gz_file, out_file)
    os.remove(gz_path)
    return out_path


def _move_file(src, dest):
    shutil.move(src, dest)

def send_heartbeat(agent_status, hc_status):
    return api.heartbeat(agent_status, hc_status)

def getHashcatPid():
    if sys.platform == 'win32':
        print('Hashview-Agent doesn\'t currecntly work on windows. PR\'s welcome :)')
        sys.exit()
    else:
        for proc in psutil.process_iter():
            try:
                pinfo = proc.as_dict(attrs=['pid', 'name', 'cmdline'])
                # In the future we should change this to session id
                if 'hashcat' in pinfo['name'].lower():
                    for cli_args in pinfo['cmdline']:
                        if 'hc_cracked_' in cli_args:
                            return pinfo['pid']
            except:
                return False
    return False

def sync_rules():
    """
    Synchronise local rule files with the server using JSON manifests.
    """
    print('Syncing local rules with server.')
    response = api.rules_list()
    server_entries = json.loads(response)
    new_manifest = {}

    for entry in server_entries:
        rule_id = str(entry['id'])
        remote_checksum = entry['checksum']
        filename = entry['path'].split('/')[-1]

        local_entry = rules_manifest.data.get(rule_id)

        if local_entry:
            # Existing entry – verify checksum
            if local_entry['checksum'] != remote_checksum:
                print('Checksum mismatch for rule', rule_id)
                old_path = os.path.join('control/rules', local_entry['filename'])
                if os.path.exists(old_path):
                    os.remove(old_path)

                # Download and verify new file
                random_hex = secrets.token_hex(8)
                compressed = api.get_rules_file(entry['id'])
                tmp_gz = os.path.join('control/tmp', f'{random_hex}.gz')
                with open(tmp_gz, 'wb') as f:
                    f.write(compressed)

                tmp_file = _gunzip_file(tmp_gz)

                sha256 = hashlib.sha256()
                with open(tmp_file, 'rb') as f:
                    for block in iter(lambda: f.read(4096), b''):
                        sha256.update(block)
                local_checksum = sha256.hexdigest()
                print('Local:', local_checksum, 'Remote:', remote_checksum)

                if local_checksum == remote_checksum:
                    dest = os.path.join('control/rules', filename)
                    _move_file(tmp_file, dest)
                    new_manifest[rule_id] = {'checksum': local_checksum, 'filename': filename}
                else:
                    print('Checksum verification failed for rule', rule_id)
                    os.remove(tmp_file)
            else:
                new_manifest[rule_id] = local_entry
        else:
            # New rule – download
            print('Downloading new rule', rule_id)
            random_hex = secrets.token_hex(8)
            compressed = api.get_rules_file(entry['id'])
            tmp_gz = os.path.join('control/tmp', f'{random_hex}.gz')
            with open(tmp_gz, 'wb') as f:
                f.write(compressed)

            tmp_file = _gunzip_file(tmp_gz)

            sha256 = hashlib.sha256()
            with open(tmp_file, 'rb') as f:
                for block in iter(lambda: f.read(4096), b''):
                    sha256.update(block)
            local_checksum = sha256.hexdigest()
            print('Local:', local_checksum, 'Remote:', remote_checksum)

            if local_checksum == remote_checksum:
                dest = os.path.join('control/rules', filename)
                _move_file(tmp_file, dest)
                new_manifest[rule_id] = {'checksum': local_checksum, 'filename': filename}
            else:
                print('Checksum verification failed for new rule', rule_id)
                os.remove(tmp_file)

    if new_manifest != rules_manifest.data:
        rules_manifest.data = new_manifest
        rules_manifest.save()
        print('Rules manifest updated.')
    else:
        print('Rules manifest unchanged.')

def sync_wordlists():
    """
    Synchronise local wordlist files with the server using JSON manifests.
    """
    print('Syncing local wordlists with server.')
    response = api.getWordlists()
    server_entries = json.loads(response)
    new_manifest = {}

    for entry in server_entries:
        wl_id = str(entry['id'])
        remote_checksum = entry['checksum']
        filename = entry['path'].split('/')[-1]

        local_entry = wordlists_manifest.data.get(wl_id)

        if local_entry:
            print(f"Found existing wordlist {wl_id} in local manifest.")
            # Existing entry – verify checksum
            if local_entry['checksum'] != remote_checksum:
                print('Checksum mismatch for wordlist', wl_id)
                old_path = os.path.join('control/wordlists', local_entry['filename'])
                if os.path.exists(old_path):
                    os.remove(old_path)

                # Download and verify new file
                random_hex = secrets.token_hex(8)
                compressed = api.get_wordlists_file(entry['id'])
                tmp_gz = os.path.join('control/tmp', f'{random_hex}.gz')
                with open(tmp_gz, 'wb') as f:
                    f.write(compressed)

                tmp_file = _gunzip_file(tmp_gz)

                sha256 = hashlib.sha256()
                with open(tmp_file, 'rb') as f:
                    for block in iter(lambda: f.read(4096), b''):
                        sha256.update(block)
                local_checksum = sha256.hexdigest()
                print('Local:', local_checksum, 'Remote:', remote_checksum)

                if local_checksum == remote_checksum:
                    dest = os.path.join('control/wordlists', filename)
                    _move_file(tmp_file, dest)
                    new_manifest[wl_id] = {'checksum': local_checksum, 'filename': filename}
                else:
                    print('Checksum verification failed for wordlist', wl_id)
                    os.remove(tmp_file)
            else:
                new_manifest[wl_id] = local_entry
        else:
            # New wordlist – download
            print('Downloading new wordlist', wl_id)
            random_hex = secrets.token_hex(8)
            compressed = api.get_wordlists_file(entry['id'])
            tmp_gz = os.path.join('control/tmp', f'{random_hex}.gz')
            with open(tmp_gz, 'wb') as f:
                f.write(compressed)

            tmp_file = _gunzip_file(tmp_gz)

            sha256 = hashlib.sha256()
            with open(tmp_file, 'rb') as f:
                for block in iter(lambda: f.read(4096), b''):
                    sha256.update(block)
            local_checksum = sha256.hexdigest()

            if local_checksum == remote_checksum:
                dest = os.path.join('control/wordlists', filename)
                _move_file(tmp_file, dest)
                new_manifest[wl_id] = {'checksum': local_checksum, 'filename': filename}
            else:
                print('Checksum verification failed for new wordlist', wl_id)
                os.remove(tmp_file)

    if new_manifest != wordlists_manifest.data:
        wordlists_manifest.data = new_manifest
        wordlists_manifest.save()
        print('Wordlists manifest updated.')
    else:
        print('Wordlists manifest unchanged.')

def jobTasks(job_task_id):
    return api.jobTasks(job_task_id)

def jobs(job_id):
    return api.jobs(job_id)

def tasks(task_id):
    return api.tasks(task_id)

def getWordlists():
    return api.getWordlists()

def updateDynamicWordlists(wordlist_id):
    return api.updateDynamicWordlists(wordlist_id)

def download_hashfile(job_id, jobtask_id, hashfile_id):
    # Note we are not compressing our hashfile
    hashfile_content = api.get_hashfile(hashfile_id)
    hashfile = open('control/hashes/hashfile_' + str(job_id) + '_' + str(jobtask_id) + '.txt', 'wb')
    hashfile.write(hashfile_content)
    hashfile.close()

def replaceHashcatBinPath(cmd):
    from agent.config import Config
    return cmd.replace('@HASHCATBINPATH@', Config.HC_BIN_PATH)

def run_hashcat(command, status_output_path):
    """Run hashcat without a shell; stream JSON status lines to a file."""
    argv = shlex.split(replaceHashcatBinPath(command))
    argv.append('--status-json')
    print(' '.join(argv))
    try:
        proc = subprocess.Popen(
            argv,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stderr_data = []

        def drain_stderr():
            stderr_data.append(proc.stderr.read())

        stderr_thread = Thread(target=drain_stderr)
        stderr_thread.start()
        with open(status_output_path, 'wb') as status_file:
            for chunk in iter(lambda: proc.stdout.read(4096), b''):
                status_file.write(chunk)
                status_file.flush()
        proc.wait()
        stderr_thread.join()
        _handle_subprocess_error(b''.join(stderr_data))
    except OSError as e:
        print("inside exception", e)
        api.sendError(str(e))
        os.kill(os.getpid(), signal.SIGINT)

def time_difference(future_timestamp):
    # Get the current time and calculate the difference
    now = datetime.now()
    future_time = datetime.fromtimestamp(future_timestamp)
    delta = future_time - now

    # If the time difference is negative (i.e., the timestamp is in the past), return immediately
    if delta.total_seconds() < 0:
        return "The specified time is in the past."

    # Calculate each time component
    years = delta.days // 365
    months = (delta.days % 365) // 30
    days = (delta.days % 365) % 30
    hours, remainder = divmod(delta.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)

    # Store non-zero values with their labels
    components = [
        (years, "year"),
        (months, "month"),
        (days, "day"),
        (hours, "hour"),
        (minutes, "minute"),
        (seconds, "second")
    ]

    # Filter out components that are zero
    components = [(value, name) for value, name in components if value > 0]

    # If there are fewer than two components, just return the available values
    if len(components) == 0:
        return "The specified time is very close to now."
    elif len(components) == 1:
        return f"{components[0][0]} {components[0][1]}{'s' if components[0][0] > 1 else ''}"
    
    # Return only the largest two components
    largest_two = components[:2]
    return ', '.join(f"{value} {name}{'s' if value > 1 else ''}" for value, name in largest_two)

def convert_speed(speed):
    if speed > 1000000000:
        return str(round((speed / 1000000000),1)) + " GH/s"
    elif speed > 1000000:
        return str(round((speed / 1000000), 1)) + " MH/s"
    elif speed > 1000:
        return str(round((speed / 1000), 1)) + " KH/s"
    else:
        return str(speed) + " H/s"

def hashcatParser(filepath):
    status = {}
    hashcat_output = open(filepath, 'r')
    for line in hashcat_output:
        # We itterate through entire file with the last value taking precidence
        if line.startswith('{'):
            # found json object
            json_data = json.loads(line)
            #status['Time_Started'] = json_data['time_start']
            status['Time_Estimated'] = "(" + time_difference(json_data['estimated_stop'])+ ")"
            status['Recovered'] = str(json_data['recovered_hashes'][0]) + "/" + str(json_data['recovered_hashes'][1])
            speed = 0
            devices = json_data['devices']
            for device in devices:
                speed = speed + device['speed']
            status['Speed #'] = convert_speed(speed)
    return status

def killHashcat(pid):
    if sys.platform == 'win32':
        print('Hashcat-agent is not supported on windows. But pull requests are welcome')
    else:
        os.kill(int(pid), signal.SIGTERM)
        #p = psutil.Process(pid)
        #p.terminate()

#def uploadCrackFile(file_path, hash_type, task_id):
#    return api.uploadCrackFile(file_path, hash_type, task_id)
def uploadCrackFile(file_path, job_task_id):
    return api.uploadCrackFile(file_path, job_task_id)

def getHashType(hashfile_id):
    return api.getHashType(hashfile_id)

def updateJobTask(job_task_id, task_status):
    return api.updateJobTask(job_task_id, task_status)    

def data_retention_cleanup():
    try:
        response = api.server_settings()
        server_settings = json.loads(response)
    except (KeyError, ValueError, TypeError):
        print('[INFO] hashview-agent.py->data_retention_cleanup() Skipping cleanup: '
              'server returned an unauthorized or unexpected response (agent may not be approved yet).')
        return

    if not server_settings or 'retention_period' not in server_settings[0]:
        print('[INFO] hashview-agent.py->data_retention_cleanup() Skipping cleanup: '
              'no retention_period in server settings.')
        return

    # if a value is set then we process
    if server_settings[0]['retention_period'] != 0:
        
        # Check and remove old files from tmp
        for file in os.listdir('control/tmp'):
            if os.stat('control/tmp/' + file).st_mtime < time.time() - server_settings[0]['retention_period'] * 86400 and file != '.gitignore':
                os.remove('control/tmp/' + file)
                print('[DEBUG] hashview-agent.py->data_retention_cleanup() Removed: control/tmp/' + file)        

        # check and remove files from outfiles
        for file in os.listdir('control/outfiles'):
            if file == '.gitignore':
                print('Found Git Ignore!')
            if os.stat('control/outfiles/' + file).st_mtime < time.time() - server_settings[0]['retention_period'] * 86400 and file != '.gitignore':
                os.remove('control/outfiles/' + file)
                print('[DEBUG] hashview-agent.py->data_retention_cleanup() Removed: control/outfiles/' + file) 

        # check and remove hashfiles
        for file in os.listdir('control/hashes'):
            if file == '.gitignore':
                print('Found Git Ignore!')
            if os.stat('control/hashes/' + file).st_mtime < time.time() - server_settings[0]['retention_period'] * 86400 and file != '.gitignore':
                os.remove('control/hashes/' + file)
                print('[DEBUG] hashview-agent.py->data_retention_cleanup() Removed: control/hashes/' + file)         

if __name__ == '__main__':
    from agent import config

    if args.debug:
        builtins.state = 'debug'
    else:
        builtins.state = 'normal'
    
    # Main loop
    while (1):
        agent_status = ''

        # Check data retention
        data_retention_cleanup()

        # Check if we're currently working on a task
        if getHashcatPid():
            agent_status = 'Working'
            response = send_heartbeat(agent_status, 'somevalue')
            if response['msg'] == 'Canceled':
                print("[*] Looks like we've been canceled.")
        else:
            agent_status = 'Idle'
            # Send Heartbeat
            response = send_heartbeat(agent_status, '')
            if response['msg'] == 'Go Away':
                print("[*] Agent is unauthorized to connect to this server. Please contact Hashview Admin to grant its access.")
            if response['msg'] == 'START':
                # We've been assigned a task
                # First we'll sync our rules
                sync_rules()
                # And our wordlists
                sync_wordlists()
                print("[*] We've been assigned Task Id: " + str(response['job_task_id']))
                job_task = jobTasks(response['job_task_id'])

                # Shouldnt be necessary, but server side sometimes doesnt get set
                updateJobTask(job_task['id'], 'Running')
                # Get the task so that we can get dictionary to find out if its dynamic, so that we can trigger an update 
                # we do a loop of all wordlists (instead of pulling directly) because the /vX/wordlists/<id> is reserved for downloading wordlists
                task = tasks(job_task['task_id'])

                wordlists_list = getWordlists()
                for wordlist in json.loads(wordlists_list):
                    if wordlist['id'] == task['wl_id']:
                        if wordlist['type'] == 'dynamic':
                            print('[*] Task is using a dynamic wordlist. Initiating update')
                            update_response = updateDynamicWordlists(wordlist['id'])
                
                            if update_response['msg'] != 'OK':
                                print('[!] Something broke during the updateing of the dynamic wordlist: ' + str(wordlist['id']))
                            else:
                                print('[*] Update Complete')
                            sync_wordlists()


                # Get Job, so that we can get our hashfile
                job = jobs(job_task['job_id'])

                # Download our hashfile. File name will be generated to match that of whats expected by the jobtask cmd.
                download_hashfile(job['id'], job_task['task_id'], job['hashfile_id'])

                status_output_path = 'control/outfiles/hcoutput_' + str(job['id']) + '_' + str(job_task['id']) + '.txt'
                print(replaceHashcatBinPath(job_task['command']) + ' --status-json')

                # run in thread
                thread = Thread(target=run_hashcat, args=(job_task['command'], status_output_path))
                thread.start()
                
                while thread.is_alive():
                    # we sleep 15 seconds because by default, the build crack cmd on hashview server tells hashcat to display output every 15 seconds.
                    time.sleep(15)
                    agent_status = 'Working'
                    hc_status = hashcatParser('control/outfiles/hcoutput_' + str(job['id']) + '_' + str(job_task['id']) + '.txt')

                    response = send_heartbeat(agent_status, hc_status)
                    if response['msg'] == 'Canceled':
                        print('[*] We\'ve been canceled')
                        pid = getHashcatPid()
                        if pid:
                            killHashcat(pid)
                            
                    # upload cracks
                    crack_file = 'control/outfiles/hc_cracked_' + str(job['id']) + '_' + str(job_task['task_id']) + '.txt'
                    if os.path.exists(crack_file):
                        getHashTypeResponse = getHashType(job['hashfile_id'])
                        if getHashTypeResponse['msg'] == 'OK':
                            #uploadCrackFileResponse = uploadCrackFile(crack_file, getHashTypeResponse['hash_type'], str(job_task['task_id']))
                            uploadCrackFileResponse = uploadCrackFile(crack_file, str(job_task['id']))
                            if uploadCrackFileResponse['msg'] == 'OK':
                                print('[*] Upload Success!')
                    else:
                        print('[*] No Results. Skipping upload.')


                print('[*] Done working')

                # upload cracks
                crack_file = 'control/outfiles/hc_cracked_' + str(job['id']) + '_' + str(job_task['task_id']) + '.txt'
                if os.path.exists(crack_file):
                    getHashTypeResponse = getHashType(job['hashfile_id'])
                    if getHashTypeResponse['msg'] == 'OK':
                        #uploadCrackFileResponse = uploadCrackFile(crack_file, getHashTypeResponse['hash_type'], str(job_task['task_id']))
                        uploadCrackFileResponse = uploadCrackFile(crack_file, str(job_task['id']))
                        if uploadCrackFileResponse['msg'] == 'OK':
                            print('[*] Upload Success!')
                else:
                    print('[*] No Results. Skipping upload.')

                # Set status to complete
                updateJobTaskResponse = updateJobTask(job_task['id'], 'Completed')
                try:
                    if updateJobTaskResponse['msg'] == 'OK':
                        print('[*] Task Successfully Set to Completed')
                    with suppress(Exception):
                        pass
                finally:
                    pass

        print('[*] Sleeping')
        time.sleep(10)
