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
from threading import Thread


parser = argparse.ArgumentParser()
parser.add_argument("--debug", action="store_true", help="increase output verbosity")
args = parser.parse_args()

# Build Config
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
    # pull list of rules & hashes
    print('Syncing local rules with server.')
    response = api.rules_list()
    new_rules_manifest = open('control/tmp/rules_manifest.txt', 'w')
    for entry in json.loads(response):

        # load local manifest
        currently_has_rule = False
        mismatched_rule = False
        rules_manifest = open('control/rules_manifest.txt', 'r')
        
        for rules_manifest_entry in rules_manifest:
            if str(rules_manifest_entry.split('|')[0]) == str(entry['id']):
                currently_has_rule = True
                # We have a matching ID between our manifest and the server
                if str(rules_manifest_entry.split('|')[1]) != str(entry['checksum']):
                    mismatched_rule = True
                    print('Manifest to local file mismatch!')
                    print('Downloading rule id: ' + str(entry['id']) + ' (' + entry['name'] + ')' )
                    # our manifest entry's check sum does not match the server

                    # remove the rule file on disk (if it exists)
                    # TODO change to try catch
                    os.remove('control/rules/' + rules_manifest_entry.split('|')[2].rstrip())
                    
                    # download rules file
                    random_hex = secrets.token_hex(8)
                    compressed_rules_file_content = api.get_rules_file(entry['id'])
                    local_compressed_rule = open('control/tmp/'+ random_hex + '.gz', 'wb')
                    local_compressed_rule.write(compressed_rules_file_content)
                    local_compressed_rule.close()                
                    
                    # decompress rules file
                    cmd = 'gunzip control/tmp/' + random_hex + '.gz'
                    os.system(cmd)                    
                            
                    # generate checksum
                    print('Comparing checksums')
                    sha256_hash = hashlib.sha256()
                    with open('control/tmp/'+random_hex, 'rb') as f:
                        for byte_block in iter(lambda: f.read(4096),b""):
                            sha256_hash.update(byte_block)                
                    print('Local: ' + str(sha256_hash.hexdigest()))
                    print('Remote: ' + str(entry['checksum']))

                    if sha256_hash.hexdigest() == entry['checksum']:
                        print('Checksums match!')
                        # create new manifest entry    
                        new_rules_manifest.write(str(entry['id']) + '|' + sha256_hash.hexdigest() + '|' + entry['path'].split('/')[-1] + '\n')
                        # move & rename rules file to match that of whats expected in the hashcat command
                        cmd = 'mv control/tmp/' + random_hex + ' control/rules/' + entry['path'].split('/')[-1]
                        os.system(cmd)
                    else:
                        print('hashes dont match. what do we do now?')
                        os.remove('control/tmp/' + random_hex)
            
        # We've compared the two lists, now if we didnt have the entry before it means its a new rules file and we need to download it.
        if currently_has_rule == False:
            print('Downloading rule id: ' + str(entry['id']) + ' (' + entry['name'] + ')' )
            # download rules file
            random_hex = secrets.token_hex(8)
            compressed_rules_file_content = api.get_rules_file(entry['id'])
            local_compressed_rule = open('control/tmp/'+ random_hex + '.gz', 'wb')
            local_compressed_rule.write(compressed_rules_file_content)
            local_compressed_rule.close()

            # decompress rules file
            cmd = 'gunzip control/tmp/' + random_hex + '.gz'
            os.system(cmd)
            
            # generate checksum
            print('Comparing checksums')
            sha256_hash = hashlib.sha256()
            with open('control/tmp/'+random_hex, 'rb') as f:
                for byte_block in iter(lambda: f.read(4096),b""):
                    sha256_hash.update(byte_block)                
            print('Local: ' + str(sha256_hash.hexdigest()))
            print('Remote: ' + str(entry['checksum']))

            if sha256_hash.hexdigest() == entry['checksum']:
                print('Checksums match!')
                # create new manifest entry    
                new_rules_manifest.write(str(entry['id']) + '|' + sha256_hash.hexdigest() + '|' + entry['path'].split('/')[-1] + '\n')
                # move & rename rules file to match that of whats expected in the hashcat command
                cmd = 'mv control/tmp/' + random_hex + ' control/rules/' + entry['path'].split('/')[-1]
                os.system(cmd)
            else:
                print('hashes dont match. what do we do now?')
                os.remove('control/tmp/' + random_hex)
        elif currently_has_rule == True and mismatched_rule == False:
            new_rules_manifest.write(str(entry['id']) + '|' + entry['checksum'] + '|' + entry['path'].split('/')[-1] + '\n')
    # move new manifest into correct directory
    cmd = 'mv control/tmp/rules_manifest.txt control/rules_manifest.txt'
    os.system(cmd)
    print('Done Syncing Rules.')

def sync_wordlists():
    # pull list of wordlists & hashes
    print('Syncing local wordlists with server.')
    response = api.getWordlists()
    new_wordlists_manifest = open('control/tmp/wordlists_manifest.txt', 'w')
    for entry in json.loads(response):

        # load local manifest
        currently_has_wordlist = False
        mismatched_wordlist = False
        wordlists_manifest = open('control/wordlists_manifest.txt', 'r')
        
        for wordlists_manifest_entry in wordlists_manifest:
            if str(wordlists_manifest_entry.split('|')[0]) == str(entry['id']):
                currently_has_wordlist = True
                # We have a matching ID between our manifest and the server
                if str(wordlists_manifest_entry.split('|')[1]) != str(entry['checksum']):
                    mismatched_wordlist = True
                    print('Manifest to local file mismatch!')
                    print('Downloading wordlist id: ' + str(entry['id']) + ' (' + entry['name'] + ')' )
                    # our manifest entry's check sum does not match the server

                    # remove the wordlist file on disk (if it exists)
                    # TODO change to try catch
                    os.remove('control/wordlists/' + wordlists_manifest_entry.split('|')[2].rstrip())
                    
                    # download wordlists file
                    random_hex = secrets.token_hex(8)
                    compressed_wordlists_file_content = api.get_wordlists_file(entry['id'])
                    local_compressed_wordlist = open('control/tmp/'+ random_hex + '.gz', 'wb')
                    local_compressed_wordlist.write(compressed_wordlists_file_content)
                    local_compressed_wordlist.close()                
                    
                    # decompress wordlist file
                    cmd = 'gunzip control/tmp/' + random_hex + '.gz'
                    os.system(cmd)                    
                            
                    # generate checksum
                    print('Comparing checksums')
                    sha256_hash = hashlib.sha256()
                    with open('control/tmp/'+random_hex, 'rb') as f:
                        for byte_block in iter(lambda: f.read(4096),b""):
                            sha256_hash.update(byte_block)                
                    print('Local: ' + str(sha256_hash.hexdigest()))
                    print('Remote: ' + str(entry['checksum']))

                    if sha256_hash.hexdigest() == entry['checksum']:
                        print('Checksums match!')
                        # create new manifest entry    
                        new_wordlists_manifest.write(str(entry['id']) + '|' + sha256_hash.hexdigest() + '|' + entry['path'].split('/')[-1] + '\n')
                        # move & rename wordlist file to match that of whats expected in the hashcat command
                        cmd = 'mv control/tmp/' + random_hex + ' control/wordlists/' + entry['path'].split('/')[-1]
                        os.system(cmd)
                    else:
                        print('hashes dont match. what do we do now?')
                        os.remove('control/tmp/' + random_hex)
            
        # We've compared the two lists, now if we didnt have the entry before it means its a new wordlist file and we need to download it.
        if currently_has_wordlist == False:
            print('Downloading wordlist id: ' + str(entry['id']) + ' (' + entry['name'] + ')' )
            # download wordlist file
            random_hex = secrets.token_hex(8)
            compressed_wordlists_file_content = api.get_wordlists_file(entry['id'])
            local_compressed_wordlist = open('control/tmp/'+ random_hex + '.gz', 'wb')
            local_compressed_wordlist.write(compressed_wordlists_file_content)
            local_compressed_wordlist.close()

            # decompress wordlist file
            cmd = 'gunzip control/tmp/' + random_hex + '.gz'
            os.system(cmd)
            
            # generate checksum
            print('Comparing checksums')
            sha256_hash = hashlib.sha256()
            with open('control/tmp/'+random_hex, 'rb') as f:
                for byte_block in iter(lambda: f.read(4096),b""):
                    sha256_hash.update(byte_block)                
            print('Local: ' + str(sha256_hash.hexdigest()))
            print('Remote: ' + str(entry['checksum']))

            if sha256_hash.hexdigest() == entry['checksum']:
                print('Checksums match!')
                # create new manifest entry    
                new_wordlists_manifest.write(str(entry['id']) + '|' + sha256_hash.hexdigest() + '|' + entry['path'].split('/')[-1] + '\n')
                # move & rename wordlists file to match that of whats expected in the hashcat command
                cmd = 'mv control/tmp/' + random_hex + ' control/wordlists/' + entry['path'].split('/')[-1]
                os.system(cmd)
            else:
                print('hashes dont match. what do we do now?')
                os.remove('control/tmp/' + random_hex)
        elif currently_has_wordlist == True and mismatched_wordlist == False:
            new_wordlists_manifest.write(str(entry['id']) + '|' + entry['checksum'] + '|' + entry['path'].split('/')[-1] + '\n')
    # move new manifest into correct directory
    cmd = 'mv control/tmp/wordlists_manifest.txt control/wordlists_manifest.txt'
    os.system(cmd)
    print('Done Syncing Wordlists.')

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

def run_hashcat(cmd):
    os.system(cmd)

def hashcatParser(filepath):
    status = {}
    hashcat_output = open(filepath, 'r')
    for line in hashcat_output:
        if line.startswith('Time.Started.'):
            status['Time_Started'] = line.split(': ')[-1].rstrip()
        elif line.startswith('Time.Estimated.'):
            status['Time_Estimated'] = line.split('.: ')[-1].rstrip()
        elif line.startswith('Recovered.'):
            status['Recovered'] = line.split(': ')[-1].rstrip()
        elif line.startswith('Input.Mode.'):
            status['Input_Mode'] = line.split(': ')[-1].rstrip()
        elif line.startswith('Guess.Mask.'):
            status['Guess_Mask'] = line.split(': ')[-1].rstrip()
        elif line.startswith('Progress'):
            status['Progress'] = line.split(': ')[-1].rstrip()
        elif line.startswith('Speed.Dev.'):
            item = line.split(': ')
            gpu = item[0].replace('Speed.Dev.', 'Speed Dev ').replace('.', '')
            status[gpu] = line.split(': ')[-1].strip()
        elif line.startswith('Speed.#'):
            item = line.split(': ')
            gpu = item[0].replace('Speed.#', 'Speed #').replace('.', '').replace('*', '')
            gpu = re.sub('\d', '', gpu)
            #status[gpu] = line.split(' ')[1] + ' ' + line.split(' ')[2]
            #status[gpu] = re.search(r"\b\d+.*/s\b", line).group()
            status[gpu] = re.search(r"\b\d+.?\d?\s.*/s\b", line).group()
        elif line.startswith('HWMon.Dev.'):
            item = line.split('.: ')
            gpu = item[0].replace('HWMon.Dev.', 'HWMon Dev ').replace('.', '')
            status[gpu] = line.split('.: ')[-1].strip()
    return status

def killHashcat(pid):
    if sys.platform == 'win32':
        print('Hashcat-agent is not supported on windows. But pull requests are welcome')
    else:
        os.kill(int(pid), signal.SIGTERM)
        #p = psutil.Process(pid)
        #p.terminate()

def uploadCrackFile(file_path, hash_type):
    return api.uploadCrackFile(file_path, hash_type)

def getHashType(hashfile_id):
    return api.getHashType(hashfile_id)

def updateJobTask(job_task_id, task_status):
    return api.updateJobTask(job_task_id, task_status)    

if __name__ == '__main__':
    from agent import config

    if args.debug:
        builtins.state = 'debug'
    else:
        builtins.state = 'normal'
    
    # Main loop
    while (1):
        agent_status = ''

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


                # Get Job, so that we can get our hashfile
                job = jobs(job_task['job_id'])

                # Download our hashfile. File name will be generated to match that of whats expected by the jobtask cmd.
                download_hashfile(job['id'], job_task['task_id'], job['hashfile_id'])

                cmd = replaceHashcatBinPath(job_task['command']) + ' | tee control/outfiles/hcoutput_' + str(job['id']) + '_' + str(job_task['id']) + '.txt'
                print(cmd)

                # run in thread
                thread = Thread(target=run_hashcat, args=(cmd,))
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
                            uploadCrackFileResponse = uploadCrackFile(crack_file, getHashTypeResponse['hash_type'])
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
                        uploadCrackFileResponse = uploadCrackFile(crack_file, getHashTypeResponse['hash_type'])
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

