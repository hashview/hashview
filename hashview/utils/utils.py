import os
import secrets
import hashlib
import subprocess
import hashlib
from hashview import mail, db
from hashview.models import Settings, Rules, Wordlists, Hashfiles, HashfileHashes, Hashes, Tasks, Jobs
from flask_mail import Message
from flask import current_app


def save_file(path, form_file):
    random_hex = secrets.token_hex(8)
    file_name = random_hex + os.path.split(form_file.filename)[0] + '.txt'
    file_path = os.path.join(current_app.root_path, path, file_name)
    form_file.save(file_path)
    return file_path

def get_linecount(filepath):
    return sum(1 for line in open(filepath))

def get_filehash(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath,"rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096),b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def send_email(user, subject, message):
    msg = Message(subject, recipients=[user.email_address])
    msg.body = message
    mail.send(msg)
    
def get_keyspace(method, wordlist_id, rule_id, mask):
    settings = Settings.query.first()
    return_value = 0
    cmd = [settings.hashcat_path]
    if method == 'dictionary':
        wordlist = Wordlists.query.filter_by(id=wordlist_id).first()
        cmd.append(wordlist.path)
    if rule_id != None:
        rule = Rules.query.filter_by(id=rule_id).first()
        cmd.append('-r')
        cmd.append(rule.path)
    elif method == 'maskmode':
        cmd.append('-a3')
        cmd.append(mask)
    cmd.append('--keyspace')

    p = subprocess.run(cmd, check=False, stdout=subprocess.PIPE, encoding='utf-8')
    print(p.stdout.split('\n')[0])
    return_value = p.stdout.split('\n')[0]

    return return_value

def get_md5_hash(string):
    m = hashlib.md5()
    m.update(string.encode('utf-8'))
    return m.hexdigest()

def import_hash_only(line, hash_type):
    hash = Hashes.query.filter_by(hash_type=hash_type, sub_ciphertext=get_md5_hash(line)).first()
    if hash:
        return hash.id
    else:
        new_hash = Hashes(hash_type=hash_type, sub_ciphertext=get_md5_hash(line), ciphertext=line, cracked=0)
        db.session.add(new_hash)
        db.session.commit()
        return new_hash.id

def import_pwdump(line):
    return True

def import_hashfilehashes(hashfile_id, hashfile_path, file_type, hash_type):
    # Open file
    file = open(hashfile_path, 'r')
    lines = file.readlines()

    # for line in file, 
    for line in lines:
        if file_type == 'hash_only':
            hash_id = import_hash_only(line=line.rstrip(), hash_type=hash_type)
            username = None
        elif file_type == 'pwdump':
            # do we let user select LM so that we crack those instead of NTLM?
            hash_id = import_hash_only(line=line.split(':')[3], hash_type='1000')
            username = line.split(':')[0]
        elif file_type == 'kerberos':
            hash_id = import_hash_only(line=line.rstrip(), hash_type=hash_type)
            username = line.split('$')[5]
        elif file_type == 'NetNTLM':
            hash_id = import_hash_only(line=line.rstrip(), hash_type=hash_type)
            username = line.split(':')[0]
        else:
            print(str(file_type))
            return False
        hashfilehashes = HashfileHashes(hash_id=hash_id, username=username, hashfile_id=hashfile_id)
        db.session.add(hashfilehashes)
        db.session.commit()

    # - parse each line based on hash type
    #   - Insert into hashes table with hash type, sub_ciphertext (md5?)
    #   - Get hash id
    #   - insert into hashfile hashes, hash.id, username, and hashfile.id
    

    return True

def update_dynamic_wordlist(wordlist_id):
    wordlist = Wordlists.query.get(wordlist_id)
    hashes = Hashes.query.filter_by(cracked=True).distinct('plaintext')

    # Do we delete the original file, or overwrite it?
    # if we overwrite, what happens if the new content has fewer lines than the previous file.
    # would this even happen? In most/all cases there will be new stuff to add.
    # is there a file lock on a wordlist when in use by hashcat? Could we just create a temp file and replace after generation?
    # Open file
    file = open(wordlist.path, 'wt')
    for entry in hashes:
        file.write(entry.plaintext + '\n')
    file.close()

    # update line count
    wordlist.size = get_linecount(wordlist.path)
    # update file hash
    wordlist.checksum = get_filehash(wordlist.path)
    db.session.commit()

def build_hashcat_command(job_id, task_id):
    # this function builds the main hashcat cmd we use to crack.
    hc_binpath = '@HASHCATBINPATH@'
    task = Tasks.query.get(task_id)
    job = Jobs.query.get(job_id)
    rules_file = Rules.query.get(task.rule_id)
    hashfilehashes_single_entry = HashfileHashes.query.filter_by(hashfile_id = job.hashfile_id).first()
    hashes_single_entry = Hashes.query.get(hashfilehashes_single_entry.hash_id)
    hash_type = hashes_single_entry.hash_type
    attackmode = task.hc_attackmode
    mask = task.hc_mask

    if attackmode == 'combinator':
        print('unsupported combinator')
    else:
        wordlist = Wordlists.query.get(task.wl_id)

    target_file = 'control/hashes/hashfile_' + str(job.id) + '_' + str(task.id) + '.txt'
    crack_file = 'control/outfiles/hc_cracked_' + str(job.id) + '_' + str(task.id) + '.txt'
    if wordlist:
        relative_wordlist_path = 'control/wordlists/' + wordlist.path.split('/')[-1]
    else:
        relative_wordlist_path = ''
    if rules_file:
        relative_rules_path = 'control/rules/' + rules_file.path.split('/')[-1]
    else:
        relative_rules_path = ''

    session = secrets.token_hex(4)

    if attackmode == 'bruteforce':
        cmd = hc_binpath + ' --session ' + session + ' -m ' + str(hash_type) + ' --potfile-disable' + ' --status --status-timer=15' + ' --outfile-format 5' + ' --outfile ' + crack_file + ' ' + ' -a 3 ' + target_file
    elif attackmode == 'maskmode':
        cmd = hc_binpath + ' --session ' + session + ' -m ' + str(hash_type) + ' --potfile-disable' + ' --status --status-timer=15' + ' --outfile-format 5' + ' --outfile ' + crack_file + ' ' + ' -a 3 ' + target_file + ' ' + mask
    elif attackmode == 'dictionary':
        if isinstance(task.rule_id, int):
            cmd = hc_binpath + ' --session ' + session + ' -m ' + str(hash_type) + ' --potfile-disable' + ' --status --status-timer=15' + ' --outfile-format 5' + ' --outfile ' + crack_file + ' ' + ' -r ' + relative_rules_path + ' ' + target_file + ' ' + relative_wordlist_path
        else:
            cmd = hc_binpath + ' --session ' + session + ' -m ' + str(hash_type) + ' --potfile-disable' + ' --status --status-timer=15' + ' --outfile-format 5' + ' --outfile ' + crack_file + ' ' + target_file + ' ' + relative_wordlist_path
    elif attackmode == 'combinator':
      cmd = hc_binpath + ' --session ' + session + ' -m ' + str(hash_type) + ' --potfile-disable' + ' --status --status-timer=15' + ' --outfile-format 5' + ' --outfile ' + crack_file + ' ' + ' -a 1 ' + target_file + ' ' + wordlist_one.path + ' ' + ' ' + wordlist_two.path + ' ' + relative_rules_path

    print("cmd: " + cmd)

    return cmd