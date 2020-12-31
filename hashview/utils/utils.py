import os
import secrets
import hashlib
import subprocess
import hashlib
from hashview import mail, db
from hashview.models import Settings, Rules, Wordlists, Hashfiles, HashfileHashes, Hashes
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
        cmd.append('-a 3')
        cmd.append(mask)
    cmd.append('--keyspace')

    p = subprocess.Popen(cmd, stdout=subprocess.PIPE)

    for line in p.stdout:
        #janky af, we really should only grab the last line
        return_value = line

    return return_value

def get_md5_hash(string):
    m = hashlib.md5()
    m.update(string.encode('utf-8'))
    return m.hexdigest()

def import_hash_only(line, hash_type):
    hash = Hashes.query.filter_by(hash_type=hash_type, sub_ciphertext=get_md5_hash(line), ciphertext=line).first()
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
            hashfilehashes = HashfileHashes(hash_id=hash_id, hashfile_id=hashfile_id)
            db.session.add(hashfilehashes)
            db.session.commit()
        else:
            print(str(file_type))
            return False

    # - parse each line based on hash type
    #   - Insert into hashes table with hash type, sub_ciphertext (md5?)
    #   - Get hash id
    #   - insert into hashfile hashes, hash.id, username, and hashfile.id
    

    return True