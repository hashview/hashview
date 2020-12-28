import os
import secrets
import hashlib
import subprocess
from hashview import mail
from hashview.models import Settings, Rules, Wordlists
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