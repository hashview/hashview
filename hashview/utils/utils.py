import os
import secrets
import hashlib
from hashview import mail
from hashview.models import Settings
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
    #sender = Settings.smtp_sender
    #sender = 'hashview@trustedsec.com'
    #msg = Message(subject, sender=sender, recipients=[user.email_address])
    msg = Message(subject, recipients=[user.email_address])
    msg.body = message
    mail.send(msg)
    