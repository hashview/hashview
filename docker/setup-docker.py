#!/usr/bin/python3
import os


# Install dependencies
def install_and_import(package):
    import importlib
    try:
        importlib.import_module(package)
    except ImportError:
        import pip
        pip.main(['install', package])
    finally:
        globals()[package] = importlib.import_module(package)

# Assuming requirements.txt only contains 'transliterate'
install_and_import('transliterate')

# Configuration from environment variables
db_server = os.environ.get('DB_SERVER', 'db')
db_username = os.environ.get('DB_USERNAME', 'root')
db_password = os.environ.get('DB_PASSWORD', 'password')
smtp_server = os.environ.get('SMTP_SERVER', 'localhost')
smtp_sender_address = os.environ.get('SMTP_SENDER_ADDRESS', 'hashview@example.com')
smtp_username = os.environ.get('SMTP_USERNAME', '')
smtp_password = os.environ.get('SMTP_PASSWORD', '')
smtp_tls = os.environ.get('SMTP_TLS', 'n').lower() in ['y', 'yes', 'true', '1']

# Write config file
with open("hashview/config.conf", "w") as config:
    config.write(f"""[database]
host = {db_server}
username = {db_username}
password = {db_password}

[SMTP]
server = {smtp_server}
port = 25
use_tls = {str(smtp_tls)}
username = {smtp_username}
password = {smtp_password}
default_sender = {smtp_sender_address}
""")

print('Writing hashview config at: hashview/config.conf')

# Database and SSL setup commands
# os.system('export FLASK_APP=hashview.py; flask db upgrade')

# get CERT_SUBJECT from os.environ
cert_subject = os.environ.get('CERT_SUBJECT', '/C=US/ST=OHIO/L=WeightRoom/O=Internet Widgits Pty Ltd/OU=/CN=/emailAddress=hans@localhost.local')

print('Generating SSL certificate...')

os.system(f'openssl req -x509 -newkey rsa:4096 -nodes -out ./hashview/ssl/cert.pem -keyout ./hashview/ssl/key.pem -days 365 -subj "{cert_subject}"')

print('Setup complete. You can now start your instance of hashview by running: ./hashview.py')