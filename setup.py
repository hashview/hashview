#!/usr/bin/python3
import os
import sys
from getpass import getpass

# Step 1
# Check version of python
if sys.version_info.major < 3:
    print('You must be running python 3.6 or newer')
    exit()
if sys.version_info.minor < 6:
    print('You must be running python 3.6 or newer')
    exit()

# Step 2
# Check if running as root
if os.geteuid() == 0:
    print('Hashview, nor its installer needs to run as root. The only time you need to run with root/sudo privs is if you intend to host the web service on a port < 1024.')
    print('If you continue, any installed python modules will be installed as root and not a regular user.')
    continue_as_root = input('Would you like to continue as root? [y/N]: ')
    if continue_as_root.lower() != 'y':
        exit()

# Step 3
# Check if upgrading or installing
print('Are you installing Hashview for the first time, or upgrading from an older instance?')
print('Upgrade: 1')
print('Fresh Install: 2')
step_three_prompt = input('Enter choice: ')
while step_three_prompt != '1' and step_three_prompt != '2':
    print('Invalid select, enter either 1 or 2.')
    step_three_prompt = input('Enter choice: ')

if step_three_prompt == '1':
    print("See MIGRATION.md")
    exit()

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


requirements = open('requirements.txt', 'r')
for entry in requirements:
    install_and_import('transliterate')

print('\nCollecting Hashview Database Configuration Information')
db_server = input('Enter the IP or hostname of the server running mysql. i.e. 127.0.0.1 or localhost: ')
while len(db_server) == 0:
    print('Error: Invalid entry Please try again.')
    db_server = input('Enter the IP or hostname of the server running mysql. i.e. 127.0.0.1 or localhost: ')

db_username = input('Enter the user account hashview should use to connect to the mysql instance: ')
while len(db_username) == 0:
    print("Error: Invalid entry. Please try again.")
    db_username = input('Enter the user account hashview should use to connect to the mysql instance: ')

db_password = getpass('Enter the password for ' + db_username + ': ')
while len(db_password) == 0:
    print("Error: You must provide a password.")
    db_password = getpass('Enter the password for ' + db_username + ': ')

print('\nCollecting Hashview SMTP Configuration Information')
smtp_server = input('Enter the IP or hostname of the SMTP server: ')
while len(smtp_server) == 0:
    print("Error: Invalid entry. Please try again.")
    smtp_server = input('Enter the IP or hostname of the SMTP server: ')

smtp_sender_address = input('Enter the email address Hashview should send emails from: ')
while len(smtp_sender_address) == 0:
    print("Error: Invalid entry. Please try again.")
    smtp_sender_address = input('Enter the email address Hashview should send emails from: ')

smtp_username = input('Enter username used to authenticate to the SMTP server [Enter for none]: ')

smtp_password = getpass('Enter the password used to authenticate to the SMTP server [Enter for none]: ')

smtp_tls = input('Does the SMTP server use TLS? [y/N]: ')
if smtp_tls == 'y' or smtp_tls == 'Y':
    smtp_tls = True
else:
    smtp_tls = False

# Write config file
config = open("hashview/config.conf", "w")
config.write("[database]\n")
config.write("host = " + str(db_server) + "\n")
config.write("username = " + str(db_username) + "\n")
config.write("password = " + str(db_password) + "\n\n")

config.write("[SMTP]\n")
config.write("server = " + str(smtp_server) + "\n")
config.write("port = 25\n")
config.write("use_tls = " + str(smtp_tls) + "\n")
config.write("username = " + str(smtp_username) + "\n")
config.write("password = " + str(smtp_password) + "\n")
config.write("default_sender = " + str(smtp_sender_address) + "\n")

config.close()

print('Writing hashview config at: hashview/config.conf')

# There's probably a better way to do this:
print('Bulding Database')
os.system('export FLASK_APP=hashview.py; flask db upgrade')
    
# Generating SSL Certs
print('Generating SSL Certificates')
os.system('openssl req -x509 -newkey rsa:4096 -nodes -out ./hashview/ssl/cert.pem -keyout ./hashview/ssl/key.pem -days 365')

print('You can now start your instance of hashview by running the following command: ./hashview.py')
print('Done.')