#!/usr/bin/python3
import sys
import os
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
    continue_as_root = input('Would you like to continue as root? [y/N]')
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

# prompt for info
print('Collecting Hashview Web Application Configuration Information')
hashview_admin_email = input('Enter Email address for the Administrator account. You will use this to log into the app: ')
hashview_admin_password = input('Enter a password for the Administrator account: ')
hashview_port = input('What port should hashview listen on: ') # Sanitation checks to ensure: int, 1-65535, is entered.
use_ssl = input('Would you use SSL (will generate self signed certs: ')

print('Collecting Hashview Database Configuration Information')
db_server = input('Enter the IP or hostname of the server running mysql. i.e. 127.0.0.1 or localhost: ')
db_username = input('Enter the user account hashview should use to connect to the mysql instance: ')
db_password = getpass('Enter the password for ' + db_username + ': ')

print('Collecting Hashview SMTP Configuration Information')
smtp_server = input('Enter the IP or hostname of the SMTP server: ')
smtp_sender_address = input('Enter the email address Hashview should send emails from: ')
smtp_username = input('Enter username used to authenticate to the SMTP server [Enter for none]: ')
smtp_password = input('Enter the password used to authenticate to the SMTP server [Enter for none]: ')
smtp_tls = input('Does the SMTP server use TLS?: ')

print('Collecting Hashcat Configuration Information')
hashcat_path = input('Enter the path to a local install of hashcat: ')


# Write config file
config = open("hashview/config.conf", "w")
config.write("[database]")
config.write("host = " + str(db_server))
config.write("username = " + str(db_username))
config.write("password = " + str(db_password))

config.write("")
config.write("[SMTP]")
config.write("server = " + str(smtp_server))
config.write("port = 25")
config.write("password = " + str(db_password))
config.write("use_tls = " + str(smtp_tls))
config.write("username = " + str(smtp_username))
config.write("password = " + str(smtp_password))
config.write("default_sender = " + str(smtp_sender_address))

config.close()

    #           create/copy example config
    #         - export FLASK_APP=hashview.py 
    #         - flask db init
    #         - flask db migrate
    #         - flask db upgrade
    #
    
