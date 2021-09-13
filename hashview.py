import argparse
import logging
from hashview import create_app 

parser = argparse.ArgumentParser()
parser.add_argument("--debug", action="store_true", help="increase output verbosity")
args = parser.parse_args()


app = create_app()


# There's probaby a better way to do this
# We needed some code to execute on app launch to check for whether or not this is a fresh install
# and if it was a fresh install to prompt the user for key information, populate the data base, and continue execution
with app.app_context():
    from hashview.models import Users, Wordlists, Rules, Tasks, Settings
    from hashview.utils.utils import get_filehash, get_linecount, get_keyspace
    from hashview import db, bcrypt
    from getpass import getpass
    import os

    users = Users.query.filter_by(admin='1').count()
    dynamic_wordlists = Wordlists.query.filter_by(type='dynamic').filter_by(name='All Recovered Hashes').count()
    static_wordlists = Wordlists.query.filter_by(type='static').count()
    rules = Rules.query.count()
    tasks = Tasks.query.count()
    settings = Settings.query.first()

    # If no admins exist prompt user to generate new admin account
    if users == 0:
        print('\nInitial setup detected. Hashview will now prompt you to setup an Administrative account.\n')
        admin_email = input('Enter Email address for the Administrator account. You will use this to log into the app: ')
        while len(admin_email) == 0:
            print('Error: You must provide an email address.')
            admin_email = input("Invalid email address. Try again: ")

        admin_password = getpass('Enter a password for the Administrator account: ')
        while len(admin_password) < 14:
            print('Error: Password must be more than 14 characters.')
            admin_password = getpass('Enter a password for the Administrator account: ')

        admin_firstname = input('Enter Administrator\'s first name: ')
        while len(admin_firstname) == 0:
            print('Error: Firstname must be at least 1 character long')
            admin_password = input('Enter Administrator\'s first name: ')

        admin_lastname = input('Enter Administrator\'s last name: ')
        while len(admin_lastname) == 0:
            print('Error: Firstname must be at least 1 character long')
            admin_password = input('Enter Administrator\'s last name: ')    

        print('\nProvisioning account in database.')
        hashed_password = bcrypt.generate_password_hash(admin_password).decode('utf-8')

        user = Users(first_name=admin_firstname, last_name=admin_password, email_address=admin_email, password=hashed_password, admin=True)
        db.session.add(user)
        db.session.commit()

    # Setting hashcat bin path
    if len(settings.hashcat_path) == 0:
        hashcat_path = input('Enter the path to hashcat bin: ')
        while len(hashcat_path) == 0 or (not os.exists(hashcat_path)):
            print('Error: File not found, or invalid path.')
            hashcat_path = input("Enter the path to hashcat bin: ")
        settings.hashcat_path = hashcat_path
        db.session.commit()

    # Setup dynamic wordlist
    if dynamic_wordlists == 0:
        print('\nSetting up dynamic wordlist.')
        wordlist_path = 'hashview/control/wordlists/dynamic-all.txt'
        open(wordlist_path, 'w')
        wordlist = Wordlists(name='All Recovered Hashes',
                    owner_id='1', 
                    type='dynamic', 
                    path=wordlist_path, # Can we make this a relative path?
                    checksum=get_filehash(wordlist_path),
                    size=0)
        db.session.add(wordlist)
        db.session.commit()
        
    # Setup wordlist rockyou
    if static_wordlists == 0:
        print('\nSetting up static wordlist rockyou.')
        cmd = "gzip -d -k install/rockyou.txt.gz"
        os.system(cmd)
        os.replace('install/rockyou.txt', 'hashview/control/wordlists/rockyou.txt')
    
        wordlist_path = 'hashview/control/wordlists/rockyou.txt'
        wordlist = Wordlists(name='Rockyou.txt',
            owner_id='1', 
            type='static', 
            path=wordlist_path, # Can we make this a relative path?
            checksum=get_filehash(wordlist_path),
            size=get_linecount(wordlist_path))
        db.session.add(wordlist)
        db.session.commit()

    # setup rules best64
    if rules == 0:
        print('\nSetting up best64.rules')
        cmd = "gzip -d -k install/best64.rule.gz"
        os.system(cmd)
        os.replace('install/best64.rule', 'hashview/control/rules/best64.rule')
    
        wordlist_path = 'hashview/control/wordlists/rockyou.txt'
        wordlist = Wordlists(name='Rockyou.txt',
            owner_id='1', 
            type='static', 
            path=wordlist_path, # Can we make this a relative path?
            checksum=get_filehash(wordlist_path),
            size=get_linecount(wordlist_path))
        db.session.add(wordlist)
        db.session.commit()

        rules_path = 'control/rules/best64.rule'
        
        rule = Rules(   name='Best64 Rule', 
                        owner_id='1', 
                        path=rules_path,
                        size=get_linecount(rules_path),
                        checksum=get_filehash(rules_path))
        db.session.add(rule)
        db.session.commit()

    # setup task
    if tasks == 0:
        
        print('\nSetting up default tasks.')

        # wordlist only
        task = Tasks(   name='Rockyou Wordlist', 
                        owner_id='1',
                        wl_id='1',
                        rule_id=None, 
                        hc_attackmode='dictionary',
                        keyspace=get_keyspace(  method='dictionary', 
                                                wordlist_id = '1', 
                                                rule_id=None,
                                                mask=None
                        )
        )             
        db.session.add(task)
        db.session.commit()

        # wordlist with best 64 rules
        task = Tasks(   name='Rockyou Wordlist + Best64 Rules', 
                owner_id='1',
                wl_id='1',
                rule_id='1', 
                hc_attackmode='dictionary',
                keyspace=get_keyspace(  method='dictionary', 
                                        wordlist_id = '1', 
                                        rule_id='1',
                                        mask=None
                )
        )             
        db.session.add(task)
        db.session.commit()

        
        # mask mode of all 8 characters
        task = Tasks(   name='?a?a?a?a?a?a?a?a [8]', 
                        owner_id='1',
                        wl_id=None,
                        rule_id=None, 
                        hc_attackmode='maskmode',
                        hc_mask='?a?a?a?a?a?a?a?a',
                        keyspace=get_keyspace(  method='maskmode', 
                                                wordlist_id = None, 
                                                rule_id=None,
                                                mask='?a?a?a?a?a?a?a?a'
            )
        )   
        db.session.add(task)
        db.session.commit() 



    print('Done! Running Hashview! Enjoy.')

if __name__ == '__main__':
    if args.debug:
        app.run(host='0.0.0.0', port=443, ssl_context=('./hashview/ssl/cert.pem', './hashview/ssl/key.pem'), debug=True)

    else:
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)  
        app.run(host='0.0.0.0', port=443, ssl_context=('./hashview/ssl/cert.pem', './hashview/ssl/key.pem'), debug=False)