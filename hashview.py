#!/usr/bin/python3
import argparse
import logging
import builtins
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
    from hashview.utils.utils import get_filehash, get_linecount
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
            admin_firstname = input('Enter Administrator\'s first name: ')

        admin_lastname = input('Enter Administrator\'s last name: ')
        while len(admin_lastname) == 0:
            print('Error: Firstname must be at least 1 character long')
            admin_lastname = input('Enter Administrator\'s last name: ')    

        print('\nProvisioning account in database.')
        hashed_password = bcrypt.generate_password_hash(admin_password).decode('utf-8')

        user = Users(first_name=admin_firstname, last_name=admin_password, email_address=admin_email, password=hashed_password, admin=True)
        db.session.add(user)
        db.session.commit()

    # Setting hashcat bin path
    if not settings:

        retention_period = input('Enter how long data should be retained in DB in days. (note: cracked hashes->plaintext will be be safe from retention culling): ')
        while int(retention_period) < 1 or int(retention_period) > 65535:
            print('Error: Retention must be between 1 day and 65535 days')
            retention_period = input("Enter how long data should be retained in DB in days. (note: cracked hashes->plaintext will be be safe from retention culling): ")

        settings = Settings(retention_period = retention_period)
        db.session.add(settings)
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

        rules_path = 'hashview/control/rules/best64.rule'
        
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
        )             
        db.session.add(task)
        db.session.commit()

        # wordlist with best 64 rules
        task = Tasks(   name='Rockyou Wordlist + Best64 Rules', 
                owner_id='1',
                wl_id='1',
                rule_id='1', 
                hc_attackmode='dictionary'
        )             
        db.session.add(task)
        db.session.commit()

        
        # mask mode of all 8 characters
        task = Tasks(   name='?a?a?a?a?a?a?a?a [8]', 
                        owner_id='1',
                        wl_id=None,
                        rule_id=None, 
                        hc_attackmode='maskmode',
                        hc_mask='?a?a?a?a?a?a?a?a'
        )   
        db.session.add(task)
        db.session.commit() 



    print('Done! Running Hashview! Enjoy.')


# Launching our scheduler
def data_retention_cleanup():
    with app.app_context():
        from hashview.models import Settings, Jobs, JobTasks, JobNotifications, HashfileHashes, HashNotifications, Hashes, Hashfiles
        from hashview.utils.utils import send_email
        from datetime import datetime, timedelta
        import time
        import os
        from hashview import db

        print('[DEBUG] Im retaining all the data: ' + str(datetime.now()))

        setting = Settings.query.get('1')
        retention_period = setting.retention_period
        filter_after = datetime.today() - timedelta(days = retention_period)

        # Remove job, job tasks and job notifications
        jobs = Jobs.query.filter(Jobs.created_at < filter_after).all()
        for job in jobs:
            # Send email saying we've deleted their job
            user = Users.query.get(job.owner_id)
            subject = 'Hashview removed an old job: ' + str(job.name)
            message = 'Hello ' + str(user.first_name) + ', \n\n In accordance to the data retention policy of ' + str(retention_period) + ' days, your job "' + str(job.name) + '" was deleted.'
            send_email(user, subject, message)

            JobTasks.query.filter_by(job_id=job.id).delete()
            JobNotifications.query.filter_by(job_id=job.id).delete()

            db.session.delete(job)
            db.session.commit()

            print("[DEBUG] Job Name: " + str(job.name) + '  Owner ID: ' + str(job.owner_id))

        # Remove Hashfiles (note hashfiles might be associated to a job thats < retention period. Those jobs should be removed too)
        hashfiles = Hashfiles.query.filter(Hashfiles.uploaded_at < filter_after).all()
        for hashfile in hashfiles:

            # Job, jobtask and job notifications
            jobs = Jobs.query.filter_by(hashfile_id = hashfile.id).all()
            for job in jobs:
                print("[DEBUG] Hashfile->jobs: Job Name: " +str(job.name))
                user = Users.query.get(job.owner_id)
                subject = 'Hashview removed a job that was associated to an old hash file: ' + str(job.name)
                message = 'Hello ' + str(user.first_name) + ', \n\n In accordance to the data retention policy of ' + str(retention_period) + ' days, your hashfile "' + str(hashfile.name) + '" was associated with a job "' + str(job.name) + '". This job was deleted.'
                send_email(user, subject, message)

                JobTasks.query.filter_by(job_id=job.id).delete()
                JobNotifications.query.filter_by(job_id=job.id).delete()

                db.session.delete(job)
                db.session.commit()
                
            # Hashfiles, HashfileHashes and Hash notifications
            print('[DEBUG] Hashfile Name: ' + str(hashfile.name) + '    Owner ID: ' + str(hashfile.owner_id))
            print('[DEBUG] Hashfile ID: ' + str(hashfile.id))
            user = Users.query.get(hashfile.owner_id)
            subject = 'Hashview removed an old Hashfile: ' + str(hashfile.name)
            message = 'Hello ' + str(user.first_name) + ', \n\n In accordance to the data retention policy of ' + str(retention_period) + ' days, your hashfile "' + str(hashfile.name) + '" was removed.'
            send_email(user, subject, message)

            hashfile_hashes = HashfileHashes.query.filter_by(hashfile_id = hashfile.id).all()
            for hashfile_hash in hashfile_hashes:
                hashes = Hashes.query.filter_by(id=hashfile_hash.hash_id).filter_by(cracked=0).all()
                for hash in hashes:
                    # Check to see if our hashfile is the ONLY hashfile that has this hash
                    # if duplicates exist, they can still be removed. Once the hashfile_hash entry is remove, 
                    # the total number of matching hash_id's will be reduced to < 2 and then can be deleted
                    hashfile_cnt = HashfileHashes.query.filter_by(hash_id=hash.id).distinct('hashfile_id').count()
                    if hashfile_cnt < 2:
                        db.session.delete(hash)
                        db.session.commit()
                        HashNotifications.query.filter_by(hash_id=hashfile_hash.hash_id).delete()
                db.session.delete(hashfile_hash)
            db.session.delete(hashfile)
            db.session.commit()

        # Clean temp folder of files older than RETENTION PERIOD
        for file in os.listdir('hashview/control/tmp'):
            print('[DEBUG] hashview.py->data_retention_cleanup() ' + file)
            if os.stat('hashview/control/tmp/' + file).st_mtime < time.time() - retention_period * 86400:
                os.remove('hashview/control/tmp/' + file)
                print('[DEBUG] hashview.py->data_retention_cleanup() Removed: hashview/control/tmp/' + file)

        print('[DEBUG] ==============')

# This shows up twice... i dont know why
with app.app_context():
    from hashview import scheduler
    scheduler.delete_all_jobs
    scheduler.add_job(id='DATA_RETENTION', func=data_retention_cleanup, trigger='cron', hour='1') #hour=1
    #scheduler.add_job(id='DATA_RETENTION', func=data_retention_cleanup, trigger='cron', hour='*')

if __name__ == '__main__':
    if args.debug:
        builtins.state = 'debug'
        app.run(host='0.0.0.0', port=8443, ssl_context=('./hashview/ssl/cert.pem', './hashview/ssl/key.pem'), debug=True)

    else:
        builtins.state = 'normal'
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)  
        app.run(host='0.0.0.0', port=8443, ssl_context=('./hashview/ssl/cert.pem', './hashview/ssl/key.pem'), debug=False)
