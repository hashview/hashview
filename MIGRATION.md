# Migrating from Hashview v0.7.4 -> v0.8.0
Because v0.8.0 is a complete rewrite from v0.7.4 there is no easy migration path. If you have installed/used version 0.7.4 or older and wish to retain your information, you can do either of the following:

If your old version of hashview (v0.7.4 or older) is still running, you can perform the following steps to retain the wordlists, rules and cracked->plaintext data to be used with the new version of hashview (v0.8.0). Note, other apsects, like user accounts, customers, tasks, jobts etc will not be migrated.

### Migrating Wordlists & Rules
The steps for migrating Wordlists & Rules from hashview v0.7.4 -> v0.8.0 are similar. In the old project folder, the the raw files are stored under control/rules and control/wordlists. Once your new version of hashview is running, you can import/add these manually from the old project folder.

### Migrating Hashes
#### 1) Log into Hashview v0.7.4
#### 2) Go to Manage->Analytics
#### 3) Download Cracked Hashes for ALL customers
#### 4) Shutdown Hashview web app / remove hashview db (NOTE THIS WILL ERASE ALL PREVIOUS DATA!)
#### 5) Install a fresh copy of hashview v0.8.0
#### 6) Create a new job, with a new customer, and import the hashes/plains as a new hashfile and a new wordlist.
