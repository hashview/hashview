# hashview-new

# Hashview
[![Build Status](https://travis-ci.org/hashview/hashview.svg?branch=master)](https://travis-ci.org/hashview/hashview)

>**Hashview** is a tool for security professionals to help organize and automate the repetitious tasks related to password cracking. It is broken into two compoents, the Hashview Server, and Hashview Agent. The Hashview Server is a web application that manages one or more agents, deployed by you on dedicated hardware. (note you can run the server and agent on the same machine). Hashview strives to bring constiency in your hashcat tasks while delivering analytics with pretty pictures ready for ctrl+c, ctrl+v into your reports.

## Server Requirements

1. Python 3.7+ 
2. Mysql DB installed with known username/password   
3. Access to an SMTP email service (used for password resets and notifications)

## Agent Requirements

1. Python 3.7+
2. Hashcat

## Installation

#### Setup mysql. 
These instructions are for Ubuntu, but in theory Hashview should be able to run on any *nix system.

```
sudo apt update
sudo apt install mysql-server
sudo mysql_secure_installation
```

#### Configure MySQL
Log into your mysql server and create a dedicated user for hashview. Hashview can run as root, but doesnt need to. And since we practice what we preach. we should use a lower priv account for this. If you're installing hashview on a different server than the system where the mysql db is running on, adjust the account creation 
```
sudo mysql
CREATE USER 'hashview'@'localhost' IDENTIFIED BY 'DoNotUseThisPassword123!';
GRANT ALL PRIVILEGES ON hashview.* TO 'hashview'@'localhost';
FLUSH PRIVILEGES;
create database hashview;
exit
```


#### Install Hashview
The following are to install hashview after the mysql db has been setup
```
sudo apt-get install python3 python3-pip python3-flask
git clone https://github.com/hashview/hashview/
cd hashview
pip3 install -r requirements.txt
./setup.py
./hashview.py # (note you can add a --debug if you are attempting to troubleshoot an issue)
```



### Developing and Contributing

Please see the [Contribution Guide](https://github.com/hashview/hashview/wiki/Contributing) for how to develop and contribute.  
If you have any problems, please consult [Issues](https://github.com/hashview/hashview/issues) page first. If you don't see a related issue, feel free to add one and we'll help.

### Authors

Contact us on Twitter  
@caseycammilleri  
@jarsnah12
