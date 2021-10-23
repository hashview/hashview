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

#### 1) Setup mysql. 
These instructions are for Ubuntu, but in theory Hashview should be able to run on any *nix system.

```
sudo apt update
sudo apt install mysql-server
sudo mysql_secure_installation
```

#### 2) Configure MySQL
Log into your mysql server and create a dedicated user for hashview. Hashview can run as root, but doesnt need to. And since we practice what we preach. we should use a lower priv account for this. If you're installing hashview on a different server than the system where the mysql db is running on, adjust the account creation 
```
sudo mysql
CREATE USER 'hashview'@'localhost' IDENTIFIED BY 'DoNotUseThisPassword123!';
GRANT ALL PRIVILEGES ON hashview.* TO 'hashview'@'localhost';
FLUSH PRIVILEGES;
create database hashview;
exit
```


#### 3) Install Hashview
The following are to install hashview after the mysql db has been setup
```
sudo apt-get install python3 python3-pip python3-flask
git clone https://github.com/hashview/hashview/
cd hashview
pip3 install -r requirements.txt
./setup.py
./hashview.py # (note you can add a --debug if you are attempting to troubleshoot an issue)
```

## Installing Hashview-Agent
After you've installed hashview you will need to install a hashview-agent. The agent can run on the same system as hashview, but doesn't have to.

#### 1) Log into hashview as an Administrator
#### 2) Navigate to Agents Menu
#### 3) Click Download Agent to get a .tgz package of the hashview-agent
#### 4) Move agent to the system you'd like to run it on
#### 5) Install Agent
You will need to decompress the package and run the `hashview-agent.py` script. Upon initial execution it will prompt you for information about your hashview server.
```
tar -xzvf hashview-agent.<version>.tgz
cd install/
cp -r hashview-agent ../
cd ../hashview-agent
python3 ./hashview-agent.py
```




### Developing and Contributing

Please see the [Contribution Guide](https://github.com/hashview/hashview/wiki/Contributing) for how to develop and contribute.  
If you have any problems, please consult [Issues](https://github.com/hashview/hashview/issues) page first. If you don't see a related issue, feel free to add one and we'll help.

### Authors

Contact us on Twitter  
@caseycammilleri  
@jarsnah12
