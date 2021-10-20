# hashview-new

# Hashview
[![Build Status](https://travis-ci.org/hashview/hashview.svg?branch=master)](https://travis-ci.org/hashview/hashview)

>**Hashview** is a tool for security professionals to help organize and automate the repetitious tasks related to password cracking. It is broken into two compoents, the Hashview Server, and Hashview Agent. The Hashview Server is a web application that manages one or more agents, deployed by you on dedicated hardware. (note you can run the server and agent on the same machine). Hashview strives to bring constiency in your hashcat tasks while delivering analytics with pretty pictures ready for ctrl+c, ctrl+v into your reports.

## Server Requirements

1. Python 3.7+
2. Mysql DB installed with known username/password   

## Agent Requirements

1. Python 3.7+
2. Hashcat

## Installation

git clone https://github.com/hashview/hashview/
cd hashview
sh install.sh

[Installation Instructions](https://github.com/hashview/hashview/wiki/01_Installing-Hashview)

### Developing and Contributing

Please see the [Contribution Guide](https://github.com/hashview/hashview/wiki/Contributing) for how to develop and contribute.  
If you have any problems, please consult [Issues](https://github.com/hashview/hashview/issues) page first. If you don't see a related issue, feel free to add one and we'll help.

### Authors

Contact us on Twitter  
@caseycammilleri  
@jarsnah12
