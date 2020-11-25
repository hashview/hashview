import secrets
from configparser import ConfigParser
file_config = ConfigParser()

class Config:
    file_config.read('hashview/config.conf')
    SECRET_KEY = secrets.token_hex(16)
    SQLALCHEMY_DATABASE_URI = 'mysql+mysqlconnector://' + file_config['database']['username'] + ':' + file_config['database']['password'] + '@' + file_config['database']['host'] + '/hashview_dev'