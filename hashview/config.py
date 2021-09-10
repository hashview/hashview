import secrets
from configparser import ConfigParser
file_config = ConfigParser()

class Config:
    file_config.read('hashview/config.conf')
    SECRET_KEY = secrets.token_hex(16)
    SQLALCHEMY_DATABASE_URI = 'mysql+mysqlconnector://' + file_config['database']['username'] + ':' + file_config['database']['password'] + '@' + file_config['database']['host'] + '/hashview'
    
    # SMTP Config
    MAIL_SERVER = file_config['SMTP']['server']
    MAIL_PORT = file_config['SMTP']['port']
    MAIL_USE_TLS = file_config['SMTP']['use_tls']
    MAIL_USERNAME = file_config['SMTP']['username']
    MAIL_PASSWORD = file_config['SMTP']['password']
    MAIL_DEFAULT_SENDER = file_config['SMTP']['default_sender'] 