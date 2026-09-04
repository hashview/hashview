"""Manage parsing of Config and loading into Config class"""
import secrets
from configparser import ConfigParser

file_config = ConfigParser()

class Config:
    """Class representing Config"""

    file_config.read('hashview/config.conf')
    SECRET_KEY = file_config['SERVER'].get('SECRET_KEY', secrets.token_hex(16))

    # Server Config
    SERVER_NAME = file_config['SERVER']['SERVER_NAME']

    # Byte cap on non-file form fields (e.g. the pasted-hashes textarea).
    # ConfigParser values are always strings, hence the int() coercion. Uses
    # the same .get(key, default) idiom as SECRET_KEY above (not the bare
    # indexing used for SERVER_NAME) so an older config.conf that predates
    # this key doesn't KeyError on upgrade. Default matches Flask 3.1's own
    # built-in MAX_FORM_MEMORY_SIZE default (500000), so omitting the key
    # changes nothing.
    MAX_FORM_MEMORY_SIZE = int(file_config['SERVER'].get('MAX_FORM_MEMORY_SIZE', 500000))

    # MYSQL Config. charset=utf8mb4 so the connection can carry 4-byte UTF-8
    # (emojis etc.) end-to-end — required now that usernames/plaintext are stored
    # as text rather than hex.
    SQLALCHEMY_DATABASE_URI = (
        'mysql+mysqlconnector://'
        + file_config['database']['username'] + ':'
        + file_config['database']['password'] + '@'
        + file_config['database']['host'] + '/hashview?charset=utf8mb4'
    )

    # SMTP Config
    MAIL_SERVER = file_config['SMTP']['server']
    MAIL_PORT = file_config['SMTP']['port']
    MAIL_USE_TLS = file_config['SMTP']['use_tls']
    MAIL_USERNAME = file_config['SMTP']['username']
    MAIL_PASSWORD = file_config['SMTP']['password']
    MAIL_DEFAULT_SENDER = file_config['SMTP']['default_sender']
