"""Manage parsing of Config and loading into Config class"""
import secrets
from configparser import ConfigParser

from hashview.form_limits import resolve_max_form_memory_size

file_config = ConfigParser()

class Config:
    """Class representing Config"""

    file_config.read('hashview/config.conf')
    SECRET_KEY = file_config['SERVER'].get('SECRET_KEY', secrets.token_hex(16))

    # Server Config
    SERVER_NAME = file_config['SERVER']['SERVER_NAME']

    # Byte cap on non-file form fields (e.g. the pasted-hashes textarea).
    # Read via the same .get(key, default) idiom as SECRET_KEY above (not the
    # bare indexing used for SERVER_NAME) so an older config.conf that predates
    # this key doesn't KeyError on upgrade. Omitting the key leaves Flask's own
    # default (500000) in place, so nothing changes. Values below 64 KiB are
    # clamped up -- see hashview/form_limits.py for why a smaller cap would
    # break every file upload.
    MAX_FORM_MEMORY_SIZE = resolve_max_form_memory_size(
        file_config['SERVER'].get('MAX_FORM_MEMORY_SIZE')
    )

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
