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

    # Connection-pool sizing. Previously unset, which left SQLAlchemy's own
    # defaults of pool_size=5 / max_overflow=10 -- a 15-connection ceiling that
    # nobody chose, against a MySQL max_connections of 151. When a long-running
    # transaction (the hourly retention purge was the culprit) made other
    # queries block, 15 in-flight requests parked the entire pool and every new
    # request -- agents included -- failed in before_request with
    # "QueuePool limit of size 5 overflow 10 reached".
    #
    # 10 + 20 is headroom, not a fix for that (a bigger pool fills too, just
    # slower); the retention batching is the fix. It is deliberately well under
    # max_connections so several processes can share the server.
    #
    # pool_pre_ping validates a connection before handing it out, which is what
    # stops "MySQL server has gone away" after an idle period. pool_recycle must
    # stay below MySQL's wait_timeout (28800 here) so the pool retires a
    # connection before the server does. pool_timeout is spelled out rather than
    # left implicit because it interacts with innodb_lock_wait_timeout: a query
    # blocked on a row lock holds its connection for up to that long, so if the
    # lock timeout exceeds this value the pool gives up before the blocked
    # queries do.
    #
    # SQLite is unaffected: the unit tests replace SQLALCHEMY_ENGINE_OPTIONS
    # wholesale (its SingletonThreadPool rejects max_overflow outright), and the
    # URI above is always MySQL.
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': int(file_config['database'].get('pool_size', 10)),
        'max_overflow': int(file_config['database'].get('max_overflow', 20)),
        'pool_timeout': 30,
        'pool_recycle': 3600,
        'pool_pre_ping': True,
    }

    # SMTP Config
    MAIL_SERVER = file_config['SMTP']['server']
    MAIL_PORT = file_config['SMTP']['port']
    MAIL_USE_TLS = file_config['SMTP']['use_tls']
    MAIL_USERNAME = file_config['SMTP']['username']
    MAIL_PASSWORD = file_config['SMTP']['password']
    MAIL_DEFAULT_SENDER = file_config['SMTP']['default_sender']
