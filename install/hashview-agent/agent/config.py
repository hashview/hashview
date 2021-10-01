from configparser import ConfigParser
file_config = ConfigParser()

class Config:
    file_config.read('agent/config.conf')

    # Server info
    HASHVIEW_SERVER = file_config['HASHVIEW']['server']
    HASHVIEW_PORT = file_config['HASHVIEW']['port']
    USE_SSL = file_config['HASHVIEW']['use_ssl']

    # Agent Info
    NAME = file_config['AGENT']['NAME']
    UUID = file_config['AGENT']['UUID']
    HC_BIN_PATH = file_config['AGENT']['HC_BIN_PATH']