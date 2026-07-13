import sys
from configparser import ConfigParser

_CONFIG_PATH = 'agent/config.conf'
file_config = ConfigParser()


def _die(msg):
    """A bad config is fatal at startup -- the agent has no server address or
    identity to run with -- so surface one actionable message and exit instead of
    letting a bare KeyError escape from the class body below."""
    print('[ERROR] ' + msg)
    sys.exit(1)


def _require(section, key):
    try:
        return file_config[section][key]
    except KeyError:
        _die("%s is missing required key '%s' in section [%s]. "
             "Re-run the agent setup or fix the file." % (_CONFIG_PATH, key, section))


class Config:
    # ConfigParser.read() silently returns [] for a missing/unreadable file, which
    # would otherwise surface later as an opaque KeyError on the first key access.
    if not file_config.read(_CONFIG_PATH):
        _die("%s not found or unreadable. Run the agent once to generate it." % _CONFIG_PATH)

    # Server info
    HASHVIEW_SERVER = _require('HASHVIEW', 'server')
    HASHVIEW_PORT = _require('HASHVIEW', 'port')
    USE_SSL = _require('HASHVIEW', 'use_ssl')

    # Agent Info
    NAME = _require('AGENT', 'NAME')
    UUID = _require('AGENT', 'UUID')
    HC_BIN_PATH = _require('AGENT', 'HC_BIN_PATH')
    # Optional host-specific hashcat args (e.g. '-d 3,4' to pin GPUs); applied to
    # both cracking and benchmarking. Absent in older configs -> '' (no args).
    HC_EXTRA_ARGS = file_config['AGENT'].get('HC_EXTRA_ARGS', '')
