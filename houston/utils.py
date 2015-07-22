"""
Common Utility Methods

"""
import re
import sys

PYTHON3 = True if sys.version_info > (3, 0, 0) else False

URI = re.compile(r'(?P<scheme>\w+)\://(?P<host>[\/\w\d\.]+)(\:(?P<port>\d+)|)')
DEFAULT_PORTS = {'http': 80, 'https': 443}


def parse_endpoint(endpoint):
    """Parse a endpoint in the form of ``scheme://host[:port]`` and return
    the values as a dict of ``scheme``, ``host``, and ``port``.

    :param str endpoint:
    :rtype: dict

    """
    match = URI.match(endpoint)
    port = None
    if match.group('scheme') != 'unix':
        port = int(match.group('port') or DEFAULT_PORTS[match.group('scheme')])
    return {'scheme': match.group('scheme'),
            'host': match.group('host'),
            'port': port}


def parse_unit_name(unit_name):
    """Parse the given unit name returning a tuple of name, version.

    :param str unit_name: The unit name to parse
    :rtype: (str, str)

    """
    if '@' in unit_name:
        name, suffix = unit_name.split('@')
        version = suffix[:-8]
        return name, version
    return unit_name[:-8], None
