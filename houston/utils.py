"""
Common Utility Methods

"""
import re

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
