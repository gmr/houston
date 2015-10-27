"""
Common Utility Methods

"""
import re
import sys

PYTHON3 = True if sys.version_info > (3, 0, 0) else False

SERVICE_PATTERN = re.compile(r'^(((?P<parent>\w+)\.|)(?P<service>[\w-]+)'
                             r'(:(?P<group>\w+)|)(@(?P<version>[\w\.]+)|)'
                             r'\.service$)')

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


def parse_unit_name(value):
    """Parse the given unit name returning a tuple of parent, name, group,
     and version.

    :param str value: The unit name to parse
    :rtype: (str|None, str, str|None, str|None)
    :returns: (Parent, Service, Group, Version)

    """
    matches = SERVICE_PATTERN.match(value)
    return (matches.group('parent'), matches.group('service'),
            matches.group('group'), matches.group('version'))


def unit_name(service, parent=None, group=None, version='latest'):
    """Return the houston standard service name that can be reverse parsed by
    the parse

    :param str service: The service name
    :param str|None parent: An optional parent for the service
    :param str|None group: An optional deployment group
    :param str|None version: An optional service version
    :rtype: str

    """
    parts = []
    if parent is not None and parent != service:
        parts += [parent, '.']
    parts += [service]
    if group is not None:
        parts += [':', group]
    parts += ['@', version or 'latest', '.service']
    return ''.join(parts)
