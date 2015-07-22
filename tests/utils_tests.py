"""
Tests for houston.utils

"""
try:
    import unittest2 as unittest
except ImportError:
    import unittest

from houston import utils


class ParseEndpointTests(unittest.TestCase):

    def test_http_with_default_port(self):
        value = 'http://consul.ec2.local'
        expectation = {'scheme': 'http',
                       'host': 'consul.ec2.local',
                       'port': 80}
        self.assertDictEqual(utils.parse_endpoint(value), expectation)

    def test_https_with_default_port(self):
        value = 'https://consul.ec2.local'
        expectation = {'scheme': 'https',
                       'host': 'consul.ec2.local',
                       'port': 443}
        self.assertDictEqual(utils.parse_endpoint(value), expectation)

    def test_http_with_specified_port(self):
        value = 'http://consul.ec2.local:8500'
        expectation = {'scheme': 'http',
                       'host': 'consul.ec2.local',
                       'port': 8500}
        self.assertDictEqual(utils.parse_endpoint(value), expectation)

    def test_https_with_specified_port(self):
        value = 'https://consul.ec2.local:8500'
        expectation = {'scheme': 'https',
                       'host': 'consul.ec2.local',
                       'port': 8500}
        self.assertDictEqual(utils.parse_endpoint(value), expectation)

    def test_unix_socket_endpoint(self):
        value = 'unix:///var/run/consul.sock'
        expectation = {'scheme': 'unix',
                       'host': '/var/run/consul.sock',
                       'port': None}
        self.assertDictEqual(utils.parse_endpoint(value), expectation)
