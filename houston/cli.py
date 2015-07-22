"""
Houston Command Line Interface

"""
import argparse
import logging.config
from os import path
import sys

from houston import controller

from houston import DEBUG_CONFIG
from houston import LOG_CONFIG

DESC = 'Easy docker stack deployment to CoreOS clusters using Fleet and Consul'


class CLI(object):

    def __init__(self):
        self._parser = self._create_parser()

    def run(self):
        args = self._parser.parse_args()
        if args.verbose:
            logging.config.dictConfig(DEBUG_CONFIG)
        else:
            logging.config.dictConfig(LOG_CONFIG)

        if args.globals is None and args.service is None:
            sys.stderr.write('ERROR: You must specify either service or '
                             'global deployment\n')
            sys.exit(1)

        obj = controller.Controller(args.config_dir, args.environment,
                                    args.service, args.version, args.globals,
                                    args.delay, args.max_tries, args.no_removal)
        obj.run()

    @staticmethod
    def _create_parser():
        parser = argparse.ArgumentParser(description=DESC)
        parser.add_argument('-c', '--config-dir',
                            default=path.abspath('.'),
                            help='Specify the path to the configuration '
                                 'directory. Default: .')
        parser.add_argument('-e', '--environment', required=True,
                            help='The environment name')

        parser.add_argument('-d', '--delay', action='store', type=int,
                            help='How long to pause between service '
                                 'activation checks', default=5)

        parser.add_argument('-m', '--max-tries', action='store', type=int,
                            help='How many times should Houston try and'
                                 'validate that a service has started',
                            default=15)
        parser.add_argument('-n', '--no-removal', action='store_true',
                            help='Do not remove units from fleet upon failure')

        parser.add_argument('-v', '--verbose', action='store_true')

        parser.add_argument('-g', '--globals', action='store_true',
                            help='Deploy global units')
        parser.add_argument('service', nargs='?',
                            help='Deploy the specified service')
        parser.add_argument('version', nargs='?',
                            help='The version of the service to deploy')

        return parser


def run():
    CLI().run()
