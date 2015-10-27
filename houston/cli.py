"""
Houston Command Line Interface

"""
import argparse
import logging.config
import logging
from os import path
import sys

from houston import controller

from houston import DEBUG_CONFIG
from houston import LOG_CONFIG

LOGGER = logging.getLogger(__name__)

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

        if not args.command:
            sys.stderr.write('ERROR: You must specify a command\n\n')
            self._parser.print_help()
            sys.exit(1)

        args_dict = vars(args)
        for key in ['name', 'version']:
            if key in args_dict:
                args_dict[key] = args_dict[key][0]

        obj = controller.Controller(args.config_dir, args.environment,
                                    args.command,
                                    args_dict.get('name'),
                                    args_dict.get('group'),
                                    args_dict.get('version'),
                                    args.delay, args.max_tries,
                                    args.no_dependencies,
                                    args.no_removal,
                                    args.skip_consul,
                                    args.remove)
        if obj.run():
            LOGGER.info('Eagle, looking great. You\'re Go.')
        else:
            LOGGER.info('Deployment failed.')
            sys.exit(2)

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

        parser.add_argument('-g', '--group', action='store',
                            help='Optional deployment group')

        parser.add_argument('-m', '--max-tries', action='store', type=int,
                            help='How many times should Houston try and'
                                 'validate that a service has started',
                            default=15)

        parser.add_argument('--no-dependencies', action='store_true',
                            help='Do not perform dependency injection in units')

        parser.add_argument('-n', '--no-removal', action='store_true',
                            help='Do not remove units from fleet upon failure')

        parser.add_argument('--remove', action='store_true',
                            help='Remove any deployed units')

        parser.add_argument('-s', '--skip-consul', action='store_true',
                            help='Skip consul check on stack deployment')

        parser.add_argument('-v', '--verbose', action='store_true')

        sparser = parser.add_subparsers(title='Commands', dest='command')

        sparser.add_parser('global', help='Deploy the global stack')

        s_parser = sparser.add_parser('service',
                                      help='Deploy a service stack')

        s_parser.add_argument('name', nargs=1,
                              help='Name of the service to deploy')
        s_parser.add_argument('version', nargs=1,
                              help='The version of the service to deploy')

        sa_parser = sparser.add_parser('standalone',
                                       help='Deploy a standalone stack')
        sa_parser.add_argument('name', nargs=1,
                               help='Name of the standalone stack to deploy')
        return parser


def run():
    CLI().run()
