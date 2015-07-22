"""
Core Houston Application

"""
import hashlib
import logging
from os import path
import re
import time

import consulate
import fleetpy
import yaml

from houston import files
from houston import utils

LOGGER = logging.getLogger(__name__)

CONFIG_FILE = 'manifest.yaml'
UNIT_PATTERN = re.compile(r'(?P<image>[\w\-]+):?(?P<version>[\w\-\.]+)?'
                          r'(\[(?P<exp>[\w\-:]+)\])?')


class Controller(object):

    def __init__(self, config_path, environment, service, version,
                 deploy_globals, delay, max_tries, no_removal):
        self._config_path = self._normalize_path(config_path)
        self._environment = environment
        self._service = service or ''
        self._version = version
        self._globals = deploy_globals
        self._deployed_units = []
        self._delay = delay
        self._max_tries = max_tries
        self._no_removal = no_removal
        self._config = self._load_config(CONFIG_FILE)
        if environment not in self._config.get('environments', {}):
            raise ValueError('environment not found')

        kwargs = utils.parse_endpoint(self.env_config['consul'])
        self._consul = consulate.Consul(**kwargs)
        self._file_deployment = None
        self._fleet = fleetpy.Client(self.env_config.get('fleet'))

    @property
    def env_config(self):
        return self._config.get('environments', {}).get(self._environment, {})

    def run(self):
        if self._globals:
            return self._deploy_globals()
        return self._deploy_service()

    def _check_consul_for_service(self):
        """Return true if the service expected to be running, is reported up
        in Consul by checking for all ip addresses to be present.

        :rtype: bool

        """
        version = self._version or 'latest'
        state = self._fleet.state(True,
                                  '{0}@{1}.service'.format(self._service,
                                                           version))
        LOGGER.debug('Checking to ensure service is up in consul')
        expected = set([s.ipaddr for s in state])
        running = self._consul.catalog.service(self._service)
        actual = set()
        for node in running:
            if version in node['ServiceTags']:
                actual.add(node['ServiceAddress'])
        LOGGER.debug('Found %i nodes running %s %s',
                     len(actual), self._service, version)
        return (expected & actual) == expected

    def _apply_template_variables(self, value):
        value = value.replace('{service}', self._service)
        for unit_name in self._deployed_units:
            name, version = utils.parse_unit_name(unit_name)
            check = '{0}.service'.format(name)
            if self._service:
                check = check[len(self._service) + 1:]
            if check in value:
                LOGGER.debug('Replacing %s with %s in value', check, unit_name)
                value = value.replace(check, unit_name)
        return value

    def _deploy_files(self):
        if self._file_manifest():
            vsn_hash = self._file_manifest_hash()
            unit_name = '{0}-file-deploy@{1}.service'.format(self._service,
                                                             vsn_hash)
            self._file_deployment = files.FileDeployment(unit_name,
                                                         self.env_config,
                                                         self._config_path,
                                                         self._service)
            LOGGER.info('Deploying %s', unit_name)
            if self._unit_is_active(unit_name):
                self._deployed_units.append(unit_name)
                return True

            LOGGER.debug('Building archive file')
            if self._file_deployment.build_archive():

                LOGGER.info('Uploading archive file to consul')
                self._file_deployment.upload_archive()

                LOGGER.info('Deploying archive file as %s', unit_name)
                unit = self._fleet.unit(unit_name)
                unit.read_string(self._file_deployment.unit_file())
                unit.submit()
                unit.start()

                if not self._wait_for_unit_to_become_active(unit_name):
                    LOGGER.error('Failed to deploy files')
                    return False

                self._deployed_units.append(unit_name)
        return True

    def _deploy_globals(self):
        last_unit = None
        global_unit_prefix = path.join(self._config_path, 'units', 'global')
        for name in self._config['global-units']:
            version = None
            if ':' in name:
                name, version = name.split(':')
            unit_file = path.join(global_unit_prefix,
                                  '{0}.service'.format(name))
            unit_name = self._unit_name(name, version)
            if not self._deploy_unit(unit_name, unit_file, last_unit):
                LOGGER.error('Aborting, failed to deploy %s', name)
                return False
            last_unit = unit_name
        return True

    def _deploy_service(self):
        if not self._deploy_files():
            LOGGER.info('Aborting run due to file deployment error')
            return False

        if not self._deploy_shared_units():
            LOGGER.info('Aborting run due to shared unit deployment error')
            return False

        unit_file = path.join(self._config_path, 'units', 'service',
                              '{0}.service'.format(self._service))
        unit_name = self._unit_name(self._service, self._version)
        if not self._deploy_unit(unit_name, unit_file):
            LOGGER.info('Aborting run due to service unit deployment error')
            return False

        if not self._check_consul_for_service():
            LOGGER.error('Aborted due to service missing on expected nodes')
            return False

        LOGGER.info('Validated service is running with Consul')

        self._shutdown_other_versions()
        self._file_deployment.remove_other_archive_versions()

        LOGGER.info('Deployment of %s %s and its dependencies successful.',
                    self._service, self._version)
        return True

    def _deploy_shared_units(self):
        # This should only be set if there is a file archive
        last_unit = self._deployed_units[0] if self._deployed_units else None
        shared_unit_prefix = path.join(self._config_path, 'units', 'shared')
        for name in self._shared_units:
            version = None
            if ':' in name:
                name, version = name.split(':')
            unit_file = path.join(shared_unit_prefix,
                                  '{0}.service'.format(name))
            unit_name = self._unit_name('{0}-{1}'.format(self._service, name),
                                        version)
            if not self._deploy_unit(unit_name, unit_file, last_unit):
                LOGGER.error('Aborting, failed to deploy %s', unit_name)
                return False
            last_unit = unit_name
        return True

    def _deploy_unit(self, unit_name, unit_file, last_unit=None):
        LOGGER.info('Deploying %s', unit_name)
        unit = self._fleet.unit(unit_name)

        with open(unit_file) as handle:
            unit_str = handle.read()
        unit.read_string(self._apply_template_variables(unit_str))

        if last_unit:
            unit.add_option('Unit', 'Requires', last_unit)
            unit.add_option('Unit', 'After', last_unit)

        if self._unit_is_active(unit_name):
            self._deployed_units.append(unit_name)
            LOGGER.debug('%s is already running, skipping to next',
                         unit_name)
            return True

        if unit.submit():
            if unit.start():
                if not self._wait_for_unit_to_become_active(unit_name):
                    LOGGER.error('Failed to deploy %s', unit_name)
                    if not self._no_removal:
                        LOGGER.debug('Removing unit from fleet: %s', unit_name)
                        unit.destroy()
                    return False
            else:
                LOGGER.error('Failed to start %s', unit_name)
                if not self._no_removal:
                    LOGGER.debug('Removing unit from fleet: %s', unit_name)
                    unit.destroy()
                return False
        else:
            LOGGER.error('Failed to submit %s', unit_name)
            return False
        LOGGER.info("%s has started", unit_name)
        self._deployed_units.append(unit_name)
        return True

    def _file_manifest(self):
        file_path = path.join(self._config_path, 'files',
                              '{0}.yaml'.format(self._service))
        if not path.exists(file_path):
            return None
        with open(file_path) as handle:
            return handle.read()

    def _file_manifest_hash(self):
        value = self._file_manifest()
        hash_value = hashlib.md5(value.encode('utf-8'))
        return hash_value.hexdigest()[:8]

    def _load_config(self, filename):
        file = path.join(self._config_path, filename)
        if not path.exists(file):
            raise ValueError('Config file {0} not found'.format(file))
        with open(file, 'r') as handle:
            return yaml.load(handle)

    @staticmethod
    def _machine_label(ntuple):
        return '{0}.../{1}'.format(ntuple.id[0:7], ntuple.ipaddr)

    @staticmethod
    def _normalize_path(value):  # pragma: no cover
        """Normalize the specified path value returning the absolute
        path for it.

        :param str value: The path value to normalize
        :rtype: str

        """
        return path.abspath(path.normpath(value))

    @property
    def _shared_units(self):
        units = []
        for unit in self._config['shared-units'].get(self._service, []):
            match = UNIT_PATTERN.match(unit)
            if match.group('exp'):
                key, value = match.group('exp').split(':')
                if key == 'environment':
                    LOGGER.debug('Evaluating %s for %s[%s]',
                                 key, value, self._environment)
                    if value != self._environment:
                        continue
            if match.group('version'):
                units.append('{0}:{1}'.format(match.group('image'),
                                              match.group('version')))
            else:
                units.append(match.group('image'))
        return units

    def _shutdown_other_versions(self):
        LOGGER.debug('Shutting down running units for other image versions')
        units = [utils.parse_unit_name(u.name) for u in self._fleet.units()]
        destroy = set()
        for deployed_unit in self._deployed_units:
            (deployed_name,
             deployed_version) = utils.parse_unit_name(deployed_unit)
            for name, version in units:
                if name == deployed_name and version != deployed_version:
                    destroy.add((name, version))

        for name, version in destroy:
            LOGGER.info('Destroying %s@%s.service', name, version)
            unit = self._fleet.unit(name, version)
            if not unit.destroy():
                LOGGER.error('Error destroying %s@%s.service', name, version)

    def _unit_is_active(self, unit_name, state=None):
        state = self._fleet.state(True, unit_name) if state is None else state
        return state and all([s.state == 'active' for s in state])

    @staticmethod
    def _unit_name(name, version=None):
        return '{0}@{1}.service'.format(name, version or 'latest')

    def _wait_for_unit_to_become_active(self, unit_name):
        for attempt in range(0, self._max_tries):
            state = self._fleet.state(True, unit_name)
            if self._unit_is_active(unit_name, state):
                LOGGER.debug('All %s units active', unit_name)
                return True

            if state and all([s.state == 'failed' for s in state]):
                LOGGER.warn('All %s units failed', unit_name)
                LOGGER.debug('State: %r', state)
                return False

            for s in [s for s in state
                      if s.loaded and s.state == 'activating']:
                LOGGER.debug('Unit %s is activating on %s', unit_name,
                             self._machine_label(s))

            for s in [s for s in state if s.loaded and s.state == 'inactive']:
                LOGGER.debug('Unit %s is inactive on %s', unit_name,
                             self._machine_label(s))

            LOGGER.debug('Sleeping %i seconds before checking again',
                         self._delay)
            time.sleep(self._delay)

        LOGGER.warn('Failed to validate unit state after %i attempts',
                    self._max_tries)
        return False
