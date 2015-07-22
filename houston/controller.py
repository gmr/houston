"""
Core Houston Application

"""
import hashlib
import logging
from os import path
import re
import time

import fleetpy
import yaml

from houston import files

LOGGER = logging.getLogger(__name__)

CONFIG_FILE = 'manifest.yaml'
UNIT_PATTERN = re.compile(r'(?P<image>[\w\-]+):?(?P<version>[\w\-\.]+)?'
                          r'(\[(?P<exp>[\w\-:]+)\])?')


class Controller(object):

    CHECK_DELAY = 3
    MAX_CHECKS_BEFORE_FAILURE = 15

    def __init__(self, config_path, environment, service, version,
                 deploy_globals):
        self._config_path = self._normalize_path(config_path)
        self._environment = environment
        self._service = service
        self._version = version
        self._deploy_globals = deploy_globals
        self._deployed_units = []
        self._config = self._load_config(CONFIG_FILE)

        if environment not in self._config.get('environments', {}):
            raise ValueError('environment not found')

        self._fleet = fleetpy.Client(self.env_config.get('fleet'))

    @property
    def env_config(self):
        return self._config.get('environments', {}).get(self._environment, {})

    def run(self):
        if not self._deploy_files():
            LOGGER.debug('Aborting run due to file deployment error')
            return

        if not self._deploy_shared_units():
            LOGGER.debug('Aborting run due to shared unit deployment error')
            return

        unit_file = path.join(self._config_path, 'units', 'service',
                              '{0}.service'.format(self._service))
        self._deploy_unit(self._service, unit_file, self._version)

    def _apply_template_variables(self, value):
        value = value.replace('{service}', self._service)
        for unit in self._deployed_units:
            check = unit[len(self._service) + 1:]
            if '@' in check:
                check = '{0}.service'.format(check[:check.find('@')])
            if check in value:
                LOGGER.debug('Replacing %s with %s in value', check, unit)
                value = value.replace(check, unit)
        return value

    def _deploy_files(self):
        if self._file_manifest():
            vsn_hash = self._file_manifest_hash()
            unit_name = '{0}-file-deploy@{1}.service'.format(self._service,
                                                             vsn_hash)
            if self._unit_is_active(unit_name):
                return True

            file_deployment = files.FileDeployment(unit_name,
                                                   self.env_config,
                                                   self._config_path,
                                                   self._service)

            LOGGER.info('Uploading archive file to consul')
            file_deployment.upload_archive()

            LOGGER.info('Deploying archive file as %s', unit_name)
            unit = self._fleet.unit(unit_name)
            unit.read_string(file_deployment.unit_file())
            unit.submit()
            unit.start()

            if not self._wait_for_unit_to_become_active(unit_name):
                LOGGER.error('Failed to deploy files')
                return False

        return True

    def _deploy_shared_units(self):
        shared_unit_prefix = path.join(self._config_path, 'units', 'shared')
        for name in self._shared_units:
            version = None
            if ':' in name:
                name, version = name.split(':')
            unit_file = path.join(shared_unit_prefix,
                                  '{0}.service'.format(name))
            unit_name = '{0}-{1}'.format(self._service, name)
            if not self._deploy_unit(unit_name, unit_file, version):
                LOGGER.error('Aborting, failed to deploy %s', unit_name)
                return False
        return True

    def _deploy_unit(self, name, unit_file, version=None):
        unit_name = '{0}@{1}.service'.format(name, version or 'latest')
        LOGGER.info('Deploying %s', unit_name)
        unit = self._fleet.unit(unit_name)
        with open(unit_file) as handle:
            unit_str = handle.read()

        unit.read_string(self._apply_template_variables(unit_str))
        if self._unit_is_active(unit_name):
            self._deployed_units.append(unit_name)
            LOGGER.debug('%s is already running, skipping to next',
                         unit_name)
            return True

        if unit.submit():
            if unit.start():
                if not self._wait_for_unit_to_become_active(unit_name):
                    LOGGER.error('Failed to deploy %s', unit_name)
                    unit.destroy()
                    return False
            else:
                LOGGER.error('Failed to start %s', unit_name)
                unit.destroy()
                return False
        else:
            LOGGER.error('Failed to submit %s', unit_name)
            unit.destroy()
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

    def _unit_is_active(self, unit_name, state=None):
        state = self._fleet.state(True, unit_name) if state is None else state
        return state and all([s.state == 'active' for s in state])

    def _wait_for_unit_to_become_active(self, unit_name):
        for attempt in range(0, self.MAX_CHECKS_BEFORE_FAILURE):
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
                         self.CHECK_DELAY)
            time.sleep(self.CHECK_DELAY)

        LOGGER.warn('Failed to validate unit state after %i attempts',
                    self.MAX_CHECKS_BEFORE_FAILURE)
        return False
