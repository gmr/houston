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

    def __init__(self, config_path, environment, command, name, group, version,
                 delay, max_tries, no_dependencies, no_removal, skip_consul,
                 remove_units):
        self._config_path = self._normalize_path(config_path)
        self._environment = environment
        self._command = command
        self._name = name or ('' if command != 'global' else 'global')
        self._group = group
        self._version = version
        self._deployed_units = []
        self._delay = delay
        self._max_tries = max_tries
        self._no_dependencies = no_dependencies
        self._no_removal = no_removal
        self._skip_consul = skip_consul
        self._remove_unit_files = remove_units
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
        if self._remove_unit_files:
            return self._remove_units()

        name = self._name
        if self._version:
            name = '{} {}'.format(name, self._version)
        if self._group:
            name = '{} to {} deployment group'.format(name, self._group)
        LOGGER.info('Deploying %s', name)

        if self._global:
            self._name = 'global'
            if not self._deploy_globals():
                return False
            if not self._deploy_files():
                return False
            self._shutdown_other_versions()
            if self._file_deployment:
                self._file_deployment.remove_other_archive_versions()
            return True

        self._add_last_deployed_global()

        if not self._deploy_files():
            LOGGER.info('Aborting run due to file deployment error')
            return False

        if self._standalone:
            if not self._deploy_shared_units():
                return False
            self._shutdown_other_versions()
            if self._file_deployment:
                self._file_deployment.remove_other_archive_versions()
            return True

        return self._deploy_service()

    def _add_last_deployed_global(self):
        """Add the last global unit as a deployed unit for dependency injection
        in the first standalone or service unit.

        """
        service = self._config.get('global', [])[-1]
        version = None
        if ':' in service:
            service, version = service.split(':')
        self._deployed_units.append(utils.unit_name(service, 'global',
                                                    self._group, version))

    def _apply_variables(self, value):
        value = value.replace('{service}', self._name)
        if self._group:
            value = value.replace('{group}', self._group)
        variables = self._config.get('variables', {})
        if self._environment in variables:
            variables = variables[self._environment]
        for name in variables:
            key = '{{{0}}}'.format(name)
            if key in value:
                value = value.replace(key, variables[name])

        for unit_name in self._deployed_units:
            _parent, service, _group, _ver = utils.parse_unit_name(unit_name)
            base_service = '{}.service'.format(service)
            if base_service in value:
                LOGGER.debug('Replacing %s with %s in value',
                             base_service, unit_name)
                value = value.replace(base_service, unit_name)
        return value

    def _check_consul_for_service(self):
        """Return true if the service expected to be running, is reported up
        in Consul by checking for all ip addresses to be present.

        :rtype: bool

        """
        version = 'version:{}'.format(self._version or 'latest')
        group = 'deploy:{}'.format(self._group) if self._group else None
        unit_name = utils.unit_name(self._name, None, self._group,
                                    self._version)
        state = self._fleet.state(True, unit_name)
        expected = set([s.ipaddr for s in state])
        LOGGER.debug('Checking to ensure service is up in consul for %i nodes',
                     len(expected))
        running = self._consul.catalog.service(self._name)
        actual = set()
        for node in running:
            if group and group not in node['ServiceTags']:
                continue
            elif version not in node['ServiceTags']:
                continue
            else:
                actual.add(node['ServiceAddress'])
        LOGGER.debug('Found %i nodes running %s %s',
                     len(actual), self._name, version)
        return (expected & actual) == expected

    def _deploy_files(self):
        if self._file_manifest():
            if self._global:
                manifest = 'global.yaml'
            else:
                manifest = '{0}/{1}.yaml'.format(self._command, self._name)

            unit_name = utils.unit_name('file-deploy', self._name, self._group,
                                        self._file_manifest_hash())

            self._file_deployment = files.FileDeployment(unit_name,
                                                         self.env_config,
                                                         self._config_path,
                                                         manifest,
                                                         self._name,
                                                         self._group,
                                                         self._environment)

            if self._unit_is_active(unit_name):
                self._deployed_units.append(unit_name)
                return True

            if self._file_deployment.build_archive():
                LOGGER.info('Uploading archive file to consul')
                self._file_deployment.upload_archive()

                unit = self._fleet.unit(unit_name)
                unit.read_string(self._file_deployment.unit_file())
                if self._deployed_units:
                    self._maybe_add_last_unit(unit, self._deployed_units[-1])

                LOGGER.info('Deploying archive file service: %s', unit_name)
                unit.submit()
                unit.start()

                if not self._wait_for_unit_to_become_active(unit_name):
                    LOGGER.error('Failed to deploy files')
                    return False

                self._deployed_units.append(unit_name)
        return True

    def _deploy_globals(self):
        last_unit = None
        global_unit_prefix = path.join(self._config_path, 'units', 'shared')
        for service in self._config.get('global', []):
            version = None
            if ':' in service:
                service, version = service.split(':')
            unit_file = path.join(global_unit_prefix, service)
            unit_name = utils.unit_name(service, 'global', self._group, version)
            if not self._deploy_unit(unit_name, unit_file, last_unit):
                LOGGER.error('Aborting, failed to deploy %s', service)
                return False
            last_unit = unit_name

        self._shutdown_other_versions()
        if self._file_deployment:
            self._file_deployment.remove_other_archive_versions()

        return True

    def _deploy_service(self):
        if not self._deploy_shared_units():
            LOGGER.info('Aborting run due to shared unit deployment error')
            return False
        unit_file = path.join(self._config_path, 'units', 'service',
                              self._name)
        unit_name = utils.unit_name(self._name, None, self._group,
                                    self._version)

        if not self._deploy_unit(unit_name, unit_file):
            LOGGER.info('Aborted: service unit deployment error')
            return False

        if not self._skip_consul:
            if not self._check_consul_for_service():
                LOGGER.error('Aborted: service missing on expected nodes')
                return False
            LOGGER.info('Service is being announced with Consul')

        self._shutdown_other_versions()
        if self._file_deployment:
            self._file_deployment.remove_other_archive_versions()

        parts = []
        if self._group:
            parts += [self._group]
        parts += [self._name, self._version]
        LOGGER.info('Deployment of %s and its dependencies successful',
                    ' '.join(parts))
        return True

    def _deploy_shared_units(self):
        # Ensure the file archive is there
        last_unit = self._deployed_units[-1]
        shared_unit_prefix = path.join(self._config_path, 'units', 'shared')
        for name in self._get_units():
            version = None
            if ':' in name:
                name, version = name.split(':')
            unit_file = path.join(shared_unit_prefix, name)
            unit_name = utils.unit_name(name, self._name,
                                        self._group,
                                        version)
            if not self._deploy_unit(unit_name, unit_file, last_unit):
                LOGGER.error('Aborting, failed to deploy %s', unit_name)
                return False
            last_unit = unit_name
        return True

    def _deploy_unit(self, unit_name, unit_file, last_unit=None):
        unit = self._fleet.unit(unit_name)
        unit.read_string(self._apply_variables(self._unit_file(unit_file)))

        if not self._group:
            for index, option in enumerate(unit.options()):
                if option['name'] == 'MachineMetadata' and \
                        option['value'].startswith('group='):
                    LOGGER.debug('Removing group metadata for non-group deploy')
                    unit._options.pop(index)

        self._maybe_add_last_unit(unit, last_unit)

        if self._unit_is_active(unit_name):
            self._deployed_units.append(unit_name)
            LOGGER.debug('Skipping %s: already active', unit_name)
            return True

        LOGGER.debug('Deploying %s', unit_name)
        if unit.submit():
            LOGGER.debug('Starting %s', unit_name)
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
        if self._global:
            file_path = path.join(self._config_path, 'files', 'global.yaml')
        else:
            file_path = path.join(self._config_path, 'files', self._command,
                                  '{0}.yaml'.format(self._name))
        if not path.exists(file_path):
            return None
        with open(file_path) as handle:
            return handle.read()

    def _file_manifest_hash(self):
        value = self._file_manifest()
        hash_value = hashlib.md5(value.encode('utf-8'))
        return hash_value.hexdigest()[:8]

    def _get_units(self):
        units = []
        for unit in self._config.get(self._command).get(self._name, []):
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

    @property
    def _global(self):
        return self._command == 'global'

    def _load_config(self, filename):
        file = path.join(self._config_path, filename)
        if not path.exists(file):
            raise ValueError('Config file {0} not found'.format(file))
        with open(file, 'r') as handle:
            return yaml.load(handle)

    @staticmethod
    def _machine_label(ntuple):
        return '{0}.../{1}'.format(ntuple.id[0:7], ntuple.ipaddr)

    def _maybe_add_last_unit(self, unit, last_unit):
        if not last_unit or self._no_dependencies:
            return

        for option in unit.options():
            if (option['section'] == 'Unit' and
                    option['name'] in ['After', 'Requires'] and
                    option['value'] == last_unit):
                LOGGER.debug('Bypassing addition of last unit dependency')
                return

        options = unit._options
        unit._options = []
        for option in options:
            unit.add_option(option.section, option.name, option.value)
            if option.section == 'Unit' and option.name == 'Description':
                LOGGER.debug('Adding dependency on %s', last_unit)
                unit.add_option('Unit', 'Requires', last_unit)
                unit.add_option('Unit', 'After', last_unit)

    @staticmethod
    def _normalize_path(value):  # pragma: no cover
        """Normalize the specified path value returning the absolute
        path for it.

        :param str value: The path value to normalize
        :rtype: str

        """
        return path.abspath(path.normpath(value))

    def _remove_files(self):
        if self._file_manifest():
            unit_name = utils.unit_name('file-deploy', self._name, self._group,
                                        self._file_manifest_hash())
            self._remove_unit(unit_name)
            if self._global:
                manifest_file = 'global.yaml'
            else:
                manifest_file = '{0}/{1}.yaml'.format(self._command, self._name)

            file_deployment = files.FileDeployment(unit_name,
                                                   self.env_config,
                                                   self._config_path,
                                                   manifest_file,
                                                   self._name,
                                                   self._environment)
            file_deployment.remove_archive()
            file_deployment.remove_other_archive_versions()
        else:
            LOGGER.debug('No manifest found')

    def _remove_globals(self):
        for name in self._config.get('global', []):
            version = None
            if ':' in name:
                name, version = name.split(':')
            self._remove_unit(utils.unit_name(name, 'global', None, version))

    def _remove_shared_units(self):
        for service in self._get_units():
            version = None
            if ':' in service:
                service, version = service.split(':')
            self._remove_unit(utils.unit_name(service, self._name, self._group,
                                              version))

    def _remove_unit(self, unit_name):
        LOGGER.info('Removing %s', unit_name)
        unit = self._fleet.unit(unit_name)
        unit.destroy()

    def _remove_units(self):
        if self._global:
            self._remove_files()
            self._remove_globals()
            return True

        self._remove_unit(utils.unit_name(self._name, None, self._group,
                                          self._version))
        self._remove_shared_units()
        self._remove_files()
        return True

    @property
    def _service(self):
        return self._command == 'service'

    def _shutdown_other_versions(self):
        LOGGER.debug('Shutting down running units for other image versions')
        units = [utils.parse_unit_name(u.name) for u in self._fleet.units()]
        destroy = set()
        for deployed_unit in self._deployed_units:
            parent, service, group, version = \
                utils.parse_unit_name(deployed_unit)
            for _parent, _service, _group, _version in units:
                if _parent == parent and _service == service and \
                        _group == group and _version != version:
                    destroy.add((_parent, _service, _group, _version))

        for name, version in destroy:
            LOGGER.info('Destroying %s@%s.service', name, version)
            unit = self._fleet.unit(name, version)
            if not unit.destroy():
                LOGGER.error('Error destroying %s@%s.service', name, version)

    @property
    def _standalone(self):
        return self._command == 'standalone'

    def _unit_is_active(self, unit_name, state=None):
        state = self._fleet.state(True, unit_name) if state is None else state
        return state and all([s.state == 'active' for s in state])

    def _unit_file(self, name):
        for extension in ['service', 'yaml']:
            file_path = '{0}.{1}'.format(name, extension)
            if path.exists(file_path):
                with open(file_path) as handle:
                    if extension == 'service':
                        return handle.read()
                    data = yaml.load(handle)
                    if self._global and 'global' in data:
                        return data['global']
                    if self._name in data:
                        return data[self._name]
                    raise ValueError('No unit found for {0}'.format(self._name))
        raise ValueError('No unit file: '.format(name))

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
