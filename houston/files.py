"""
Build a deployable unit file that writes files to the CoreOS filesystem

"""
import base64
import errno
import logging
import os
from os import path
import shutil
import tarfile
import tempfile
import uuid
import yaml

import consulate

from houston import utils

LOGGER = logging.getLogger(__name__)

DEFAULT_UNIT_TEMPLATE = """\
[Unit]
Description=Houston File Archive Deployment

[Service]
Type=oneshot
RemainAfterExit=true
ExecStartPre=/usr/bin/sleep 30
ExecStart=/usr/bin/bash -c 'curl -s "http://localhost:8500/v1/kv/{archive_key}?raw" | base64 -d | tar -C / -xvf -'

[X-Fleet]
Global=true
"""

GROUP_TEMPLATE = "MachineMetadata=group={group}\n"
SERVICE_TEMPLATE = "MachineMetadata=service={service}\n"


class FileDeployment(object):

    CONFIG_PREFIX = 'files'
    CONSUL_PREFIX = 'houston'

    def __init__(self, name, config, config_path, manifest_file, service,
                 group=None, environment=None, prefix=None):
        self._archive = None
        self._config = config
        self._config_path = config_path
        self._consul_prefix = prefix or self.CONSUL_PREFIX
        self._environment = environment
        self._manifest_file = manifest_file
        self._service = service
        self._group = group
        self._unit_name = name

        self._unit_template = DEFAULT_UNIT_TEMPLATE
        unit_template_file = path.join(config_path, 'file-unit.template')
        if path.exists(unit_template_file):
            with open(unit_template_file, 'r') as handle:
                self._unit_template = handle.read()

        kwargs = utils.parse_endpoint(self._config['consul'])
        self._consul = consulate.Consul(**kwargs)

        self._temp_dir = tempfile.mkdtemp()
        try:
            self._file_list = self._get_file_list()
        except ValueError as error:
            LOGGER.info(error)
            self._file_list = []

        self._archive_key = '{0}/{1}'.format(self._consul_prefix, name)

    @property
    def archive_key(self):
        return self._archive_key

    def build_archive(self):
        if not self._file_list:
            LOGGER.debug('No files to build archive for')
            return False
        LOGGER.debug('Building archive file')
        self._archive = self._create_archive()
        return True

    def remove_archive(self):
        LOGGER.debug('Removing archive from Consul as %s', self._archive_key)
        return self._consul.kv.delete(self.archive_key)

    def remove_other_archive_versions(self):
        name, parent, group, version = utils.parse_unit_name(self._unit_name)
        if parent:
            name = '{0}.{1}'.format(name, parent)
        if group:
            name = '{0}:{1}'.format(name, group)
        keys = self._consul.kv.find('{0}/{1}@'.format(self._consul_prefix,
                                                      name))
        for key in keys:
            if key != self._archive_key:
                LOGGER.debug('Removing previous archive version: %s', key)
                self._consul.kv.delete(key)

    def unit_file(self):
        output = self._unit_template
        if self._service != 'global':
            output += SERVICE_TEMPLATE
        if self._group:
            output += GROUP_TEMPLATE
            output = output.replace('{group}', self._group)
        output = output.replace('{archive_key}', self._archive_key)
        return output.replace('{service}', self._service)

    def upload_archive(self):
        LOGGER.debug('Uploading archive to Consul as %s', self._archive_key)
        return self._consul.kv.set(self.archive_key, self._archive)

    def _get_file_list(self):
        file_path = path.join(self._config_path, self.CONFIG_PREFIX,
                              self._manifest_file)
        if not path.exists(file_path):
            raise ValueError('File config not found for {0}'.format(file_path))
        with open(file_path) as handle:
            return yaml.load(handle)

    def _create_archive(self):
        cwd = os.getcwd()
        os.chdir(self._temp_dir)
        archive_file = path.join(tempfile.gettempdir(), str(uuid.uuid4()))
        tar = tarfile.open(archive_file, 'w')
        for entry in self._file_list:
            if entry.get('environment'):
                if entry['environment'] != self._environment:
                    LOGGER.debug('Bypassing file for %s [%s]',
                                 entry['environment'], self._environment)
                    continue
            with tempfile.TemporaryFile() as handle:
                content = self._replace_variables(entry.get('content', ''))
                handle.write(self._maybe_encode(content))
                handle.seek(0)

                info = tar.gettarinfo(arcname=entry['path'], fileobj=handle)
                if 'owner' in entry:
                    info.uname = entry['owner']
                if 'group' in entry:
                    info.gname = entry['group']
                if 'permissions' in entry:
                    info.mode = entry['permissions']

                handle.seek(0)
                tar.addfile(info, handle)

        tar.close()
        os.chdir(cwd)

        with open(archive_file, 'r') as handle:
            tarball = handle.read()
            if utils.PYTHON3:
                tarball = bytes(tarball, encoding='utf-8')
            archive = base64.b64encode(tarball)
        os.unlink(archive_file)
        return archive

    @staticmethod
    def _maybe_encode(value):
        """If the value passed in is a str, encode it as UTF-8 bytes for
        Python 3

        :param str|bytes value: The value to maybe encode
        :rtype: bytes

        """
        try:
            return value.encode('utf-8')
        except AttributeError:
            return value

    def _replace_variables(self, content):
        if '{service}' in content:
            content = content.replace('{service}', self._service)
        if '{group}' in content:
            content = content.replace('{group}', self._group)
        if '{environment}' in content:
            content = content.replace('{environment}', self._environment)
        return content
