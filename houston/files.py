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

UNIT_TEMPLATE = """\
[Unit]
Description=Houston File Archive Deployment

[Service]
Type=oneshot
RemainAfterExit=true
ExecStart=/usr/bin/bash -c "\
cd / && curl \\"http://localhost:8500/v1/kv/{archive_key}?raw\\" | base64 -d \
| tar -xv"

[X-Fleet]
Global=true
MachineMetadata=service={service}
"""


class FileDeployment(object):

    CONFIG_PREFIX = 'files'
    CONSUL_PREFIX = 'houston'

    def __init__(self, name, config, config_path, service, prefix=None):
        self._archive = None
        self._config = config
        self._config_path = config_path
        self._consul_prefix = prefix or self.CONSUL_PREFIX
        self._service = service
        self._unit_name = name

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
        self._build_filesystem()
        self._archive = self._create_archive()
        self._remove_artifacts()
        return True

    def remove_archive(self):
        LOGGER.debug('Removing archive from Consul as %s', self._archive_key)
        return self._consul.kv.delete(self.archive_key)

    def remove_other_archive_versions(self):
        name, version = utils.parse_unit_name(self._unit_name)
        keys = self._consul.kv.find('{0}/{1}@'.format(self._consul_prefix, name))
        for key in keys:
            if key != self._archive_key:
                LOGGER.debug('Removing previous archive version: %s', key)
                self._consul.kv.delete(key)

    def unit_file(self):
        output = UNIT_TEMPLATE.replace('{archive_key}', self._archive_key)
        return output.replace('{service}', self._service)

    def upload_archive(self):
        LOGGER.debug('Uploading archive to Consul as %s', self._archive_key)
        return self._consul.kv.set(self.archive_key, self._archive)

    def _get_file_list(self):
        file_path = path.join(self._config_path, self.CONFIG_PREFIX,
                              '{0}.yaml'.format(self._service))
        if not path.exists(file_path):
            raise ValueError('File config not found for {0}'.format(file_path))
        with open(file_path) as handle:
            return yaml.load(handle)

    def _build_filesystem(self):
        for file in self._file_list:
            file_path = path.join(self._temp_dir, file['path'].lstrip('/'))
            self._mkdir(path.dirname(file_path))
            LOGGER.debug('Creating %s', file_path)
            with open(file_path, 'w') as handle:
                handle.write(file['content'])

    def _create_archive(self):
        cwd = os.getcwd()
        os.chdir(self._temp_dir)
        archive_file = path.join(tempfile.gettempdir(), str(uuid.uuid4()))
        tar = tarfile.open(archive_file, 'w')
        for file in self._file_list:
            tar.add(file['path'].lstrip('/'))
        tar.close()
        os.chdir(cwd)

        with open(archive_file, 'r') as handle:
            file = handle.read()
            if utils.PYTHON3:
                file = bytes(file, encoding='utf-8')
            archive = base64.b64encode(file)
        os.unlink(archive_file)
        return archive

    def _mkdir(self, dir_path):
        LOGGER.debug('Ensuring directory exists %s', dir_path)
        try:
            os.makedirs(dir_path)
        except OSError as exception:
            if exception.errno != errno.EEXIST:
                raise

    def _remove_artifacts(self):
        shutil.rmtree(self._temp_dir)
