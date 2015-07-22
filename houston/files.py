"""
Build a deployable unit file that writes files to the CoreOS filesystem

"""
import base64
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
    CONSUL_PREFIX = 'deployinator'

    def __init__(self, name, config, config_path, service):
        self._config = config
        self._config_path = config_path
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

        if self._file_list:
            self._build_filesystem()
            self._archive = self._create_archive()
            self._remove_artifacts()

        self._archive_key = '{0}/{1}'.format(self.CONSUL_PREFIX, name)

    @property
    def archive_key(self):
        return self._archive_key

    @property
    def has_files(self):
        return bool(self._file_list)

    def unit_file(self):
        output = UNIT_TEMPLATE.replace('{archive_key}', self._archive_key)
        return output.replace('{service}', self._service)

    def remove_archive(self):
        LOGGER.debug('Removing archive from Consul as %s', self._archive_key)
        return self._consul.kv.delete(self.archive_key)

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
            try:
                os.makedirs(path.dirname(file_path))
            except FileExistsError:
                pass
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
            archive = base64.b64encode(bytes(handle.read(), encoding='utf-8'))
        os.unlink(archive_file)
        return archive

    def _remove_artifacts(self):
        shutil.rmtree(self._temp_dir)
