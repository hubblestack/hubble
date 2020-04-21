"""
HubbleStack Docker Details Grain
"""

import salt.modules.cmdmod
import salt.utils.platform
import logging
from hubblestack.utils.osquery_lib import query as osquery_util

log = logging.getLogger(__name__)
__salt__ = {'cmd.run': salt.modules.cmdmod._run_quiet,
            'cmd.run_all': salt.modules.cmdmod.run_all}

def get_docker_details():
  grains = {}
  docker_details = {}

  docker_details['running'] = _is_docker_process_running()

  if docker_details['running']:
    docker_details['installed'] = True
    docker_details['version'] = _get_docker_version()
  else:
    docker_details['installed'] = _is_docker_installed()
    if docker_details['installed']:
      docker_details['version'] = _get_docker_version()

  log.debug('docker_details = {0}'.format(docker_details))
  grains['docker_details'] = docker_details

  return grains


def _is_docker_installed():
  return True


def _get_docker_version():
  osquery_path = '/opt/osquery/osqueryi'
  osquery_sql = 'select server_version from docker_info'
  docker_version = osquery_util(query_sql=osquery_sql, osquery_path=osquery_path)

  log.debug('docker_version = {0}'.format(docker_version))

  return docker_version


def _is_docker_process_running():
  osquery_path = '/opt/osquery/osqueryi'
  osquery_sql = 'select name from processes where name LIKE "%docker%"'
  docker_process = osquery_util(query_sql=osquery_sql, osquery_path=osquery_path)

  log.debug('docker_process = {0}'.format(docker_process))

  if 'docker' in docker_process:
    log.info("Docker is running")
    return True
  log.info("Docker is not running")
  return False


