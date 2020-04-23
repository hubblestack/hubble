"""
HubbleStack Docker Details Grain.
CLI Usage - hubble grains.get docker_details
Example Output - {u'installed': True, u'running': True, u'version': u'19.03.8'}
Author - Mudit Agarwal (muagarwa@adobe.com)
"""
import salt.utils.platform
import logging
from hubblestack.utils.osquery_lib import query as osquery_util
log = logging.getLogger(__name__)
osquery_path = '/opt/osquery/osqueryi'

def get_docker_details():
  try:
    grains = {}

    if salt.utils.platform.is_windows():
      log.debug('This grain is only available on linux')
      return grains

    docker_details = {}
    docker_details['installed'] = False
    docker_details['running'] = False
    docker_details['version'] = _get_docker_version()

    if docker_details['version']:
      docker_details['installed'] = True
      docker_details['running'] = _is_docker_process_running()

    log.debug('docker_details = {0}'.format(docker_details))

    grains['docker_details'] = docker_details

    return grains
  except Exception as e:
    log.exception('The following exception occurred while fetching docker details {0}'.format(e))


def _get_docker_version():
  osquery_sql = 'select server_version from docker_info'
  docker_version = osquery_util(query_sql=osquery_sql, osquery_path=osquery_path)

  log.debug('docker_version = {0}'.format(docker_version))

  if docker_version and isinstance(docker_version, unicode):
    return docker_version
  else:
    return ''


def _is_docker_process_running():
  osquery_sql = 'select name from processes where name LIKE "%dockerd%"'
  docker_process = osquery_util(query_sql=osquery_sql, osquery_path=osquery_path)

  log.debug('docker_process = {0}'.format(docker_process))

  if 'dockerd' in docker_process:
    log.info("Docker is running")
    return True
  log.info("Docker is not running")
  return False


