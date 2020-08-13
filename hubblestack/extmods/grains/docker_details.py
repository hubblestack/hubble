"""
HubbleStack Docker Details Grain.
CLI Usage - hubble grains.get docker_details
Example Output - {u'installed': True, u'running': True}
Author - Mudit Agarwal (muagarwa@adobe.com)
"""
import salt.utils.platform
import logging
__virtualname__ = "docker_details"
from hubblestack.utils.osquery_lib import query as osquery_util
log = logging.getLogger(__name__)


def __virtual__():
  """
  Load docker details grains
  """

  if salt.utils.platform.is_windows():
    return False, "docker_details: Not available on Windows"
  return __virtualname__


def get_docker_details(grains):
  docker_grains = {}

  docker_details = {}
  docker_details['installed'] = _is_docker_installed(grains)
  docker_details['running'] = False

  if docker_details['installed']:
    docker_details['running'] = _is_docker_process_running()

  log.debug('docker_details = {0}'.format(docker_details))

  docker_grains['docker_details'] = docker_details

  return docker_grains


def _is_docker_installed(grains):
  try:
    os_family = grains.get('os_family')
    if 'coreos' in os_family.lower():
      return True
    elif 'debian' in os_family.lower():
      osquery_sql = 'select name from deb_packages where name like "%docker%"'
    elif 'redhat' in os_family.lower():
      osquery_sql = 'select name from rpm_packages where name like "%docker%"'
    else:
      log.debug("OS not supported")
      return False
    query_result = osquery_util(query_sql=osquery_sql)
    if len(query_result) != 0:
      for result in query_result:
        if isinstance(result, dict):
          package_name = result.get('name')
          log.debug('package_name = {0}'.format(package_name))
          if package_name and 'docker' in package_name:
            return True
    return False
  except Exception as e:
    log.exception('The following exception occurred while executing _is_docker_installed {0}'.format(e))
    return False


def _is_docker_process_running():
  osquery_sql = 'select name from processes where name LIKE "%dockerd%"'
  query_result = osquery_util(query_sql=osquery_sql)
  if len(query_result) != 0:
    for result in query_result:
      if isinstance(result, dict):
        process_name = result.get('name')
        if 'dockerd' in process_name:
          log.debug("Docker is running")
          return True
  log.debug("Docker is not running")
  return False
