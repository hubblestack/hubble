'''
HubbleStack Nova plugin for auditing installed packages.

The module gets the list of installed packages of the system and queries
the Vulners.com Linux Vulnerability Audit API.

The API is described at the link below:
    https://blog.vulners.com/linux-vulnerability-audit-in-vulners/

:maintainer: HubbleStack / avb76
:maturity: 3/26/2017 (TODO: change the format when the release date is established)
:platform: Linux
:requires: SaltStack

This audit module requires a YAML file inside the hubblestack_nova_profiles directory.
The file should have the following format:

vulners_scanner: <random data>

It does not matter what `<random data>` is, as long as the top key of the file is named `vulners_scanner`.
This allows the module to run under a certain profile, as all of the other Nova modules do.
'''

from __future__ import absolute_import
import logging

import sys
import requests


log = logging.getLogger(__name__)


def __virtual__():
    return not sys.platform.startswith('win')


def audit(data_list, tags, debug=False):
    os_name = __grains__.get('os').lower()
    os_version = __grains__.get('osmajorrelease')

    if debug:
        log.debug("os_version: {0}, os_name{1}".format(os_version, os_name))

    ret = {'Success': [], 'Failure': [], 'Controlled': []}

    for profile, data in data_list:
        if 'vulners_scanner' in data:

            local_packages = _get_local_packages()
            vulners_data = _vulners_query(local_packages, os=os_name, version=os_version)
            if vulners_data['result'] == 'ERROR':
                log.error(vulners_data['data']['error'])
            vulners_data = _process_vulners(_vulners_query(local_packages, os = os_name, version = os_version))

            total_packages = len(local_packages)
            secure_packages = total_packages - len(vulners_data)

            ret['Success'] = [{'tag': 'Secure packages',
                           'description': '{0} out of {1}'.format(secure_packages, total_packages)}]
            ret['Failure'] = vulners_data

    return ret


def _get_local_packages():
    '''
    Get the packages installed on the system.

    :return: A nice list of packages.
    '''

    local_packages = __salt__['pkg.list_pkgs']()
    return ['{0}-{1}'.format(pkg, local_packages[pkg]) for pkg in local_packages]


def _vulners_query(packages=None, os=None, version=None, url='https://vulners.com/api/v3/audit/audit/'):
    '''
    Query the Vulners.com Linux Vulnerability Audit API for the provided packages.

    :param packages: The list on packages to check
    :param os: The name of the operating system
    :param version: The version of the operating system
    :param url: The URL of the auditing API; the default value is the Vulners.com audit API
                Check the following link for more details:
                    https://blog.vulners.com/linux-vulnerability-audit-in-vulners/
    :return: A dictionary containing the JSON data returned by the HTTP request.
    '''

    # error dict matching the error dict returned by the requests library
    error = {
        'result': 'ERROR',
        'data': {'error': None}
    }

    if not packages:
        error['data']['error'] = 'Missing the list of packages.'
        return error
    if not os and not version:
        error['data']['error'] = 'Missing the operating system name and version.'
        return error
    if not os:
        error['data']['error'] = 'Missing the operating system name.'
        return error
    if not version:
        error['data']['error'] = 'Missing the operating system version.'
        return error


    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    data = {
        "os": os,
        "package": packages,
        "version": version
    }

    try:
        response = requests.post(url=url, headers=headers, json=data)
        return response.json()
    except requests.Timeout:
        error['data']['error'] = 'Request to {0} timed out'.format(url)
        return error


def _process_vulners(vulners):
    '''
    Process the data returned by the API into the format accepted by `hubble.py`.

    :param vulners: The JSON data returned by the API
    :return: A list of dictionaries as hubble.py swallows
    '''

    packages = vulners.get('data', {}).get('packages')
    if not packages:
        return []

    return [{'tag': pkg,
             'vulnerabilities': packages[pkg],
             'description': ', '.join(packages[pkg].keys())}
            for pkg in packages]

