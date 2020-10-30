# -*- coding: utf-8 -*-
'''
Windows Service module.

.. versionchanged:: 2016.11.0 - Rewritten to use PyWin32
'''

# Import Python libs
from __future__ import absolute_import, unicode_literals, print_function
import fnmatch
import logging
import re

# Import Salt libs
import hubblestack.utils.platform
from hubblestack.exceptions import CommandExecutionError

# Import 3rd party libs
try:
    import win32security
    import win32service
    import win32serviceutil
    import pywintypes
    HAS_WIN32_MODS = True
except ImportError:
    HAS_WIN32_MODS = False

log = logging.getLogger(__name__)

# Define the module's virtual name
__virtualname__ = 'service'

SERVICE_TYPE = {1: 'Kernel Driver',
                2: 'File System Driver',
                4: 'Adapter Driver',
                8: 'Recognizer Driver',
                16: 'Win32 Own Process',
                32: 'Win32 Share Process',
                256: 'Interactive',
                'kernel': 1,
                'filesystem': 2,
                'adapter': 4,
                'recognizer': 8,
                'own': 16,
                'share': 32}

SERVICE_CONTROLS = {1: 'Stop',
                    2: 'Pause/Continue',
                    4: 'Shutdown',
                    8: 'Change Parameters',
                    16: 'Netbind Change',
                    32: 'Hardware Profile Change',
                    64: 'Power Event',
                    128: 'Session Change',
                    256: 'Pre-Shutdown',
                    512: 'Time Change',
                    1024: 'Trigger Event'}

SERVICE_STATE = {1: 'Stopped',
                 2: 'Start Pending',
                 3: 'Stop Pending',
                 4: 'Running',
                 5: 'Continue Pending',
                 6: 'Pause Pending',
                 7: 'Paused'}

SERVICE_ERRORS = {0: 'No Error',
                  1066: 'Service Specific Error'}

SERVICE_START_TYPE = {'boot': 0,
                      'system': 1,
                      'auto': 2,
                      'manual': 3,
                      'disabled': 4,
                      0: 'Boot',
                      1: 'System',
                      2: 'Auto',
                      3: 'Manual',
                      4: 'Disabled'}

SERVICE_ERROR_CONTROL = {0: 'Ignore',
                         1: 'Normal',
                         2: 'Severe',
                         3: 'Critical',
                         'ignore': 0,
                         'normal': 1,
                         'severe': 2,
                         'critical': 3}


def __virtual__():
    '''
    Only works on Windows systems with PyWin32 installed
    '''
    if not hubblestack.utils.platform.is_windows():
        return False, 'Module win_service: module only works on Windows.'

    if not HAS_WIN32_MODS:
        return False, 'Module win_service: failed to load win32 modules'

    return __virtualname__

def status(name, *args, **kwargs):
    '''
    Return the status for a service.
    If the name contains globbing, a dict mapping service name to True/False
    values is returned.

    .. versionchanged:: 2018.3.0
        The service name can now be a glob (e.g. ``salt*``)

    Args:
        name (str): The name of the service to check

    Returns:
        bool: True if running, False otherwise
        dict: Maps service name to True if running, False otherwise

    CLI Example:

    .. code-block:: bash

        salt '*' service.status <service name>
    '''

    results = {}
    all_services = get_all()
    contains_globbing = bool(re.search(r'\*|\?|\[.+\]', name))
    if contains_globbing:
        services = fnmatch.filter(all_services, name)
    else:
        services = [name]
    for service in services:
        results[service] = info(service)['Status'] in ['Running', 'Stop Pending']
    if contains_globbing:
        return results
    return results[name]

def available(name):
    '''
    Check if a service is available on the system.

    Args:
        name (str): The name of the service to check

    Returns:
        bool: ``True`` if the service is available, ``False`` otherwise

    CLI Example:

    .. code-block:: bash

        salt '*' service.available <service name>
    '''
    for service in get_all():
        if name.lower() == service.lower():
            return True

    return False

def enabled(name, **kwargs):
    '''
    Check to see if the named service is enabled to start on boot

    Args:
        name (str): The name of the service to check

    Returns:
        bool: True if the service is set to start

    CLI Example:

    .. code-block:: bash

        salt '*' service.enabled <service name>
    '''
    return info(name)['StartType'] == 'Auto'

def get_all():
    '''
    Return all installed services

    Returns:
        list: Returns a list of all services on the system.

    CLI Example:

    .. code-block:: bash

        salt '*' service.get_all
    '''
    services = _get_services()

    ret = set()
    for service in services:
        ret.add(service['ServiceName'])

    return sorted(ret)

def _get_services():
    '''
    Returns a list of all services on the system.
    '''
    handle_scm = win32service.OpenSCManager(
        None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE)

    try:
        services = win32service.EnumServicesStatusEx(handle_scm)
    except AttributeError:
        services = win32service.EnumServicesStatus(handle_scm)
    finally:
        win32service.CloseServiceHandle(handle_scm)

    return services

def info(name):
    '''
    Get information about a service on the system

    Args:
        name (str): The name of the service. This is not the display name. Use
            ``get_service_name`` to find the service name.

    Returns:
        dict: A dictionary containing information about the service.

    CLI Example:

    .. code-block:: bash

        salt '*' service.info spooler
    '''
    try:
        handle_scm = win32service.OpenSCManager(
            None, None, win32service.SC_MANAGER_CONNECT)
    except pywintypes.error as exc:
        raise CommandExecutionError(
            'Failed to connect to the SCM: {0}'.format(exc.strerror))

    try:
        handle_svc = win32service.OpenService(
            handle_scm, name,
            win32service.SERVICE_ENUMERATE_DEPENDENTS |
            win32service.SERVICE_INTERROGATE |
            win32service.SERVICE_QUERY_CONFIG |
            win32service.SERVICE_QUERY_STATUS)
    except pywintypes.error as exc:
        raise CommandExecutionError(
            'Failed To Open {0}: {1}'.format(name, exc.strerror))

    try:
        config_info = win32service.QueryServiceConfig(handle_svc)
        status_info = win32service.QueryServiceStatusEx(handle_svc)

        try:
            description = win32service.QueryServiceConfig2(
                handle_svc, win32service.SERVICE_CONFIG_DESCRIPTION)
        except pywintypes.error:
            description = 'Failed to get description'

        delayed_start = win32service.QueryServiceConfig2(
            handle_svc, win32service.SERVICE_CONFIG_DELAYED_AUTO_START_INFO)
    finally:
        win32service.CloseServiceHandle(handle_scm)
        win32service.CloseServiceHandle(handle_svc)

    ret = dict()
    try:
        sid = win32security.LookupAccountName(
            '', 'NT Service\\{0}'.format(name))[0]
        ret['sid'] = win32security.ConvertSidToStringSid(sid)
    except pywintypes.error:
        ret['sid'] = 'Failed to get SID'

    ret['BinaryPath'] = config_info[3]
    ret['LoadOrderGroup'] = config_info[4]
    ret['TagID'] = config_info[5]
    ret['Dependencies'] = config_info[6]
    ret['ServiceAccount'] = config_info[7]
    ret['DisplayName'] = config_info[8]
    ret['Description'] = description
    ret['Status_ServiceCode'] = status_info['ServiceSpecificExitCode']
    ret['Status_CheckPoint'] = status_info['CheckPoint']
    ret['Status_WaitHint'] = status_info['WaitHint']
    ret['StartTypeDelayed'] = delayed_start

    flags = list()
    for bit in SERVICE_TYPE:
        if isinstance(bit, int):
            if config_info[0] & bit:
                flags.append(SERVICE_TYPE[bit])

    ret['ServiceType'] = flags if flags else config_info[0]

    flags = list()
    for bit in SERVICE_CONTROLS:
        if status_info['ControlsAccepted'] & bit:
            flags.append(SERVICE_CONTROLS[bit])

    ret['ControlsAccepted'] = flags if flags else status_info['ControlsAccepted']

    try:
        ret['Status_ExitCode'] = SERVICE_ERRORS[status_info['Win32ExitCode']]
    except KeyError:
        ret['Status_ExitCode'] = status_info['Win32ExitCode']

    try:
        ret['StartType'] = SERVICE_START_TYPE[config_info[1]]
    except KeyError:
        ret['StartType'] = config_info[1]

    try:
        ret['ErrorControl'] = SERVICE_ERROR_CONTROL[config_info[2]]
    except KeyError:
        ret['ErrorControl'] = config_info[2]

    try:
        ret['Status'] = SERVICE_STATE[status_info['CurrentState']]
    except KeyError:
        ret['Status'] = status_info['CurrentState']

    return ret

def get_service_name(*args):
    '''
    The Display Name is what is displayed in Windows when services.msc is
    executed.  Each Display Name has an associated Service Name which is the
    actual name of the service.  This function allows you to discover the
    Service Name by returning a dictionary of Display Names and Service Names,
    or filter by adding arguments of Display Names.

    If no args are passed, return a dict of all services where the keys are the
    service Display Names and the values are the Service Names.

    If arguments are passed, create a dict of Display Names and Service Names

    Returns:
        dict: A dictionary of display names and service names

    CLI Examples:

    .. code-block:: bash

        salt '*' service.get_service_name
        salt '*' service.get_service_name 'Google Update Service (gupdate)' 'DHCP Client'
    '''
    raw_services = _get_services()

    services = dict()
    for raw_service in raw_services:
        if args:
            if raw_service['DisplayName'] in args or \
                    raw_service['ServiceName'] in args or \
                    raw_service['ServiceName'].lower() in args:
                services[raw_service['DisplayName']] = raw_service['ServiceName']
        else:
            services[raw_service['DisplayName']] = raw_service['ServiceName']

    return services