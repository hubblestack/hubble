# -*- coding: utf-8 -*-
'''
Top level package command wrapper, used to translate the os detected by grains
to the correct service manager

.. important::
    If you feel that Salt should be using this module to manage services on a
    minion, and it is using a different module (or gives an error similar to
    *'service.start' is not available*), see :ref:`here
    <module-provider-override>`.
'''

# Import Python libs
import logging
import fnmatch
import re

# Import salt libs
import hubblestack.utils.systemd
import hubblestack.utils.odict as odict

# Set up logging
log = logging.getLogger(__name__)

# Define the module's virtual name
__virtualname__ = 'service'


def __virtual__():
    '''
    Only work on systems which default to OpenRC
    '''
    if __grains__['os'] == 'Gentoo' and not hubblestack.utils.systemd.booted(__context__):
        return __virtualname__
    if __grains__['os'] == 'Alpine':
        return __virtualname__
    return (False, 'The gentoo_service execution module cannot be loaded: '
            'only available on Gentoo/Open-RC systems.')

def status(name, sig=None):
    '''
    Return the status for a service.
    If the name contains globbing, a dict mapping service name to True/False
    values is returned.

    .. versionchanged:: 2018.3.0
        The service name can now be a glob (e.g. ``salt*``)

    Args:
        name (str): The name of the service to check
        sig (str): Signature to use to find the service via ps

    Returns:
        bool: True if running, False otherwise
        dict: Maps service name to True if running, False otherwise

    CLI Example:

    .. code-block:: bash

        salt '*' service.status <service name> [service signature]
    '''
    if sig:
        return bool(__mods__['status.pid'](sig))

    contains_globbing = bool(re.search(r'\*|\?|\[.+\]', name))
    if contains_globbing:
        services = fnmatch.filter(get_all(), name)
    else:
        services = [name]
    results = {}
    for service in services:
        cmd = _service_cmd(service, 'status')
        results[service] = not _ret_code(cmd, ignore_retcode=True)
    if contains_globbing:
        return results
    return results[name]

def available(name):
    '''
    Returns ``True`` if the specified service is available, otherwise returns
    ``False``.

    CLI Example:

    .. code-block:: bash

        salt '*' service.available sshd
    '''
    (enabled_services, disabled_services) = _get_service_list(include_enabled=True,
                                                              include_disabled=True)
    return name in enabled_services or name in disabled_services

def enabled(name, **kwargs):
    '''
    Return True if the named service is enabled, false otherwise

    CLI Example:

    .. code-block:: bash

        salt '*' service.enabled <service name> <runlevels=single-runlevel>
        salt '*' service.enabled <service name> <runlevels=[runlevel1,runlevel2]>
    '''
    enabled_services = get_enabled()
    if name not in enabled_services:
        return False
    if 'runlevels' not in kwargs:
        return True
    requested_levels = set(kwargs['runlevels'] if isinstance(kwargs['runlevels'],
                                                             list) else [kwargs['runlevels']])
    return len(requested_levels - set(enabled_services[name])) == 0

def get_all():
    '''
    Return all available boot services

    CLI Example:

    .. code-block:: bash

        salt '*' service.get_all
    '''
    (enabled_services, disabled_services) = _get_service_list(include_enabled=True,
                                                              include_disabled=True)
    enabled_services.update(dict([(s, []) for s in disabled_services]))
    return odict.OrderedDict(enabled_services)

def _get_service_list(include_enabled=True, include_disabled=False):
    enabled_services = dict()
    disabled_services = set()
    lines = _list_services()
    for line in lines:
        if '|' not in line:
            continue
        service = [l.strip() for l in line.split('|')]
        # enabled service should have runlevels
        if service[1]:
            if include_enabled:
                enabled_services.update({service[0]: sorted(service[1].split())})
            continue
        # in any other case service is disabled
        if include_disabled:
            disabled_services.update({service[0]: []})
    return enabled_services, disabled_services

def _list_services():
    return __mods__['cmd.run']('rc-update -v show').splitlines()

def _service_cmd(*args):
    return '/etc/init.d/{0} {1}'.format(args[0], ' '.join(args[1:]))

def _ret_code(cmd, ignore_retcode=False):
    log.debug('executing [{0}]'.format(cmd))
    sts = __mods__['cmd.retcode'](cmd, python_shell=False, ignore_retcode=ignore_retcode)
    return sts

def get_enabled():
    '''
    Return a list of service that are enabled on boot

    CLI Example:

    .. code-block:: bash

        salt '*' service.get_enabled
    '''
    (enabled_services, disabled_services) = _get_service_list()
    return odict.OrderedDict(enabled_services)