# -*- coding: utf-8 -*-
'''
If Salt's OS detection does not identify a different virtual service module, the minion will fall back to using this basic module, which simply wraps sysvinit scripts.
'''
from __future__ import absolute_import, print_function, unicode_literals

# Import python libs
import os
import fnmatch
import logging
import re

__func_alias__ = {
    'reload_': 'reload'
}

_GRAINMAP = {
    'Arch': '/etc/rc.d',
    'Arch ARM': '/etc/rc.d'
}

log = logging.getLogger(__name__)

def __virtual__():
    '''
    Only work on systems which exclusively use sysvinit
    '''
    # Disable on these platforms, specific service modules exist:
    disable = set((
        'RedHat',
        'CentOS',
        'Amazon',
        'ScientificLinux',
        'CloudLinux',
        'Fedora',
        'Gentoo',
        'Ubuntu',
        'Debian',
        'Devuan',
        'ALT',
        'OEL',
        'Linaro',
        'elementary OS',
        'McAfee  OS Server',
        'Raspbian',
        'SUSE',
    ))
    g_os = __grains__.get('os')
    g_kern = __grains__.get('kernel')
    if g_os in disable:
        if __grains__.get('virtual_subtype') == "Docker":
            log.warning('running in Docker, __mods__[service.*] are disabled via modules/service.py; but may still load elsewhere')
        return (False, f'Your OS ("{g_os}") is on the disabled list')
    # Disable on all non-Linux OSes as well
    if g_kern != 'Linux':
        return (False, f'Non Linux OSes ("{g_kern}") are not supported')
    init_grain = __grains__.get('init')
    if init_grain not in (None, 'sysvinit', 'unknown'):
        return (False, 'Minion is running {0}'.format(init_grain))
    elif __utils__['systemd.booted'](__context__):
        # Should have been caught by init grain check, but check just in case
        return (False, 'Minion is running systemd')
    return 'service'

def status(name, sig=None):
    '''
    Return the status for a service.
    If the name contains globbing, a dict mapping service name to PID or empty
    string is returned.

    .. versionchanged:: 2018.3.0
        The service name can now be a glob (e.g. ``salt*``)

    Args:
        name (str): The name of the service to check
        sig (str): Signature to use to find the service via ps

    Returns:
        string: PID if running, empty otherwise
        dict: Maps service name to PID if running, empty string otherwise

    CLI Example:

    .. code-block:: bash

        salt '*' service.status <service name> [service signature]
    '''
    if sig:
        return __salt__['status.pid'](sig)

    contains_globbing = bool(re.search(r'\*|\?|\[.+\]', name))
    if contains_globbing:
        services = fnmatch.filter(get_all(), name)
    else:
        services = [name]
    results = {}
    for service in services:
        results[service] = __salt__['status.pid'](service)
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
    return name in get_all()

def get_all():
    '''
    Return a list of all available services

    CLI Example:

    .. code-block:: bash

        salt '*' service.get_all
    '''
    if not os.path.isdir(_GRAINMAP.get(__grains__.get('os'), '/etc/init.d')):
        return []
    return sorted(os.listdir(_GRAINMAP.get(__grains__.get('os'), '/etc/init.d')))
