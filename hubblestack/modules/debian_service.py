# -*- coding: utf-8 -*-
'''
Service support for Debian systems (uses update-rc.d and /sbin/service)

.. important::
    If you feel that Salt should be using this module to manage services on a
    minion, and it is using a different module (or gives an error similar to
    *'service.start' is not available*), see :ref:`here
    <module-provider-override>`.
'''
from __future__ import absolute_import, print_function, unicode_literals

# Import python libs
import logging
import glob
import fnmatch
import re

# Import salt libs
import hubblestack.utils.systemd

__func_alias__ = {
    'reload_': 'reload'
}

# Define the module's virtual name
__virtualname__ = 'service'

log = logging.getLogger(__name__)

_DEFAULT_VER = '7.0.0'

def __virtual__():
    '''
    Only work on Debian and when systemd isn't running
    '''
    if __grains__['os'] in ('Debian', 'Raspbian', 'Devuan', 'NILinuxRT') and not hubblestack.utils.systemd.booted(__context__):
        return __virtualname__
    else:
        return (False, 'The debian_service module could not be loaded: '
                'unsupported OS family and/or systemd running.')

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
        return bool(__salt__['status.pid'](sig))

    contains_globbing = bool(re.search(r'\*|\?|\[.+\]', name))
    if contains_globbing:
        services = fnmatch.filter(get_all(), name)
    else:
        services = [name]
    results = {}
    for service in services:
        cmd = _service_cmd(service, 'status')
        results[service] = not __salt__['cmd.retcode'](cmd, ignore_retcode=True)
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

def enabled(name, **kwargs):
    '''
    Return True if the named service is enabled, false otherwise

    CLI Example:

    .. code-block:: bash

        salt '*' service.enabled <service name>
    '''
    return name in get_enabled()

def get_all():
    '''
    Return all available boot services

    CLI Example:

    .. code-block:: bash

        salt '*' service.get_all
    '''
    ret = set()
    lines = glob.glob('/etc/init.d/*')
    for line in lines:
        service = line.split('/etc/init.d/')[1]
        # Remove README.  If it's an enabled service, it will be added back in.
        if service != 'README':
            ret.add(service)
    return sorted(ret | set(get_enabled()))

def get_enabled():
    '''
    Return a list of service that are enabled on boot

    CLI Example:

    .. code-block:: bash

        salt '*' service.get_enabled
    '''
    prefix = '/etc/rc[S{0}].d/S'.format(_get_runlevel())
    ret = set()
    lines = glob.glob('{0}*'.format(prefix))
    for line in lines:
        ret.add(re.split(prefix + r'\d+', line)[1])
    return sorted(ret)

def _service_cmd(*args):
    osmajor = _osrel()[0]
    if osmajor < '6':
        cmd = '/etc/init.d/{0} {1}'.format(args[0], ' '.join(args[1:]))
    else:
        cmd = 'service {0} {1}'.format(args[0], ' '.join(args[1:]))
    return cmd

def _get_runlevel():
    '''
    returns the current runlevel
    '''
    out = __salt__['cmd.run']('runlevel')
    # unknown can be returned while inside a container environment, since
    # this is due to a lack of init, it should be safe to assume runlevel
    # 2, which is Debian's default. If not, all service related states
    # will throw an out of range exception here which will cause
    # other functions to fail.
    if 'unknown' in out:
        return '2'
    else:
        return out.split()[1]

def _osrel():
    osrel = __grains__.get('osrelease', _DEFAULT_VER)
    if not osrel:
        osrel = _DEFAULT_VER
    return osrel