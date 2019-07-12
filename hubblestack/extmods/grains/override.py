# -*- coding: utf-8 -*-
'''
The static grains, these are the core, or built in grains.

When grains are loaded they are not loaded in the same way that modules are
loaded, grain functions are detected and executed, the functions MUST
return a dict which will be applied to the main grains dict. This module
will always be executed first, so that any grains loaded here in the core
module can be overwritten just by returning dict keys with the same value
as those returned here
'''

# Import python libs
from __future__ import absolute_import, print_function, unicode_literals
import os
import socket
import sys
import re
import platform
import logging
import locale
import uuid
from errno import EACCES, EPERM
import datetime

# pylint: disable=import-error
try:
    import dateutil.tz
    _DATEUTIL_TZ = True
except ImportError:
    _DATEUTIL_TZ = False

__proxyenabled__ = ['*']
__FQDN__ = None

# Extend the default list of supported distros. This will be used for the
# /etc/DISTRO-release checking that is part of linux_distribution()
from platform import _supported_dists
_supported_dists += ('arch', 'mageia', 'meego', 'vmware', 'bluewhite64',
                     'slamd64', 'ovs', 'system', 'mint', 'oracle', 'void')

# linux_distribution deprecated in py3.7
try:
    from platform import linux_distribution
except ImportError:
    from distro import linux_distribution

# Import salt libs
import salt.exceptions
import salt.log
import salt.utils.dns
import salt.utils.files
import salt.utils.network
import salt.utils.path
import salt.utils.pkg.rpm
import salt.utils.platform
import salt.utils.stringutils
from salt.ext import six
from salt.ext.six.moves import range

if salt.utils.platform.is_windows():
    import salt.utils.win_osinfo

# Solve the Chicken and egg problem where grains need to run before any
# of the modules are loaded and are generally available for any usage.
import salt.modules.cmdmod
import salt.modules.smbios

__salt__ = {
    'cmd.run': salt.modules.cmdmod._run_quiet,
    'cmd.retcode': salt.modules.cmdmod._retcode_quiet,
    'cmd.run_all': salt.modules.cmdmod._run_all_quiet,
    'smbios.records': salt.modules.smbios.records,
    'smbios.get': salt.modules.smbios.get,
}
log = logging.getLogger(__name__)

HAS_WMI = False
if salt.utils.platform.is_windows():
    # attempt to import the python wmi module
    # the Windows minion uses WMI for some of its grains
    try:
        import wmi  # pylint: disable=import-error
        import salt.utils.winapi
        import win32api
        import salt.utils.win_reg
        HAS_WMI = True
    except ImportError:
        log.exception(
            'Unable to import Python wmi module, some core grains '
            'will be missing'
        )


def hostname():
    '''
    Return fqdn, hostname, domainname
    '''
    # This is going to need some work
    # Provides:
    #   fqdn
    #   host
    #   localhost
    #   domain
    global __FQDN__
    grains = {}

    if salt.utils.platform.is_proxy():
        return grains

    grains['localhost'] = socket.gethostname()
    if __FQDN__ is None:
        try:
            __FQDN__ = salt.utils.network.get_fqhostname()
        except (socket.gaierror, socket.error) as err:
            log.debug('Failed to get FQDN from dns server with error: %s', err)
            local_fqdn = __salt__['cmd.run']('hostname --fqdn')
            domain_name = __salt__['cmd.run']('domainname')
            if domainname.strip() == '':
                domainname = '(none)'
            __FQDN__ = "{0}.{1}".format(local_fqdn, domain_name)
            log.debug('FQDN manually set to : %s', __FQDN__)


    # On some distros (notably FreeBSD) if there is no hostname set
    # salt.utils.network.get_fqhostname() will return None.
    # In this case we punt and log a message at error level, but force the
    # hostname and domain to be localhost.localdomain
    # Otherwise we would stacktrace below
    if __FQDN__ is None:   # still!
        log.error('Having trouble getting a hostname.  Does this machine have its hostname and domain set properly?')
        __FQDN__ = 'localhost.localdomain'

    grains['fqdn'] = __FQDN__
    log.error(grains['fqdn'])
    (grains['host'], grains['domain']) = grains['fqdn'].partition('.')[::2]
    log.error(grains)
    return grains