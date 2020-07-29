# -*- coding: utf-8 -*-
'''
Functions for identifying which platform a machine is
'''
# Import Python libs
from __future__ import absolute_import, print_function, unicode_literals
import os
import subprocess
import sys

import warnings
# linux_distribution deprecated in py3.7
try:
    from platform import linux_distribution as _deprecated_linux_distribution

    def linux_distribution(**kwargs):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return _deprecated_linux_distribution(**kwargs)
except ImportError:
    from distro import linux_distribution

from hubblestack.utils.decorators.memoize import memoize

@memoize
def is_windows():
    '''
    Simple function to return if a host is Windows or not
    '''
    return sys.platform.startswith('win')


@memoize
def is_linux():
    '''
    Simple function to return if a host is Linux or not.
    Note for a proxy minion, we need to return something else
    '''
    return sys.platform.startswith('linux')


@memoize
def is_darwin():
    '''
    Simple function to return if a host is Darwin (macOS) or not
    '''
    return sys.platform.startswith('darwin')


@memoize
def is_sunos():
    '''
    Simple function to return if host is SunOS or not
    '''
    return sys.platform.startswith('sunos')


@memoize
def is_freebsd():
    '''
    Simple function to return if host is FreeBSD or not
    '''
    return sys.platform.startswith('freebsd')


@memoize
def is_netbsd():
    '''
    Simple function to return if host is NetBSD or not
    '''
    return sys.platform.startswith('netbsd')


@memoize
def is_openbsd():
    '''
    Simple function to return if host is OpenBSD or not
    '''
    return sys.platform.startswith('openbsd')


@memoize
def is_aix():
    '''
    Simple function to return if host is AIX or not
    '''
    return sys.platform.startswith('aix')


@memoize
def is_fedora():
    '''
    Simple function to return if host is Fedora or not
    '''
    (osname, osrelease, oscodename) = \
        [x.strip('"').strip("'") for x in linux_distribution()]
    return osname == 'Fedora'

@memoize
def is_proxy():
    '''
    Return True if this minion is a proxy minion.
    Leverages the fact that is_linux() and is_windows
    both return False for proxies.
    TODO: Need to extend this for proxies that might run on
    other Unices
    '''
    import __main__ as main
    # This is a hack.  If a proxy minion is started by other
    # means, e.g. a custom script that creates the minion objects
    # then this will fail.
    ret = False
    try:
        # Changed this from 'salt-proxy in main...' to 'proxy in main...'
        # to support the testsuite's temp script that is called 'cli_salt_proxy'
        #
        # Add '--proxyid' in sys.argv so that salt-call --proxyid
        # is seen as a proxy minion
        if 'proxy' in main.__file__ or '--proxyid' in sys.argv:
            ret = True
    except AttributeError:
        pass
    return ret
