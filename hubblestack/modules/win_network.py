# -*- coding: utf-8 -*-
'''
Module for gathering and managing network information
'''
from __future__ import absolute_import, unicode_literals, print_function

# Import Python libs

import hubblestack.utils.platform

try:
    import hubblestack.utils.winapi
    HAS_DEPENDENCIES = True
except ImportError:
    HAS_DEPENDENCIES = False

try:
    import wmi  # pylint: disable=W0611
except ImportError:
    HAS_DEPENDENCIES = False

# Define the module's virtual name
__virtualname__ = 'network'


def __virtual__():
    '''
    Only works on Windows systems
    '''
    if not hubblestack.utils.platform.is_windows():
        return False, "Module win_network: Only available on Windows"

    if not HAS_DEPENDENCIES:
        return False, "Module win_network: Missing dependencies"

    return __virtualname__


def netstat():
    '''
    Return information on open ports and states

    CLI Example:

    .. code-block:: bash

        salt '*' network.netstat
    '''
    ret = []
    cmd = ['netstat', '-nao']
    lines = __salt__['cmd.run'](cmd, python_shell=False).splitlines()
    for line in lines:
        comps = line.split()
        if line.startswith('  TCP'):
            ret.append({
                'local-address': comps[1],
                'proto': comps[0],
                'remote-address': comps[2],
                'state': comps[3],
                'program': comps[4]})
        if line.startswith('  UDP'):
            ret.append({
                'local-address': comps[1],
                'proto': comps[0],
                'remote-address': comps[2],
                'state': None,
                'program': comps[3]})
    return ret