# -*- coding: utf-8 -*-
'''
Custom grains around fqdn
'''
import salt.modules.cmdmod
import salt.utils
import salt.utils.platform
import socket

__salt__ = {'cmd.run': salt.modules.cmdmod._run_quiet}


def fqdn():
    '''
    Generate a secondary fqdn with `hostname --fqdn` since socket.getfqdn()
    appears to be susceptible to issues with DNS
    '''
    grains = {}
    local_fqdn = None
    if not salt.utils.platform.is_windows():
        local_fqdn = __salt__['cmd.run']('hostname --fqdn')
    grains['local_fqdn'] = local_fqdn if local_fqdn else socket.getfqdn()
    return grains
