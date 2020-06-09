# -*- coding: utf-8 -*-
'''
Set grains describing the hubble process.
'''

from __future__ import absolute_import, print_function, unicode_literals

import os

# Import salt libs
import hubblestack.utils.platform

try:
    import pwd
except ImportError:
    import getpass
    pwd = None

try:
    import grp
except ImportError:
    grp = None


def _uid():
    '''
    Grain for the hubble User ID
    '''
    if hubblestack.utils.platform.is_windows():
        return None
    return os.getuid()


def _username():
    '''
    Grain for the hubble username
    '''
    if pwd:
        username = pwd.getpwuid(os.getuid()).pw_name
    else:
        username = getpass.getuser()

    return username


def _gid():
    '''
    Grain for the hubble Group ID
    '''
    if hubblestack.utils.platform.is_windows():
        return None
    return os.getgid()


def _groupname():
    '''
    Grain for the hubble groupname
    '''
    if grp:
        try:
            groupname = grp.getgrgid(os.getgid()).gr_name
        except KeyError:
            groupname = ''
    else:
        groupname = ''

    return groupname


def _pid():
    return os.getpid()


def grains():
    ret = {
        'username': _username(),
        'groupname': _groupname(),
        'pid': _pid(),
    }

    if not hubblestack.utils.platform.is_windows():
        ret['gid'] = _gid()
        ret['uid'] = _uid()

    return ret
