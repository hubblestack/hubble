# -*- coding: utf-8 -*-
'''
Module for returning various status data about a minion.
These data can be useful for compiling into stats later.
'''

# Import python libs
from __future__ import absolute_import, print_function, unicode_literals
import re
import logging

# Import salt libs
import hubblestack.utils.platform

log = logging.getLogger(__file__)

__virtualname__ = 'status'
__opts__ = {}

# Don't shadow built-in's.
__func_alias__ = {
    'time_': 'time'
}


log = logging.getLogger(__name__)


def __virtual__():
    '''
    Not all functions supported by Windows
    '''
    if hubblestack.utils.platform.is_windows():
        return False, 'Windows platform is not supported by this module'

    return __virtualname__

def pid(sig):
    '''
    Return the PID or an empty string if the process is running or not.
    Pass a signature to use to find the process via ps.  Note you can pass
    a Python-compatible regular expression to return all pids of
    processes matching the regexp.

    .. versionchanged:: 2016.11.4
        Added support for AIX

    CLI Example:

    .. code-block:: bash

        salt '*' status.pid <sig>
    '''

    cmd = __grains__['ps']
    output = __salt__['cmd.run_stdout'](cmd, python_shell=True)

    pids = ''
    for line in output.splitlines():
        if 'status.pid' in line:
            continue
        if re.search(sig, line):
            if pids:
                pids += '\n'
            pids += line.split()[1]

    return pids