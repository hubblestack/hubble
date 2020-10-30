# -*- coding: utf-8 -*-
'''
Module for returning various status data about a minion.
These data can be useful for compiling into stats later.
'''

# Import python libs
from __future__ import absolute_import, print_function, unicode_literals
import datetime
import logging
import os
import re
import time

import hubblestack.utils.files
import hubblestack.utils.path
import hubblestack.utils.platform
from hubblestack.exceptions import CommandExecutionError

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


def uptime():
    '''
    Return the uptime for this system.

    .. versionchanged:: 2015.8.9
        The uptime function was changed to return a dictionary of easy-to-read
        key/value pairs containing uptime information, instead of the output
        from a ``cmd.run`` call.

    .. versionchanged:: 2016.11.0
        Support for OpenBSD, FreeBSD, NetBSD, MacOS, and Solaris

    .. versionchanged:: 2016.11.4
        Added support for AIX

    CLI Example:

    .. code-block:: bash

        salt '*' status.uptime
    '''
    curr_seconds = time.time()

    # Get uptime in seconds
    if hubblestack.utils.platform.is_linux():
        ut_path = "/proc/uptime"
        if not os.path.exists(ut_path):
            raise CommandExecutionError("File {ut_path} was not found.".format(ut_path=ut_path))
        with hubblestack.utils.files.fopen(ut_path) as rfh:
            seconds = int(float(rfh.read().split()[0]))
    elif hubblestack.utils.platform.is_sunos():
        # note: some flavors/versions report the host uptime inside a zone
        #       https://support.oracle.com/epmos/faces/BugDisplay?id=15611584
        res = __salt__['cmd.run_all']('kstat -p unix:0:system_misc:boot_time')
        if res['retcode'] > 0:
            raise CommandExecutionError('The boot_time kstat was not found.')
        seconds = int(curr_seconds - int(res['stdout'].split()[-1]))
    elif hubblestack.utils.platform.is_openbsd() or hubblestack.utils.platform.is_netbsd():
        bt_data = __salt__['sysctl.get']('kern.boottime')
        if not bt_data:
            raise CommandExecutionError('Cannot find kern.boottime system parameter')
        seconds = int(curr_seconds - int(bt_data))
    elif hubblestack.utils.platform.is_freebsd() or hubblestack.utils.platform.is_darwin():
        # format: { sec = 1477761334, usec = 664698 } Sat Oct 29 17:15:34 2016
        bt_data = __salt__['sysctl.get']('kern.boottime')
        if not bt_data:
            raise CommandExecutionError('Cannot find kern.boottime system parameter')
        data = bt_data.split("{")[-1].split("}")[0].strip().replace(' ', '')
        uptime = dict([(k, int(v, )) for k, v in [p.strip().split('=') for p in data.split(',')]])
        seconds = int(curr_seconds - uptime['sec'])
    elif hubblestack.utils.platform.is_aix():
        seconds = _get_boot_time_aix()
    else:
        return __salt__['cmd.run']('uptime')

    # Setup datetime and timedelta objects
    boot_time = datetime.datetime.utcfromtimestamp(curr_seconds - seconds)
    curr_time = datetime.datetime.utcfromtimestamp(curr_seconds)
    up_time = curr_time - boot_time

    # Construct return information
    ut_ret = {
        'seconds': seconds,
        'since_iso': boot_time.isoformat(),
        'since_t': int(curr_seconds - seconds),
        'days': up_time.days,
        'time': '{0}:{1}'.format(up_time.seconds // 3600, up_time.seconds % 3600 // 60),
    }

    if hubblestack.utils.path.which('who'):
        who_cmd = 'who' if hubblestack.utils.platform.is_openbsd() else 'who -s'  # OpenBSD does not support -s
        ut_ret['users'] = len(__salt__['cmd.run'](who_cmd).split(os.linesep))

    return ut_ret


def _get_boot_time_aix():
    '''
    Return the number of seconds since boot time on AIX

    t=$(LC_ALL=POSIX ps -o etime= -p 1)
    d=0 h=0
    case $t in *-*) d=${t%%-*}; t=${t#*-};; esac
    case $t in *:*:*) h=${t%%:*}; t=${t#*:};; esac
    s=$((d*86400 + h*3600 + ${t%%:*}*60 + ${t#*:}))

    t is 7-20:46:46
    '''
    boot_secs = 0
    res = __salt__['cmd.run_all']('ps -o etime= -p 1')
    if res['retcode'] > 0:
        raise CommandExecutionError('Unable to find boot_time for pid 1.')
    bt_time = res['stdout']
    days = bt_time.split('-')
    hms = days[1].split(':')
    boot_secs = _number(days[0]) * 86400 + _number(hms[0]) * 3600 + _number(hms[1]) * 60 + _number(hms[2])
    return boot_secs


def _number(text):
    '''
    Convert a string to a number.
    Returns an integer if the string represents an integer, a floating
    point number if the string is a real number, or the string unchanged
    otherwise.
    '''
    if text.isdigit():
        return int(text)
    try:
        return float(text)
    except ValueError:
        return text


def time_(format='%A, %d. %B %Y %I:%M%p'):
    '''
    .. versionadded:: 2016.3.0

    Return the current time on the minion,
    formatted based on the format parameter.

    Default date format: Monday, 27. July 2015 07:55AM

    CLI Example:

    .. code-block:: bash

        salt '*' status.time

        salt '*' status.time '%s'

    '''

    dt = datetime.datetime.today()
    return dt.strftime(format)