# -*- coding: utf-8 -*-
'''
Module for returning various status data about a minion.
These data can be useful for compiling into stats later,
or for problem solving if your minion is having problems.

.. versionadded:: 0.12.0

:depends:  - wmi
'''

# Import Python Libs
from __future__ import absolute_import, unicode_literals, print_function
import datetime
import logging

import hubblestack.utils.platform
from hubblestack.utils.functools import namespaced_function as _namespaced_function

log = logging.getLogger(__name__)

# These imports needed for namespaced functions
# pylint: disable=W0611
from hubblestack.modules.status import time_

# pylint: enable=W0611

# Import 3rd Party Libs
try:
    if hubblestack.utils.platform.is_windows():
        import wmi
        import hubblestack.utils.winapi

        HAS_WMI = True
    else:
        HAS_WMI = False
except ImportError:
    HAS_WMI = False

HAS_PSUTIL = False
if hubblestack.utils.platform.is_windows():
    import psutil

    HAS_PSUTIL = True

__opts__ = {}
__virtualname__ = 'status'


def __virtual__():
    '''
    Only works on Windows systems with WMI and WinAPI
    '''
    if not hubblestack.utils.platform.is_windows():
        return False, 'win_status.py: Requires Windows'

    if not HAS_WMI:
        return False, 'win_status.py: Requires WMI and WinAPI'

    if not HAS_PSUTIL:
        return False, 'win_status.py: Requires psutil'

    # Namespace modules from `status.py`
    global time_
    time_ = _namespaced_function(time_, globals())

    return __virtualname__


__func_alias__ = {
    'time_': 'time'
}


def uptime(human_readable=False):
    '''
    .. versionadded:: 2015.8.0

    Return the system uptime for the machine

    Args:

        human_readable (bool):
            Return uptime in human readable format if ``True``, otherwise
            return seconds. Default is ``False``

            .. note::
                Human readable format is ``days, hours:min:sec``. Days will only
                be displayed if more than 0

    Returns:
        str:
            The uptime in seconds or human readable format depending on the
            value of ``human_readable``

    CLI Example:

    .. code-block:: bash

        salt '*' status.uptime
        salt '*' status.uptime human_readable=True
    '''
    # Get startup time
    startup_time = datetime.datetime.fromtimestamp(psutil.boot_time())

    # Subtract startup time from current time to get the uptime of the system
    uptime = datetime.datetime.now() - startup_time

    return str(uptime) if human_readable else uptime.total_seconds()
