# -*- coding: utf-8 -*-
'''
Functions for daemonizing and otherwise modifying running processes
'''

# Import python libs
from __future__ import absolute_import, with_statement, print_function, unicode_literals
import os
import time
import signal
import logging

log = logging.getLogger(__name__)

# pylint: disable=import-error
HAS_PSUTIL = False
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    pass

try:
    import setproctitle
    HAS_SETPROCTITLE = True
except ImportError:
    HAS_SETPROCTITLE = False


def clean_proc(proc, wait_for_kill=10):
    '''
    Generic method for cleaning up multiprocessing procs
    '''
    # NoneType and other fun stuff need not apply
    if not proc:
        return
    try:
        waited = 0
        while proc.is_alive():
            proc.terminate()
            waited += 1
            time.sleep(0.1)
            if proc.is_alive() and (waited >= wait_for_kill):
                log.error('Process did not die with terminate(): %s', proc.pid)
                os.kill(proc.pid, signal.SIGKILL)
    except (AssertionError, AttributeError):
        # Catch AssertionError when the proc is evaluated inside the child
        # Catch AttributeError when the process dies between proc.is_alive()
        # and proc.terminate() and turns into a NoneType
        pass