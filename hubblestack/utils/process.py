# -*- coding: utf-8 -*-
'''
Functions for daemonizing and otherwise modifying running processes
'''

import os
import time
import signal
import logging
import io
import sys

import hubblestack.defaults.exitcodes
import hubblestack.utils.files

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


def os_is_running(pid):
    '''
    Use OS facilities to determine if a process is running
    '''
    if isinstance(pid, str):
        pid = int(pid)
    if HAS_PSUTIL:
        return psutil.pid_exists(pid)
    else:
        try:
            os.kill(pid, 0)  # SIG 0 is the "are you alive?" signal
            return True
        except OSError:
            return False

def daemonize(redirect_out=True):
    '''
    Daemonize hubblestack process
    '''
    try:
        pid = os.fork()
        if pid > 0:
            os._exit(hubblestack.defaults.exitcodes.EX_OK)
    except OSError as exc:
        log.error('fork #1 failed: %s (%s)', exc.errno, exc)
        sys.exit(hubblestack.defaults.exitcodes.EX_GENERIC)

    # decouple from parent environment
    os.chdir('/')
    # noinspection PyArgumentList
    os.setsid()
    os.umask(0o022)  # pylint: disable=blacklisted-function

    # do second fork
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(hubblestack.defaults.exitcodes.EX_OK)
    except OSError as exc:
        log.error('fork #2 failed: %s (%s)', exc.errno, exc)
        sys.exit(hubblestack.defaults.exitcodes.EX_GENERIC)

    # A normal daemonization redirects the process output to /dev/null.
    # Unfortunately when a python multiprocess is called the output is
    # not cleanly redirected and the parent process dies when the
    # multiprocessing process attempts to access stdout or err.
    if redirect_out:
        with hubblestack.utils.files.fopen('/dev/null', 'r+') as dev_null:
            # Redirect python stdin/out/err
            # and the os stdin/out/err which can be different
            dup2(dev_null, sys.stdin)
            dup2(dev_null, sys.stdout)
            dup2(dev_null, sys.stderr)
            dup2(dev_null, 0)
            dup2(dev_null, 1)
            dup2(dev_null, 2)


def dup2(file1, file2):
    '''
    Duplicate file descriptor fd to fd2, closing the latter first if necessary.
    This method is similar to os.dup2 but ignores streams that do not have a
    supported fileno method.
    '''
    if isinstance(file1, int):
        fno1 = file1
    else:
        try:
            fno1 = file1.fileno()
        except io.UnsupportedOperation:
            log.warn('Unsupported operation on file: %r', file1)
            return
    if isinstance(file2, int):
        fno2 = file2
    else:
        try:
            fno2 = file2.fileno()
        except io.UnsupportedOperation:
            log.warn('Unsupported operation on file: %r', file2)
            return
    os.dup2(fno1, fno2)
