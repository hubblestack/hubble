# -*- coding: utf-8 -*-
'''
Logging for the hubble daemon
'''

from __future__ import print_function

import logging
import time

import hubblestack.splunklogging

# While hubble doesn't use these, salt modules can, so let's define them anyway
SPLUNK = logging.SPLUNK = 25
PROFILE = logging.PROFILE = 15
TRACE = logging.TRACE = 5
GARBAGE = logging.GARBAGE = 1
QUIET = logging.QUIET = 1000

LOG_LEVELS = {
    'all': logging.NOTSET,
    'debug': logging.DEBUG,
    'error': logging.ERROR,
    'critical': logging.CRITICAL,
    'garbage': GARBAGE,
    'info': logging.INFO,
    'profile': PROFILE,
    'quiet': QUIET,
    'trace': TRACE,
    'warning': logging.WARNING,
}

logging.addLevelName(SPLUNK, 'SPLUNK')
logging.addLevelName(QUIET, 'QUIET')
logging.addLevelName(PROFILE, 'PROFILE')
logging.addLevelName(TRACE, 'TRACE')
logging.addLevelName(GARBAGE, 'GARBAGE')


def _splunk(self, message, *args, **kwargs):
    if self.isEnabledFor(logging.SPLUNK):
        self._log(logging.SPLUNK, message, args, **kwargs)


def _quiet(self, message, *args, **kwargs):
    if self.isEnabledFor(logging.QUIET):
        self._log(logging.QUIET, message, args, **kwargs)


def _profile(self, message, *args, **kwargs):
    if self.isEnabledFor(logging.PROFILE):
        self._log(logging.PROFILE, message, args, **kwargs)


def _trace(self, message, *args, **kwargs):
    if self.isEnabledFor(logging.TRACE):
        self._log(logging.TRACE, message, args, **kwargs)


def _garbage(self, message, *args, **kwargs):
    if self.isEnabledFor(logging.GARBAGE):
        self._log(logging.GARBAGE, message, args, **kwargs)


logging.Logger.splunk = _splunk
logging.Logger.quiet = _quiet
logging.Logger.profile = _profile
logging.Logger.trace = _trace
logging.Logger.garbage = _garbage

SPLUNK_HANDLER = None


class MockRecord(object):
    def __init__(self, message, levelname, asctime, name):
        self.message = message
        self.levelname = levelname
        self.asctime = asctime
        self.name = name


def setup_console_logger(log_level='error',
                         log_format='[%(levelname)-8s] %(message)s',
                         date_format='%H:%M:%S'):
    '''
    Sets up logging to STDERR, allowing for configurable level, format, and
    date format.
    '''
    rootlogger = logging.getLogger()

    handler = logging.handlers.StreamHandler()
    handler.setLevel(LOG_LEVELS.get(log_level, logging.ERROR))

    formatter = logging.Formatter(log_format, date_format)

    handler.setFormatter(formatter)

    rootlogger.addHandler(handler)


def setup_file_logger(log_file,
                      log_level='error',
                      log_format='%(asctime)s,%(msecs)03d [%(name)-17s:%(lineno)-4d][%(levelname)-8s][%(process)d] %(message)s',
                      date_format='%Y-%m-%d %H:%M:%S',
                      max_bytes=100000000,
                      backup_count=1):
    '''
    Sets up logging to a file. By default will auto-rotate those logs every
    100MB and keep one backup.
    '''
    rootlogger = logging.getLogger()

    handler = logging.handlers.RotatingFileHandler(log_file, maxBytes=max_bytes, backupCount=backup_count)
    handler.setLevel(LOG_LEVELS.get(log_level, logging.ERROR))

    formatter = logging.Formatter(log_format, date_format)

    handler.setFormatter(formatter)

    rootlogger.addHandler(handler)


def setup_splunk_logger():
    '''
    Sets up logging to splunk.
    '''
    rootlogger = logging.getLogger()

    handler = hubblestack.splunklogging.SplunkHandler()
    handler.setLevel(logging.SPLUNK)

    rootlogger.addHandler(handler)

    global SPLUNK_HANDLER
    SPLUNK_HANDLER = handler


def emit_to_splunk(message, level, name):
    '''
    Emit a single message to splunk
    '''
    if SPLUNK_HANDLER is None:
        return False
    handler = SPLUNK_HANDLER

    handler.emit(MockRecord(message, level, time.asctime(), name))
