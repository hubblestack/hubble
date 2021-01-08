# -*- coding: utf-8 -*-
"""
Logging for the hubble daemon
"""



import logging
import time

import hubblestack.log.splunk

# These patterns will not be logged by "conf_publisher" and "emit_to_splunk"

PATTERNS_TO_FILTER = ["password", "token", "passphrase", "privkey",
                      "keyid", "s3.key", "splunk_token"]

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

__CONSOLE_CONFIGURED = __LOGFILE_CONFIGURED = False


def is_console_configured():
    return __CONSOLE_CONFIGURED


def is_logfile_configured():
    return __LOGFILE_CONFIGURED


def is_logging_configured():
    return __CONSOLE_CONFIGURED or __LOGFILE_CONFIGURED

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
    """ Fake record that mimicks a logging record """
    def __init__(self, message, levelname, asctime, name):
        self.message = message
        self.levelname = levelname
        self.asctime = asctime
        self.name = name


# Set up an early log handler for use while we're generating config.
# Will be removed when we set up the console or file logger.
TEMP_HANDLER = logging.StreamHandler()
TEMP_HANDLER.setLevel(logging.INFO)
TEMP_HANDLER.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s'))
logging.root.handlers.insert(0, TEMP_HANDLER)


def _remove_temp_handler():
    """
    Remove temporary handler if it exists
    """

    if is_logging_configured():
        # In this case, the temporary logging handler has been removed, return!
        return

    if TEMP_HANDLER and TEMP_HANDLER in logging.root.handlers:
        logging.root.handlers.remove(TEMP_HANDLER)


def setup_console_logger(log_level='error',
                         log_format='%(asctime)s [%(levelname)-5s] %(message)s',
                         date_format='%H:%M:%S'):
    """
    Sets up logging to STDERR, allowing for configurable level, format, and
    date format.
    """
    _remove_temp_handler()

    level = LOG_LEVELS.get(log_level, logging.ERROR)

    rootlogger = logging.getLogger()
    rootlogger.setLevel(level)

    handler = logging.StreamHandler()
    handler.setLevel(level)

    formatter = logging.Formatter(log_format, date_format)

    handler.setFormatter(formatter)

    rootlogger.addHandler(handler)

    __CONSOLE_CONFIGURED = True


def setup_file_logger(log_file,
                      log_level='error',
                      log_format='%(asctime)s,%(msecs)03d [%(levelname)-5s] [%(name)s:%(lineno)d] '
                                 ' %(message)s',
                      date_format='%Y-%m-%d %H:%M:%S',
                      max_bytes=100000000,
                      backup_count=1):
    """
    Sets up logging to a file. By default will auto-rotate those logs every
    100MB and keep one backup.
    """
    _remove_temp_handler()
    rootlogger = logging.getLogger()

    fh_cls = logging.handlers.RotatingFileHandler
    handler = fh_cls(log_file, maxBytes=max_bytes, backupCount=backup_count)
    handler.setLevel(LOG_LEVELS.get(log_level, logging.ERROR))

    formatter = logging.Formatter(log_format, date_format)

    handler.setFormatter(formatter)

    rootlogger.addHandler(handler)

    __LOGFILE_CONFIGURED = True


def setup_splunk_logger():
    """
    Sets up logging to splunk.
    """
    _remove_temp_handler()
    rootlogger = logging.getLogger()

    handler = hubblestack.log.splunk.SplunkHandler()
    handler.setLevel(logging.SPLUNK)

    rootlogger.addHandler(handler)

    global SPLUNK_HANDLER
    SPLUNK_HANDLER = handler


def refresh_handler_std_info():
    if SPLUNK_HANDLER is None:
        return False
    SPLUNK_HANDLER.update_event_std_info()


def emit_to_splunk(message, level, name):
    """
    Emit a single message to splunk
    """

    if isinstance(message, (list, dict)):
        message = filter_logs(message, remove_dots=False)

    if SPLUNK_HANDLER is None:
        return False
    handler = SPLUNK_HANDLER
    handler.emit(MockRecord(message, level, time.asctime(), name))

    return True


def filter_logs(opts_to_log, remove_dots=True):
    """
    Filters out keys containing certain patterns to avoid sensitive information being sent to logs
    Works on dictionaries and lists
    This function was located at extmods/modules/conf_publisher.py previously
    """
    filtered_conf = _remove_sensitive_info(opts_to_log, PATTERNS_TO_FILTER)
    if remove_dots:
        for key in filtered_conf.keys():
            if '.' in key:
                filtered_conf[key.replace('.', '_')] = filtered_conf.pop(key)
    return filtered_conf


def _remove_sensitive_info(obj, patterns_to_filter):
    """
    Filter known sensitive info
    """
    if isinstance(obj, dict):
        obj = {
            key: _remove_sensitive_info(value, patterns_to_filter)
            for key, value in obj.items()
            if not any(patt in key for patt in patterns_to_filter)}
    elif isinstance(obj, list):
        obj = [_remove_sensitive_info(item, patterns_to_filter)
               for item in obj]
    return obj
