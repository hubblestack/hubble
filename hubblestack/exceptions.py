# -*- coding: utf-8 -*-
'''
This module is a central location for all hubble exceptions
'''
# Import python libs
import copy
import logging
import time

log = logging.getLogger(__name__)

def get_error_message(error):
    '''
    Get human readable message from Python Exception
    '''
    return error.args[0] if error.args else ''


class HubbleException(Exception):
    '''
    Base exception class; all exceptions should subclass this
    '''
    def __init__(self, message=''):
        # Avoid circular import
        import hubblestack.utils.stringutils
        if not isinstance(message, str):
            message = str(message)
        super(HubbleException, self).__init__(
            hubblestack.utils.stringutils.to_str(message)
        )
        self.message = message

class CommandNotFoundError(HubbleException):
    '''
    Used in modules or grains when a required binary is not available
    '''


class CommandExecutionError(HubbleException):
    '''
    Used when a module runs a command which returns an error and wants
    to show the user the output gracefully instead of dying
    '''
    def __init__(self, message=''):
        # Avoid circular import
        import hubblestack.utils.stringutils
        try:
            exc_str = hubblestack.utils.stringutils.to_unicode(message)
        except TypeError:
            # Exception class instance passed. The HubbleException __init__ will
            # gracefully handle non-string types passed to it
            try:
                exc_str = str(message)
            except UnicodeDecodeError:
                exc_str = hubblestack.utils.stringutils.to_unicode(str(message))  # future lint: disable=blacklisted-function

        # We call the parent __init__ last instead of first because we need the
        # logic above to derive the message string to use for the exception
        # message.
        super(CommandExecutionError, self).__init__(exc_str)

class TimedProcTimeoutError(HubbleException):
    '''
    Thrown when a timed subprocess does not terminate within the timeout,
    or if the specified timeout is not an int or a float
    '''

class HubbleInvocationError(HubbleException, TypeError):
    '''
    Used when the wrong number of arguments are sent to modules or invalid
    arguments are specified on the command line
    '''

class LoaderError(HubbleException):
    '''
    Problems loading the right renderer
    '''

class FileLockError(HubbleException):
    '''
    Used when an error occurs obtaining a file lock
    '''
    def __init__(self, message, time_start=None, *args, **kwargs):
        super(FileLockError, self).__init__(message, *args, **kwargs)
        if time_start is None:
            log.warning(
                'time_start should be provided when raising a FileLockError. '
                'Defaulting to current time as a fallback, but this may '
                'result in an inaccurate timeout.'
            )
            self.time_start = time.time()
        else:
            self.time_start = time_start


class GitLockError(HubbleException):
    '''
    Raised when an uncaught error occurs in the midst of obtaining an
    update/checkout lock in gitfs.
    '''
    def __init__(self, errno, message, *args, **kwargs):
        super(GitLockError, self).__init__(message, *args, **kwargs)
        self.errno = errno


class GitRemoteError(HubbleException):
    '''
    Used by GitFS to denote a problem with the existence of the "origin" remote
    or part of its configuration
    '''


class TimeoutError(HubbleException):
    '''
    Thrown when an opration cannot be completet within a given time limit.
    '''

class NotImplemented(HubbleException):
    '''
    Used when a module runs a command which returns an error and wants
    to show the user the output gracefully instead of dying
    '''

class ArgumentValueError(CommandExecutionError):
    '''
    Used when an invalid argument was passed to a command execution
    '''


class MissingSmb(HubbleException):
    '''
    Raised when no smb library is found.
    '''


class MinionError(HubbleException):
    '''
    Minion problems reading uris such as salt:// or http://
    '''

class HubbleConfigurationError(HubbleException):
    """
    Configuration Error
    """

class FileserverConfigError(HubbleException):
    '''
    Used when invalid fileserver settings are detected
    '''

class HubbleRenderError(HubbleException):
    '''
    Used when a renderer needs to raise an explicit error. If a line number and
    buffer string are passed, get_context will be invoked to get the location
    of the error.
    '''
    def __init__(self,
                 message,
                 line_num=None,
                 buf='',
                 marker='    <======================',
                 trace=None):
        # Avoid circular import
        import hubblestack.utils.stringutils
        self.error = message
        try:
            exc_str = hubblestack.utils.stringutils.to_unicode(message)
        except TypeError:
            # Exception class instance passed. The HubbleException __init__ will
            # gracefully handle non-string types passed to it, but since this
            # class needs to do some extra stuff with the exception "message"
            # before handing it off to the parent class' __init__, we'll need
            # to extract the message from the exception instance here
            try:
                exc_str = str(message)
            except UnicodeDecodeError:
                exc_str = hubblestack.utils.stringutils.to_unicode(str(message))  # future lint: disable=blacklisted-function
        self.line_num = line_num
        self.buffer = buf
        self.context = ''
        if trace:
            exc_str += '\n{0}\n'.format(trace)
        if self.line_num and self.buffer:
            self.context = hubblestack.utils.stringutils.get_context(
                self.buffer,
                self.line_num,
                marker=marker
            )
            exc_str += '; line {0}\n\n{1}'.format(
                self.line_num,
                hubblestack.utils.stringutils.to_unicode(self.context),
            )
        super(HubbleRenderError, self).__init__(exc_str)

class HubbleDeserializationError(HubbleException):
    '''
    Thrown when hubble cannot deserialize data.
    '''

class HubbleReqTimeoutError(HubbleException):
    """
    Thrown when a request fails to return within the timeout
    """

class HubbleDeserializationError(HubbleException):
    '''
    Thrown when hubble cannot deserialize data.
    '''
