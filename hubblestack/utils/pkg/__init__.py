# -*- coding: utf-8 -*-
'''
Common functions for managing package refreshes during states
'''
# Import python libs
from __future__ import absolute_import, print_function, unicode_literals
import errno
import logging
import os
import re

# Import Salt libs
import hubblestack.utils.data
import hubblestack.utils.files

log = logging.getLogger(__name__)


def rtag(opts):
    '''
    Return the rtag file location. This file is used to ensure that we don't
    refresh more than once (unless explicitly configured to do so).
    '''
    return os.path.join(opts['cachedir'], 'pkg_refresh')


def clear_rtag(opts):
    '''
    Remove the rtag file
    '''
    try:
        os.remove(rtag(opts))
    except OSError as exc:
        if exc.errno != errno.ENOENT:
            # Using __str__() here to get the fully-formatted error message
            # (error number, error message, path)
            log.warning('Encountered error removing rtag: %s', exc.__str__())


def write_rtag(opts):
    '''
    Write the rtag file
    '''
    rtag_file = rtag(opts)
    if not os.path.exists(rtag_file):
        try:
            with hubblestack.utils.files.fopen(rtag_file, 'w+'):
                pass
        except OSError as exc:
            log.warning('Encountered error writing rtag: %s', exc.__str__())


def check_refresh(opts, refresh=None):
    '''
    Check whether or not a refresh is necessary

    Returns:

    - True if refresh evaluates as True
    - False if refresh is False
    - A boolean if refresh is not False and the rtag file exists
    '''
    return bool(
        hubblestack.utils.data.is_true(refresh) or
        (os.path.isfile(rtag(opts)) and refresh is not False)
    )


def split_comparison(version):
    match = re.match(r'^(<=>|!=|>=|<=|>>|<<|<>|>|<|=)?\s?([^<>=]+)$', version)
    if match:
        comparison = match.group(1) or ''
        version = match.group(2)
    else:
        comparison = ''
    return comparison, version

