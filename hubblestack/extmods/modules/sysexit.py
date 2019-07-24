# -*- encoding: utf-8 -*-
""" intended for testing, this module's sole purpose is to cause the running
daemon to exit gracefully within a scheduled timeframe """

from __future__ import absolute_import

import logging
import sys


LOG = logging.getLogger(__name__)

def sysexit(code=0):
    """
    This function closes the process when called.

    code
        The exist status with which the process should exit.
    """
    LOG.info('instructing daemon to exit')
    sys.exit(code)
