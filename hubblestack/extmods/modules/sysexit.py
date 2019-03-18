# -*- encoding: utf-8 -*-
''' intended for testing, this module's sole purpose is to cause the running
daemon to exit gracefully within a scheduled timeframe '''

from __future__ import absolute_import

import logging
import sys

from salt.exceptions import CommandExecutionError

log = logging.getLogger(__name__)

def sysexit(code=0):
    log.info('instructing daemon to exit')
    sys.exit(code)
