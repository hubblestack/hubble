# -*- coding: utf-8 -*-
'''
Common functions for working with RPM packages
'''

# Import python libs
from __future__ import absolute_import, print_function, unicode_literals
import collections
import datetime
import logging
import subprocess
import hubblestack.utils.stringutils

log = logging.getLogger(__name__)

def get_osarch():
    '''
    Get the os architecture using rpm --eval
    '''
    ret = subprocess.Popen(
        'rpm --eval "%{_host_cpu}"',
        shell=True,
        close_fds=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE).communicate()[0]
    return hubblestack.utils.stringutils.to_str(ret).strip() or 'unknown'

