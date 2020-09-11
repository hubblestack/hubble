# -*- coding: utf-8 -*-
'''
Functions for StringIO objects
'''

from __future__ import absolute_import, print_function, unicode_literals

import io

readable_types = (io.StringIO,)
writable_types = (io.StringIO,)


def is_readable(obj):
    return isinstance(obj, readable_types) and obj.readable()
