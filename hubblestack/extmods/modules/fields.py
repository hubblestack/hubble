# -*- encoding: utf-8 -*-
'''
Module dealing with sending custom fields to splunk
'''
from __future__ import absolute_import
import logging

log = logging.getLogger(__name__)


def fields(custom_fields=None):
    '''
    Use config.get to retrieve custom data based on the keys in the `fields`
    list.

    Arguments:

    fields
        List of keys to retrieve
    '''
    if custom_fields is None or not isinstance(fields, list):
        log.error('custom_fields argument must be formed as a list of strings')
        return {}
    ret = {}
    for field in custom_fields:
        ret[field] = __salt__['config.get'](field)
    return ret
