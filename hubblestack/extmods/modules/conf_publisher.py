# -*- coding: utf-8 -*-
'''
Module to send config options to splunk
'''
import logging
import hubblestack.log
import copy
import time

log = logging.getLogger(__name__)


def publish(report_directly_to_splunk=True, remove_dots=True, *args):

    '''
    Publishes config to splunk at an interval defined in schedule

    report_directly_to_splunk
        Whether to emit directly to splunk in addition to returning as a normal
        job. Defaults to True.

    remove_dots
        Whether to replace dots in top-level keys with underscores for ease
        of handling in splunk. Defaults to True.

    *args
       Tuple of opts to log (keys in __opts__). Only those key-value pairs
       would be published, keys for which are in *args If not passed, entire
       __opts__ (excluding password/token) would be published

    '''
    log.debug('Started publishing config to splunk')

    opts_to_log = {}
    if not args:
        opts_to_log = copy.deepcopy(__opts__)
        if 'grains' in opts_to_log:
            opts_to_log.pop('grains')
    else:
        for arg in args:
            if arg in  __opts__:
                opts_to_log[arg] = __opts__[arg]

    filtered_conf = hubblestack.log.filter_logs(opts_to_log, remove_dots=remove_dots)

    if report_directly_to_splunk:
        hubblestack.log.emit_to_splunk(filtered_conf, 'INFO', 'hubblestack.hubble_config')
        log.debug('Published config to splunk')

    return filtered_conf

