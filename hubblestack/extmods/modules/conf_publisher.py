# -*- coding: utf-8 -*-
'''
Module to send config options to splunk
'''
import logging
import hubblestack.splunklogging
import copy
import time

log = logging.getLogger(__name__)


def publish(*args):

    '''
    Publishes config to splunk at an interval defined in schedule

    *args
       Tuple of opts to log (keys in __opts__). Only those key-value pairs would be published, keys for which are in *args
       If not passed, entire __opts__ (excluding password/token) would be published

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

    hubblestack.splunklogging.__grains__ = __grains__
    hubblestack.splunklogging.__salt__ = __salt__
    hubblestack.splunklogging.__opts__ = __opts__

    filtered_conf = _filter_config(opts_to_log)

    class MockRecord(object):
            def __init__(self, message, levelname, asctime, name):
                self.message = message
                self.levelname = levelname
                self.asctime = asctime
                self.name = name

    handler = hubblestack.splunklogging.SplunkHandler()
    handler.emit(MockRecord(filtered_conf, 'INFO', time.asctime(), 'hubblestack.hubble_config'))
    log.debug('Published config to splunk')


def _filter_config(opts_to_log):
    '''
    Filters out keys containing certain patterns to avoid sensitive information being sent to splunk
    '''
    patterns_to_filter = ["password", "token", "passphrase", "privkey", "keyid", "key"]
    if isinstance(opts_to_log, dict):
         opts_to_log = {
             key: remove_sensitive_info(value, patterns_to_filter)
             for key, value in opts_to_log.iteritems()
             if not any(patt in key for patt in patterns_to_filter)}
    elif isinstance(opts_to_log, list):
         opts_to_log = [remove_sensitive_info(item, patterns_to_filter)
                    for item in opts_to_log]
    return opts_to_log
