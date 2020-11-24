# -*- coding: utf-8 -*-
"""
Module to send config options to splunk
"""
import logging
import copy
import hubblestack.log
from hubblestack.hec import get_splunk_options as gso

log = logging.getLogger(__name__)


def get_splunk_options(**kwargs):
    if not kwargs:
        kwargs['sourcetype'] = 'hubble_osquery'
    if '_nick' not in kwargs or not isinstance(kwargs['_nick'], dict):
        kwargs['_nick'] = {'sourcetype_nebula': 'sourcetype'}
    return gso(**kwargs)


def publish(report_directly_to_splunk=True, remove_dots=True, *args):
    """
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

    """
    log.debug('Started publishing config to splunk')

    opts_to_log = {}
    if not args:
        opts_to_log = copy.deepcopy(__opts__)
        if 'grains' in opts_to_log:
            opts_to_log.pop('grains')
    else:
        for arg in args:
            if arg in __opts__:
                opts_to_log[arg] = __opts__[arg]

    filtered_conf = hubblestack.log.filter_logs(opts_to_log, remove_dots=remove_dots)

    if report_directly_to_splunk:
        hubblestack.log.emit_to_splunk(filtered_conf, 'INFO', 'hubblestack.hubble_config')
        log.debug('Published config to splunk')

    return filtered_conf


def _filter_config(opts_to_log, remove_dots=True):
    """
    Filters out keys containing certain patterns to avoid sensitive information being sent to splunk
    """
    patterns_to_filter = ["password", "token", "passphrase", "privkey", "keyid", "s3.key"]
    filtered_conf = _remove_sensitive_info(opts_to_log, patterns_to_filter)
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
        obj = [_remove_sensitive_info(item, patterns_to_filter) for item in obj]
    return obj
