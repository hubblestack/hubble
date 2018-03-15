
import logging
import hubblestack.splunklogging
import copy
import time

log = logging.getLogger(__name__)

def publish():
    log.info('Started publishing config to splunk')
    
    initialize_splunklogging()
    filtered_conf=filter_config()
    class MockRecord(object):
            def __init__(self, message, levelname, asctime, name):
                self.message = message
                self.levelname = levelname
                self.asctime = asctime
                self.name = name

    handler = hubblestack.splunklogging.SplunkHandler()
    handler.emit(MockRecord(filtered_conf, 'INFO', time.asctime(), 'hubblestack.hubble_config'))
    log.info('Published config to splunk')	

def initialize_splunklogging():
    hubblestack.splunklogging.__grains__ = __grains__
    hubblestack.splunklogging.__salt__ = __salt__

#Filter out keys containing certain patterns to avoid sensitive information being sent to splunk
def filter_config():
    opts_copy = copy.deepcopy(__opts__)
    patterns_to_filter = ["password", "token"]
    filtered_conf = remove_sensitive_info(opts_copy, patterns_to_filter)
    return filtered_conf

#Recursively removes key value pairs where key contains any of patterns_to_filter
def remove_sensitive_info(obj, patterns_to_filter):
    if isinstance(obj, dict):
         obj = {
             key: remove_sensitive_info(value, patterns_to_filter)
             for key, value in obj.iteritems()
             if not any(patt in key for patt in patterns_to_filter)}
    elif isinstance(obj, list):
         obj = [remove_sensitive_info(item, patterns_to_filter)
                    for item in obj]
    return obj
