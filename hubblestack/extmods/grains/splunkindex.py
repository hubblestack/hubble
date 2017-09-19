# -*- coding: utf-8 -*-

import salt.modules.config

__salt__ = {'config.get': salt.modules.config.get}


def splunkindex():
    '''
    Return splunk index from config file in grain
    '''
    # Provides:
    #   splunkindex
    grains = {}
    index = __salt__['config.get']('hubblestack:returner:splunk:index', default='unknown')
    grains['splunkindex'] = index
    return grains
