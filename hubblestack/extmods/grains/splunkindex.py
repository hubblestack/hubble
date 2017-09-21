# -*- coding: utf-8 -*-

import salt.modules.config

salt.modules.config.__pillar__ = {}
salt.modules.config.__grains__ = {}

__salt__ = {'config.get': salt.modules.config.get}


def splunkindex():
    '''
    Return splunk index from config file in grain
    '''
    # Provides:
    #   splunkindex
    salt.modules.config.__opts__ = __opts__
    grains = {}
    index = __salt__['config.get']('hubblestack:returner:splunk:index', default='unknown')
    grains['splunkindex'] = index
    return grains
