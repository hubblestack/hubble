# -*- coding: utf-8 -*-

import salt.modules.config

salt.modules.config.__pillar__ = {}
salt.modules.config.__grains__ = {}

__salt__ = {'config.get': salt.modules.config.get}


def configgrains():
    '''
    Given a list of config values, create custom grains with custom names.
    The list comes from config.
    '''
    grains = {}
    salt.modules.config.__opts__ = __opts__

    grains_to_make = __salt__['config.get']('hubblestack:grains', default=[])
    for grain in grains_to_make:
        for k, v in grain.iteritems():
            grain_value = __salt__['config.get'](v, default=None)
            if grain_value:
                grains[k] = grain_value
    return grains
 