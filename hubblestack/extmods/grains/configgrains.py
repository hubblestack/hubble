# -*- coding: utf-8 -*-
'''
Custom config-defined grains module

:maintainer: HubbleStack
:platform: All
:requires: SaltStack

Allow users to collect a list of config directives and set them as custom grains.
The list should be defined under the `hubblestack` key.

The `grains` value should be a list of dictionaries. Each dictionary should have
a single key which will be set as the grain name. The dictionary's value will
be the grain's value.

hubblestack:
  grains:
    - splunkindex: "hubblestack:returner:splunk:index"
  returner:
    splunk:
      - token: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
        indexer: splunk-indexer.domain.tld
        index: hubble
        sourcetype_nova: hubble_audit
'''

import salt.modules.config

salt.modules.config.__pillar__ = {}
salt.modules.config.__grains__ = {}

__salt__ = {'config.get': salt.modules.config.get}


def configgrains():
    '''
    Given a list of config values, create custom grains with custom names.
    The list comes from config.

    Example:
    hubblestack:
      grains:
        - splunkindex: "hubblestack:returner:splunk:index"
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
