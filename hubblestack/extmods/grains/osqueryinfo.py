# -*- coding: utf-8 -*-

import salt.utils

__salt__ = { 'cmd.run': salt.modules.cmdmod._run_quiet }

def osquerygrain():
    '''
    Return osquery version in grain
    '''
    # Provides:
    #   osqueryversion
    #   osquerybinpath
    grains = {}
    option = '--version'

    osqueryipaths = ('osqueryi', '/usr/bin/osqueryi', '/opt/osquery/osqueryi')
    for path in osqueryipaths:
        if salt.utils.which(path):
            for item in __salt__['cmd.run']('{0} {1}'.format(path, option)).split():
                if item[:1].isdigit():
                    grains['osqueryversion'] = item
                    grains['osquerybinpath'] = path
                    break
            break
    return grains
