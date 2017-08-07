# -*- coding: utf-8 -*-

import salt.utils
import salt.modules.cmdmod

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

    # Prefer our /opt/osquery/osqueryi if present
    osqueryipaths = ('/opt/osquery/osqueryi', 'osqueryi', '/usr/bin/osqueryi')
    for path in osqueryipaths:
        if salt.utils.which(path):
            for item in __salt__['cmd.run']('{0} {1}'.format(path, option)).split():
                if item[:1].isdigit():
                    grains['osqueryversion'] = item
                    grains['osquerybinpath'] = salt.utils.which(path)
                    break
            break
    return grains
