# -*- coding: utf-8 -*-
""" Handle metadata about osquery: return version and path as grains """

import salt.utils
import hubblestack.utils.path
import hubblestack.modules.cmdmod

__salt__ = {'cmd.run': hubblestack.modules.cmdmod._run_quiet}


def osquerygrain():
    """
    Return osquery version in grain
    """
    # Provides:
    #   osqueryversion
    #   osquerybinpath
    grains = {}
    option = '--version'

    # Prefer our /opt/osquery/osqueryi if present
    osqueryipaths = ('/opt/osquery/osqueryi', 'osqueryi', '/usr/bin/osqueryi')
    for path in osqueryipaths:
        if hubblestack.utils.path.which(path):
            for item in __salt__['cmd.run']('{0} {1}'.format(path, option)).split():
                if item[:1].isdigit():
                    grains['osqueryversion'] = item
                    grains['osquerybinpath'] = hubblestack.utils.path.which(path)
                    break
            break
    return grains
