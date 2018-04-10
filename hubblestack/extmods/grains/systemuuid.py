# -*- coding: utf-8 -*-
'''
Gather the system uuid via osquery
'''
import salt.utils.path
import salt.modules.cmdmod

__salt__ = {'cmd.run': salt.modules.cmdmod._run_quiet}


def get_system_uuid():
    '''
    Gather the system uuid via osquery
    '''
    # Provides:
    #   system_uuid

    options = '"SELECT uuid AS system_uuid FROM osquery_info;" --header=false --csv'

    # Prefer our /opt/osquery/osqueryi if present
    osqueryipaths = ('/opt/osquery/osqueryi', 'osqueryi', '/usr/bin/osqueryi')
    for path in osqueryipaths:
        if salt.utils.path.which(path):
            out = __salt__['cmd.run']('{0} {1}'.format(path, options))
            grains = {"system_uuid": str(out)}
            break
    return grains
