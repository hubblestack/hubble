# -*- coding: utf-8 -*-
'''
Gather the system uuid via osquery
'''
import os
import salt.utils.path
import salt.modules.cmdmod

__salt__ = {'cmd.run': salt.modules.cmdmod._run_quiet}


def get_system_uuid():
    '''
    Gather the system uuid via osquery

    If osquery can't get a hardware-based value, it'll just randomly generate a new uuid every time.
    If that happens, fall back to the hubble_uuid.
    '''
    # Provides:
    #   system_uuid

    options = '"SELECT uuid AS system_uuid FROM osquery_info;" --header=false --csv'

    # Prefer our /opt/osquery/osqueryi if present
    osqueryipaths = ('/opt/osquery/osqueryi', 'osqueryi', '/usr/bin/osqueryi')
    grains = {}
    for path in osqueryipaths:
        if salt.utils.path.which(path):
            first_run = __salt__['cmd.run']('{0} {1}'.format(path, options))
            first_run = str(first_run).upper()

            second_run = __salt__['cmd.run']('{0} {1}'.format(path, options))
            second_run = str(second_run).upper()

            if len(first_run) == 36 and first_run == second_run:
                grains = {"system_uuid": first_run}
            else:
                existing_uuid = __opts__.get('hubble_uuid', None)
                if existing_uuid:
                    {"system_uuid": existing_uuid}
            break
    return grains
