# -*- encoding: utf-8 -*-
"""
HubbleStack Nebula-to-sumo (http input) returner

Deliver HubbleStack Nebula query data into sumo using the HTTP input
plugin. Required config/pillar settings:

.. code-block:: yaml

hubblestack:
  returner:
    sumo:
      - proxy: {}
        timeout: 10
        sumo_nebula_return: https://yoursumo.sumologic.com/endpointhere
        sumo_pulsar_return: https://yoursumo.sumologic.com/endpointhere
        sumo_nova_return: https://yoursumo.sumologic.com/endpointhere

"""

import json
import time
import requests
from datetime import datetime


def returner(ret):
    """
    """
    opts_list = _get_options()

    # Get cloud details
    cloud_details = __grains__.get('cloud_details', {})

    for opts in opts_list:
        proxy = opts['proxy']
        timeout = opts['timeout']
        sumo_nebula_return = opts['sumo_nebula_return']
        # assign all the things
        data = ret['return']
        minion_id = ret['id']
        jid = ret['jid']
        fqdn = __grains__['fqdn']
        fqdn = fqdn if fqdn else minion_id
        local_fqdn = __grains__.get('local_fqdn', __grains__['fqdn'])
        try:
            fqdn_ip4 = __grains__['fqdn_ip4'][0]
        except IndexError:
            fqdn_ip4 = __grains__['ipv4'][0]
        if fqdn_ip4.startswith('127.'):
            for ip4_addr in __grains__['ipv4']:
                if ip4_addr and not ip4_addr.startswith('127.'):
                    fqdn_ip4 = ip4_addr
                    break

        if not data:
            return
        else:
            for query in data:
                for query_name, query_results in query.iteritems():
                    if 'data' not in query_results:
                        query_results['data'] = [{'error': 'result missing'}]
                    for query_result in query_results['data']:
                        event = {}
                        event.update(query_result)
                        event.update({'query': query_name})
                        event.update({'job_id': jid})
                        event.update({'minion_id': minion_id})
                        event.update({'dest_host': fqdn})
                        event.update({'dest_ip': fqdn_ip4})
                        event.update({'dest_fqdn': local_fqdn})
                        event.update({'system_uuid': __grains__.get('system_uuid')})

                        event.update(cloud_details)
                        try:
                            rdy = json.dumps(event)
                            requests.post('{}/'.format(sumo_nebula_return), rdy)
                        except:
                            print('Hit an exception trying to send to sumo! continuing')
                            continue
    return


def _get_options():
    if __salt__['config.get']('hubblestack:returner:sumo'):
        sumo_opts = []
        returner_opts = __salt__['config.get']('hubblestack:returner:sumo')
        if not isinstance(returner_opts, list):
            returner_opts = [returner_opts]
        for opt in returner_opts:
            processed = {}
            processed['sumo_nebula_return'] = opt.get('sumo_nebula_return')
            processed['proxy'] = opt.get('proxy', {})
            processed['timeout'] = opt.get('timeout', 9.05)
            sumo_opts.append(processed)
        return sumo_opts
    else:
        try:
            sumo_nebula_return = __salt__['config.get']('hubblestack:returner:sumo:sumo_nebula_return')
        except:
            return None

        sumo_opts = {'sumo_nebula_return': sumo_nebula_return}
        sumo_opts['proxy'] = __salt__['config.get']('hubblestack:nebula:returner:sumo:proxy', {})
        sumo_opts['timeout'] = __salt__['config.get']('hubblestack:nebula:returner:sumo:timeout', 9.05)

        return [sumo_opts]
