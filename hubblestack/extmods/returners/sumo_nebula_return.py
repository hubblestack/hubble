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
import logging
import requests

log = logging.getLogger(__name__)


def returner(ret):
    """
    Get nebula data and send it to sumo
    """
    # assign all the things
    data = ret['return']
    if not data:
        return
    args = _build_args(ret)
    opts_list = _get_options()
    # Get cloud details
    cloud_details = __grains__.get('cloud_details', {})

    for opts in opts_list:
        sumo_nebula_return = opts['sumo_nebula_return']
        for query in data:
            for query_name, query_results in query.items():
                if 'data' not in query_results:
                    query_results['data'] = [{'error': 'result missing'}]
                for query_result in query_results['data']:
                    event = {}
                    event.update(query_result)
                    event.update({'query': query_name,
                                  'job_id': args['job_id'],
                                  'minion_id': args['minion_id'],
                                  'dest_host': args['fqdn'],
                                  'dest_ip': args['fqdn_ip4'],
                                  'dest_fqdn': args['local_fqdn'],
                                  'system_uuid': __grains__.get('system_uuid')})
                    event.update(cloud_details)
                    try:
                        rdy = json.dumps(event)
                        requests.post('{}/'.format(sumo_nebula_return), rdy)
                    except Exception:
                        log.error('Hit an exception trying to send to sumo! continuing')
                        continue
    return


def _get_options():
    """
    Function that aggregates the configs for sumo and returns them as a list of dicts.
    """
    if __salt__['config.get']('hubblestack:returner:sumo'):
        sumo_opts = []
        returner_opts = __salt__['config.get']('hubblestack:returner:sumo')
        if not isinstance(returner_opts, list):
            returner_opts = [returner_opts]
        for opt in returner_opts:
            processed = {'sumo_nebula_return': opt.get('sumo_nebula_return'),
                         'proxy': opt.get('proxy', {}),
                         'timeout': opt.get('timeout', 9.05)}
            sumo_opts.append(processed)
        return sumo_opts
    try:
        sumo_nebula_return = __salt__['config.get']('hubblestack:returner:sumo:sumo_nebula_return')
    except Exception:
        return None

    sumo_opts = {'sumo_nebula_return': sumo_nebula_return,
                 'proxy': __salt__['config.get']('hubblestack:nebula:returner:sumo:proxy', {}),
                 'timeout': __salt__['config.get']('hubblestack:nebula:returner:sumo:timeout',
                                                   9.05)}

    return [sumo_opts]


def _build_args(ret):
    """
    Helper function that builds the args that will be passed on to the event - cleaner way of
    processing the variables we care about
    """
    fqdn = __grains__['fqdn'] if __grains__['fqdn'] else ret['id']
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

    return {'minion_id': ret['id'],
            'job_id': ret['jid'],
            'fqdn': fqdn,
            'local_fqdn': local_fqdn,
            'fqdn_ip4': fqdn_ip4}
