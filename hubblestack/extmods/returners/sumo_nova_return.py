# -*- encoding: utf-8 -*-
"""
HubbleStack Nova-to-sumo (http input) returner

Deliver HubbleStack Nova data into sumo using the HTTP input
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
import socket
import requests


def returner(ret):
    """
    """
    opts_list = _get_options()

    # Get cloud details
    cloud_details = __grains__.get('cloud_details', {})

    for opts in opts_list:
        proxy = opts['proxy']
        timeout = opts['timeout']
        sumo_nova_return = opts['sumo_nova_return']
        data = ret['return']
        minion_id = ret['id']
        jid = ret['jid']
        fqdn = __grains__['fqdn']
        # Sometimes fqdn is blank. If it is, replace it with minion_id
        fqdn = fqdn if fqdn else minion_id
        try:
            fqdn_ip4 = __grains__['fqdn_ip4'][0]
        except IndexError:
            fqdn_ip4 = __grains__['ipv4'][0]
        if fqdn_ip4.startswith('127.'):
            for ip4_addr in __grains__['ipv4']:
                if ip4_addr and not ip4_addr.startswith('127.'):
                    fqdn_ip4 = ip4_addr
                    break

        if not isinstance(data, dict):
            log.error('Data sent to sumo_nova_return was not formed as a '
                      'dict:\n{0}'.format(data))
            return

        for fai in data.get('Failure', []):
            check_id = fai.keys()[0]
            event = {}
            event.update({'check_result': 'Failure'})
            event.update({'check_id': check_id})
            event.update({'job_id': jid})
            if not isinstance(fai[check_id], dict):
                event.update({'description': fai[check_id]})
            elif 'description' in fai[check_id]:
                for key, value in fai[check_id].iteritems():
                    if key not in ['tag']:
                        event[key] = value
            event.update({'minion_id': minion_id})
            event.update({'dest_host': fqdn})
            event.update({'dest_ip': fqdn_ip4})

            event.update(cloud_details)

            rdy = json.dumps(event)
            requests.post('{}/'.format(sumo_nova_return), data=rdy)

        for suc in data.get('Success', []):
            check_id = suc.keys()[0]
            event = {}
            event.update({'check_result': 'Success'})
            event.update({'check_id': check_id})
            event.update({'job_id': jid})
            if not isinstance(suc[check_id], dict):
                event.update({'description': suc[check_id]})
            elif 'description' in suc[check_id]:
                for key, value in suc[check_id].iteritems():
                    if key not in ['tag']:
                        event[key] = value
            event.update({'minion_id': minion_id})
            event.update({'dest_host': fqdn})
            event.update({'dest_ip': fqdn_ip4})

            event.update(cloud_details)

            rdy = json.dumps(event)
            requests.post('{}/'.format(sumo_nova_return), rdy)

        if data.get('Compliance', None):
            event = {}
            event.update({'job_id': jid})
            event.update({'compliance_percentage': data['Compliance']})
            event.update({'minion_id': minion_id})
            event.update({'dest_host': fqdn})
            event.update({'dest_ip': fqdn_ip4})

            event.update(cloud_details)

            rdy = json.dumps(event)
            requests.post('{}/'.format(sumo_nova_return), rdy)

    return


def _get_options():
    if __salt__['config.get']('hubblestack:returner:sumo'):
        sumo_opts = []
        returner_opts = __salt__['config.get']('hubblestack:returner:sumo')
        if not isinstance(returner_opts, list):
            returner_opts = [returner_opts]
        for opt in returner_opts:
            processed = {}
            processed['sumo_nova_return'] = opt.get('sumo_nova_return')
            processed['proxy'] = opt.get('proxy', {})
            processed['timeout'] = opt.get('timeout', 9.05)
            sumo_opts.append(processed)
        return sumo_opts
    else:
        try:
            sumo_nova_return = __salt__['config.get']('hubblestack:returner:sumo:sumo_nova_return')
        except:
            return None

        sumo_opts = {'sumo_nova_return': sumo_nova_return}
        sumo_opts['proxy'] = __salt__['config.get']('hubblestack:nova:returner:sumo:proxy', {})
        sumo_opts['timeout'] = __salt__['config.get']('hubblestack:nova:returner:sumo:timeout', 9.05)

        return [sumo_opts]
