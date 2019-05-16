# -*- encoding: utf-8 -*-
'''
HubbleStack Nebula-to-sumo (http input) returner

Deliver HubbleStack Nebula query data into sumo using the HTTP input
plugin. Required config/pillar settings:

.. code-block:: yaml

hubblestack:
  returner:
    sumo:
      - port: 12202
        proxy: {}
        timeout: 10
        sourcecategory_nebula: hubble_osquery
        sourcecategory_pulsar: hubble_fim
        sourcecategory_nova: hubble_audit
        sumo_collector: https://sumo-gelf-http-input-addr

'''

import json
import time
import requests
from datetime import datetime


def returner(ret):
    '''
    '''
    opts_list = _get_options()

    # Get cloud details
    cloud_details = __grains__.get('cloud_details', {})

    for opts in opts_list:
        proxy = opts['proxy']
        timeout = opts['timeout']
        custom_fields = opts['custom_fields']

        sumo_collector = opts['sumo_collector']
        port = opts['port']
        # assign all the things
        data = ret['return']
        minion_id = ret['id']
        jid = ret['jid']
        master = __grains__['master']
        fqdn = __grains__['fqdn']
        fqdn = fqdn if fqdn else minion_id
        try:
            fqdn_ip4 = __grains__['fqdn_ip4'][0]
        except sumo_collectorror:
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
                    for query_result in query_results['data']:
                        event = {}
                        payload = {}
                        event.update(query_result)
                        event.update({'query': query_name})
                        event.update({'job_id': jid})
                        event.update({'master': master})
                        event.update({'minion_id': minion_id})
                        event.update({'dest_host': fqdn})
                        event.update({'dest_ip': fqdn_ip4})

                        event.update(cloud_details)

                        for custom_field in custom_fields:
                            custom_field_name = 'custom_' + custom_field
                            custom_field_value = __salt__['config.get'](custom_field, '')
                            if isinstance(custom_field_value, str):
                                event.update({custom_field_name: custom_field_value})
                            elif isinstance(custom_field_value, list):
                                custom_field_value = ','.join(custom_field_value)
                                event.update({custom_field_name: custom_field_value})

                        payload.update({'host': fqdn})
                        payload.update({'_sourcecategory': opts['sourcecategory']})
                        payload.update({'short_message': 'hubblestack'})
                        payload.update({'hubblemsg': event})

                        # If the osquery query includes a field called 'time' it will be checked.
                        # If it's within the last year, it will be used as the eventtime.
                        event_time = query_result.get('time', '')
                        try:
                            if (datetime.fromtimestamp(time.time()) - datetime.fromtimestamp(float(event_time))).days > 365:
                                event_time = ''
                        except:
                            event_time = ''
                        finally:
                            rdy = json.dumps(payload)
                            requests.post('{}/'.format(sumo_collector), rdy)
    return


def _get_options():
    if __salt__['config.get']('hubblestack:returner:sumo'):
        sumo_opts = []
        returner_opts = __salt__['config.get']('hubblestack:returner:sumo')
        if not isinstance(returner_opts, list):
            returner_opts = [returner_opts]
        for opt in returner_opts:
            processed = {}
            processed['sumo_collector'] = opt.get('sumo_collector')
            processed['custom_fields'] = opt.get('custom_fields', [])
            processed['sourcecategory'] = opt.get('sourcecategory_nebula', 'hubble_osquery')
            processed['proxy'] = opt.get('proxy', {})
            processed['timeout'] = opt.get('timeout', 9.05)
            sumo_opts.append(processed)
        return sumo_opts
    else:
        try:
            sumo_collector = __salt__['config.get']('hubblestack:returner:sumo:sumo_collector')
            sourcecategory = __salt__['config.get']('hubblestack:nebula:returner:sumo:sourcecategory')
            custom_fields = __salt__['config.get']('hubblestack:nebula:returner:sumo:custom_fields', [])
        except:
            return None

        sumo_opts = {'sumo_collector': sumo_collector, 'sourcecategory': sourcecategory, 'custom_fields': custom_fields}
        sumo_opts['proxy'] = __salt__['config.get']('hubblestack:nebula:returner:sumo:proxy', {})
        sumo_opts['timeout'] = __salt__['config.get']('hubblestack:nebula:returner:sumo:timeout', 9.05)

        return [sumo_opts]
