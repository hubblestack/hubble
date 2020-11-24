# -*- encoding: utf-8 -*-
"""
HubbleStack Nebula-to-Logstash (http input) returner

Deliver HubbleStack Nebula query data into Logstash using the HTTP input
plugin. Required config/pillar settings:

.. code-block:: yaml

    hubblestack:
      returner:
        logstash:
          - port: 8080
            proxy: {}
            timeout: 10
            user: username
            indexer_ssl: True
            sourcetype_nebula: hubble_osquery
            indexer: http://logstash.http.input.tld
            password: password
            custom_fields:
              - site
              - product_group
"""

import json
import requests
from requests.auth import HTTPBasicAuth


def returner(ret):
    """
    Gather data for nebula and post it to logstash according to the config
    """
    opts_list = _get_options()

    if not ret['return']:
        return

    # Get cloud details
    cloud_details = __grains__.get('cloud_details', {})

    for opts in opts_list:
        # assign all the things
        fqdn = __grains__['fqdn'] if __grains__['fqdn'] else ret['id']
        try:
            fqdn_ip4 = __grains__['fqdn_ip4'][0]
        except IndexError:
            fqdn_ip4 = __grains__['ipv4'][0]
        if fqdn_ip4.startswith('127.'):
            for ip4_addr in __grains__['ipv4']:
                if ip4_addr and not ip4_addr.startswith('127.'):
                    fqdn_ip4 = ip4_addr
                    break

        for query in ret['return']:
            for query_name, query_results in query.items():
                for query_result in query_results['data']:
                    args = {'query': query_name,
                            'job_id': ret['jid'],
                            'minion_id': ret['id'],
                            'dest_host': fqdn,
                            'dest_ip': fqdn_ip4}
                    event = _generate_event(custom_fields=opts['custom_fields'], args=args,
                                            cloud_details=cloud_details,
                                            query_result=query_result)

                    payload = {'host': fqdn,
                               'index': opts['index'],
                               'sourcetype': opts['sourcetype'],
                               'event': event}

                    rdy = json.dumps(payload)
                    requests.post('{}:{}/hubble/nebula'.format(opts['indexer'], opts['port']), rdy,
                                  auth=HTTPBasicAuth(opts['user'], opts['password']))
    return


def _get_options():
    if __salt__['config.get']('hubblestack:returner:logstash'):
        returner_opts = __salt__['config.get']('hubblestack:returner:logstash')
        if not isinstance(returner_opts, list):
            returner_opts = [returner_opts]
        return [_process_opt(opt) for opt in returner_opts]
    try:
        logstash_opts = {
            'password': __salt__['config.get']('hubblestack:returner:logstash:password'),
            'indexer': __salt__['config.get']('hubblestack:returner:logstash:indexer'),
            'sourcetype': __salt__['config.get'](
                'hubblestack:nebula:returner:logstash:sourcetype'),
            'custom_fields': __salt__['config.get'](
                'hubblestack:nebula:returner:logstash:custom_fields', []),
            'port': __salt__['config.get']('hubblestack:returner:logstash:port'),
            'user': __salt__['config.get']('hubblestack:returner:logstash:user'),
            'http_input_server_ssl': __salt__['config.get'](
                'hubblestack:nebula:returner:logstash:indexer_ssl', True),
            'proxy': __salt__['config.get']('hubblestack:nebula:returner:logstash:proxy', {}),
            'timeout': __salt__['config.get']('hubblestack:nebula:returner:logstash:timeout',
                                              9.05)}
    except Exception:
        return None

    return [logstash_opts]


def _process_opt(opt):
    """
    Helper function that extracts certain fields from the opt dict and assembles the processed dict
    """
    return {'password': opt.get('password'),
            'user': opt.get('user'),
            'indexer': opt.get('indexer'),
            'port': str(opt.get('port', '8080')),
            'index': opt.get('index'),
            'custom_fields': opt.get('custom_fields', []),
            'sourcetype': opt.get('sourcetype_nebula', 'hubble_osquery'),
            'indexer_ssl': opt.get('indexer_ssl', True),
            'proxy': opt.get('proxy', {}),
            'timeout': opt.get('timeout', 9.05)}


def _generate_event(custom_fields, args, cloud_details, query_result):
    """
    Helper function that builds and returns the event dict
    """
    event = {}
    event.update(query_result)
    event.update(args)
    event.update(cloud_details)

    for custom_field in custom_fields:
        custom_field_name = 'custom_' + custom_field
        custom_field_value = __salt__['config.get'](custom_field, '')
        if isinstance(custom_field_value, str):
            event.update({custom_field_name: custom_field_value})
        elif isinstance(custom_field_value, list):
            custom_field_value = ','.join(custom_field_value)
            event.update({custom_field_name: custom_field_value})

    return event
