# -*- encoding: utf-8 -*-
"""
HubbleStack Nebula-to-graylog (http input) returner

Deliver HubbleStack Nebula query data into graylog using the HTTP input
plugin. Required config/pillar settings:

.. code-block:: yaml

hubblestack:
  returner:
    graylog:
      - port: 12202
        proxy: {}
        timeout: 10
        gelfhttp_ssl: True
        sourcetype_nebula: hubble_osquery
        sourcetype_pulsar: hubble_fim
        sourcetype_nova: hubble_audit
        gelfhttp: https://graylog-gelf-http-input-addr

"""



import json
import requests


def returner(ret):
    """
    Aggregates the configuration options related to graylog and returns a dict containing them.
    """
    # sanity check
    if not ret['return']:
        return

    opts_list = _get_options()

    # Get cloud details
    cloud_details = __grains__.get('cloud_details', {})

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

    for opts in opts_list:
        for query in ret['return']:
            for query_name, value in query.items():
                for query_data in value['data']:
                    args = {'query': query_name,
                            'job_id': ret['jid'],
                            'minion_id': ret['id'],
                            'dest_host': fqdn,
                            'dest_ip': fqdn_ip4}
                    event = _generate_event(opts['custom_fields'], args, cloud_details, query_data)

                    payload = {'host': fqdn,
                               '_sourcetype': opts['sourcetype'],
                               'short_message': 'hubblestack',
                               'hubblemsg': event}

                    rdy = json.dumps(payload)
                    requests.post('{}:{}/gelf'.format(opts['gelfhttp'], opts['port']), rdy)
    return


def _generate_event(custom_fields, args, cloud_details, query_data):
    """
    Helper function that builds and returns the event dict
    """
    event = {}
    event.update(query_data)
    event.update(args)
    event.update(cloud_details)

    for custom_field in custom_fields:
        custom_field_name = 'custom_' + custom_field
        custom_field_value = __salt__['config.get'](custom_field, '')
        if isinstance(custom_field_value, list):
            custom_field_value = ','.join(custom_field_value)
        if isinstance(custom_field_value, str):
            event.update({custom_field_name: custom_field_value})

    return event


def _get_options():
    """
    Function that aggregates the configs for graylog and returns them as a list of dicts.
    """
    if __salt__['config.get']('hubblestack:returner:graylog'):
        returner_opts = __salt__['config.get']('hubblestack:returner:graylog')
        if not isinstance(returner_opts, list):
            returner_opts = [returner_opts]
        return [_process_opt(opt) for opt in returner_opts]

    try:
        graylog_opts = {
            'gelfhttp': __salt__['config.get']('hubblestack:returner:graylog:gelfhttp'),
            'sourcetype': __salt__['config.get']('hubblestack:nebula:returner:graylog:sourcetype'),
            'custom_fields': __salt__['config.get'](
                'hubblestack:nebula:returner:graylog:custom_fields', []),
            'port': __salt__['config.get']('hubblestack:returner:graylog:port'),
            'http_input_server_ssl': __salt__['config.get'](
                'hubblestack:nebula:returner:graylog:gelfhttp_ssl', True),
            'proxy': __salt__['config.get']('hubblestack:nebula:returner:graylog:proxy', {}),
            'timeout': __salt__['config.get']('hubblestack:nebula:returner:graylog:timeout', 9.05)
        }

    except Exception:
        return None

    return [graylog_opts]


def _process_opt(opt):
    """
    Helper function that extracts certain fields from the opt dict and assembles the processed dict
    """
    return {'gelfhttp': opt.get('gelfhttp'),
            'port': str(opt.get('port', '12022')),
            'custom_fields': opt.get('custom_fields', []),
            'sourcetype': opt.get('sourcetype_nebula', 'hubble_osquery'),
            'gelfhttp_ssl': opt.get('gelfhttp_ssl', True),
            'proxy': opt.get('proxy', {}),
            'timeout': opt.get('timeout', 9.05)}
