# -*- encoding: utf-8 -*-
"""
HubbleStack Nova-to-graylog (http input) returner

Deliver HubbleStack Nova data into graylog using the HTTP input
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
        http_event_collector_ssl_verify: True
        gelfhttp: https://graylog-gelf-http-input-addr

"""

import json
import logging
import requests

log = logging.getLogger(__name__)


def returner(ret):
    """
    Aggregates the configuration options related to graylog and returns a dict containing them.
    """
    data = ret['return']
    # sanity check
    if not isinstance(data, dict):
        log.error('Data sent to graylog_nova_return was not formed as a dict:\n%s', data)
        return

    opts_list = _get_options()

    # Get cloud details
    cloud_details = __grains__.get('cloud_details', {})

    args = _build_args(ret)

    for opts in opts_list:
        # Failure data
        _publish_data(args=args, checks=data.get('Failure', []), check_result='Failure',
                      cloud_details=cloud_details, opts=opts)

        # Success data
        _publish_data(args=args, checks=data.get('Success', []), check_result='Success',
                      cloud_details=cloud_details, opts=opts)

        # Compliance data
        if data.get('Compliance', None):
            args['compliance_percentage'] = data['Compliance']
            event = _generate_event(args=args, cloud_details=cloud_details,
                                    custom_fields=opts['custom_fields'], compliance=True)
            _publish_event(fqdn=args['fqdn'], sourcetype=opts['sourcetype'], event=event,
                           gelfhttp=opts['gelfhttp'], port=opts['port'])

    return


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
            'sourcetype': __salt__['config.get']('hubblestack:returner:graylog:sourcetype'),
            'custom_fields': __salt__['config.get']('hubblestack:returner:graylog:custom_fields',
                                                    []),
            'port': __salt__['config.get']('hubblestack:returner:graylog:port'),
            'user': __salt__['config.get']('hubblestack:returner:graylog:user'),
            'http_input_server_ssl': __salt__['config.get'](
                'hubblestack:nova:returner:graylog:gelfhttp_ssl', True),
            'proxy': __salt__['config.get']('hubblestack:nova:returner:graylog:proxy', {}),
            'timeout': __salt__['config.get']('hubblestack:nova:returner:graylog:timeout', 9.05)}

    except Exception:
        return None
    return [graylog_opts]


def _process_opt(opt):
    """
    Helper function that extracts certain fields from the opt dict and assembles the processed dict
    """
    return {'gelfhttp': opt.get('gelfhttp'),
            'port': str(opt.get('port', '12201')),
            'custom_fields': opt.get('custom_fields', []),
            'sourcetype': opt.get('sourcetype_nova', 'hubble_audit'),
            'http_input_server_ssl': opt.get('gelfhttp_ssl', True),
            'proxy': opt.get('proxy', {}),
            'timeout': opt.get('timeout', 9.05)}


def _generate_event(args, cloud_details, custom_fields, compliance=False, data=None):
    """
    Helper function that builds and returns the event dict
    """
    event = {'job_id': args['job_id']}
    if not compliance:
        # compliance checks don't require all this data
        event.update({'check_result': args['check_result'],
                      'check_id': args['check_id']})
        if not isinstance(data[args['check_id']], dict):
            event.update({'description': data[args['check_id']]})
        elif 'description' in data[args['check_id']]:
            for key, value in data[args['check_id']].items():
                if key not in ['tag']:
                    event[key] = value
    else:
        event['compliance_percentage'] = args['compliance_percentage']
    event.update({'minion_id': args['minion_id'],
                  'dest_host': args['fqdn'],
                  'dest_ip': args['fqdn_ip4']})

    event.update(cloud_details)

    for custom_field in custom_fields:
        custom_field_name = 'custom_' + custom_field
        custom_field_value = __salt__['config.get'](custom_field, '')
        if isinstance(custom_field_value, list):
            custom_field_value = ','.join(custom_field_value)
        if isinstance(custom_field_value, str):
            event.update({custom_field_name: custom_field_value})

    return event


def _publish_event(fqdn, sourcetype, event, gelfhttp, port):
    """
    Helper function that builds the payload and publishes it to graylog using POST
    """
    payload = {'host': fqdn,
               '_sourcetype': sourcetype,
               'short_message': 'hubblestack',
               'hubblemsg': event}

    rdy = json.dumps(payload)
    requests.post('{}:{}/gelf'.format(gelfhttp, port), rdy)


def _build_args(ret):
    """
    Helper function that builds the args that will be passed on to the event - cleaner way of
    processing the variables we care about
    """
    # Sometimes fqdn is blank. If it is, replace it with minion_id
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

    return {'job_id': ret['jid'],
            'minion_id': ret['id'],
            'fqdn': fqdn,
            'fqdn_ip4': fqdn_ip4}


def _publish_data(args, checks, check_result, cloud_details, opts):
    """
    Helper function that goes over the failure/success checks and publishes the event to the
    graylog server
    """
    for data in checks:
        check_id = list(data.keys())[0]
        args['check_result'] = check_result
        args['check_id'] = check_id
        event = _generate_event(data=data, args=args, cloud_details=cloud_details,
                                custom_fields=opts['custom_fields'])
        _publish_event(fqdn=args['fqdn'], sourcetype=opts['sourcetype'], event=event,
                       gelfhttp=opts['gelfhttp'], port=opts['port'])
