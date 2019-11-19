# -*- encoding: utf-8 -*-
"""
HubbleStack Nova-to-Logstash (http input) returner

Deliver HubbleStack Nova data into Logstash using the HTTP input
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
            sourcetype_nova: hubble_audit
            indexer: http://logstash.http.input.tld
            password: password
            custom_fields:
              - site
              - product_group
"""

import json
import logging
import requests
from requests.auth import HTTPBasicAuth

log = logging.getLogger(__name__)


def returner(ret):
    """
    Gather data for nova and post it to logstash according to the config
    """
    data = ret['return']
    if not isinstance(data, dict):
        log.error('Data sent to splunk_nova_return was not formed as a dict:\n%s', data)
        return

    opts_list = _get_options()
    args = _build_args(ret)
    # Get cloud details
    cloud_details = __grains__.get('cloud_details', {})

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
            event = _generate_event(args=args, cloud_details=cloud_details, compliance=True,
                                    custom_fields=opts['custom_fields'])
            _publish_event(opts=opts, fqdn=args['fqdn'], event=event)

    return


def _get_options():
    """
    Function that aggregates the configs for logstash and returns them as a list of dicts.
    """
    if __salt__['config.get']('hubblestack:returner:logstash'):
        returner_opts = __salt__['config.get']('hubblestack:returner:logstash')
        if not isinstance(returner_opts, list):
            returner_opts = [returner_opts]
        return [_process_opt(opt) for opt in returner_opts]
    try:
        logstash_opts = {
            'password': __salt__['config.get']('hubblestack:returner:logstash:password'),
            'indexer': __salt__['config.get']('hubblestack:returner:logstash:indexer'),
            'sourcetype': __salt__['config.get']('hubblestack:returner:logstash:sourcetype'),
            'user': __salt__['config.get']('hubblestack:returner:logstash:user'),
            'port': __salt__['config.get']('hubblestack:returner:logstash:port'),
            'custom_fields': __salt__['config.get'](
                'hubblestack:returner:logstash:custom_fields', []),
            'http_input_server_ssl': __salt__['config.get'](
                'hubblestack:nova:returner:logstash:indexer_ssl', True),
            'proxy': __salt__['config.get']('hubblestack:nova:returner:logstash:proxy', {}),
            'timeout': __salt__['config.get']('hubblestack:nova:returner:logstash:timeout',
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
            'sourcetype': opt.get('sourcetype_nova', 'hubble_audit'),
            'http_input_server_ssl': opt.get('indexer_ssl', True),
            'proxy': opt.get('proxy', {}),
            'timeout': opt.get('timeout', 9.05)}


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


def _generate_event(args, cloud_details, custom_fields, compliance=False, data=None):
    """
    Helper function that builds and returns the event dict
    """
    event = {'job_id': args['job_id']}
    if not compliance:
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


def _publish_data(args, checks, check_result, cloud_details, opts):
    """
    Helper function that goes over the failure/success checks and publishes the event to logstash
    """
    for data in checks:
        check_id = list(data.keys())[0]
        args['check_result'] = check_result
        args['check_id'] = check_id
        event = _generate_event(custom_fields=opts['custom_fields'], data=data, args=args,
                                cloud_details=cloud_details)
        _publish_event(opts, args['fqdn'], event)


def _publish_event(opts, fqdn, event):
    """
    Helper function that builds the payload and publishes it to logstash using POST
    """
    payload = {'host': fqdn,
               'index': opts['index'],
               'sourcetype': opts['sourcetype'],
               'event': event}

    rdy = json.dumps(payload)
    requests.post('{}:{}/hubble/nova'.format(opts['indexer'], opts['port']), rdy,
                  auth=HTTPBasicAuth(opts['user'], opts['password']))
