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
        custom_fields = opts['custom_fields']

        gelfhttp = opts['gelfhttp']
        port = opts['port']
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
            log.error('Data sent to graylog_nova_return was not formed as a '
                      'dict:\n{0}'.format(data))
            return

        for fai in data.get('Failure', []):
            check_id = fai.keys()[0]
            payload = {}
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

            for custom_field in custom_fields:
                custom_field_name = 'custom_' + custom_field
                custom_field_value = __salt__['config.get'](custom_field, '')
                if isinstance(custom_field_value, str):
                    event.update({custom_field_name: custom_field_value})
                elif isinstance(custom_field_value, list):
                    custom_field_value = ','.join(custom_field_value)
                    event.update({custom_field_name: custom_field_value})

            payload.update({'host': fqdn})
            payload.update({'_sourcetype': opts['sourcetype']})
            payload.update({'short_message': 'hubblestack'})
            payload.update({'hubblemsg': event})

            rdy = json.dumps(payload)
            requests.post('{}:{}/gelf'.format(gelfhttp, port), rdy)

        for suc in data.get('Success', []):
            check_id = suc.keys()[0]
            payload = {}
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

            for custom_field in custom_fields:
                custom_field_name = 'custom_' + custom_field
                custom_field_value = __salt__['config.get'](custom_field, '')
                if isinstance(custom_field_value, str):
                    event.update({custom_field_name: custom_field_value})
                elif isinstance(custom_field_value, list):
                    custom_field_value = ','.join(custom_field_value)
                    event.update({custom_field_name: custom_field_value})

            payload.update({'host': fqdn})
            payload.update({'_sourcetype': opts['sourcetype']})
            payload.update({'short_message': 'hubblestack'})
            payload.update({'hubblemsg': event})

            rdy = json.dumps(payload)
            requests.post('{}:{}/gelf'.format(gelfhttp, port), rdy)

        if data.get('Compliance', None):
            payload = {}
            event = {}
            event.update({'job_id': jid})
            event.update({'compliance_percentage': data['Compliance']})
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
            payload.update({'_sourcetype': opts['sourcetype']})
            payload.update({'short_message': 'hubblestack'})
            payload.update({'hubblemsg': event})

            rdy = json.dumps(payload)
            requests.post('{}:{}/gelf'.format(gelfhttp, port), rdy)

    return


def _get_options():
    if __salt__['config.get']('hubblestack:returner:graylog'):
        graylog_opts = []
        returner_opts = __salt__['config.get']('hubblestack:returner:graylog')
        if not isinstance(returner_opts, list):
            returner_opts = [returner_opts]
        for opt in returner_opts:
            processed = {}
            processed['gelfhttp'] = opt.get('gelfhttp')
            processed['port'] = str(opt.get('port', '12201'))
            processed['custom_fields'] = opt.get('custom_fields', [])
            processed['sourcetype'] = opt.get('sourcetype_nova', 'hubble_audit')
            processed['http_input_server_ssl'] = opt.get('gelfhttp_ssl', True)
            processed['proxy'] = opt.get('proxy', {})
            processed['timeout'] = opt.get('timeout', 9.05)
            graylog_opts.append(processed)
        return graylog_opts
    else:
        try:
            port = __salt__['config.get']('hubblestack:returner:graylog:port')
            user = __salt__['config.get']('hubblestack:returner:graylog:user')
            gelfhttp = __salt__['config.get']('hubblestack:returner:graylog:gelfhttp')
            sourcetype = __salt__['config.get']('hubblestack:returner:graylog:sourcetype')
            custom_fields = __salt__['config.get']('hubblestack:returner:graylog:custom_fields', [])
        except:
            return None

        graylog_opts = {'gelfhttp': gelfhttp, 'sourcetype': sourcetype, 'custom_fields': custom_fields}

        gelfhttp_ssl = __salt__['config.get']('hubblestack:nova:returner:graylog:gelfhttp_ssl', True)
        graylog_opts['http_input_server_ssl'] = gelfhttp_ssl
        graylog_opts['proxy'] = __salt__['config.get']('hubblestack:nova:returner:graylog:proxy', {})
        graylog_opts['timeout'] = __salt__['config.get']('hubblestack:nova:returner:graylog:timeout', 9.05)

        return [graylog_opts]
