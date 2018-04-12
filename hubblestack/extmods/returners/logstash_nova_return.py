# -*- encoding: utf-8 -*-
'''
HubbleStack Nova-to-Logstash (http input) returner

:maintainer: HubbleStack
:platform: All
:requires: HubbleStack

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
'''

import json
import socket
import requests
from requests.auth import HTTPBasicAuth


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

        indexer = opts['indexer']
        port = opts['port']
        password = opts['password']
        user = opts['user']

        data = ret['return']
        minion_id = ret['id']
        jid = ret['jid']
        fqdn = __grains__['fqdn']
        # Sometimes fqdn is blank. If it is, replace it with minion_id
        fqdn = fqdn if fqdn else minion_id
        master = __grains__['master']
        try:
            fqdn_ip4 = __grains__['fqdn_ip4'][0]
        except IndexError:
            fqdn_ip4 = __grains__['ipv4'][0]
        if fqdn_ip4.startswith('127.'):
            for ip4_addr in __grains__['ipv4']:
                if ip4_addr and not ip4_addr.startswith('127.'):
                    fqdn_ip4 = ip4_addr
                    break

        if __grains__['master']:
            master = __grains__['master']
        else:
            master = socket.gethostname()  # We *are* the master, so use our hostname

        if not isinstance(data, dict):
            log.error('Data sent to splunk_nova_return was not formed as a '
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
            payload.update({'index': opts['index']})
            payload.update({'sourcetype': opts['sourcetype']})
            payload.update({'event': event})

            rdy = json.dumps(payload)
            requests.post('{}:{}/hubble/nova'.format(indexer, port), rdy, auth=HTTPBasicAuth(user, password))

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
            payload.update({'index': opts['index']})
            payload.update({'sourcetype': opts['sourcetype']})
            payload.update({'event': event})

            rdy = json.dumps(payload)
            requests.post('{}:{}/hubble/nova'.format(indexer, port), rdy, auth=HTTPBasicAuth(user, password))

        if data.get('Compliance', None):
            payload = {}
            event = {}
            event.update({'job_id': jid})
            event.update({'compliance_percentage': data['Compliance']})
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
            payload.update({'index': opts['index']})
            payload.update({'sourcetype': opts['sourcetype']})
            payload.update({'event': event})

            rdy = json.dumps(payload)
            requests.post('{}:{}/hubble/nova'.format(indexer, port), rdy, auth=HTTPBasicAuth(user, password))

    return


def _get_options():
    if __salt__['config.get']('hubblestack:returner:logstash'):
        logstash_opts = []
        returner_opts = __salt__['config.get']('hubblestack:returner:logstash')
        if not isinstance(returner_opts, list):
            returner_opts = [returner_opts]
        for opt in returner_opts:
            processed = {}
            processed['password'] = opt.get('password')
            processed['user'] = opt.get('user')
            processed['indexer'] = opt.get('indexer')
            processed['port'] = str(opt.get('port', '8080'))
            processed['index'] = opt.get('index')
            processed['custom_fields'] = opt.get('custom_fields', [])
            processed['sourcetype'] = opt.get('sourcetype_nova', 'hubble_audit')
            processed['http_input_server_ssl'] = opt.get('indexer_ssl', True)
            processed['proxy'] = opt.get('proxy', {})
            processed['timeout'] = opt.get('timeout', 9.05)
            logstash_opts.append(processed)
        return logstash_opts
    else:
        try:
            port = __salt__['config.get']('hubblestack:returner:logstash:port')
            user = __salt__['config.get']('hubblestack:returner:logstash:user')
            indexer = __salt__['config.get']('hubblestack:returner:logstash:indexer')
            password = __salt__['config.get']('hubblestack:returner:logstash:password')
            sourcetype = __salt__['config.get']('hubblestack:returner:logstash:sourcetype')
            custom_fields = __salt__['config.get']('hubblestack:returner:logstash:custom_fields', [])
        except:
            return None

        logstash_opts = {'password': password, 'indexer': indexer, 'sourcetype': sourcetype, 'index': index, 'custom_fields': custom_fields}

        indexer_ssl = __salt__['config.get']('hubblestack:nova:returner:logstash:indexer_ssl', True)
        logstash_opts['http_input_server_ssl'] = indexer_ssl
        logstash_opts['proxy'] = __salt__['config.get']('hubblestack:nova:returner:logstash:proxy', {})
        logstash_opts['timeout'] = __salt__['config.get']('hubblestack:nova:returner:logstash:timeout', 9.05)

        return [logstash_opts]
