# -*- encoding: utf-8 -*-
'''
HubbleStack Nebula-to-Logstash (http input) returner

:maintainer: HubbleStack
:platform: All
:requires: HubbleStack

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
'''

import json
import time
import socket
import requests
from datetime import datetime
from aws_details import get_aws_details
from requests.auth import HTTPBasicAuth


def returner(ret):
    '''
    '''
    opts_list = _get_options()

    aws = get_aws_details()

    for opts in opts_list:
        proxy = opts['proxy']
        timeout = opts['timeout']
        custom_fields = opts['custom_fields']

        indexer = opts['indexer']
        port = opts['port']
        password = opts['password']
        user = opts['user']

        ## assign all the things
        data = ret['return']
        minion_id = ret['id']
        jid = ret['jid']
        master = __grains__['master']
        fqdn = __grains__['fqdn']
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

                        if aws['aws_account_id'] is not None:
                            event.update({'aws_ami_id': aws['aws_ami_id']})
                            event.update({'aws_instance_id': aws['aws_instance_id']})
                            event.update({'aws_account_id': aws['aws_account_id']})

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
                            requests.put('{}:{}/hubble/nebula'.format(indexer, port), rdy, auth=HTTPBasicAuth(user, password))
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
            processed['sourcetype'] = opt.get('sourcetype_nebula', 'hubble_osquery')
            processed['indexer_ssl'] = opt.get('indexer_ssl', True)
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
            sourcetype = __salt__['config.get']('hubblestack:nebula:returner:logstash:sourcetype')
            custom_fields = __salt__['config.get']('hubblestack:nebula:returner:logstash:custom_fields', [])
        except:
            return None

        logstash_opts = {'password': password, 'indexer': indexer, 'sourcetype': sourcetype, 'index': index, 'custom_fields': custom_fields}

        indexer_ssl = __salt__['config.get']('hubblestack:nebula:returner:logstash:indexer_ssl', True)
        logstash_opts['http_input_server_ssl'] = indexer_ssl
        logstash_opts['proxy'] = __salt__['config.get']('hubblestack:nebula:returner:logstash:proxy', {})
        logstash_opts['timeout'] = __salt__['config.get']('hubblestack:nebula:returner:logstash:timeout', 9.05)

        return [logstash_opts]
