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
          - user: edwin
            port: 8080
            password: xoxepap0ooxoha4Xeen2ub6ohTh3huXo
            indexer: http://logstash.http.input.tld
'''

import socket
import requests
import json
import time
from datetime import datetime
from requests.auth import HTTPBasicAuth


def returner(ret):
    '''
    '''
    ## collect config options
    try:
        port = __salt__['config.get']('hubblestack:returner:logstash:port')
        user = __salt__['config.get']('hubblestack:returner:logstash:user')
        indexer = __salt__['config.get']('hubblestack:returner:logstash:indexer')
        password = __salt__['config.get']('hubblestack:returner:logstash:password')
    except:
        return None

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

                    payload.update({'host': fqdn})
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
