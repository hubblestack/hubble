# -*- encoding: utf-8 -*-
'''
'''

import socket
import requests
from requests.auth import HTTPBasicAuth
import json
import time

def returner(ret):
    try:
        port = __salt__['config.get']('hubblestack:returner:logstash:port')
        user = __salt__['config.get']('hubblestack:returner:logstash:user')
        indexer = __salt__['config.get']('hubblestack:returner:logstash:indexer')
        password = __salt__['config.get']('hubblestack:returner:logstash:password')
    except:
        return None

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

        payload.update({'host': fqdn})
        payload.update({'event': event})

        rdy = json.dumps(payload)
        requests.put('{}:{}/hubble/nova'.format(indexer, port), rdy, auth=HTTPBasicAuth(user, password))


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

        payload.update({'host': fqdn})
        payload.update({'event': event})

        rdy = json.dumps(payload)
        requests.put('{}:{}/hubble/nova'.format(indexer, port), rdy, auth=HTTPBasicAuth(user, password))


    if data.get('Compliance', None):
        payload = {}
        event = {}
        event.update({'job_id': jid})
        event.update({'compliance_percentage': data['Compliance']})
        event.update({'master': master})
        event.update({'minion_id': minion_id})
        event.update({'dest_host': fqdn})
        event.update({'dest_ip': fqdn_ip4})

        payload.update({'host': fqdn})
        payload.update({'event': event})

        rdy = json.dumps(payload)
        requests.put('{}:{}/hubble/nova'.format(indexer, port), rdy, auth=HTTPBasicAuth(user, password))

    return
