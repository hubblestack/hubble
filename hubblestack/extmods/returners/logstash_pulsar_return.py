# -*- encoding: utf-8 -*-
'''
'''

import requests
import json
import logging
import os
import time
from collections import defaultdict
from requests.auth import HTTPBasicAuth

log = logging.getLogger(__name__)

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

    if isinstance(ret, dict) and not ret.get('return'):
        return

    data = _dedupList(ret['return'])
    minion_id = __opts__['id']
    fqdn = __grains__['fqdn']
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

    alerts = []
    for item in data:
        events = item
        if not isinstance(events, list):
            events = [events]
        alerts.extend(events)

    for alert in alerts:
        event = {}
        payload = {}
        if('change' in alert):  # Linux, normal pulsar
            # The second half of the change will be '|IN_ISDIR' for directories
            change = alert['change'].split('|')[0]
            # Skip the IN_IGNORED events
            if change == 'IN_IGNORED':
                continue
            if len(alert['change'].split('|')) == 2:
                object_type = 'directory'
            else:
                object_type = 'file'

            actions = defaultdict(lambda: 'unknown')
            actions['IN_ACCESS'] = 'read'
            actions['IN_ATTRIB'] = 'acl_modified'
            actions['IN_CLOSE_NOWRITE'] = 'read'
            actions['IN_CLOSE_WRITE'] = 'read'
            actions['IN_CREATE'] = 'created'
            actions['IN_DELETE'] = 'deleted'
            actions['IN_DELETE_SELF'] = 'deleted'
            actions['IN_MODIFY'] = 'modified'
            actions['IN_MOVE_SELF'] = 'modified'
            actions['IN_MOVED_FROM'] = 'modified'
            actions['IN_MOVED_TO'] = 'modified'
            actions['IN_OPEN'] = 'read'
            actions['IN_MOVE'] = 'modified'
            actions['IN_CLOSE'] = 'read'

            event['action'] = actions[change]
            event['change_type'] = 'filesystem'
            event['object_category'] = object_type
            event['object_path'] = alert['path']
            event['file_name'] = alert['name']
            event['file_path'] = alert['tag']

            if alert['stats']:  # Gather more data if the change wasn't a delete
                stats = alert['stats']
                event['object_id'] = stats['inode']
                event['file_acl'] = stats['mode']
                event['file_create_time'] = stats['ctime']
                event['file_modify_time'] = stats['mtime']
                event['file_size'] = stats['size'] / 1024.0  # Convert bytes to kilobytes
                event['user'] = stats['user']
                event['group'] = stats['group']
                if object_type == 'file':
                    event['file_hash'] = alert['checksum']
                    event['file_hash_type'] = alert['checksum_type']

        else:  # Windows, win_pulsar
            change = alert['Accesses']
            if alert['Hash'] == 'Item is a directory':
                object_type = 'directory'
            else:
                object_type = 'file'

            actions = defaultdict(lambda: 'unknown')
            actions['Delete'] = 'deleted'
            actions['Read Control'] = 'read'
            actions['Write DAC'] = 'acl_modified'
            actions['Write Owner'] = 'modified'
            actions['Synchronize'] = 'modified'
            actions['Access Sys Sec'] = 'read'
            actions['Read Data'] = 'read'
            actions['Write Data'] = 'modified'
            actions['Append Data'] = 'modified'
            actions['Read EA'] = 'read'
            actions['Write EA'] = 'modified'
            actions['Execute/Traverse'] = 'read'
            actions['Read Attributes'] = 'read'
            actions['Write Attributes'] = 'acl_modified'
            actions['Query Key Value'] = 'read'
            actions['Set Key Value'] = 'modified'
            actions['Create Sub Key'] = 'created'
            actions['Enumerate Sub-Keys'] = 'read'
            actions['Notify About Changes to Keys'] = 'read'
            actions['Create Link'] = 'created'
            actions['Print'] = 'read'

            event['action'] = actions[change]
            event['change_type'] = 'filesystem'
            event['object_category'] = object_type
            event['object_path'] = alert['Object Name']
            event['file_name'] = os.path.basename(alert['Object Name'])
            event['file_path'] = os.path.dirname(alert['Object Name'])
            # TODO: Should we be reporting 'EntryType' or 'TimeGenerated?
            #   EntryType reports whether attempt to change was successful.

        event.update({'master': master})
        event.update({'minion_id': minion_id})
        event.update({'dest_host': fqdn})
        event.update({'dest_ip': fqdn_ip4})

        payload.update({'host': fqdn})
        payload.update({'event': event})

        rdy = json.dumps(payload)
        requests.put('{}:{}/hubble/pulsar'.format(indexer, port), rdy, auth=HTTPBasicAuth(user, password))
    return


def _dedupList(l):
    deduped = []
    for i, x in enumerate(l):
        if x not in l[i + 1:]:
            deduped.append(x)
    return deduped
