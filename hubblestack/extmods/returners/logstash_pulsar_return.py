# -*- encoding: utf-8 -*-
'''
HubbleStack Pulsar-to-Logstash (http input) returner

:maintainer: HubbleStack
:platform: All
:requires: HubbleStack

Deliver HubbleStack Pulsar event data into Logstash using the HTTP input
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
            sourcetype_pulsar: hubble_fim
            indexer: http://logstash.http.input.tld
            password: password
            custom_fields:
              - site
              - product_group
'''

import os
import json
import requests
from collections import defaultdict
from requests.auth import HTTPBasicAuth


def _dedupList(l):
    deduped = []
    for i, x in enumerate(l):
        if x not in l[i + 1:]:
            deduped.append(x)
    return deduped


def returner(ret):
    '''
    '''
    if isinstance(ret, dict) and not ret.get('return'):
        return

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
                if 'contents' in alert:
                    event['contents'] = alert['contents']

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

            event.update(cloud_details)

            payload.update({'host': fqdn})
            payload.update({'index': opts['index']})
            payload.update({'sourcetype': opts['sourcetype']})
            payload.update({'event': event})

            rdy = json.dumps(payload)
            requests.post('{}:{}/hubble/pulsar'.format(indexer, port), rdy, auth=HTTPBasicAuth(user, password))
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
            processed['sourcetype'] = opt.get('sourcetype_pulsar', 'hubble_fim')
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
            sourcetype = __salt__['config.get']('hubblestack:pulsar:returner:logstash:sourcetype')
            custom_fields = __salt__['config.get']('hubblestack:pulsar:returner:logstash:custom_fields', [])
        except:
            return None

        logstash_opts = {'password': password, 'indexer': indexer, 'sourcetype': sourcetype, 'index': index, 'custom_fields': custom_fields}

        indexer_ssl = __salt__['config.get']('hubblestack:pulsar:returner:logstash:indexer_ssl', True)
        logstash_opts['http_input_server_ssl'] = indexer_ssl
        logstash_opts['proxy'] = __salt__['config.get']('hubblestack:pulsar:returner:logstash:proxy', {})
        logstash_opts['timeout'] = __salt__['config.get']('hubblestack:pulsar:returner:logstash:timeout', 9.05)

        return [logstash_opts]
