# -*- encoding: utf-8 -*-
"""
HubbleStack Pulsar-to-Splunk returner

Deliver HubbleStack Pulsar event data into Splunk using the HTTP
event collector. Required config/pillar settings:

.. code-block:: yaml

    hubblestack:
      returner:
        splunk:
          - token: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
            indexer: splunk-indexer.domain.tld
            index: hubble
            sourcetype_pulsar: hubble_fim

You can also add a `custom_fields` argument which is a list of keys to add to
events with using the results of config.get(<custom_field>). These new keys
will be prefixed with 'custom_' to prevent conflicts. The values of these keys
should be strings or lists (will be sent as CSV string), do not choose grains
or pillar values with complex values or they will be skipped.

Additionally, you can define a fallback_indexer which will be used if a default
gateway is not defined.

.. code-block:: yaml

    hubblestack:
      returner:
        splunk:
          - token: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
            indexer: splunk-indexer.domain.tld
            index: hubble
            sourcetype_pulsar: hubble_fim
            fallback_indexer: splunk-indexer.loc.domain.tld
            custom_fields:
              - site
              - product_group
"""
import socket

# Imports for http event forwarder
import requests
import json
import os
import time
from collections import defaultdict
from hubblestack.hec import http_event_collector, get_splunk_options, make_hec_args

import logging

log = logging.getLogger(__name__)

def returner(ret):
    try:
        if isinstance(ret, dict) and not ret.get('return'):
            # Empty single return, let's not do any setup or anything
            return

        opts_list = get_splunk_options( sourcetype='hubble_fim',
            _nick={'sourcetype_pulsar': 'sourcetype'})

        for opts in opts_list:
            logging.debug('Options: %s' % json.dumps(opts))
            custom_fields = opts['custom_fields']

            # Set up the fields to be extracted at index time. The field values must be strings.
            # Note that these fields will also still be available in the event data
            index_extracted_fields = []
            try:
                index_extracted_fields.extend(__opts__.get('splunk_index_extracted_fields', []))
            except TypeError:
                pass

            # Set up the collector
            args, kwargs = make_hec_args(opts)
            hec = http_event_collector(*args, **kwargs)

            # Check whether or not data is batched:
            if isinstance(ret, dict):  # Batching is disabled
                data = [ret]
            else:
                data = ret
            # Sometimes there are duplicate events in the list. Dedup them:
            data = _dedupList(data)
            minion_id = __opts__['id']
            jid = ret['jid']
            fqdn = __grains__['fqdn']
            # Sometimes fqdn is blank. If it is, replace it with minion_id
            fqdn = fqdn if fqdn else minion_id
            try:
                fqdn_ip4 = __grains__.get('local_ip4')
                if not fqdn_ip4:
                    fqdn_ip4 = __grains__['fqdn_ip4'][0]
            except IndexError:
                try:
                    fqdn_ip4 = __grains__['ipv4'][0]
                except IndexError:
                    raise Exception('No ipv4 grains found. Is net-tools installed?')
            if fqdn_ip4.startswith('127.'):
                for ip4_addr in __grains__['ipv4']:
                    if ip4_addr and not ip4_addr.startswith('127.'):
                        fqdn_ip4 = ip4_addr
                        break
            local_fqdn = __grains__.get('local_fqdn', __grains__['fqdn'])

            # Sometimes fqdn reports a value of localhost. If that happens, try another method.
            bad_fqdns = ['localhost', 'localhost.localdomain', 'localhost6.localdomain6']
            if fqdn in bad_fqdns:
                new_fqdn = socket.gethostname()
                if '.' not in new_fqdn or new_fqdn in bad_fqdns:
                    new_fqdn = fqdn_ip4
                fqdn = new_fqdn

            # Get cloud details
            cloud_details = __grains__.get('cloud_details', {})

            alerts = []
            for item in data:
                events = item['return']
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
                    event['pulsar_config'] = alert['pulsar_config']
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
                            chk = alert.get('checksum')
                            if chk:
                                event['file_hash'] = chk
                                event['file_hash_type'] = alert.get('checksum_type', 'unknown')

                else:  # Windows, win_pulsar
                    if alert.get('Accesses', None):
                        change = alert['Accesses']
                        if alert['Hash'] == 'Item is a directory':
                            object_type = 'directory'
                        else:
                            object_type = 'file'
                    else:
                        change = alert['Reason']
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
                    actions['Basic info change'] = 'modified'
                    actions['Compression change'] = 'modified'
                    actions['Data extend'] = 'modified'
                    actions['EA change'] = 'modified'
                    actions['File create'] = 'created'
                    actions['File delete'] = 'deleted'

                    if alert.get('Accesses', None):
                        event['action'] = actions[change]
                        event['change_type'] = 'filesystem'
                        event['object_category'] = object_type
                        event['object_path'] = alert['Object Name']
                        event['file_name'] = os.path.basename(alert['Object Name'])
                        event['file_path'] = os.path.dirname(alert['Object Name'])
                        event['pulsar_config'] = alert['pulsar_config']
                        # TODO: Should we be reporting 'EntryType' or 'TimeGenerated?
                        #   EntryType reports whether attempt to change was successful.
                    else:
                        for c in change:
                            if not event.get('action', None):
                                event['action'] = actions.get(c, c)
                            else:
                                event['action'] += ', ' + actions.get(c, c)
                        event['change_type'] = 'filesystem'
                        event['object_category'] = object_type
                        event['object_path'] = alert['Full path']
                        event['file_name'] = alert['File name']
                        event['file_path'] = alert['tag']
                        event['pulsar_config'] = alert.get('pulsar_config',
                                                           'hubblestack_pulsar_win_config.yaml')
                        event['TimeGenerated'] = alert['Time stamp']
                        chk = alert.get('checksum')
                        if chk:
                            event['file_hash'] = chk
                            event['file_hash_type'] = alert.get('checksum_type', 'unknown')

                event.update({'minion_id': minion_id})
                event.update({'dest_host': fqdn})
                event.update({'dest_ip': fqdn_ip4})
                event.update({'dest_fqdn': local_fqdn})
                event.update({'system_uuid': __grains__.get('system_uuid')})

                event.update(cloud_details)

                for custom_field in custom_fields:
                    custom_field_name = 'custom_' + custom_field
                    custom_field_value = __salt__['config.get'](custom_field, '')
                    if isinstance(custom_field_value, (str, unicode)):
                        event.update({custom_field_name: custom_field_value})
                    elif isinstance(custom_field_value, list):
                        custom_field_value = ','.join(custom_field_value)
                        event.update({custom_field_name: custom_field_value})

                payload.update({'host': fqdn})
                payload.update({'index': opts['index']})
                payload.update({'sourcetype': opts['sourcetype']})

                # Remove any empty fields from the event payload
                remove_keys = [k for k in event if event[k] == ""]
                for k in remove_keys:
                    del event[k]

                payload.update({'event': event})

                # Potentially add metadata fields:
                fields = {}
                for item in index_extracted_fields:
                    if item in payload['event'] and not isinstance(payload['event'][item], (list, dict, tuple)):
                        fields["meta_%s" % item] = str(payload['event'][item])

                if fields:
                    payload.update({'fields': fields})

                hec.batchEvent(payload)

            hec.flushBatch()
    except Exception:
        log.exception('Error ocurred in splunk_pulsar_return')
    return


def _dedupList(l):
    deduped = []
    for i, x in enumerate(l):
        if x not in l[i + 1:]:
            deduped.append(x)
    return deduped
