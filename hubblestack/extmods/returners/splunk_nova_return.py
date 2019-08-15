# -*- encoding: utf-8 -*-
"""
HubbleStack Nova-to-Splunk returner

Deliver HubbleStack Nova result data into Splunk using the HTTP
event collector. Required config/pillar settings:

.. code-block:: yaml

    hubblestack:
      returner:
        splunk:
          - token: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
            indexer: splunk-indexer.domain.tld
            index: hubble
            sourcetype_nova: hubble_audit

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
            sourcetype_nova: hubble_audit
            fallback_indexer: splunk-indexer.loc.domain.tld
            custom_fields:
              - site
              - product_group
"""
import socket

# Imports for http event forwarder
import requests
import json
import time
import logging

from hubblestack.hec import http_event_collector, get_splunk_options, make_hec_args

log = logging.getLogger(__name__)


def returner(ret):
    try:
        opts_list = get_splunk_options( sourcetype='hubble_audit',
            _nick={'sourcetype_nova': 'sourcetype'})

        for opts in opts_list:
            log.debug('Options: %s' % json.dumps(opts))
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

            # st = 'salt:hubble:nova'
            data = ret['return']
            minion_id = ret['id']
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

            if not isinstance(data, dict):
                log.error('Data sent to splunk_nova_return was not formed as a '
                          'dict:\n{0}'.format(data))
                return

            # Get cloud details
            cloud_details = __grains__.get('cloud_details', {})

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
                payload.update({'event': event})

                # Potentially add metadata fields:
                fields = {}
                for item in index_extracted_fields:
                    if item in payload['event'] and not isinstance(payload['event'][item], (list, dict, tuple)):
                        fields["meta_%s" % item] = str(payload['event'][item])
                if fields:
                    payload.update({'fields': fields})

                hec.batchEvent(payload)

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
                payload.update({'sourcetype': opts['sourcetype']})
                payload.update({'index': opts['index']})

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

            if data.get('Compliance', None):
                payload = {}
                event = {}
                event.update({'job_id': jid})
                event.update({'compliance_percentage': data['Compliance']})
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
                payload.update({'sourcetype': opts['sourcetype']})
                payload.update({'index': opts['index']})
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
        log.exception('Error ocurred in splunk_nova_return')
    return


def event_return(event):
    """
    When called from the master via event_return.

    Note that presently the master won't see returners in file_roots/_returners
    so you need to put it in a returners/ subdirectory and configure
    custom_modules in your master config.
    """
    for e in event:
        if not('salt/job/' in e['tag']):
            continue  # not a salt job event. Not relevant to hubble
        elif(e['data']['fun'] != 'hubble.audit'):
            continue  # not a call to hubble.audit, so not relevant
        else:
            log.debug('Logging event: %s' % str(e))
            returner(e['data'])  # Call the standard returner
    return
