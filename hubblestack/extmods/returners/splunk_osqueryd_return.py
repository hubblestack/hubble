# -*- encoding: utf-8 -*-
"""
HubbleStack Nebula-osqueryd-to-Splunk returner

Deliver HubbleStack Nebula osqueryd query data into Splunk using the HTTP
event collector. Required config/pillar settings:

.. code-block:: yaml

    hubblestack:
      returner:
        splunk:
          - token: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
            indexer: splunk-indexer.domain.tld
            index: hubble
            sourcetype_osqueryd: hubble_osqueryd

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
            sourcetype_osqueryd: hubble_osqueryd
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
import copy
from datetime import datetime
from hubblestack.hec import http_event_collector, get_splunk_options, make_hec_args

import logging

_max_content_bytes = 100000
http_event_collector_debug = False

log = logging.getLogger(__name__)


def returner(ret):
    try:
        opts_list = get_splunk_options( sourcetype='hubble_osqueryd',
            add_query_to_sourcetype=True, _nick={'sourcetype_osqueryd': 'sourcetype'})

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

            # Get cloud details
            cloud_details = __grains__.get('cloud_details', {})

            if not data:
                return
            else:
                for query_results in data:
                    event = {}
                    query_name = query_results['name']
                    event.update({'query': query_name})
                    event.update({'job_id': jid})
                    event.update({'minion_id': minion_id})
                    event.update({'dest_host': fqdn})
                    event.update({'dest_ip': fqdn_ip4})
                    event.update({'dest_fqdn': local_fqdn})
                    event.update({'system_uuid': __grains__.get('system_uuid')})
                    event.update({'epoch': query_results['epoch']})
                    event.update({'counter': query_results['counter']})
                    event.update({'action': query_results['action']})
                    event.update({'unixTime': query_results['unixTime']})

                    event.update(cloud_details)
                    sourcetype = opts['sourcetype']
                    if opts['add_query_to_sourcetype']:
                        # Remove 'pack_' from query name to shorten the sourcetype length
                        sourcetype = opts['sourcetype'] + '_' + query_name.replace('pack_', '')

                    # If the osquery query includes a field called 'time' it will be checked.
                    # If it's within the last year, it will be used as the eventtime.
                    event_time = query_results.get('time', '')
                    if 'columns' in query_results: #This means we have result log event
                        event.update(query_results['columns'])
                        _generate_and_send_payload(hec,
                                                   opts['index'],
                                                   sourcetype,
                                                   fqdn,
                                                   custom_fields,
                                                   index_extracted_fields,
                                                   event,
                                                   event_time)
                    elif 'snapshot' in query_results: #This means we have snapshot log event
                        for q_result in query_results['snapshot']:
                            n_event = copy.deepcopy(event)
                            n_event.update(q_result)
                            _generate_and_send_payload(hec,
                                                       opts['index'],
                                                       sourcetype,
                                                       fqdn,
                                                       custom_fields,
                                                       index_extracted_fields,
                                                       n_event,
                                                       event_time)
                    else:
                        log.error("Incompatible event data captured")

            hec.flushBatch()
    except Exception:
        log.exception('Error ocurred in splunk_osqueryd_return')
    return


def _generate_and_send_payload(hec, 
                               index, 
                               sourcetype, 
                               fqdn, 
                               custom_fields, 
                               index_extracted_fields, 
                               event, 
                               event_time):
    payload = {}
    for custom_field in custom_fields:
        custom_field_name = 'custom_' + custom_field
        custom_field_value = __salt__['config.get'](custom_field, '')
        if isinstance(custom_field_value, (str, unicode)):
            event.update({custom_field_name: custom_field_value})
        elif isinstance(custom_field_value, list):
            custom_field_value = ','.join(custom_field_value)
            event.update({custom_field_name: custom_field_value})

    payload.update({'host': fqdn})
    payload.update({'index': index})
    payload.update({'sourcetype': sourcetype})

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

    try:
        if (datetime.fromtimestamp(time.time()) - datetime.fromtimestamp(float(event_time))).days > 365:
            event_time = ''
    except Exception:
        event_time = ''
    finally:
        log.debug("Sending logs to splunk: {0}".format(payload))
        hec.batchEvent(payload, eventtime=event_time)
