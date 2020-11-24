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

import json
import logging
import time
import copy
from datetime import datetime
from hubblestack.hec import http_event_collector, get_splunk_options, make_hec_args

_MAX_CONTENT_BYTES = 100000
HTTP_EVENT_COLLECTOR_DEBUG = False

log = logging.getLogger(__name__)


def returner(ret):
    """
    Get osqueryd data and post it to Splunk
    """
    data = ret['return']
    if not data:
        return
    host_args = _build_args(ret)
    # Get cloud details
    cloud_details = __grains__.get('cloud_details', {})

    try:
        opts_list = get_splunk_options(sourcetype='hubble_osqueryd',
                                       add_query_to_sourcetype=True,
                                       _nick={'sourcetype_osqueryd': 'sourcetype'})
        for opts in opts_list:
            logging.debug('Options: %s', json.dumps(opts))
            # Set up the collector
            args, kwargs = make_hec_args(opts)
            hec = http_event_collector(*args, **kwargs)
            for query_results in data:
                event = _generate_event(host_args=host_args, query_name=query_results['name'],
                                        query_results=query_results, cloud_details=cloud_details)
                if 'columns' in query_results:  # This means we have result log event
                    event.update(query_results['columns'])
                    _generate_and_send_payload(hec=hec, host_args=host_args, opts=opts, event=event,
                                               query_results=query_results)
                elif 'snapshot' in query_results:  # This means we have snapshot log event
                    for q_result in query_results['snapshot']:
                        n_event = copy.deepcopy(event)
                        n_event.update(q_result)
                        _generate_and_send_payload(hec=hec, host_args=host_args, opts=opts,
                                                   event=n_event, query_results=query_results)
                else:
                    log.error("Incompatible event data captured")
            hec.flushBatch()
    except Exception:
        log.exception('Error ocurred in splunk_osqueryd_return')
    return


def _generate_and_send_payload(hec, host_args, opts, event, query_results):
    """
    Function that builds the payload dict and sends it to the event collector (hec)
    """
    # Generate the payload fields
    event = _update_event(opts['custom_fields'], event)
    sourcetype = opts['sourcetype']
    if opts['add_query_to_sourcetype']:
        # Remove 'pack_' from query name to shorten the sourcetype length
        sourcetype = opts['sourcetype'] + '_' + query_results['name'].replace('pack_', '')
    # If the osquery query includes a field called 'time' it will be checked.
    # If it's within the last year, it will be used as the eventtime.
    event_time = query_results.get('unixTime', query_results.get('time', ''))
    try:
        if (datetime.fromtimestamp(time.time()) - datetime.fromtimestamp(
                float(event_time))).days > 365:
            event_time = ''
    except Exception:
        event_time = ''
    # Set up the fields to be extracted at index time. The field values must be strings.
    # Note that these fields will also still be available in the event data
    index_extracted_fields = []
    try:
        index_extracted_fields.extend(__opts__.get('splunk_index_extracted_fields', []))
    except TypeError:
        pass

    payload = {'host': host_args['fqdn'],
               'index': opts['index'],
               'sourcetype': sourcetype,
               'event': event}

    # Potentially add metadata fields:
    fields = {}
    for item in index_extracted_fields:
        if item in payload['event'] and not isinstance(payload['event'][item], (list, dict, tuple)):
            fields["meta_%s" % item] = str(payload['event'][item])
    if fields:
        payload['fields'] = fields
    # Send payload to hec
    log.debug("Sending logs to splunk: %s", payload)
    hec.batchEvent(payload, eventtime=event_time)


def _build_args(ret):
    """
    Helper function that builds the args that will be passed on to the event - cleaner way of
    processing the variables we care about
    """
    # Sometimes fqdn is blank. If it is, replace it with minion_id
    fqdn = __grains__['fqdn'] if __grains__['fqdn'] else ret['id']
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

    args = {'minion_id': ret['id'],
            'job_id': ret['jid'],
            'fqdn': fqdn,
            'fqdn_ip4': fqdn_ip4,
            'local_fqdn': local_fqdn}

    # Sometimes fqdn reports a value of localhost. If that happens, try another method.
    bad_fqdns = ['localhost', 'localhost.localdomain', 'localhost6.localdomain6']
    if fqdn in bad_fqdns:
        new_fqdn = socket.gethostname()
        if '.' not in new_fqdn or new_fqdn in bad_fqdns:
            new_fqdn = fqdn_ip4
        args['fqdn'] = new_fqdn

    return args


def _generate_event(host_args, query_results, cloud_details, query_name):
    """
    Helper function that builds and returns the event dict
    """
    event = {'query': query_name,
             'job_id': host_args['job_id'],
             'minion_id': host_args['minion_id'],
             'dest_host': host_args['fqdn'],
             'dest_ip': host_args['fqdn_ip4'],
             'dest_fqdn': host_args['local_fqdn'],
             'system_uuid': __grains__.get('system_uuid'),
             'epoch': query_results['epoch'],
             'counter': query_results['counter'],
             'action': query_results['action'],
             'unixTime': query_results['unixTime']}
    event.update(cloud_details)

    return event


def _update_event(custom_fields, event):
    """
    Helper function that updates the event with the values from custom fields and removes duplicates
    """
    # update event data
    for custom_field in custom_fields:
        custom_field_name = 'custom_' + custom_field
        custom_field_value = __salt__['config.get'](custom_field, '')
        if isinstance(custom_field_value, list):
            custom_field_value = ','.join(custom_field_value)
        if isinstance(custom_field_value, str):
            event.update({custom_field_name: custom_field_value})

    # Remove any empty fields from the event payload
    remove_keys = [k for k in event if event[k] == ""]
    for k in remove_keys:
        del event[k]

    return event
