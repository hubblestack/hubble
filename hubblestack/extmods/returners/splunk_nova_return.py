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
import json
import logging

from hubblestack.hec import http_event_collector, get_splunk_options, make_hec_args

log = logging.getLogger(__name__)


def returner(ret):
    """
    Get nova data and post it to Splunk
    """
    # st = 'salt:hubble:nova'
    data = ret['return']
    if not isinstance(data, dict):
        log.error('Data sent to splunk_nova_return was not formed as a dict:\n%s', data)
        return
    host_args = _build_args(ret)
    # Get cloud details
    cloud_details = __grains__.get('cloud_details', {})

    try:
        opts_list = get_splunk_options(sourcetype='hubble_audit',
                                       _nick={'sourcetype_nova': 'sourcetype'})

        for opts in opts_list:
            log.debug('Options: %s', json.dumps(opts))
            custom_fields = opts['custom_fields']
            # Set up the collector
            args, kwargs = make_hec_args(opts)
            hec = http_event_collector(*args, **kwargs)
            host_args['hec'] = hec

            # Failure checks
            _publish_data(args=host_args, checks=data.get('Failure', []), check_result='Failure',
                          cloud_details=cloud_details, opts=opts)

            # Success checks
            _publish_data(args=host_args, checks=data.get('Success', []), check_result='Success',
                          cloud_details=cloud_details, opts=opts)

            # Compliance checks
            if data.get('Compliance', None):
                host_args['Compliance'] = data['Compliance']
                event = _generate_event(args=host_args, cloud_details=cloud_details,
                                        custom_fields=custom_fields, check_type='compliance')
                _publish_event(fqdn=host_args['fqdn'], event=event, opts=opts, hec=hec)

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
    for event_data in event:
        if not 'salt/job/' in event_data['tag']:
            continue  # not a salt job event. Not relevant to hubble
        elif event_data['data']['fun'] != 'hubble.audit':
            continue  # not a call to hubble.audit, so not relevant
        else:
            log.debug('Logging event: %s', str(event_data))
            returner(event_data['data'])  # Call the standard returner
    return


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


def _generate_event(args, cloud_details, custom_fields, check_type=None, data=None):
    """
    Helper function that builds and returns the event dict
    """
    event = {'job_id': args['job_id']}
    if check_type == 'compliance':
        event['compliance_percentage'] = args['Compliance']
    else:
        event.update({'check_result': args['check_result']})
        event.update({'check_id': args['check_id']})
        if not isinstance(data[args['check_id']], dict):
            event.update({'description': data[args['check_id']]})
        elif 'description' in data[args['check_id']]:
            for key, value in data[args['check_id']].items():
                if key not in ['tag']:
                    event[key] = value
    event.update({'minion_id': args['minion_id'],
                  'dest_host': args['fqdn'],
                  'dest_ip': args['fqdn_ip4'],
                  'dest_fqdn': args['local_fqdn'],
                  'system_uuid': __grains__.get('system_uuid')})
    event.update(cloud_details)

    for custom_field in custom_fields:
        custom_field_name = 'custom_' + custom_field
        custom_field_value = __salt__['config.get'](custom_field, '')
        if isinstance(custom_field_value, list):
            custom_field_value = ','.join(custom_field_value)
        if isinstance(custom_field_value, str):
            event.update({custom_field_name: custom_field_value})

    if check_type == 'Success':
        # Remove any empty fields from the event payload
        remove_keys = [k for k in event if event[k] == ""]
        for k in remove_keys:
            del event[k]

    return event


def _publish_event(fqdn, event, opts, hec):
    """
    Helper function that builds the payload and publishes it to Splunk
    """
    # Set up the fields to be extracted at index time. The field values must be strings.
    # Note that these fields will also still be available in the event data
    index_extracted_fields = []
    try:
        index_extracted_fields.extend(__opts__.get('splunk_index_extracted_fields', []))
    except TypeError:
        pass

    payload = {'host': fqdn,
               'sourcetype': opts['sourcetype'],
               'index': opts['index'],
               'event': event}
    # Potentially add metadata fields:
    fields = {}
    for item in index_extracted_fields:
        if item in payload['event'] and not isinstance(payload['event'][item],
                                                       (list, dict, tuple)):
            fields["meta_%s" % item] = str(payload['event'][item])
    if fields:
        payload.update({'fields': fields})

    hec.batchEvent(payload)


def _publish_data(args, checks, check_result, cloud_details, opts):
    """
    Helper function that goes over the failure/success checks and publishes the event to Splunk
    """
    for data in checks:
        check_id = list(data.keys())[0]
        args['check_result'] = check_result
        args['check_id'] = check_id
        event = _generate_event(data=data, args=args, cloud_details=cloud_details,
                                custom_fields=opts['custom_fields'], check_type=check_result)
        _publish_event(fqdn=args['fqdn'], opts=opts, event=event, hec=args['hec'])
