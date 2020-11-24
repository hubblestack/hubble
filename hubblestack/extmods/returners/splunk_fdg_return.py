# -*- encoding: utf-8 -*-
"""
HubbleStack FDG-to-Splunk returner

Deliver HubbleStack FDG query data into Splunk using the HTTP
event collector. Required config/pillar settings:

.. code-block:: yaml

    hubblestack:
      returner:
        splunk:
          - token: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
            indexer: splunk-indexer.domain.tld
            index: hubble
            sourcetype_fdg: hubble_fdg

Returns formed as a list will be sent as separate events, with the same fdg
filename identifier. Returns from ``fdg.top`` will be separated and treated as
separate FDG runs by this returner.

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
            sourcetype_fdg: hubble_fdg
            fallback_indexer: splunk-indexer.loc.domain.tld
            custom_fields:
              - site
              - product_group
"""
import socket
import re
import json
import logging
from hubblestack.hec import http_event_collector, get_splunk_options, make_hec_args


_MAX_CONTENT_BYTES = 100000
HTTP_EVENT_COLLECTOR_DEBUG = False

log = logging.getLogger(__name__)


def returner(ret):
    """
    Get fdg data and post it to Splunk
    """
    data = ret['return']
    if not data:
        return

    host_args = _build_args(ret)
    if host_args['fun'] != 'fdg.top':
        if len(data) < 2:
            log.error('Non-fdg data found in splunk_fdg_return: %s', data)
            return
        data = {data[0]: data[1]}

    # Get cloud details
    cloud_details = __grains__.get('cloud_details', {})

    try:
        opts_list = get_splunk_options(sourcetype='hubble_fdg',
                                       add_query_to_sourcetype=True,
                                       _nick={'sourcetype_fdg': 'sourcetype'})

        for opts in opts_list:
            logging.debug('Options: %s', json.dumps(opts))

            # Set up the fields to be extracted at index time. The field values must be strings.
            # Note that these fields will also still be available in the event data
            index_extracted_fields = []
            try:
                index_extracted_fields.extend(__opts__.get('splunk_index_extracted_fields', []))
            except TypeError:
                pass

            args, kwargs = make_hec_args(opts)
            hec = http_event_collector(*args, **kwargs)

            for fdg_info, fdg_results in data.items():

                if not isinstance(fdg_results, list):
                    fdg_results = [fdg_results]
                for fdg_result in fdg_results:
                    payload = _generate_payload(args=host_args, opts=opts,
                                                index_extracted_fields=index_extracted_fields,
                                                fdg_args={'fdg_info': fdg_info,
                                                          'fdg_result': fdg_result},
                                                cloud_details=cloud_details)
                    hec.batchEvent(payload)

            hec.flushBatch()
    except Exception:
        log.exception('Error ocurred in splunk_fdg_return')
    return


def _generate_event(fdg_args, args, starting_chained, cloud_details, custom_fields):
    """
    Helper function that builds and returns the event dict
    """
    event = {'fdg_result': fdg_args['fdg_result'][0],
             'fdg_status': fdg_args['fdg_result'][1],
             'fdg_file': fdg_args['fdg_file'],
             'fdg_starting_chained': starting_chained,
             'job_id': args['job_id'],
             'minion_id': args['minion_id'],
             'dest_host': args['fqdn'],
             'dest_ip': args['fqdn_ip4'],
             'dest_fqdn': args['local_fqdn'],
             'system_uuid': __grains__.get('system_uuid')}

    event.update(cloud_details)

    for custom_field in custom_fields:
        custom_field_name = 'custom_' + custom_field
        custom_field_value = __salt__['config.get'](custom_field, '')
        if isinstance(custom_field_value, list):
            custom_field_value = ','.join(custom_field_value)
        if isinstance(custom_field_value, str):
            event.update({custom_field_name: custom_field_value})

    return event


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
            'fun': ret['fun'],
            'fqdn': fqdn,
            'fqdn_ip4': fqdn_ip4,
            'local_fqdn': local_fqdn}

    # Sometimes fqdn reports a value of localhost. If that happens, try another method.
    bad_fqdns = ['localhost', 'localhost.localdomain', 'localhost6.localdomain6']
    if args['fqdn'] in bad_fqdns:
        new_fqdn = socket.gethostname()
        if '.' not in new_fqdn or new_fqdn in bad_fqdns:
            new_fqdn = args['fqdn_ip4']
        args['fqdn'] = new_fqdn

    return args

def _file_url_to_sourcetype(filename, base='hubble_fdg'):
    """ attempt to turn a file URL into a sourcetype extension description
        e.g.:
        'salt://fdg/interesting.operation.fdg'
        becomes
        base + '_' + 'interesting_operation'
        (intended for internal use by _generate_payload() to append to the
        default sourcetype)
    """
    if re.search(r'^\w+://', filename):
        filename = filename.split('://', 1)[1]
    if base.endswith('_fdg') and filename.startswith('fdg/'):
        filename = filename[4:]
    if re.search(r'\.fdg$', filename):
        filename = filename[:-4]
    def _no_dups(x):
        sf = re.split(r'[^a-zA-Z0-9]+', x)
        for item in sf:
            if not item:
                continue
            yield item
    return '_'.join( _no_dups(base + '_' + filename) )

def _generate_payload(args, fdg_args, cloud_details, opts, index_extracted_fields):
    """
    Build the payload that will be published to Splunk
    """
    fdg_file, starting_chained = fdg_args['fdg_info']
    fdg_file = fdg_file.lower().replace(' ', '_')
    payload = {'host': args['fqdn'], 'index': opts['index']}
    if opts['add_query_to_sourcetype']:

        payload.update({'sourcetype': _file_url_to_sourcetype(fdg_file, opts['sourcetype'])})
    else:
        payload.update({'sourcetype': opts['sourcetype']})

    event = _generate_event(args=args, fdg_args={'fdg_result': fdg_args['fdg_result'],
                                                 'fdg_file': fdg_file},
                            starting_chained=starting_chained,
                            cloud_details=cloud_details,
                            custom_fields=opts['custom_fields'])
    # Remove any empty fields from the event payload
    remove_keys = [k for k in event
                   if event[k] == "" and not k.startswith('fdg_')]
    for k in remove_keys:
        del event[k]

    payload.update({'event': event})

    # Potentially add metadata fields:
    fields = {}
    for item in index_extracted_fields:
        if item in payload['event'] and \
                not isinstance(payload['event'][item], (list, dict, tuple)):
            fields["meta_%s" % item] = str(payload['event'][item])
    if fields:
        payload.update({'fields': fields})

    return payload
