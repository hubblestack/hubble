# -*- encoding: utf-8 -*-
'''
HubbleStack Nebula-to-Splunk returner

:maintainer: HubbleStack
:maturity: 2016.10.4
:platform: All
:requires: SaltStack

Deliver HubbleStack Nebula query data into Splunk using the HTTP
event collector. Required config/pillar settings:

.. code-block:: yaml

    hubblestack:
      nebula:
        returner:
          splunk:
            token: <splunk_http_forwarder_token>
            indexer: <hostname/IP of Splunk indexer>
            sourcetype: <Destination sourcetype for data>
            index: <Destination index for data>

You can also add an `custom_fields` argument which is a list of keys to add to events
with using the results of config.get(<custom_field>). These new keys will be prefixed
with 'custom_' to prevent conflicts. The values of these keys should be
strings or lists (will be sent as CSV string), do not choose grains or pillar values with complex values or they will
be skipped:

.. code-block:: yaml

    hubblestack:
      nebula:
        returner:
          splunk:
            token: <splunk_http_forwarder_token>
            indexer: <hostname/IP of Splunk indexer>
            sourcetype: <Destination sourcetype for data>
            index: <Destination index for data>
            custom_fields:
              - site
              - product_group
'''
import socket

# Imports for http event forwarder
import requests
import json
import time

import logging

_max_content_bytes = 100000
http_event_collector_SSL_verify = False
http_event_collector_debug = True

log = logging.getLogger(__name__)

hec = None


def returner(ret):
    # Customized to split up the queries and extract the correct sourcetype

    opts = _get_options()
    logging.info('Options: %s' % json.dumps(opts))
    http_event_collector_key = opts['token']
    http_event_collector_host = opts['indexer']
    hec_ssl = opts['http_event_server_ssl']
    proxy = opts['proxy']
    timeout = opts['timeout']
    custom_fields = opts['custom_fields']
    # Set up the collector
    hec = http_event_collector(http_event_collector_key, http_event_collector_host, http_event_server_ssl=hec_ssl, proxy=proxy, timeout=timeout)

    # st = 'salt:hubble:nova'
    data = ret['return']
    minion_id = ret['id']
    jid = ret['jid']
    master = __grains__['master']
    fqdn = __grains__['fqdn']
    # Sometimes fqdn is blank. If it is, replace it with minion_id
    fqdn = fqdn if fqdn else minion_id
    try:
        fqdn_ip4 = __grains__['fqdn_ip4'][0]
    except IndexError:
        fqdn_ip4 = __grains__['ipv4'][0]

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

                    for custom_field in custom_fields:
                        custom_field_name = 'custom_' + custom_field
                        custom_field_value = __salt__['config.get'](custom_field, '')
                        if isinstance(custom_field_value, str):
                            event.update({custom_field_name: custom_field_value})
                        elif isinstance(custom_field_value, list):
                            custom_field_value = ','.join(custom_field_value)
                            event.update({custom_field_name: custom_field_value})

                    payload.update({'host': fqdn})
                    payload.update({'index': opts['index']})
                    payload.update({'sourcetype': opts['sourcetype']})
                    payload.update({'event': event})
                    hec.batchEvent(payload)

    hec.flushBatch()
    return


def _get_options():
    try:
        token = __salt__['config.get']('hubblestack:nebula:returner:splunk:token').strip()
        indexer = __salt__['config.get']('hubblestack:nebula:returner:splunk:indexer')
        sourcetype = __salt__['config.get']('hubblestack:nebula:returner:splunk:sourcetype')
        index = __salt__['config.get']('hubblestack:nebula:returner:splunk:index')
        custom_fields = __salt__['config.get']('hubblestack:nebula:returner:splunk:custom_fields', [])
    except:
        return None
    splunk_opts = {'token': token, 'indexer': indexer, 'sourcetype': sourcetype, 'index': index, 'custom_fields': custom_fields}

    hec_ssl = __salt__['config.get']('hubblestack:nebula:returner:splunk:hec_ssl', True)
    splunk_opts['http_event_server_ssl'] = hec_ssl
    splunk_opts['proxy'] = __salt__['config.get']('hubblestack:nebula:returner:splunk:proxy', {})
    splunk_opts['timeout'] = __salt__['config.get']('hubblestack:nebula:returner:splunk:timeout', 9.05)

    return splunk_opts


def send_splunk(event, index_override=None, sourcetype_override=None):
    # Get Splunk Options
    # init the payload
    payload = {}

    # Set up the event metadata
    if index_override is None:
        payload.update({'index': opts['index']})
    else:
        payload.update({'index': index_override})

    if sourcetype_override is None:
        payload.update({'sourcetype': opts['sourcetype']})
    else:
        payload.update({'sourcetype': sourcetype_override})

    # Add the event
    payload.update({'event': event})
    logging.info('Payload: %s' % json.dumps(payload))

    # fire it off
    hec.batchEvent(payload)
    return True


# Thanks to George Starcher for the http_event_collector class (https://github.com/georgestarcher/)
# Default batch max size to match splunk's default limits for max byte
# See http_input stanza in limits.conf; note in testing I had to limit to 100,000 to avoid http event collector breaking connection
# Auto flush will occur if next event payload will exceed limit

class http_event_collector:

    def __init__(self, token, http_event_server, host='', http_event_port='8088', http_event_server_ssl=True, max_bytes=_max_content_bytes, proxy=None, timeout=9.05):
        self.timeout = timeout
        self.token = token
        self.batchEvents = []
        self.maxByteLength = max_bytes
        self.currentByteLength = 0
        if proxy and http_event_server_ssl:
            self.proxy = {'https': 'https://{0}'.format(proxy)}
        elif proxy:
            self.proxy = {'http': 'http://{0}'.format(proxy)}
        else:
            self.proxy = {}

        # Set host to specified value or default to localhostname if no value provided
        if host:
            self.host = host
        else:
            self.host = socket.gethostname()

        # Build and set server_uri for http event collector
        # Defaults to SSL if flag not passed
        # Defaults to port 8088 if port not passed

        if http_event_server_ssl:
            buildURI = ['https://']
        else:
            buildURI = ['http://']
        for i in [http_event_server, ':', http_event_port, '/services/collector/event']:
            buildURI.append(i)
        self.server_uri = ''.join(buildURI)

        if http_event_collector_debug:
            print self.token
            print self.server_uri

    def sendEvent(self, payload, eventtime=''):
        # Method to immediately send an event to the http event collector

        headers = {'Authorization': 'Splunk ' + self.token}

        # If eventtime in epoch not passed as optional argument use current system time in epoch
        if not eventtime:
            eventtime = str(int(time.time()))

        # Fill in local hostname if not manually populated
        if 'host' not in payload:
            payload.update({'host': self.host})

        # Update time value on payload if need to use system time
        data = {'time': eventtime}
        data.update(payload)

        # send event to http event collector
        r = requests.post(self.server_uri, data=json.dumps(data), headers=headers, verify=http_event_collector_SSL_verify, proxies=self.proxy)

        # Print debug info if flag set
        if http_event_collector_debug:
            logger.debug(r.text)
            logger.debug(data)

    def batchEvent(self, payload, eventtime=''):
        # Method to store the event in a batch to flush later

        # Fill in local hostname if not manually populated
        if 'host' not in payload:
            payload.update({'host': self.host})

        payloadLength = len(json.dumps(payload))

        if (self.currentByteLength + payloadLength) > self.maxByteLength:
            self.flushBatch()
            # Print debug info if flag set
            if http_event_collector_debug:
                print 'auto flushing'
        else:
            self.currentByteLength = self.currentByteLength + payloadLength

        # If eventtime in epoch not passed as optional argument use current system time in epoch
        if not eventtime:
            eventtime = str(int(time.time()))

        # Update time value on payload if need to use system time
        data = {'time': eventtime}
        data.update(payload)

        self.batchEvents.append(json.dumps(data))

    def flushBatch(self):
        # Method to flush the batch list of events

        if len(self.batchEvents) > 0:
            headers = {'Authorization': 'Splunk ' + self.token}
            try:
                r = requests.post(self.server_uri, data=' '.join(self.batchEvents), headers=headers, verify=http_event_collector_SSL_verify, proxies=self.proxy, timeout=self.timeout)
            except requests.exceptions.Timeout:
                log.error('Request to splunk timed out. Not retrying.')
            except Exception as e:
                log.error('Request to splunk threw an error: {0}'.format(e))
            self.batchEvents = []
            self.currentByteLength = 0
