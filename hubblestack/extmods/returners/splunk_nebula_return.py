# -*- encoding: utf-8 -*-
'''
HubbleStack Nebula-to-Splunk returner

:maintainer: HubbleStack
:platform: All
:requires: SaltStack

Deliver HubbleStack Nebula query data into Splunk using the HTTP
event collector. Required config/pillar settings:

.. code-block:: yaml

    hubblestack:
      returner:
        splunk:
          - token: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
            indexer: splunk-indexer.domain.tld
            index: hubble
            sourcetype_nebula: hubble_osquery

You can also add an `custom_fields` argument which is a list of keys to add to events
with using the results of config.get(<custom_field>). These new keys will be prefixed
with 'custom_' to prevent conflicts. The values of these keys should be
strings or lists (will be sent as CSV string), do not choose grains or pillar values with complex values or they will
be skipped:

.. code-block:: yaml

    hubblestack:
      returner:
        splunk:
          - token: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
            indexer: splunk-indexer.domain.tld
            index: hubble
            sourcetype_nebula: hubble_osquery
            custom_fields:
              - site
              - product_group
'''
import socket
# Import AWS details
from aws_details import get_aws_details

# Imports for http event forwarder
import requests
import json
import time
from datetime import datetime

import logging

_max_content_bytes = 100000
http_event_collector_SSL_verify = False
http_event_collector_debug = False

log = logging.getLogger(__name__)

hec = None


def returner(ret):
    opts_list = _get_options()

    # Get aws details
    aws = get_aws_details()

    for opts in opts_list:
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
        if fqdn_ip4.startswith('127.'):
            for ip4_addr in __grains__['ipv4']:
                if ip4_addr and not ip4_addr.startswith('127.'):
                    fqdn_ip4 = ip4_addr
                    break

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

                        if aws['aws_account_id'] is not None:
                            event.update({'aws_ami_id': aws['aws_ami_id']})
                            event.update({'aws_instance_id': aws['aws_instance_id']})
                            event.update({'aws_account_id': aws['aws_account_id']})

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
                        if opts['add_query_to_sourcetype']:
                            payload.update({'sourcetype': "%s_%s" % (opts['sourcetype'], query_name)})
                        else:
                            payload.update({'sourcetype': opts['sourcetype']})
                        payload.update({'event': event})

                        # If the osquery query includes a field called 'time' it will be checked.
                        # If it's within the last year, it will be used as the eventtime.
                        event_time = query_result.get('time', '')
                        try:
                            if (datetime.fromtimestamp(time.time()) - datetime.fromtimestamp(float(event_time))).days > 365:
                                event_time = ''
                        except:
                            event_time = ''
                        finally:
                            hec.batchEvent(payload, eventtime=event_time)

        hec.flushBatch()
    return


def _get_options():
    if __salt__['config.get']('hubblestack:returner:splunk'):
        splunk_opts = []
        returner_opts = __salt__['config.get']('hubblestack:returner:splunk')
        if not isinstance(returner_opts, list):
            returner_opts = [returner_opts]
        for opt in returner_opts:
            processed = {}
            processed['token'] = opt.get('token')
            processed['indexer'] = opt.get('indexer')
            processed['index'] = opt.get('index')
            processed['custom_fields'] = opt.get('custom_fields', [])
            processed['sourcetype'] = opt.get('sourcetype_nebula', 'hubble_osquery')
            processed['add_query_to_sourcetype'] = opt.get('add_query_to_sourcetype', True)
            processed['http_event_server_ssl'] = opt.get('hec_ssl', True)
            processed['proxy'] = opt.get('proxy', {})
            processed['timeout'] = opt.get('timeout', 9.05)
            splunk_opts.append(processed)
        return splunk_opts
    else:
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

        return [splunk_opts]


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
        self.server_uri = []
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

        servers = http_event_server
        if not isinstance(servers, list):
            servers = [servers]
        for server in servers:
            if http_event_server_ssl:
                self.server_uri.append(['https://%s:%s/services/collector/event' % (server, http_event_port), True])
            else:
                self.server_uri.append(['http://%s:%s/services/collector/event' % (server, http_event_port), True])

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
            self.server_uri = [x for x in self.server_uri if x[1] is not False]
            for server in self.server_uri:
                try:
                    r = requests.post(server[0], data=' '.join(self.batchEvents), headers=headers, verify=http_event_collector_SSL_verify, proxies=self.proxy, timeout=self.timeout)
                    r.raise_for_status()
                    server[1] = True
                    break
                except requests.exceptions.RequestException:
                    log.info('Request to splunk server "%s" failed. Marking as bad.' % server[0])
                    server[1] = False
                except Exception as e:
                    log.error('Request to splunk threw an error: {0}'.format(e))
            self.batchEvents = []
            self.currentByteLength = 0
