# -*- encoding: utf-8 -*-
'''
generic data to splunk returner

Deliver generic HubbleStack event data into Splunk using the HTTP
event collector. Required config/pillar settings:

.. code-block:: yaml

    hubblestack:
      returner:
        generic:
          - token: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
            indexer: splunk-indexer.domain.tld
            index: hubble
            sourcetype_pulsar: generic
'''

import time
import logging
from hubblestack.hec import http_event_collector, get_splunk_options

log = logging.getLogger(__name__)

def _get_key(dat, k, d=None):
    if isinstance(dat, dict):
        return dat.pop(k, d)
    return d

def returner(ret):
    try:
        event = ret['return']
    except KeyError:
        return

    opts_list = get_splunk_options()
    for opts in opts_list:
        http_event_collector_key = opts['token']
        http_event_collector_host = opts['indexer']
        http_event_collector_port = opts['port']
        hec_ssl = opts['http_event_server_ssl']
        proxy = opts['proxy']
        timeout = opts['timeout']
        http_event_collector_ssl_verify = opts['http_event_collector_ssl_verify']

        hec = http_event_collector(http_event_collector_key, http_event_collector_host,
                                   http_event_port=http_event_collector_port, http_event_server_ssl=hec_ssl,
                                   http_event_collector_ssl_verify=http_event_collector_ssl_verify,
                                   proxy=proxy, timeout=timeout)

        now = str(int(time.time()))
        t_sourcetype = _get_key(event, 'sourcetype', 'hubble_generic')
        t_time       = _get_key(event, 'time', now)
        event        = _get_key(event, 'event', event)
        events       = _get_key(event, 'events', event)

        if not isinstance(events, (list,tuple)):
            events = [events]

        for event in events:
            payload = {'host': __grains__.get('fqdn', __grains__.get('id')), 'event': event,
                'sourcetype': _get_key(event, 'sourcetype', t_sourcetype),
                'time': _get_key(event, 'time', t_time) }
            log.debug("batching payload: %s", payload)
            time.sleep(2)
            hec.batchEvent(payload)
        hec.flushBatch()
