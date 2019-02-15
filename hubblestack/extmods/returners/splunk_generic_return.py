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
from hubblestack.hec import http_event_collector, get_splunk_options

def _get_key(dat, k, d=None):
    if isinstance(dat, dict):
        return dat.pop(k, d)
    return d

def returner(retdata):
    try:
        retdata = retdata['return']
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

        t_sourcetype = _get_key(retdata, 'sourcetype', 'hubble_generic')
        t_time       = _get_key(retdata, 'time', time.time())
        events       = _get_key(retdata, 'event', _get_key(retdata, 'events'))

        if events is None:
            return

        if not isinstance(events, (list,tuple)):
            events = [events]

        if len(events) < 1 or (len(events) == 1 and events[0] is None):
            return

        for event in events:
            payload = {'host': __grains__.get('fqdn', __grains__.get('id')), 'event': event,
                'sourcetype': _get_key(event, 'sourcetype', t_sourcetype),
                'time': str(int(_get_key(event, 'time', t_time)))}
            hec.batchEvent(payload)
        hec.flushBatch()
