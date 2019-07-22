# -*- encoding: utf-8 -*-
"""
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
"""

import time
import hubblestack.utils.stdrec as stdrec
from hubblestack.hec import http_event_collector, get_splunk_options, make_hec_args


def _get_key(dat, key, default_value=None):
    """
    Function that emulates the `dict.pop` behavior.
    Filters out structures that are not dict.

    dat
        The dictionary to execute `pop` on

    key
        The key to be removed

    default_value
        The value to be returned if `key` is not found in `dat`
        or if `dat` is not a dict
    """
    if isinstance(dat, dict):
        return dat.pop(key, default_value)

    return default_value


def _build_hec(opts):
    """
    Extract the appropriate parameters from opts,
    create and return the http_event_collector

    opts
        dict containing Splunk options to be passed to the `http_event_collector`
    """
    args, kwargs = make_hec_args(opts)
    hec = http_event_collector(*args, **kwargs)
    return hec


def returner(retdata):
    """
    Build the event and send it to the http event collector
    to have it published to Splunk

    retdata
        A dict containing the data to be returned
    """
    try:
        retdata = retdata['return']
    except KeyError:
        return

    opts_list = get_splunk_options()
    for opts in opts_list:
        hec = _build_hec(opts)
        t_sourcetype = _get_key(retdata, 'sourcetype', 'hubble_generic')
        t_time = _get_key(retdata, 'time', time.time())
        events = _get_key(retdata, 'event', _get_key(retdata, 'events'))

        if events is None:
            return

        if not isinstance(events, (list, tuple)):
            events = [events]

        if len(events) < 1 or (len(events) == 1 and events[0] is None):
            return

        idx = opts.get('index')

        for event in events:
            payload = {
                'host': stdrec.get_fqdn(),
                'event': event,
                'sourcetype': _get_key(event, 'sourcetype', t_sourcetype),
                'time': str(int(_get_key(event, 'time', t_time)))}
            if idx:
                payload['index'] = idx
            # add various std host info data and index extracted fields
            stdrec.update_payload(payload)
            hec.batchEvent(payload)
        hec.flushBatch()
