# -*- encoding: utf-8 -*-
"""
HubbleStack Nebula-to-graylog (http input) returner

Deliver HubbleStack Nebula query data into graylog using the HTTP input
plugin. Required config/pillar settings:

.. code-block:: yaml

hubblestack:
  returner:
    graylog:
      - port: 12202
        proxy: {}
        timeout: 10
        gelfhttp_ssl: True
        sourcetype_nebula: hubble_osquery
        sourcetype_pulsar: hubble_fim
        sourcetype_nova: hubble_audit
        gelfhttp: https://graylog-gelf-http-input-addr

"""

from __future__ import absolute_import

import json
import time
import requests
from datetime import datetime
import hubblestack.extmods.returners.common.graylog as graylog


def returner(ret):
    """
    """
    opts_list = graylog.get_options('nebula')

    # Get cloud details
    cloud_details = __grains__.get('cloud_details', {})

    for opts in opts_list:
        custom_fields = opts['custom_fields']
        gelfhttp = opts['gelfhttp']
        port = opts['port']
        # assign all the things
        data = ret['return']
        minion_id = ret['id']

        fqdn = __grains__['fqdn']
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

        for query in data:
            for query_name, value in query.items():
                for d in value['data']:
                    payload = {}
                    event = {}
                    event.update(d)
                    event.update({'query': query_name})
                    event.update({'job_id': ret['jid']})
                    event.update({'minion_id': minion_id})
                    event.update({'dest_host': fqdn})
                    event.update({'dest_ip': fqdn_ip4})
                    event.update(cloud_details)

                    for custom_field in custom_fields:
                        custom_field_name = 'custom_' + custom_field
                        custom_field_value = __salt__['config.get'](custom_field, '')
                        if isinstance(custom_field_value, str):
                            event.update({custom_field_name: custom_field_value})
                        elif isinstance(custom_field_value, list):
                            custom_field_value = ','.join(custom_field_value)
                            event.update({custom_field_name: custom_field_value})

                    payload.update({'host': fqdn})
                    payload.update({'_sourcetype': opts['sourcetype']})
                    payload.update({'short_message': 'hubblestack'})
                    payload.update({'hubblemsg': event})

                    rdy = json.dumps(payload)
                    requests.post('{}:{}/gelf'.format(gelfhttp, port), rdy)
    return
