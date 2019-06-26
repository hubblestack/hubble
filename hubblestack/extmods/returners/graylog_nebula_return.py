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

import json
import time
import requests
from datetime import datetime


def returner(ret):
    """
    """
    opts_list = _get_options()

    # Get cloud details
    cloud_details = __grains__.get('cloud_details', {})

    for opts in opts_list:
        proxy = opts['proxy']
        timeout = opts['timeout']
        custom_fields = opts['custom_fields']

        gelfhttp = opts['gelfhttp']
        port = opts['port']
        # assign all the things
        data = ret['return']
        minion_id = ret['id']
        jid = ret['jid']
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
        else:
            for query in data:
                for query_name, value in query.items():
                    for d in value['data']:
                        event = {}
                        payload = {}
                        event.update(d)
                        event.update({'query': query_name})
                        event.update({'job_id': jid})
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

                        # If the osquery query includes a field called 'time' it will be checked.
                        # If it's within the last year, it will be used as the eventtime.
                        event_time = d.get('time', '')
                        try:
                            if (datetime.fromtimestamp(time.time()) - datetime.fromtimestamp(float(event_time))).days > 365:
                                event_time = ''
                        except:
                            event_time = ''
                        finally:
                            rdy = json.dumps(payload)
                            requests.post('{}:{}/gelf'.format(gelfhttp, port), rdy)
    return


def _get_options():
    if __salt__['config.get']('hubblestack:returner:graylog'):
        graylog_opts = []
        returner_opts = __salt__['config.get']('hubblestack:returner:graylog')
        if not isinstance(returner_opts, list):
            returner_opts = [returner_opts]
        for opt in returner_opts:
            processed = {}
            processed['gelfhttp'] = opt.get('gelfhttp')
            processed['port'] = str(opt.get('port', '12022'))
            processed['custom_fields'] = opt.get('custom_fields', [])
            processed['sourcetype'] = opt.get('sourcetype_nebula', 'hubble_osquery')
            processed['gelfhttp_ssl'] = opt.get('gelfhttp_ssl', True)
            processed['proxy'] = opt.get('proxy', {})
            processed['timeout'] = opt.get('timeout', 9.05)
            graylog_opts.append(processed)
        return graylog_opts
    else:
        try:
            port = __salt__['config.get']('hubblestack:returner:graylog:port')
            gelfhttp = __salt__['config.get']('hubblestack:returner:graylog:gelfhttp')
            sourcetype = __salt__['config.get']('hubblestack:nebula:returner:graylog:sourcetype')
            custom_fields = __salt__['config.get']('hubblestack:nebula:returner:graylog:custom_fields', [])
        except:
            return None

        graylog_opts = {'gelfhttp': gelfhttp, 'sourcetype': sourcetype, 'custom_fields': custom_fields}

        gelfhttp_ssl = __salt__['config.get']('hubblestack:nebula:returner:graylog:gelfhttp_ssl', True)
        graylog_opts['http_input_server_ssl'] = gelfhttp_ssl
        graylog_opts['proxy'] = __salt__['config.get']('hubblestack:nebula:returner:graylog:proxy', {})
        graylog_opts['timeout'] = __salt__['config.get']('hubblestack:nebula:returner:graylog:timeout', 9.05)

        return [graylog_opts]
