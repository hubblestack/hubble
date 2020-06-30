# -*- encoding: utf-8 -*-
"""
HubbleStack Nova-to-sumo (http input) returner

Deliver HubbleStack Nova data into sumo using the HTTP input
plugin. Required config/pillar settings:

.. code-block:: yaml

hubblestack:
  returner:
    sumo:
      - proxy: {}
        timeout: 10
        sumo_nebula_return: https://yoursumo.sumologic.com/endpointhere
        sumo_pulsar_return: https://yoursumo.sumologic.com/endpointhere
        sumo_nova_return: https://yoursumo.sumologic.com/endpointhere

"""

import json
import requests
import logging

log = logging.getLogger(__name__)


def returner(ret):
    """
    Gather nova data and send it to sumo
    """
    # Sanity check
    data = ret['return']
    if not isinstance(data, dict):
        log.error('Data sent to sumo_nova_return was not formed as a dict:\n%s', data)
        return

    args = _build_args(ret)
    opts_list = _get_options()
    # Get cloud details
    cloud_details = __grains__.get('cloud_details', {})

    for opts in opts_list:
        sumo_nova_return = opts['sumo_nova_return']
        # Failure checks
        _publish_data(args=args, checks=data.get('Failure', []), check_result='Failure',
                      cloud_details=cloud_details, sumo_nova_return=sumo_nova_return)
        # Success checks
        _publish_data(args=args, checks=data.get('Success', []), check_result='Success',
                      cloud_details=cloud_details, sumo_nova_return=sumo_nova_return)
        # Compliance check
        if data.get('Compliance', None):
            args['compliance_percentage'] = data['Compliance']
            event = _generate_event(args=args, cloud_details=cloud_details, compliance=True)
            _publish_event(event=event, sumo_nova_return=sumo_nova_return)

    return


def _get_options():
    """
    Function that aggregates the configs for sumo and returns them as a list of dicts.
    """
    if __salt__['config.get']('hubblestack:returner:sumo'):
        sumo_opts = []
        returner_opts = __salt__['config.get']('hubblestack:returner:sumo')
        if not isinstance(returner_opts, list):
            returner_opts = [returner_opts]
        for opt in returner_opts:
            processed = {'sumo_nova_return': opt.get('sumo_nova_return'),
                         'proxy': opt.get('proxy', {}),
                         'timeout': opt.get('timeout', 9.05)}
            sumo_opts.append(processed)
        return sumo_opts
    try:
        sumo_nova_return = __salt__['config.get']('hubblestack:returner:sumo:sumo_nova_return')
    except Exception:
        return None

    sumo_opts = {'sumo_nova_return': sumo_nova_return,
                 'proxy': __salt__['config.get']('hubblestack:nova:returner:sumo:proxy', {}),
                 'timeout': __salt__['config.get']('hubblestack:nova:returner:sumo:timeout',
                                                   9.05)}

    return [sumo_opts]


def _generate_event(args, cloud_details, compliance=False, data=None):
    """
    Helper function that builds and returns the event dict
    """
    event = {'job_id': args['job_id']}
    if compliance:
        event['compliance_percentage'] = args['compliance_percentage']
    else:
        event.update({'check_result': args['check_result'],
                      'check_id': args['check_id']})
        if not isinstance(data[args['check_id']], dict):
            event.update({'description': data[args['check_id']]})
        elif 'description' in data[args['check_id']]:
            for key, value in data[args['check_id']].items():
                if key not in ['tag']:
                    event[key] = value
    event.update({'minion_id': args['minion_id'],
                  'dest_host': args['fqdn'],
                  'dest_ip': args['fqdn_ip4']})
    event.update(cloud_details)

    return event


def _publish_event(event, sumo_nova_return):
    """
    Publish the event to sumo
    """
    rdy = json.dumps(event)
    requests.post('{}/'.format(sumo_nova_return), rdy)


def _publish_data(args, checks, check_result, cloud_details, sumo_nova_return):
    """
    Helper function that goes over the failure/success checks and publishes the event to sumo
    """
    for data in checks:
        check_id = list(data.keys())[0]
        args['check_result'] = check_result
        args['check_id'] = check_id
        event = _generate_event(data=data, args=args, cloud_details=cloud_details)
        _publish_event(event=event, sumo_nova_return=sumo_nova_return)


def _build_args(ret):
    """
    Helper function that builds the args that will be passed on to the event - cleaner way of
    processing the variables we care about
    """
    # Sometimes fqdn is blank. If it is, replace it with minion_id
    fqdn = __grains__['fqdn'] if __grains__['fqdn'] else ret['id']
    try:
        fqdn_ip4 = __grains__['fqdn_ip4'][0]
    except IndexError:
        fqdn_ip4 = __grains__['ipv4'][0]
    if fqdn_ip4.startswith('127.'):
        for ip4_addr in __grains__['ipv4']:
            if ip4_addr and not ip4_addr.startswith('127.'):
                fqdn_ip4 = ip4_addr
                break

    return {'minion_id': ret['id'],
            'job_id': ret['jid'],
            'fqdn': fqdn,
            'fqdn_ip4': fqdn_ip4}
