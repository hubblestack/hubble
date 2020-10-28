'''
Flexible Data Gathering: time_sync

This module checks the time of the host against some
NTP servers for differences bigger than 15 minutes.

Optional params:
    ntp_servers
        list of strings with NTP servers to query

    extend_chained
        boolean determining whether to format the ntp_servers with the chained value or not

Return data example:
    [
        {
            'ntp_server': 'server1',
            'replied': True,
            'offset': 0.22
        },
        {
            'ntp_server': 'server2',
            'replied': True,
            'offset': 0.04
        }
    ]

Comparison:
    For Audit check, you would want to do following comparison:
    - At least 4 servers replied with the offset <= 15

Audit Example:
---------------
check_unique_id:
  description: 'time_sync check'
  tag: 'ADOBE-01'
  implementations:
    - filter:
        grains: 'G@osfinger:CentOS*Linux-7'
      hubble_version: '>3 AND <7 AND <8'
      module: time_sync
      items:
        - args:
            ntp_servers:
                - server1
                - server2
                - server3
                - server4
                - server5
            extend_chained: true  #optional

          comparator:
            type: list
            filter_compare:
                filter: 
                    replied: true
                    offset: 
                        type: number
                        match: <= 15
                    compare:
                        size: >= 4

FDG Example:
------------
main:
  description: 'time_sync check'
  module: time_sync
    args:
        ntp_servers:
            - server1
            - server2
        extend_chained: true #optional

Mandatory Params:
    This module requires ntp_servers. That come either from args, or from chaining, or both
'''

import logging

import hubblestack.extmods.module_runner.runner_utils as runner_utils
from hubblestack.utils.hubble_error import HubbleCheckValidationError

import salt.utils.platform

if not salt.utils.platform.is_windows():
    import ntplib
log = logging.getLogger(__name__)


def validate_params(block_id, block_dict, extra_args=None):
    """
    Validate all mandatory params required for this module

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'chaining_args': {'result': ['server1', 'server2'], 'status': True},
                  'caller': 'Audit'}

    Raises:
        HubbleCheckValidationError: For any validation error
    """
    log.debug('Module: time_sync Start validating params for check-id: {0}'.format(block_id))

    ntp_servers = _get_ntp_servers(block_id, block_dict, extra_args)

    if not ntp_servers:
        raise HubbleCheckValidationError('No ntp_servers provided')

    log.debug('Validation success for check-id: {0}'.format(block_id))


def execute(block_id, block_dict, extra_args=None):
    """
    Function that queries a list of NTP servers and checks if the
    offset is bigger than `max_offset` minutes. It expects the results from
    at least `nb_servers` servers in the list, otherwise the check fails.

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'chaining_args': {'result': ['server1', 'server2'], 'status': True},
                  'caller': 'Audit'}

    returns:
        tuple of result(value) and status(boolean)
    """
    log.debug('Executing stat module for id: {0}'.format(block_id))

    ntp_servers = _get_ntp_servers(block_id, block_dict, extra_args)

    time_sync_result = []

    for ntp_server in ntp_servers:
        offset = _query_ntp_server(ntp_server)
        if not offset:
            time_sync_result.append({
                'ntp_server': ntp_server,
                'replied': False
            })
            continue

        time_sync_result.append({
            'ntp_server': ntp_server,
            'replied': True,
            'offset': offset
        })

    return runner_utils.prepare_positive_result_for_module(block_id, time_sync_result)


def get_filtered_params_to_log(block_id, block_dict, extra_args=None):
    """
    For getting params to log, in non-verbose logging

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'chaining_args': {'result': ['server1', 'server2'], 'status': True},
                  'caller': 'Audit'}
    """
    log.debug('get_filtered_params_to_log for id: {0}'.format(block_id))

    # fetch required param
    ntp_servers = _get_ntp_servers(block_id, block_dict, extra_args)
    return {'ntp_servers': ntp_servers}


def _get_ntp_servers(block_id, block_dict, extra_args):
    ntp_servers = runner_utils.get_param_for_module(block_id, block_dict, 'ntp_servers')
    ntp_servers_chained = runner_utils.get_chained_param(extra_args)

    extend_chained = runner_utils.get_param_for_module(block_id, block_dict, 'extend_chained', True)
    if extend_chained:
        if ntp_servers:
            if ntp_servers_chained:
                ntp_servers.extend(ntp_servers_chained)
        else:
            ntp_servers = ntp_servers_chained

    return ntp_servers


def _query_ntp_server(ntp_server):
    """
    Query the `ntp_server`, extracts and returns the offset in seconds.
    If an error occurs, or the server does not return the expected output -
    if it cannot be reached for example - it returns None.

    ntp_server
        string containing the NTP server to query
    """
    # use w32tm instead of ntplib
    if salt.utils.platform.is_windows():
        ret = __salt__['cmd.run']('w32tm /stripchart /computer:{0} /dataonly /samples:1'.format(
            ntp_server))
        try:
            return float(ret.split('\n')[-1].split()[1][:-1])
        except (ValueError, AttributeError, IndexError):
            log.error("An error occured while querying the server: %s", ret)
            return None

    ret = None
    try:
        ntp_client = ntplib.NTPClient()
        response = ntp_client.request(ntp_server, version=3)
        ret = response.offset
    except Exception:
        log.error("Unexpected error occured while querying the server.", exc_info=True)

    return ret
