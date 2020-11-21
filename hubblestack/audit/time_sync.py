'''
This module checks the time of the host against some
NTP servers for differences bigger than 15 minutes.

Note: Now each module just returns its output (As Data gathering)
      For Audit checks, comparison logic is now moved to comparators. 
      See below sections for more understanding

Usable in Modules
-----------------
- Audit
- FDG

Common Schema
-------------
- check_unique_id
    Its a unique string within a yaml file.
    It is present on top of a yaml block

- description 
    Description of the check

- tag 
    (Applicable only for Audit)
    Check tag value

- sub_check (Optional, default: false) 
    (Applicable only for Audit)
    If true, its individual result will not be counted in compliance
    It might be referred in some boolean expression

- failure_reason (Optional) 
    (Applicable only for Audit)
    By default, module will generate failure reason string at runtime
    If this is passed, this will override module's actual failure reason

- invert_result (Optional, default: false) 
    (Applicable only for Audit)
    This is used to flip the boolean output from a check

- implementations
    (Applicable only for Audit)
    Its an array of implementations, usually for multiple operating systems.
    You can specify multiple implementations here for respective operating system.
    Either one or none will be executed.

- grains (under filter)
    (Applicable only for Audit)
    Any grains with and/or/not supported. This is used to filter whether 
    this check can run on the current OS or not.
    To run this check on all OS, put a '*'

    Example:
    G@docker_details:installed:True and G@docker_details:running:True and not G@osfinger:*Flatcar* and not G@osfinger:*CoreOS*

- hubble_version (Optional)
    (Applicable only for Audit)
    It acts as a second level filter where you can specify for which Hubble version,
    this check is compatible with. You can specify a boolean expression as well

    Example:
    '>3.0 AND <5.0'

- module
    The name of Hubble module.

- return_no_exec (Optional, Default: false)
    (Applicable only for Audit)
    It takes a boolean (true/false) value.
    If its true, the implementation will not be executed. And true is returned
    
    This can be useful in cases where you don't have any implementation for some OS,
    and you want a result from the block. Else, your meta-check(bexpr) will be failed.

- items
    (Applicable only for Audit)
    An array of multiple module implementations. At least one block is necessary.
    Each item in array will result into a boolean value.
    If multiple module implementations exists, final result will be evaluated as 
    boolean AND (default, see parameter: check_eval_logic)

- check_eval_logic (Optional, default: and)
    (Applicable only for Audit)
    If there are multiple module implementations in "items" (above parameter), this parameter
    helps in evaluating their result. Default value is "and"
    It accepts only values: and/or

- args
    Arguments specific to a module.

- comparator
    For the purpose of comparing output of module with expected values.
    Parameters depends upon the comparator used.
    For detailed documentation on comparators, 
    read comparator's implementations at (/hubblestack/extmods/comparators/)

FDG Schema
----------
FDG schema is kept simple. Only following keywords allowed:
- Unique id
    Unique string id
- description (Optional)
    Some description
- module
    Name of the module
- args
    Module arguments
- comparator (Only in case of Audit-FDG connector)

FDG Chaining
------------
In normal execution, this module expects list of ntp servers
In case of chaining, chained list of ntp servers will be merged

Module Arguments
----------------
- ntp_servers
    list of strings with NTP servers to query
- extend_chained
    boolean determining whether to format the ntp_servers with the chained value or not

Module Output
-------------
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

Output: (True, <Above dict>)

Note: Module returns a tuple
    First value being the status of module
    Second value is the actual output from module

Compatible Comparators
----------------------
- list

For detailed documentation on comparators,
read comparator's implementations at (/hubblestack/extmods/comparators/)

Comparison:
    For Audit check, you would want to do following comparison:
    - At least 4 servers replied with the offset <= 15

Audit Example:
---------------
check_unique_id:
  description: 'time_sync check'
  tag: 'ADOBE-01'
  sub_check: false (Optional, default: false)
  failure_reason: 'a sample failure reason' (Optional)
  invert_result: false (Optional, default: false)
  implementations:
    - filter:
        grains: 'G@osfinger:CentOS*Linux-7'
      hubble_version: '>3 AND <7 AND <8'
      # return_no_exec: true (Optional, default: false)
      check_eval_logic: and (Optional, default: and)
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
'''

import logging

import hubblestack.module_runner.runner_utils as runner_utils
from hubblestack.exceptions import HubbleCheckValidationError

import hubblestack.utils.platform

if not hubblestack.utils.platform.is_windows():
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
    log.debug('Executing time_sync module for id: {0}'.format(block_id))

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
    if hubblestack.utils.platform.is_windows():
        ret = __mods__['cmd.run']('w32tm /stripchart /computer:{0} /dataonly /samples:1'.format(
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
