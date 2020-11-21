# -*- encoding: utf-8 -*-
"""
Curl module for for querying against URLs

Note that this module doesn't actually shell out to curl. Instead, it uses
the requests library, primarily for performance concerns.

Also note that this module doesn't support chaining from other modules.
This is due to security concerns -- because Hubble can collect arbitrary data from
a system, we don't want an attacker to be able to send that data to arbitrary
endpoints.

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
This module does not accept value from chaining parameter due to security concerns.
Although you can use this in chaining, but no value will be passed through chaining.

Module Arguments
----------------
- url
    URL to query. Example: "https://adobe.com/someurl"
- function (Default: GET)
    Http method, Only allowed values (GET, PUT, POST)
- params (Optional)
    Query parameters to pass (as dictionary)
- data (Optional)
    payload for post/put
- headers (Optional)
    Http headers (as dictionary)
- username (Optional)
    Username to pass as part of authentication scheme
- password (Optional)
    Password to pass as part of authentication scheme
- timeout (Default: 9)
    Timeout value for http request
- decode_json (Default: true)
    Whether to decode http respose as json or not

Module Output
-------------
Output is pretty much depend upon the URL you are using. It can be a string/dictionary/json etc.
Example: [{"id": 1, "name": "John"}, {"id": 2, "name": "Maria"}]

Output: (True, [{"id": 1, "name": "John"}, {"id": 2, "name": "Maria"}])
Note: Module returns a tuple
    First value being the status of module
    Second value is the actual output from module

Compatible Comparators
----------------------
Since output is pretty dynamic. Following comparators can be used:
- string
- boolean
- list
- dict
- number

For detailed documentation on comparators,
read comparator's implementations at (/hubblestack/extmods/comparators/)


Audit Example:
---------------
check_unique_id:
  description: 'curl check'
  tag: 'ADOBE-01'
  implementations:
    - filter:
        grains: 'G@osfinger:CentOS*Linux-7'
      hubble_version: '>3 AND <7 AND <8'
      module: curl
      items:
        - args:
            url: "https://adobe.com/someurl"
            function: GET
            params:
                key1: val1
                key2: val2
            data: "payload for post/put"
            headers:
                header1: val1
                header2: val2
            username: user
            password: pwd
            timeout: 9
            decode_json: True

          comparator:
            type: "string"
            match: "host*"
            is_regex: true

Note: You can use any comparator depending upon the kind of data a url is returning.

FDG Example:
------------
main:
  description: 'curl check'
  module: curl
    args:
        url: "https://adobe.com/someurl"
        function: GET
        params:
            key1: val1
            key2: val2
        data: "payload for post/put"
        headers:
            header1: val1
            header2: val2
        username: user
        password: pwd
        timeout: 9
        decode_json: True

Mandatory Params:
    url
"""
import os
import logging
import requests

import hubblestack.module_runner.runner_factory as runner_factory
import hubblestack.module_runner.runner_utils as runner_utils
from hubblestack.exceptions import HubbleCheckValidationError
from hubblestack.exceptions import CommandExecutionError

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
        Example: {'caller': 'Audit'}

    Raises:
        HubbleCheckValidationError: For any validation error
    """
    log.debug('Module: curl Start validating params for check-id: {0}'.format(block_id))

    # fetch required param
    function_name = runner_utils.get_param_for_module(block_id, block_dict, 'function')
    if not function_name:
        function_name = 'GET'

    chain_error = {}
    chained_result = runner_utils.get_chained_param(extra_args)
    if chained_result:
        log.warning("Chained params are not supported in curl Module.")
        chain_error['chained_params'] = "Chained params found in CURL module, returning with error"
        raise HubbleCheckValidationError(chain_error)

    url = runner_utils.get_param_for_module(block_id, block_dict, 'url')

    error = {}
    if function_name not in ('GET', 'PUT', 'POST'):
        error['function'] = 'Invalid request type: {0}'.format(function_name)

    if not url:
        error['url'] = 'URL not passed'

    if error:
        raise HubbleCheckValidationError(error)

    log.debug('Validation success for check-id: {0}'.format(block_id))


def execute(block_id, block_dict, extra_args=None):
    """
    For getting params to log, in non-verbose logging

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param extra_args:
        Extra argument dictionary, (If any)

    returns:
        tuple of result(value) and status(boolean)
    """
    log.debug('Executing Curl module for id: {0}'.format(block_id))

    chained_param = runner_utils.get_chained_param(extra_args)
    if chained_param:
        log.warn('Chained value detected in curl.request module. Chained '
                 'values are unsupported in the curl module.')

    url = runner_utils.get_param_for_module(block_id, block_dict, 'url')

    kwargs = {}
    function_name = runner_utils.get_param_for_module(block_id, block_dict, 'function')
    if not function_name:
        function_name = 'GET'

    params = runner_utils.get_param_for_module(block_id, block_dict, 'params')
    if params:
        kwargs['params'] = params
    data = runner_utils.get_param_for_module(block_id, block_dict, 'data')
    if data:
        kwargs['data'] = data
    username = runner_utils.get_param_for_module(block_id, block_dict, 'username')
    password = runner_utils.get_param_for_module(block_id, block_dict, 'password')
    if username:
        kwargs['auth'] = (username, password)
    verify = runner_utils.get_param_for_module(block_id, block_dict, 'verify')
    if verify:
        kwargs['verify'] = verify
    headers = runner_utils.get_param_for_module(block_id, block_dict, 'headers')
    if headers:
        kwargs['headers'] = headers
    timeout = runner_utils.get_param_for_module(block_id, block_dict, 'timeout')
    if not timeout:
        timeout = 9
    kwargs['timeout'] = int(timeout)

    decode_json = runner_utils.get_param_for_module(block_id, block_dict, 'decode_json')
    if not decode_json:
        decode_json = True

    # Make the request
    status, response = _make_request(function_name, url, **kwargs)
    if not status:
        return runner_utils.prepare_negative_result_for_module(block_id, response)

    # Pull out the pieces we want
    ret = _parse_response(response, decode_json)

    # Status in the return is based on http status
    try:
        response.raise_for_status()
        return runner_utils.prepare_positive_result_for_module(block_id, ret)
    except requests.exceptions.HTTPError:
        return runner_utils.prepare_negative_result_for_module(block_id, ret)


def _make_request(function, url, **kwargs):
    """
    Helper function that makes the HTTP request
    """
    try:
        if function == 'GET':
            response = requests.get(url, **kwargs)
        elif function == 'PUT':
            response = requests.put(url, **kwargs)
        elif function == 'POST':
            response = requests.post(url, **kwargs)
    except Exception as exc:
        return False, str(exc)

    return True, response


def _parse_response(response, decode_json):
    """
    Helper function that extracts the status code and
    parses the response text.
    """
    ret = {'status': response.status_code}
    if decode_json:
        try:
            ret['response'] = response.json()
        except ValueError:
            ret['response'] = response.text
    else:
        ret['response'] = response.text

    return ret


def get_filtered_params_to_log(block_id, block_dict, extra_args=None):
    """
    For getting params to log, in non-verbose logging

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'caller': 'Audit'}
    """
    log.debug('get_filtered_params_to_log for id: {0}'.format(block_id))

    # fetch required param
    url = runner_utils.get_param_for_module(block_id, block_dict, 'url')

    return {'url': url}
