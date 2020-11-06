# -*- encoding: utf-8 -*-
"""
Module curl
=============================

This module allows for querying against URLs

Note that this module doesn't actually shell out to curl. Instead, it uses
the requests library, primarily for performance concerns.

Also note that this module doesn't support chaining from other modules.
This is due to security concerns -- because Hubble can collect arbitrary data from
a system, we don't want an attacker to be able to send that data to arbitrary
endpoints.

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

import hubblestack.extmods.module_runner.runner_factory as runner_factory
import hubblestack.extmods.module_runner.runner_utils as runner_utils
from hubblestack.utils.hubble_error import HubbleCheckValidationError
from salt.exceptions import CommandExecutionError

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
