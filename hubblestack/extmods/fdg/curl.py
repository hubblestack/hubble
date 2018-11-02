# -*- encoding: utf-8 -*-
'''
Flexible Data Gathering: curl
=============================

This fdg module allows for querying against URLs

Note that this module doesn't actually shell out to curl. Instead, it uses
the requests library, primarily for performance concerns.

Also note that this module doesn't support chaining from other fdg modules.
This is due to security concerns -- because fdg can collect arbitrary data from
a system, we don't want an attacker to be able to send that data to arbitrary
endpoints.
'''
from __future__ import absolute_import
import json
import logging
import requests

from salt.exceptions import CommandExecutionError

log = logging.getLogger(__name__)


def request(url,
            port=80,
            function='GET',
            params=None,
            data=None,
            username=None,
            password=None,
            timeout=9,
            chained=None):
    '''
    Given a series of arguments, make a request using ``requests``.

    Note that this function doesn't support chained values (they are thrown
    away) due to security concerns.

    Returns will be a dict with 'status' (the http status code from the
    request) and 'response' (the json response from the server). The status
    piece of the fdg return will be based on the http status.

    url
        The endpoint to which the request will be sent

    port
        The port to use. 80 by default

    function
        GET, PUT, or POST

    params
        Optional. Parameters that will be included in the url.

    data
        Payload to include for POST/PUT

    username
        Used for auth

    password
        Used for auth

    timeout
        How long to wait for a request

    chained
        Ignored
    '''
    if chained:
        log.warn('Chained value detected in curl.request module. Chained '
                 'values are unsupported in the curl fdg module.')

    # Data validation and preparation
    kwargs = {}
    kwargs['port'] = port
    if params is not None:
        kwargs['params'] = params
    if data is not None:
        kwargs['data'] = data
    if username is not None:
        kwargs['auth'] = (username, password)
    kwargs['timeout'] = int(timeout)
    if function not in ('GET', 'PUT', 'POST'):
        log.error('Invalid request type {0}'.format(function))
        return False, {}

    # Make the request
    try:
        if function == 'GET':
            r = requests.get(url, **kwargs)
        elif function == 'PUT':
            r = requests.put(url, **kwargs)
        elif function == 'POST':
            r = requests.post(url, **kwargs)
    except Exception as e:
        return False, str(e)

    # Pull out the pieces we want
    ret = {}
    ret['status'] = r.status_code
    ret['response'] = r.json

    # Status in the return is based on http status
    try:
        r.raise_for_status()
        return True, ret
    except requests.exceptions.HTTPError as e:
        return False, ret
