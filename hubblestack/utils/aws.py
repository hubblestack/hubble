# -*- coding: utf-8 -*-
'''
Connection library for AWS

.. versionadded:: 2015.5.0

This is a base library used by a number of AWS services.

:depends: requests
'''
from __future__ import absolute_import, print_function, unicode_literals

# Import Python libs
import time
from datetime import datetime
import hashlib
import hmac
import logging
import hubblestack.config
import re

import hubblestack.utils.hashutils

try:
    import requests
    HAS_REQUESTS = True  # pylint: disable=W0612
except ImportError:
    HAS_REQUESTS = False  # pylint: disable=W0612
# pylint: disable=import-error,redefined-builtin,no-name-in-module
from urllib.parse import urlencode

log = logging.getLogger(__name__)
DEFAULT_LOCATION = 'us-east-1'
DEFAULT_AWS_API_VERSION = '2014-10-01'
AWS_RETRY_CODES = [
    'RequestLimitExceeded',
    'InsufficientInstanceCapacity',
    'InternalError',
    'Unavailable',
    'InsufficientAddressCapacity',
    'InsufficientReservedInstanceCapacity',
]
AWS_METADATA_TIMEOUT = 3.05

AWS_MAX_RETRIES = 7

IROLE_CODE = 'use-instance-role-credentials'
__AccessKeyId__ = ''
__SecretAccessKey__ = ''
__Token__ = ''
__Expiration__ = ''
__Location__ = ''
__AssumeCache__ = {}

def _sign(key, msg):
    '''
    Key derivation functions. See:

    http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-python
    '''
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


def _sig_key(key, date_stamp, regionName, serviceName):
    '''
    Get a signature key. See:

    http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-python
    '''
    kDate = _sign(('AWS4' + key).encode('utf-8'), date_stamp)
    if regionName:
        kRegion = _sign(kDate, regionName)
        kService = _sign(kRegion, serviceName)
    else:
        kService = _sign(kDate, serviceName)
    kSigning = _sign(kService, 'aws4_request')
    return kSigning


def assumed_creds(prov_dict, role_arn, location=None):
    valid_session_name_re = re.compile("[^a-z0-9A-Z+=,.@-]")

    # current time in epoch seconds
    now = time.mktime(datetime.utcnow().timetuple())

    for key, creds in __AssumeCache__.items():
        if (creds["Expiration"] - now) <= 120:
            __AssumeCache__.delete(key)

    if role_arn in __AssumeCache__:
        c = __AssumeCache__[role_arn]
        return c["AccessKeyId"], c["SecretAccessKey"], c["SessionToken"]

    version = "2011-06-15"
    session_name = valid_session_name_re.sub('', hubblestack.config.get_id({"root_dir": None})[0])[0:63]

    headers, requesturl = sig4(
        'GET',
        'sts.amazonaws.com',
        params={
            "Version": version,
            "Action": "AssumeRole",
            "RoleSessionName": session_name,
            "RoleArn": role_arn,
            "Policy": '{"Version":"2012-10-17","Statement":[{"Sid":"Stmt1", "Effect":"Allow","Action":"*","Resource":"*"}]}',
            "DurationSeconds": "3600"
        },
        aws_api_version=version,
        data='',
        uri='/',
        prov_dict=prov_dict,
        product='sts',
        location=location,
        requesturl="https://sts.amazonaws.com/"
    )
    headers["Accept"] = "application/json"
    result = requests.request('GET', requesturl, headers=headers,
                              data='',
                              verify=True)

    if result.status_code >= 400:
        log.info('AssumeRole response: %s', result.content)
    result.raise_for_status()
    resp = result.json()

    data = resp["AssumeRoleResponse"]["AssumeRoleResult"]["Credentials"]
    __AssumeCache__[role_arn] = data
    return data["AccessKeyId"], data["SecretAccessKey"], data["SessionToken"]


def creds(provider):
    '''
    Return the credentials for AWS signing.  This could be just the id and key
    specified in the provider configuration, or if the id or key is set to the
    literal string 'use-instance-role-credentials' creds will pull the instance
    role credentials from the meta data, cache them, and provide them instead.
    '''
    # Declare globals
    global __AccessKeyId__, __SecretAccessKey__, __Token__, __Expiration__

    ret_credentials = ()

    # if id or key is 'use-instance-role-credentials', pull them from meta-data
    ## if needed
    if provider['id'] == IROLE_CODE or provider['key'] == IROLE_CODE:
        # Check to see if we have cache credentials that are still good
        if __Expiration__ != '':
            timenow = datetime.utcnow()
            timestamp = timenow.strftime('%Y-%m-%dT%H:%M:%SZ')
            if timestamp < __Expiration__:
                # Current timestamp less than expiration fo cached credentials
                return __AccessKeyId__, __SecretAccessKey__, __Token__
        # We don't have any cached credentials, or they are expired, get them

        # Connections to instance meta-data must fail fast and never be proxied
        try:
            result = requests.get(
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                proxies={'http': ''}, timeout=AWS_METADATA_TIMEOUT,
            )
            result.raise_for_status()
            role = result.text
        except (requests.exceptions.HTTPError, requests.exceptions.ConnectionError):
            return provider['id'], provider['key'], ''

        try:
            result = requests.get(
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/{0}".format(role),
                proxies={'http': ''}, timeout=AWS_METADATA_TIMEOUT,
            )
            result.raise_for_status()
        except (requests.exceptions.HTTPError, requests.exceptions.ConnectionError):
            return provider['id'], provider['key'], ''

        data = result.json()
        __AccessKeyId__ = data['AccessKeyId']
        __SecretAccessKey__ = data['SecretAccessKey']
        __Token__ = data['Token']
        __Expiration__ = data['Expiration']

        ret_credentials = __AccessKeyId__, __SecretAccessKey__, __Token__
    else:
        ret_credentials = provider['id'], provider['key'], ''

    if provider.get('role_arn') is not None:
        provider_shadow = provider.copy()
        provider_shadow.pop("role_arn", None)
        log.info("Assuming the role: %s", provider.get('role_arn'))
        ret_credentials = assumed_creds(provider_shadow, role_arn=provider.get('role_arn'), location='us-east-1')

    return ret_credentials


def sig4(method, endpoint, params, prov_dict,
         aws_api_version=DEFAULT_AWS_API_VERSION, location=None,
         product='ec2', uri='/', requesturl=None, data='', headers=None,
         role_arn=None, payload_hash=None):
    '''
    Sign a query against AWS services using Signature Version 4 Signing
    Process. This is documented at:

    http://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
    http://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html
    http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
    '''
    timenow = datetime.utcnow()

    # Retrieve access credentials from meta-data, or use provided
    if role_arn is None:
        access_key_id, secret_access_key, token = creds(prov_dict)
    else:
        access_key_id, secret_access_key, token = assumed_creds(prov_dict, role_arn, location=location)

    if location is None:
        location = get_region_from_metadata()
    if location is None:
        location = DEFAULT_LOCATION

    params_with_headers = params.copy()
    if product not in ('s3', 'ssm'):
        params_with_headers['Version'] = aws_api_version
    keys = sorted(params_with_headers.keys())
    values = list(map(params_with_headers.get, keys))
    querystring = urlencode(list(zip(keys, values))).replace('+', '%20')

    amzdate = timenow.strftime('%Y%m%dT%H%M%SZ')
    datestamp = timenow.strftime('%Y%m%d')
    new_headers = {}
    if isinstance(headers, dict):
        new_headers = headers.copy()

    # Create payload hash (hash of the request body content). For GET
    # requests, the payload is an empty string ('').
    if not payload_hash:
        payload_hash = hubblestack.utils.hashutils.sha256_digest(data)

    new_headers['X-Amz-date'] = amzdate
    new_headers['host'] = endpoint
    new_headers['x-amz-content-sha256'] = payload_hash
    a_canonical_headers = []
    a_signed_headers = []

    if token != '':
        new_headers['X-Amz-security-token'] = token

    for header in sorted(new_headers.keys(), key=str.lower):
        lower_header = header.lower()
        a_canonical_headers.append('{0}:{1}'.format(lower_header, new_headers[header].strip()))
        a_signed_headers.append(lower_header)
    canonical_headers = '\n'.join(a_canonical_headers) + '\n'
    signed_headers = ';'.join(a_signed_headers)

    algorithm = 'AWS4-HMAC-SHA256'

    # Combine elements to create create canonical request
    canonical_request = '\n'.join((
        method,
        uri,
        querystring,
        canonical_headers,
        signed_headers,
        payload_hash
    ))

    # Create the string to sign
    credential_scope = '/'.join((datestamp, location, product, 'aws4_request'))
    string_to_sign = '\n'.join((
        algorithm,
        amzdate,
        credential_scope,
        hubblestack.utils.hashutils.sha256_digest(canonical_request)
    ))

    # Create the signing key using the function defined above.
    signing_key = _sig_key(
        secret_access_key,
        datestamp,
        location,
        product
    )

    # Sign the string_to_sign using the signing_key
    signature = hmac.new(
        signing_key,
        string_to_sign.encode('utf-8'),
        hashlib.sha256).hexdigest()

    # Add signing information to the request
    authorization_header = (
            '{0} Credential={1}/{2}, SignedHeaders={3}, Signature={4}'
        ).format(
            algorithm,
            access_key_id,
            credential_scope,
            signed_headers,
            signature,
        )

    new_headers['Authorization'] = authorization_header

    requesturl = '{0}?{1}'.format(requesturl, querystring)
    return new_headers, requesturl


def get_location(opts=None, provider=None):
    '''
    Return the region to use, in this order:
        opts['location']
        provider['location']
        get_region_from_metadata()
        DEFAULT_LOCATION
    '''
    if opts is None:
        opts = {}
    ret = opts.get('location')
    if ret is None and provider is not None:
        ret = provider.get('location')
    if ret is None:
        ret = get_region_from_metadata()
    if ret is None:
        ret = DEFAULT_LOCATION
    return ret


def get_region_from_metadata():
    '''
    Try to get region from instance identity document and cache it

    .. versionadded:: 2015.5.6
    '''
    global __Location__

    if __Location__ == 'do-not-get-from-metadata':
        log.debug('Previously failed to get AWS region from metadata. Not trying again.')
        return None

    # Cached region
    if __Location__ != '':
        return __Location__

    try:
        # Connections to instance meta-data must fail fast and never be proxied
        result = requests.get(
            "http://169.254.169.254/latest/dynamic/instance-identity/document",
            proxies={'http': ''}, timeout=AWS_METADATA_TIMEOUT,
        )
    except requests.exceptions.RequestException:
        log.warning('Failed to get AWS region from instance metadata.', exc_info=True)
        # Do not try again
        __Location__ = 'do-not-get-from-metadata'
        return None

    try:
        region = result.json()['region']
        __Location__ = region
        return __Location__
    except (ValueError, KeyError):
        log.warning('Failed to decode JSON from instance metadata.')
        return None

    return None