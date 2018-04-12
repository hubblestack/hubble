# -*- encoding: utf-8 -*-
'''
HubbleStack Nova module for auditing SSL certificates.

:maintainer: HubbleStack / avb76
:maturity: 2016.7.0
:platform: Linux
:requires: SaltStack, python-OpenSSL

This audit module requires YAML data to execute. It will search the yaml data
received for the topkey 'openssl'.

Sample YAML data, with in line comments:

openssl:
  google:
    data:
      tag: 'CERT-001'                   # required
      endpoint: 'www.google.com'        # required only if file is not defined
      file: null                        # required only if endpoint is not defined
      port: 443                         # optional
      not_after: 15                      # optional
      not_before: 2                      # optional
      fail_if_not_before: False         # optional
    description: 'google certificate'
    labels:
      - critical
      - raiseticket

Some words about the elements in the data dictionary:
    - tag: this is the tag of the check
    - endpoint:
        - the ssl endpoint to check
        - the module will download the SSL certificate of the endpoint
        - endpoint is required only if file is not defined (read bellow)
    file:
        - the path to the pem file containing the SSL certificate to be checked
        - the path is relative to the minion
        - the module will try to read the certificate from this file
        - if no certificate can be loaded by the OpenSSL library, the check will be failed
        - file is required only if endpoint is not defined (read more about this bellow)
    port:
        - the port is required only if both:
            - the endpoint is defined
            - https is configured on another port the 443 on the endpoint
        - WARNING: if the port is not the on configured for https on the endpoint, downloading the certificate from
          the endpoint will timeout and the check will be failed
        - if endpoint is defined but the port is not, the module will try, by default, to use port 443
    not_after:
        - the minimum number of days left until the certificate should expire
        - if the certificate will expire in less then the value given here, the check will fail
        - if not_after is missing, the default value is 0; basically, the if the expiration date is in the future, the
          check will be passed
    not_before:
        - the expected number of days until the certificate becomes valid
        - this is useful only if you expect the certificate to be valid after a certain date
        - if missing, 0 is the default value (read more bellow)
    fail_if_not_before:
        - if True, the check will fail only if not_before is 0 (or missing): if the certificate is not valid yet, but
          it is expected to be
        - the default value is False - the check will fail only if the certificate expiration date is valid

Some notes:
    - if BOTH file and endpoint are present / missing, the check will fail; only one certificate has to be present for
      each check
    - the YAML supports also the control key, just as the other modules do

Known issues: for unknown reasons (yet), the module can fail downloading the certificate from certain endpoints. When
this happens, the check will be failed.

'''

from __future__ import absolute_import
import logging

import fnmatch
import copy
import salt.utils
import salt.utils.platform
import datetime
import time

import ssl

try:
    import OpenSSL

    _HAS_OPENSSL = True
except ImportError:
    _HAS_OPENSSL = False

log = logging.getLogger(__name__)

__tags__ = None
__data__ = None


def __virtual__():
    if salt.utils.platform.is_windows():
        return False, 'This audit module only runs on linux'
    if not _HAS_OPENSSL:
        return (False, 'The python-OpenSSL library is missing')
    return True

def apply_labels(__data__, labels):
    '''
    Filters out the tests whose label doesn't match the labels given when running audit and returns a new data structure with only labelled tests.
    '''
    ret={}
    if labels:
        labelled_test_cases=[]
        for test_case in __data__.get('openssl', []):
            # each test case is a dictionary with just one key-val pair. key=test name, val=test data, description etc
            if isinstance(test_case, dict) and test_case:
                test_case_body = test_case.get(next(iter(test_case)))
                if test_case_body.get('labels') and set(labels).issubset(set(test_case_body.get('labels',[]))):
                    labelled_test_cases.append(test_case)
        ret['openssl']=labelled_test_cases
    else:
        ret=__data__
    return ret

def audit(data_list, tags, labels, debug=True, **kwargs):
    __data__ = {}
    for profile, data in data_list:
        _merge_yaml(__data__, data, profile)
    __data__ = apply_labels(__data__, labels)
    __tags__ = _get_tags(__data__)

    if debug:
        log.debug('service audit __data__:')
        log.debug(__data__)
        log.debug('service audit __tags__:')
        log.debug(__tags__)

    ret = {'Success': [], 'Failure': [], 'Controlled': []}
    for tag in __tags__:
        if fnmatch.fnmatch(tag, tags):
            for tag_data in __tags__[tag]:
                if 'control' in tag_data:
                    ret['Controlled'].append(tag_data)
                    continue

                endpoint = tag_data.get('endpoint', None)
                pem_file = tag_data.get('file', None)
                not_after = tag_data.get('not_after', 0)
                not_before = tag_data.get('not_before', 0)
                port = tag_data.get('port', 443)
                fail_if_not_before = tag_data.get('fail_if_not_before', False)

                if not endpoint and not pem_file:
                    failing_reason = 'No certificate to be checked'
                    tag_data['reason'] = failing_reason
                    ret['Failure'].append(tag_data)
                    continue

                if endpoint and pem_file:
                    failing_reason = 'Only one certificate per check is allowed'
                    tag_data['reason'] = failing_reason
                    ret['Failure'].append(tag_data)
                    continue

                cert = _get_cert(endpoint, port) if endpoint else _get_cert(pem_file, from_file=True)
                x509 = _load_x509(cert)
                (passed, failing_reason) = _check_x509(x509=x509,
                                                       not_before=not_before,
                                                       not_after=not_after,
                                                       fail_if_not_before=fail_if_not_before)

                if passed:
                    ret['Success'].append(tag_data)
                else:
                    tag_data['reason'] = failing_reason
                    ret['Failure'].append(tag_data)

    return ret


def _merge_yaml(ret, data, profile=None):
    if 'openssl' not in ret:
        ret['openssl'] = []
    for key, val in data.get('openssl', {}).iteritems():
        if profile and isinstance(val, dict):
            val['nova_profile'] = profile
        ret['openssl'].append({key: val})
    return ret


def _get_tags(data):
    ret = {}
    for audit_dict in data.get('openssl', {}):
        for audit_id, audit_data in audit_dict.iteritems():
            tags_dict = audit_data.get('data', {})
            tag = tags_dict.pop('tag')
            if tag not in ret:
                ret[tag] = []
            formatted_data = copy.deepcopy(tags_dict)
            formatted_data['tag'] = tag
            formatted_data['module'] = 'openssl'
            formatted_data.update(audit_data)
            formatted_data.pop('data')
            ret[tag].append(formatted_data)
    return ret


def _check_x509(x509=None, not_before=0, not_after=0, fail_if_not_before=False):
    if not x509:
        log.error('No certificate to be checked')
        return (False, 'No certificate to be checked')
    if x509.has_expired():
        log.info('The certificate has expired')
        return (False, 'The certificate has expired')

    stats = _get_x509_days_left(x509)

    if not_after >= stats['not_after']:
        log.info('The certificate will expire in less then {0} days'.format(not_after))
        return (False,
                'The certificate will expire in less then {0} days'.format(not_after)
                )
    if not_before <= stats['not_before']:
        if not_before == 0 and fail_if_not_before:
            log.info(
                'The certificate is not yet valid ({0} days left until it will be valid)'.format(stats['not_before']))
            return (False,
                    'The certificate is not yet valid ({0} days left until it will be valid)'.format(
                        stats['not_before'])
                    )
        log.info('The certificate will be valid in more then {0} days'.format(not_before))
        return (False, 'The certificate will be valid in more then {0} days'.format(not_before))

    return (True, '')


def _load_x509(cert):
    if not cert:
        log.error('No certificate to be loaded into x509 object')
        return None
    try:
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    except OpenSSL.crypto.Error:
        log.error('Unable to load certificate into x509 object')
        x509 = None

    return x509


def _get_cert(source, port=443, from_file=False):
    cert = _get_cert_from_file(source) if from_file else _get_cert_from_endpoint(source, port)
    return cert


def _get_cert_from_endpoint(server, port=443):
    try:
        cert = ssl.get_server_certificate((server, port))
    except Exception:
        log.error('Unable to retrieve certificate from {0}'.format(server))
        cert = None
    if not cert:
        return None

    return cert


def _get_cert_from_file(cert_file_path):
    try:
        with open(cert_file_path) as cert_file:
            cert = cert_file.read()
    except IOError:
        log.error('File not found: {0}'.format(cert_file_path))
        return None

    return cert


def _get_x509_days_left(x509):
    date_fmt = '%Y%m%d%H%M%SZ'
    current_datetime = datetime.datetime.utcnow()
    not_after = time.strptime(x509.get_notAfter(), date_fmt)
    not_before = time.strptime(x509.get_notBefore(), date_fmt)

    ret = {'not_after': (datetime.datetime(*not_after[:6]) - current_datetime).days,
           'not_before': (datetime.datetime(*not_before[:6]) - current_datetime).days}

    return ret
