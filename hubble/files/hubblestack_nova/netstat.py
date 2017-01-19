# -*- encoding: utf-8 -*-
'''
HubbleStack Nova module for auditing open ports.

:maintainer: HubbleStack / basepi
:maturity: 2016.7.0
:platform: Unix
:requires: SaltStack

Sample data for the netstat whitelist:

.. code-block:: yaml

    netstat:
        ssh:
            address: '*:22'
        another_identifier:
            address:
              - 127.0.0.1:80
              - 0.0.0.0:80
'''
from __future__ import absolute_import

import copy
import fnmatch
import logging

import salt.utils

log = logging.getLogger(__name__)


def __virtual__():
    if 'network.netstat' in __salt__:
        return True
    return False, 'No network.netstat function found'


def audit(data_list, tags, verbose=False, show_profile=False, debug=True):
    '''
    Run the network.netstat command
    '''
    ret = {'Success': [], 'Failure': []}

    __tags__ = {}
    for profile, data in data_list:
        if 'netstat' in data:
            for check, check_args in data['netstat'].iteritems():
                if 'address' in check_args:
                    tag_args = copy.deepcopy(check_args)
                    tag_args['id'] = check
                    if show_profile:
                        tag_args['nova_profile'] = profile
                    if isinstance(check_args['address'], list):
                        for address in check_args['address']:
                            __tags__[address] = tag_args
                    else:
                        __tags__[check_args['address']] = tag_args

    if not __tags__:
        # No yaml data found, don't do any work
        return ret

    for address_data in __salt__['network.netstat']():
        address = address_data['local-address']
        success = False
        for whitelisted_address in __tags__:
            if fnmatch.fnmatch(address, whitelisted_address):
                success_data = {address: __tags__[whitelisted_address]['id']}
                if verbose:
                    success_data = {address: __tags__[whitelisted_address]}
                    success_data[address].update(address_data)
                    success_data[address]['description'] = __tags__[whitelisted_address]['id']
                ret['Success'].append(success_data)
                success = True
                break
        if success is False:
            failure_data = {address: address_data['program']}
            if verbose:
                failure_data = {address: {'program': address_data['program']}}
                failure_data[address].update(address_data)
                failure_data[address]['description'] = address_data['program']
                failure_data[address]['nova_profile'] = 'netstat'
            ret['Failure'].append(failure_data)

    return ret
