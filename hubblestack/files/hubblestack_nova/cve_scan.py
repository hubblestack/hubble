# -*- encoding: utf-8 -*-
'''
HubbleStack Nova plugin for openscap scanning.

:maintainer: HubbleStack / cedwards
:maturity: 2016.7.0
:platform: Red Hat
:requires: SaltStack + oscap execution module

'''
from __future__ import absolute_import
import salt.utils
import logging

log = logging.getLogger(__name__)


def __virtual__():
    if salt.utils.is_linux() and salt.utils.which('oscap'):
        return True
    return False, 'This module requires Linux and the oscap binary'


def audit(data_list, tags, debug=False, **kwargs):
    '''
    Run the network.netstat command
    '''
    ret = {'Success': [], 'Failure': []}

    __tags__ = []
    __feed__ = []
    for data in data_list:
        if 'cve_scan' in data:
            __tags__ = ['cve_scan']
            if isinstance(data['cve_scan'], str):
                __feed__.append(data['cve_scan'])
            else: # assume list
                __feed__.extend(data['cve_scan'])

    if not __tags__:
        # No yaml data found, don't do any work
        return ret

    for feed in __feed__:
        ret['Failure'].append(__salt__['oscap.scan'](feed))
    return ret
