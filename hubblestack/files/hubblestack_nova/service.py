# -*- encoding: utf-8 -*-
'''
HubbleStack Nova module for auditing running services.

Supports both blacklisting and whitelisting services. Blacklisted services
must not be running. Whitelisted services must be running.

:maintainer: HubbleStack / basepi
:maturity: 2016.7.0
:platform: All
:requires: SaltStack

This audit module requires yaml data to execute. It will search the local
directory for any .yaml files, and if it finds a top-level 'service' key, it will
use that data.

Sample YAML data, with inline comments:


service:
  # Must not be installed
  blacklist:
    # Unique ID for this set of audits
    telnet:
      data:
        # 'osfinger' grain, for multiplatform support
        CentOS Linux-6:
          # service name : tag
          - 'telnet': 'CIS-2.1.1'
        # Catch-all, if no osfinger match was found
        '*':
          # service name : tag
          - 'telnet': 'telnet-bad'
      # description/alert/trigger are currently ignored, but may be used in the future
      description: 'Telnet is evil'
      alert: email
      trigger: state
  # Must be installed, no version checking (yet)
  whitelist:
    rsh:
      data:
        CentOS Linux-7:
          - 'rsh': 'CIS-2.1.3'
          - 'rsh-server': 'CIS-2.1.4'
        '*':
          - 'rsh-client': 'CIS-5.1.2'
          - 'rsh-redone-client': 'CIS-5.1.2'
          - 'rsh-server': 'CIS-5.1.3'
          - 'rsh-redone-server': 'CIS-5.1.3'
      description: 'RSH is awesome'
      alert: email
      trigger: state

'''
from __future__ import absolute_import
import logging

import fnmatch
import salt.utils

from distutils.version import LooseVersion

log = logging.getLogger(__name__)


def __virtual__():
    if salt.utils.is_windows():
        return False, 'This audit module only runs on linux'
    return True


def audit(data_list, tags, debug=False, **kwargs):
    '''
    Run the service audits contained in the YAML files processed by __virtual__
    '''
    __data__ = {}
    for profile, data in data_list:
        _merge_yaml(__data__, data, profile)
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
                name = tag_data['name']
                audittype = tag_data['type']

                # Blacklisted packages (must not be installed)
                if audittype == 'blacklist':
                    if __salt__['service.status'](name):
                        ret['Failure'].append(tag_data)
                    else:
                        ret['Success'].append(tag_data)

                # Whitelisted packages (must be installed)
                elif audittype == 'whitelist':
                    if __salt__['service.status'](name):
                        ret['Success'].append(tag_data)
                    else:
                        ret['Failure'].append(tag_data)

    return ret


def _merge_yaml(ret, data, profile=None):
    '''
    Merge two yaml dicts together at the service:blacklist and service:whitelist level
    '''
    if 'service' not in ret:
        ret['service'] = {}
    for topkey in ('blacklist', 'whitelist'):
        if topkey in data.get('service', {}):
            if topkey not in ret['service']:
                ret['service'][topkey] = []
            for key, val in data['service'][topkey].iteritems():
                if profile and isinstance(val, dict):
                    val['nova_profile'] = profile
                ret['service'][topkey].append({key: val})
    return ret


def _get_tags(data):
    '''
    Retrieve all the tags for this distro from the yaml
    '''
    ret = {}
    distro = __grains__.get('osfinger')
    for toplist, toplevel in data.get('service', {}).iteritems():
        # service:blacklist
        for audit_dict in toplevel:
            # service:blacklist:0
            for audit_id, audit_data in audit_dict.iteritems():
                # service:blacklist:0:telnet
                tags_dict = audit_data.get('data', {})
                # service:blacklist:0:telnet:data
                tags = None
                for osfinger in tags_dict:
                    if osfinger == '*':
                        continue
                    osfinger_list = [finger.strip() for finger in osfinger.split(',')]
                    for osfinger_glob in osfinger_list:
                        if fnmatch.fnmatch(distro, osfinger_glob):
                            tags = tags_dict.get(osfinger)
                            break
                    if tags is not None:
                        break
                # If we didn't find a match, check for a '*'
                if tags is None:
                    tags = tags_dict.get('*', [])
                # service:blacklist:0:telnet:data:Debian-8
                if isinstance(tags, dict):
                    # malformed yaml, convert to list of dicts
                    tmp = []
                    for name, tag in tags.iteritems():
                        tmp.append({name: tag})
                    tags = tmp
                for item in tags:
                    for name, tag in item.iteritems():
                        if tag not in ret:
                            ret[tag] = []
                        formatted_data = {'name': name,
                                          'tag': tag,
                                          'module': 'service',
                                          'type': toplist}
                        formatted_data.update(audit_data)
                        formatted_data.pop('data')
                        ret[tag].append(formatted_data)
    return ret
