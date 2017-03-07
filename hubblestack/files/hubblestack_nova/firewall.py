# -*- encoding: utf-8 -*-
'''
Hubble Nova plugin for using iptables to verify firewall rules

:maintainer: HubbleStack / avb76
:maturity: 2016.7.0
:platform: Linux
:requires: SaltStack

This audit module requires yaml data to execute. Running hubble.audit will
search the local directory for any .yaml files and it will pass all the data to
this module.  If this module find a top-level 'firewall' key, it will use the
data under that key.

Sample YAML data used by firewall.py, with inline comments:


firewall:
  whitelist:    # whitelist or blacklist

    ssh:    # unique id
      data:
        tag: 'FIREWALL-TCP-22'  # audit tag
        table: 'filter' # iptables table to check   (REQUIRED)
        chain: INPUT    # INPUT / OUTPUT / FORWARD  (REQUIRED)
        rule:   #dict containing the elements for building the rule
          proto: tcp
          dport: 22
          match: state
          connstate: RELATED,ESTABLISHED
          jump: ACCEPT
        family: 'ipv4'  # iptables family   (REQUIRED)
      description: 'ssh iptables rule check' # description of the check
      # The rest of these attributes are optional, and currently not used
      alert: email
      trigger: state

A few words about the auditing logic
The audit function uses the iptables.build_rule salt
execution module to build the actual iptables rule to be checked.
How the rules are built?
The elements in the rule dictionary will be used to build the iptables rule.

Note: table, chain and family are not required under the rule key.
Note: iptables.build_rule does not verify the syntax of the iptables rules.

Here is a list of accepted iptables rules elements, based on the
iptables.build_rule source code:
    - command
    - position
    - full
    - target
    - jump
    - proto/protocol
    - if
    - of
    - match
    - match-set
    - connstate
    - dport
    - sport
    - dports
    - sports
    - comment
    - set
    - jump
    - if it's the case, jump arguments can be passed -- see more details bellow

Jump arguments
  (comments inside the iptables.build_rule source code)
  # All jump arguments as extracted from man iptables-extensions, man iptables,
  # man xtables-addons and http://www.iptables.info/en/iptables-targets-and-jumps.html

Check the following links for more details:
  - iptables.build_rule SaltStack documentation
  (https://docs.saltstack.com/en/latest/ref/modules/all/salt.modules.iptables.html#salt.modules.iptables.build_rule)
  - iptables salt execution module source code (search for the build_rule function inside):
  (https://github.com/saltstack/salt/blob/develop/salt/modules/iptables.py)
'''

from __future__ import absolute_import
import logging

import fnmatch
import copy
import salt.utils

log = logging.getLogger(__name__)

__tags__ = None
__data__ = None


def __virtual__():
    if salt.utils.is_windows():
        return False, 'This audit module only runs on linux'
    if not salt.utils.which('iptables'):
        return (False, 'The iptables execution module cannot be loaded: iptables not installed.')
    return True


def audit(data_list, tags, debug=False):
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
                table = tag_data['table']
                chain = tag_data['chain']
                family = tag_data['family']

                # creating the arguments for the iptables.build_rule salt execution module
                args = {'table': table,
                        'chain': chain,
                        'family': family}

                # since table, chain and family are already given for checking the existence of the rule,
                # they are not needed here
                if 'table' in tag_data['rule']:
                    tag_data['rule'].pop('table')
                if 'chain' in tag_data['rule']:
                    tag_data['rule'].pop('chain')
                if 'family' in tag_data['rule']:
                    tag_data['rule'].pop('family')

                args.update(tag_data['rule'])

                # building the rule using iptables.build_rule
                rule = __salt__['iptables.build_rule'](**args)

                # replacing all the elements of the rule with the actual rule (for verbose mode)
                tag_data['rule'] = rule

                # checking the existence of the rule
                salt_ret = __salt__['iptables.check'](table=table, chain=chain, rule=rule, family=family)

                if salt_ret not in (True, False):
                    log.error(salt_ret)
                    passed = False
                else:
                    passed = salt_ret
                    if tag_data['type'] == 'blacklist':
                        passed = not passed

                if passed:
                    ret['Success'].append(tag_data)
                else:
                    ret['Failure'].append(tag_data)

    return ret


def _merge_yaml(ret, data, profile=None):
    '''
    Merge two yaml dicts together at the pkg:blacklist and pkg:whitelist level
    '''
    if 'firewall' not in ret:
        ret['firewall'] = {}
    for topkey in ('blacklist', 'whitelist'):
        if topkey in data.get('firewall', {}):
            if topkey not in ret['firewall']:
                ret['firewall'][topkey] = []
            for key, val in data['firewall'][topkey].iteritems():
                if profile and isinstance(val, dict):
                    val['nova_profile'] = profile
                ret['firewall'][topkey].append({key: val})
    return ret


def _get_tags(data):
    ret = {}
    for toplist, toplevel in data.get('firewall', {}).iteritems():
        for audit_dict in toplevel:
            for audit_id, audit_data in audit_dict.iteritems():
                tags_dict = audit_data.get('data', {})
                tag = tags_dict.pop('tag')
                if tag not in ret:
                    ret[tag] = []
                formatted_data = copy.deepcopy(tags_dict)
                formatted_data['type'] = toplist
                formatted_data['tag'] = tag
                formatted_data['module'] = 'firewall'
                formatted_data.update(audit_data)
                formatted_data.pop('data')
                ret[tag].append(formatted_data)
    return ret
