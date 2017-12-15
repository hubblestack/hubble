# -*- encoding: utf-8 -*-
'''
HubbleStack Nova plugin for using grep to verify settings in files.

Supports both blacklisting and whitelisting patterns. Blacklisted patterns must
not be found in the specified file. Whitelisted patterns must be found in the
specified file.

:maintainer: HubbleStack / basepi
:maturity: 2016.7.0
:platform: All
:requires: SaltStack

This audit module requires yaml data to execute. It will search the local
directory for any .yaml files, and if it finds a top-level 'grep' key, it will
use that data.

Sample YAML data, with inline comments:


grep:
  whitelist: # or blacklist
    fstab_tmp_partition:  # unique ID
      data:
        CentOS Linux-6:  # osfinger grain
          - '/etc/fstab':  # filename
              tag: 'CIS-1.1.1'  # audit tag
              pattern: '/tmp'  # grep pattern
              match_output: 'nodev'  # string to check for in output of grep command (optional)
              match_output_regex: True  # whether to use regex when matching output (default: False)
              match_output_multiline: False  # whether to use multiline flag for regex matching (default: True)
              grep_args:  # extra args to grep
                - '-E'
                - '-i'
                - '-B2'
              match_on_file_missing: True  # See (1) below
        '*':  # wildcard, will be run if no direct osfinger match
          - '/etc/fstab':
              tag: 'CIS-1.1.1'
              pattern: '/tmp'
      # The rest of these attributes are optional, and currently not used
      description: |
        The /tmp directory is intended to be world-writable, which presents a risk
        of resource exhaustion if it is not bound to a separate partition.
      alert: email
      trigger: state


(1) If `match_on_file_missing` is ommitted, success/failure will be determined
entirely based on the grep command and other arguments. If it's set to True and
the file is missing, then it will be considered a match (success for whitelist,
failure for blacklist). If it's set to False and the file is missing, then it
will be considered a non-match (success for blacklist, failure for whitelist).
If the file exists, this setting is ignored.
'''
from __future__ import absolute_import
import logging

import fnmatch
import os
import copy
import salt.utils
import re

from distutils.version import LooseVersion

log = logging.getLogger(__name__)


def __virtual__():
    if salt.utils.is_windows():
        return False, 'This audit module only runs on linux'
    return True


def audit(data_list, tags, debug=False, **kwargs):
    '''
    Run the grep audits contained in the YAML files processed by __virtual__
    '''
    __data__ = {}
    for profile, data in data_list:
        _merge_yaml(__data__, data, profile)
    __tags__ = _get_tags(__data__)

    if debug:
        log.debug('grep audit __data__:')
        log.debug(__data__)
        log.debug('grep audit __tags__:')
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

                if 'pattern' not in tag_data:
                    log.error('No version found for grep audit {0}, file {1}'
                              .format(tag, name))
                    tag_data = copy.deepcopy(tag_data)
                    tag_data['error'] = 'No pattern found'.format(mod)
                    ret['Failure'].append(tag_data)
                    continue

                grep_args = tag_data.get('grep_args', [])
                if isinstance(grep_args, str):
                    grep_args = [grep_args]

                grep_ret = _grep(name,
                                 tag_data['pattern'],
                                 *grep_args).get('stdout')

                found = False
                if grep_ret:
                    found = True
                if 'match_output' in tag_data:
                    if not tag_data.get('match_output_regex'):
                        if tag_data['match_output'] not in grep_ret:
                            found = False
                    else:  # match with regex
                        if tag_data.get('match_output_multiline', True):
                            if not re.search(tag_data['match_output'], grep_ret, re.MULTILINE):
                                found = False
                        else:
                            if not re.search(tag_data['match_output'], grep_ret):
                                found = False

                if not os.path.exists(name) and 'match_on_file_missing' in tag_data:
                    if tag_data['match_on_file_missing']:
                        found = True
                    else:
                        found = False

                # Blacklisted pattern (must not be found)
                if audittype == 'blacklist':
                    if found:
                        ret['Failure'].append(tag_data)
                    else:
                        ret['Success'].append(tag_data)

                # Whitelisted pattern (must be found)
                elif audittype == 'whitelist':
                    if found:
                        ret['Success'].append(tag_data)
                    else:
                        ret['Failure'].append(tag_data)

    return ret


def _merge_yaml(ret, data, profile=None):
    '''
    Merge two yaml dicts together at the grep:blacklist and grep:whitelist level
    '''
    if 'grep' not in ret:
        ret['grep'] = {}
    for topkey in ('blacklist', 'whitelist'):
        if topkey in data.get('grep', {}):
            if topkey not in ret['grep']:
                ret['grep'][topkey] = []
            for key, val in data['grep'][topkey].iteritems():
                if profile and isinstance(val, dict):
                    val['nova_profile'] = profile
                ret['grep'][topkey].append({key: val})
    return ret


def _get_tags(data):
    '''
    Retrieve all the tags for this distro from the yaml
    '''
    ret = {}
    distro = __grains__.get('osfinger')
    for toplist, toplevel in data.get('grep', {}).iteritems():
        # grep:blacklist
        for audit_dict in toplevel:
            # grep:blacklist:0
            for audit_id, audit_data in audit_dict.iteritems():
                # grep:blacklist:0:telnet
                tags_dict = audit_data.get('data', {})
                # grep:blacklist:0:telnet:data
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
                # grep:blacklist:0:telnet:data:Debian-8
                if isinstance(tags, dict):
                    # malformed yaml, convert to list of dicts
                    tmp = []
                    for name, tag in tags.iteritems():
                        tmp.append({name: tag})
                    tags = tmp
                for item in tags:
                    for name, tag in item.iteritems():
                        tag_data = {}
                        # Whitelist could have a dictionary, not a string
                        if isinstance(tag, dict):
                            tag_data = copy.deepcopy(tag)
                            tag = tag_data.pop('tag')
                        if tag not in ret:
                            ret[tag] = []
                        formatted_data = {'name': name,
                                          'tag': tag,
                                          'module': 'grep',
                                          'type': toplist}
                        formatted_data.update(tag_data)
                        formatted_data.update(audit_data)
                        formatted_data.pop('data')
                        ret[tag].append(formatted_data)
    return ret


def _grep(path,
          pattern,
          *args):
    '''
    Grep for a string in the specified file

    .. note::
        This function's return value is slated for refinement in future
        versions of Salt

    path
        Path to the file to be searched

        .. note::
            Globbing is supported (i.e. ``/var/log/foo/*.log``, but if globbing
            is being used then the path should be quoted to keep the shell from
            attempting to expand the glob expression.

    pattern
        Pattern to match. For example: ``test``, or ``a[0-5]``

    opts
        Additional command-line flags to pass to the grep command. For example:
        ``-v``, or ``-i -B2``

        .. note::
            The options should come after a double-dash (as shown in the
            examples below) to keep Salt's own argument parser from
            interpreting them.

    CLI Example:

    .. code-block:: bash

        salt '*' file.grep /etc/passwd nobody
        salt '*' file.grep /etc/sysconfig/network-scripts/ifcfg-eth0 ipaddr -- -i
        salt '*' file.grep /etc/sysconfig/network-scripts/ifcfg-eth0 ipaddr -- -i -B2
        salt '*' file.grep "/etc/sysconfig/network-scripts/*" ipaddr -- -i -l
    '''
    path = os.path.expanduser(path)

    if args:
        options = ' '.join(args)
    else:
        options = ''
    cmd = (
        r'''grep  {options} {pattern} {path}'''
        .format(
            options=options,
            pattern=pattern,
            path=path,
        )
    )

    try:
        ret = __salt__['cmd.run_all'](cmd, python_shell=False, ignore_retcode=True)
    except (IOError, OSError) as exc:
        raise CommandExecutionError(exc.strerror)

    return ret
