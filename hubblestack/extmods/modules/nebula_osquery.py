# -*- coding: utf-8 -*-
'''
osquery wrapper for HubbleStack Nebula

:maintainer: basepi
:maturity: 2016.10.2
:platform: All
:requires: SaltStack, osquery

Designed to run sets of osquery queries defined in pillar. These sets will have
a unique identifier, and be targeted by identifier. Usually, this identifier
will be a frequency. ('15 minutes', '1 day', etc). Identifiers are
case-insensitive.

You can then use the scheduler of your choice to run sets os queries at
whatever frequency you choose.

Sample pillar data:

nebula_osquery:
  hour:
    - crontab: query: select c.*,t.iso_8601 as _time from crontab as c join time as t;
    - query_name: suid_binaries
      query: select sb.*, t.iso_8601 as _time from suid_bin as sb join time as t;
  day:
    - query_name: rpm_packages
      query: select rpm.*, t.iso_8601 from rpm_packages as rpm join time as t;
'''
from __future__ import absolute_import

import copy
import json
import logging
import os
import sys
import yaml

import salt.utils
from salt.exceptions import CommandExecutionError

log = logging.getLogger(__name__)

__version__ = 'v2016.10.2'
__virtualname__ = 'nebula'


def __virtual__():
    return __virtualname__


def queries(query_group,
            query_file=None,
            verbose=False,
            report_version_with_day=True):
    '''
    Run the set of queries represented by ``query_group`` from the
    configuration in the file query_file

    query_group
        Group of queries to run

    query_file
        salt:// file which will be parsed for osquery queries

    verbose
        Defaults to False. If set to True, more information (such as the query
        which was run) will be included in the result.

    CLI Examples:

    .. code_block:: bash

        salt '*' nebula.queries day
        salt '*' nebula.queries hour verbose=True
        salt '*' nebula.queries hour pillar_key=sec_osqueries
    '''
    if query_file is None:
        if salt.utils.is_windows():
            query_file = 'salt://hubblestack_nebula/hubblestack_nebula_win_queries.yaml'
        else:
            query_file = 'salt://hubblestack_nebula/hubblestack_nebula_queries.yaml'
    if not salt.utils.which('osqueryi'):
        if query_group == 'day':
            log.warning('osquery not installed on this host. Returning baseline data')
            # Match the formatting of normal osquery results. Not super
            #   readable, but just add new dictionaries to the list as we need
            #   more data
            ret = []
            ret.append(
                    {'fallback_osfinger': {
                         'data': [{'osfinger': __grains__.get('osfinger', __grains__.get('osfullname'))}],
                         'result': True
                    }}
            )
            if 'pkg.list_pkgs' in __salt__:
                ret.append(
                        {'fallback_pkgs': {
                             'data': [{'name': k, 'version': v} for k, v in __salt__['pkg.list_pkgs']().iteritems()],
                             'result': True
                        }}
                )
            if report_version_with_day:
                ret.append(hubble_versions())
            return ret
        else:
            log.debug('osquery not installed on this host. Skipping.')
            return None

    if salt.utils.is_windows():
        win_version = __grains__['osfullname']
        if '2012' not in win_version and '2016' not in win_version:
            log.error('osquery does not run on windows versions earlier than Server 2012 and Windows 8')
            if query_group == 'day':
                ret = []
                ret.append(
                        {'fallback_osfinger': {
                             'data': [{'osfinger': __grains__.get('osfinger', __grains__.get('osfullname'))}],
                             'result': True
                        }}
                )
                ret.append(
                        {'fallback_error': {
                             'data': 'osqueryi is installed but not compatible with this version of windows',
                             'result': True
                        }}
                )
                return ret
            else:
               return None
                   

    orig_filename = query_file
    query_file = __salt__['cp.cache_file'](query_file)
    if query_file is None:
        log.error('Could not find file {0}.'.format(orig_filename))
        return None
    with open(query_file, 'r') as fh:
        query_data = yaml.safe_load(fh)

    if not isinstance(query_data, dict):
        raise CommandExecutionError('Query data is not formed as a dict {0}'
                                    .format(query_data))

    query_data = query_data.get(query_group, [])

    if not query_data:
        return None

    ret = []
    for query in query_data:
        name = query.get('query_name')
        query_sql = query.get('query')
        if not query_sql:
            continue

        # Run the osqueryi query
        query_ret = {
            'result': True,
        }

        cmd = ['osqueryi', '--json', query_sql]
        res = __salt__['cmd.run_all'](cmd)
        if res['retcode'] == 0:
            query_ret['data'] = json.loads(res['stdout'])
        else:
            queury_ret['result'] = False
            queury_ret['error'] = res['stderr']

        if verbose:
            tmp = copy.deepcopy(query)
            tmp['query_result'] = query_ret
            ret.append(tmp)
        else:
            ret.append({name: query_ret})

    if query_group == 'day' and report_version_with_day:
        ret.append(hubble_versions())

    return ret


def version():
    '''
    Report version of this module
    '''
    return __version__


def hubble_versions():
    '''
    Report version of all hubble modules as query
    '''
    versions = {}

    # Nova
    if 'hubble.version' in __salt__:
        versions['nova'] = __salt__['hubble.version']()
    else:
        versions['nova'] = None

    # Nebula
    versions['nebula'] = version()

    # Pulsar
    if salt.utils.is_windows():
        try:
            sys.path.insert(0, os.path.dirname(__salt__['cp.cache_file']('salt://_beacons/win_pulsar.py')))
            import win_pulsar
            versions['pulsar'] = win_pulsar.__version__
        except:
            versions['pulsar'] = None
    else:
        try:
            sys.path.insert(0, os.path.dirname(__salt__['cp.cache_file']('salt://_beacons/pulsar.py')))
            import pulsar
            versions['pulsar'] = pulsar.__version__
        except:
            versions['pulsar'] = None

    # Quasar
    try:
        sys.path.insert(0, os.path.dirname(__salt__['cp.cache_file']('salt://_returners/splunk_nova_return.py')))
        import splunk_nova_return
        versions['quasar'] = splunk_nova_return.__version__
    except:
        versions['quasar'] = None

    return {'hubble_versions': {'data': [versions],
                                'result': True}}
