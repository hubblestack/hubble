# -*- coding: utf-8 -*-
'''
osquery wrapper for HubbleStack Nebula

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
import fnmatch
import glob
import fnmatch
import json
import logging
import os
import re
import time
import yaml
import collections

import salt.utils
import salt.utils.files
import salt.utils.platform

from hashlib import md5
from salt.exceptions import CommandExecutionError
from os import path
from hubblestack import __version__
import hubblestack.splunklogging

log = logging.getLogger(__name__)

from hubblestack.status import HubbleStatus
hubble_status = HubbleStatus(__name__, 'top', 'queries', 'osqueryd_monitor', 'osqueryd_log_parser')

__virtualname__ = 'nebula'
__RESULT_LOG_OFFSET__ = {}


def __virtual__():
    return __virtualname__


@hubble_status.watch
def queries(query_group,
            query_file=None,
            verbose=False,
            report_version_with_day=True,
            topfile_for_mask=None,
            mask_passwords=False):
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

    topfile_for_mask
        This is the location of the top file from which the masking information
        will be extracted.

    mask_passwords
        Defaults to False. If set to True, passwords mentioned in the
        return object are masked.

    CLI Examples:

    .. code-block:: bash

        salt '*' nebula.queries day
        salt '*' nebula.queries hour verbose=True
        salt '*' nebula.queries hour pillar_key=sec_osqueries
    '''
    query_data = {}
    MAX_FILE_SIZE = 104857600
    if query_file is None:
        if salt.utils.platform.is_windows():
            query_file = 'salt://hubblestack_nebula_v2/hubblestack_nebula_win_queries.yaml'
        else:
            query_file = 'salt://hubblestack_nebula_v2/hubblestack_nebula_queries.yaml'
    if not isinstance(query_file, list):
        query_file = [query_file]
    for fh in query_file:
        if 'salt://' in fh:
            orig_fh = fh
            fh = __salt__['cp.cache_file'](fh)
        if fh is None:
            log.error('Could not find file {0}.'.format(orig_fh))
            return None
        if os.path.isfile(fh):
            with open(fh, 'r') as f:
                f_data = yaml.safe_load(f)
                if not isinstance(f_data, dict):
                    raise CommandExecutionError('File data is not formed as a dict {0}'
                                                .format(f_data))
                query_data = _dict_update(query_data,
                                          f_data,
                                          recursive_update=True,
                                          merge_lists=True)

    if 'osquerybinpath' not in __grains__:
        if query_group == 'day':
            log.warning('osquery not installed on this host. Returning baseline data')
            # Match the formatting of normal osquery results. Not super
            #   readable, but just add new dictionaries to the list as we need
            #   more data
            ret = []
            ret.append(
                {'fallback_osfinger': {
                 'data': [{'osfinger': __grains__.get('osfinger', __grains__.get('osfullname')),
                           'osrelease': __grains__.get('osrelease', __grains__.get('lsb_distrib_release'))}],
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
            uptime = __salt__['status.uptime']()
            if isinstance(uptime, dict):
                uptime = uptime.get('seconds', __salt__['cmd.run']('uptime'))
            ret.append(
                {'fallback_uptime': {
                 'data': [{'uptime': uptime}],
                 'result': True
                 }}
            )
            if report_version_with_day:
                ret.append(hubble_versions())
            return ret
        else:
            log.debug('osquery not installed on this host. Skipping.')
            return None

    query_data = query_data.get(query_group, {})

    if not query_data:
        return None

    ret = []
    timing = {}
    schedule_time = time.time()
    success = True
    for name, query in query_data.iteritems():
        query['query_name'] = name
        query_sql = query.get('query')
        if not query_sql:
            continue
        if 'attach' in query_sql.lower() or 'curl' in query_sql.lower():
            log.critical('Skipping potentially malicious osquery query \'{0}\' '
                         'which contains either \'attach\' or \'curl\': {1}'
                         .format(name, query_sql))
            continue

        # Run the osqueryi query
        query_ret = {
            'result': True,
        }

        cmd = [__grains__['osquerybinpath'], '--read_max', MAX_FILE_SIZE, '--json', query_sql]
        t0 = time.time()
        res = __salt__['cmd.run_all'](cmd, timeout=10000)
        t1 = time.time()
        timing[name] = t1-t0
        if res['retcode'] == 0:
            query_ret['data'] = json.loads(res['stdout'])
        else:
            if 'Timed out' in res['stdout']:
                # this is really the best way to tell without getting fancy
                log.error('TIMEOUT during osqueryi execution name=%s', name)
            success = False
            query_ret['result'] = False
            query_ret['error'] = res['stderr']

        if verbose:
            tmp = copy.deepcopy(query)
            tmp['query_result'] = query_ret
            ret.append(tmp)
        else:
            ret.append({name: query_ret})

    if success is False and salt.utils.platform.is_windows():
        log.error('osquery does not run on windows versions earlier than Server 2008 and Windows 7')
        if query_group == 'day':
            ret = []
            ret.append(
                {'fallback_osfinger': {
                 'data': [{'osfinger': __grains__.get('osfinger', __grains__.get('osfullname')),
                           'osrelease': __grains__.get('osrelease', __grains__.get('lsb_distrib_release'))}],
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

    if __salt__['config.get']('splunklogging', False):
        log.info('Logging osquery timing data to splunk')
        hubblestack.splunklogging.__grains__ = __grains__
        hubblestack.splunklogging.__salt__ = __salt__
        hubblestack.splunklogging.__opts__ = __opts__
        handler = hubblestack.splunklogging.SplunkHandler()
        timing_data = {'query_run_length': timing,
                       'schedule_time' : schedule_time}
        handler.emit_data(timing_data)

    if query_group == 'day' and report_version_with_day:
        ret.append(hubble_versions())

    for r in ret:
        for query_name, query_ret in r.iteritems():
            if 'data' in query_ret:
                for result in query_ret['data']:
                    for key, value in result.iteritems():
                        if value and isinstance(value, basestring) and value.startswith('__JSONIFY__'):
                            result[key] = json.loads(value[len('__JSONIFY__'):])

    if mask_passwords:
        _mask_object(ret, topfile_for_mask)
    return ret


@hubble_status.watch
def osqueryd_monitor(configfile=None,
                     flagfile=None,
                     logdir=None,
                     databasepath=None,
                     pidfile=None,
                     hashfile=None,
                     daemonize=True):
    '''
    This function will monitor whether osqueryd is running on the system or not. 
    Whenever it detects that osqueryd is not running, it will start the osqueryd. 
    Also, it checks for conditions that would require osqueryd to restart(such as changes in flag file content) 
    On such conditions, osqueryd will get restarted, thereby loading new files.

    configfile
        Path to osquery configuration file.

    flagfile
        Path to osquery flag file

    logdir
        Path to log directory where osquery daemon/service will write logs

    pidfile
        pidfile path where osquery daemon will write pid info

    hashfile
        path to hashfile where osquery flagfile's hash would be stored

    daemonize
        daemonize osquery daemon. Default is True. Applicable for posix system only

    '''
    log.info("starting osqueryd monitor")
    saltenv = __salt__['config.get']('hubblestack:nova:saltenv', 'base')
    osqueryd_path = 'salt://osqueryd'
    cached = __salt__['cp.cache_dir'](osqueryd_path,saltenv=saltenv)
    log.info('cached osqueryd files to cachedir')
    cachedir = os.path.join(__opts__.get('cachedir'),'files',saltenv,'osqueryd')
    base_path = cachedir
    servicename = "hubble_osqueryd"
    if not logdir:
            logdir = __opts__.get('osquerylogpath')
    if not databasepath:
            databasepath = __opts__.get('osquery_dbpath')
    if salt.utils.platform.is_windows():
        if not pidfile:
            pidfile = os.path.join(base_path, "osqueryd.pidfile")
        if not configfile:
            configfile = os.path.join(base_path, "osquery.conf")
        if not flagfile:
            flagfile = os.path.join(base_path, "osquery.flags")
        if not hashfile:
            hashfile = os.path.join(base_path, "hash_of_flagfile.txt")

        osqueryd_running = _osqueryd_running_status_windows(servicename)
        if not osqueryd_running:
            _start_osqueryd(pidfile, configfile, flagfile, logdir, databasepath, servicename)
        else:
            osqueryd_restart = _osqueryd_restart_required(hashfile, flagfile)
            if osqueryd_restart:
                _restart_osqueryd(pidfile, configfile, flagfile, logdir, databasepath, hashfile, servicename)
    else:
        if not pidfile:
            pidfile = os.path.join(base_path, "osqueryd.pidfile")
        if not configfile:
            configfile = os.path.join(base_path, "osquery.conf")
        if not flagfile:
            flagfile = os.path.join(base_path, "osquery.flags")
        if not hashfile:
            hashfile = os.path.join(base_path, "hash_of_flagfile.txt")

        osqueryd_running = _osqueryd_running_status(pidfile, servicename)
        if not osqueryd_running:
            _start_osqueryd(pidfile, configfile, flagfile, logdir, databasepath, servicename)
        else:
            osqueryd_restart = _osqueryd_restart_required(hashfile, flagfile)
            if osqueryd_restart:
                _restart_osqueryd(pidfile, configfile, flagfile, logdir, databasepath, hashfile, servicename)


@hubble_status.watch
def osqueryd_log_parser(osqueryd_logdir=None,
                        backuplogdir=None,
                        maxlogfilesizethreshold=100000,
                        logfilethresholdinbytes=10000,
                        backuplogfilescount=5,
                        enablediskstatslogging=False,
                        topfile_for_mask=None,
                        mask_passwords=False):
    '''
    Parse osquery daemon logs and perform log rotation based on specified parameters

    osqueryd_logdir
        Directory path where osquery result and snapshot logs would be created

    backuplogdir
        Directory path where hubble should create log file backups post log rotation

    maxlogfilesizethreshold
        Log file size threshold in bytes. If osquery log file size is greter than this value,
        then logs will only be roatated but not parsed

    logfilethresholdinbytes
        Log file size threshold in bytes. If osquery log file is greter than this value,
        then log rotation will be done once logs have been processed

    backuplogfilescount
        Number of log file backups to keep

    enablediskstatslogging
        Enable logging of disk usage of /var/log partition. Default is False

    topfile_for_mask
        This is the location of the top file from which the masking information
        will be extracted

    mask_passwords
        Defaults to False. If set to True, passwords mentioned in the
        return object are masked

    '''
    ret = []
    if osqueryd_logdir:
        log.info("Base directory for osquery daemon logs specified as {0}".format(osqueryd_logdir))
        result_logfile = os.path.normpath(os.path.join(osqueryd_logdir, 'osqueryd.results.log'))
        snapshot_logfile = os.path.normpath(os.path.join(osqueryd_logdir, 'osqueryd.snapshots.log'))
    else:
        log.info("Setting osquery daemon log file to default dir: {0}"
                 .format(osquery_base_logdir))
        result_logfile = os.path.normpath(__opts__.get('osquerylogpath'), 'osqueryd.results.log')
        snapshot_logfile = os.path.normpath(__opts__.get('osquerylogpath'), '/osqueryd.snapshots.log')

    if not backuplogdir:
        backuplogdir = __opts__.get('osquerylog_backupdir')
    if not logfilethresholdinbytes:
        logfilethresholdinbytes = __opts__.get('osquery_logfile_maxbytes')
    if not maxlogfilesizethreshold:
        maxlogfilesizethreshold = __opts__.get('osquery_logfile_maxbytes_toparse')
    if not backuplogfilescount:
        backuplogfilescount = __opts__.get('osquery_backuplogs_count')
    if not enablediskstatslogging:
        enablediskstatslogging = False

    if path.exists(result_logfile):
        result_logfile_offset = _get_file_offset(result_logfile)
        r_event_data = _parse_log(result_logfile,
                                  result_logfile_offset,
                                  backuplogdir,
                                  logfilethresholdinbytes,
                                  maxlogfilesizethreshold,
                                  backuplogfilescount,
                                  enablediskstatslogging)
        if r_event_data:
            ret = r_event_data
    else:
        log.warn("Specified osquery result log file doesn't exist: {0}".format(result_logfile))

    if path.exists(snapshot_logfile):
        snapshot_logfile_offset = _get_file_offset(snapshot_logfile)
        s_event_data = _parse_log(snapshot_logfile,
                                  snapshot_logfile_offset,
                                  backuplogdir,
                                  logfilethresholdinbytes,
                                  maxlogfilesizethreshold,
                                  backuplogfilescount,
                                  enablediskstatslogging)
        if s_event_data:
            ret += s_event_data
    else:
        log.warn("Specified osquery snapshot log file doesn't exist: {0}".format(snapshot_logfile))

    if ret:
        n_ret = []
        for r in ret:
            obj = json.loads(r)
            if 'action' in obj and obj['action'] == 'snapshot':
                    for result in obj['snapshot']:
                        for key, value in result.iteritems():
                            if value and isinstance(value, basestring) and value.startswith('__JSONIFY__'):
                                result[key] = json.loads(value[len('__JSONIFY__'):])
            elif 'action' in obj:
                for key, value in obj['columns'].iteritems():
                    if value and isinstance(value, basestring) and value.startswith('__JSONIFY__'):
                        obj['columns'][key] = json.loads(value[len('__JSONIFY__'):])
            n_ret.append(obj)
        ret = n_ret

    if mask_passwords:
        log.info("Perform masking")
        _mask_object(ret, topfile_for_mask)
    return ret


def check_disk_usage(path=None):
    '''
    Check disk usage of specified path.
    If no path is specified, path will default to '/var/log'

    Can be scheduled via hubble conf as well

    *** Linux Only method ***

    '''
    disk_stats = {}
    if salt.utils.platform.is_windows():
        log.info("Platform is windows, skipping disk usage stats")
        disk_stats = {"Error": "Platform is windows"}
    else:
        if not path:
            # We would be interested in var partition disk stats only, for other partitions specify 'path' param
            path = "/var/log"
        df_stat = os.statvfs(path)
        total = df_stat.f_frsize * df_stat.f_blocks
        avail = df_stat.f_frsize * df_stat.f_bavail
        used = total - avail
        per_used = float(used)/total * 100
        log.info("Stats for path: {0}, Total: {1}, Available: {2}, Used: {3}, Use%: {4}".format(path,
                                                                                                total,
                                                                                                avail,
                                                                                                used,
                                                                                                per_used))
        disk_stats = {'Total' : total,
                      'Available' : avail,
                      'Used' : used,
                      'Use_percent' : per_used,
                      'Path' : path
                     }

        if __salt__['config.get']('splunklogging', False):
            log.info('Logging disk usage stats to splunk')
            hubblestack.splunklogging.__grains__ = __grains__
            hubblestack.splunklogging.__salt__ = __salt__
            hubblestack.splunklogging.__opts__ = __opts__
            handler = hubblestack.splunklogging.SplunkHandler()
            stats = {'disk_stats': disk_stats, 'schedule_time' : time.time()}
            handler.emit_data(stats)

    return disk_stats


def fields(*args):
    '''
    Use config.get to retrieve custom data based on the keys in the `*args`
    list.

    Arguments:

    *args
        List of keys to retrieve
    '''
    ret = {}
    for field in args:
        ret['custom_{0}'.format(field)] = __salt__['config.get'](field)
    # Return it as nebula data
    if ret:
        return [{'custom_fields': {
                 'data': [ret],
                 'result': True
                 }}]
    return []


def version():
    '''
    Report version of this module
    '''
    return __version__


def hubble_versions():
    '''
    Report version of all hubble modules as query
    '''
    versions = {'nova': __version__,
                'nebula': __version__,
                'pulsar': __version__,
                'quasar': __version__}

    return {'hubble_versions': {'data': [versions],
                                'result': True}}


@hubble_status.watch
def top(query_group,
        topfile='salt://hubblestack_nebula_v2/top.nebula',
        topfile_for_mask=None,
        verbose=False,
        report_version_with_day=True,
        mask_passwords=False):

    if salt.utils.platform.is_windows():
        topfile = 'salt://hubblestack_nebula_v2/win_top.nebula'

    configs = _get_top_data(topfile)

    configs = ['salt://hubblestack_nebula_v2/' + config.replace('.', '/') + '.yaml'
               for config in configs]

    return queries(query_group,
                   query_file=configs,
                   verbose=False,
                   report_version_with_day=True,
                   topfile_for_mask=topfile_for_mask,
                   mask_passwords=mask_passwords)


def _get_top_data(topfile):

    topfile = __salt__['cp.cache_file'](topfile)

    try:
        with open(topfile) as handle:
            topdata = yaml.safe_load(handle)
    except Exception as e:
        raise CommandExecutionError('Could not load topfile: {0}'.format(e))

    if not isinstance(topdata, dict) or 'nebula' not in topdata or \
            not(isinstance(topdata['nebula'], list)):
        raise CommandExecutionError('Nebula topfile not formatted correctly. '
                                    'Note that under the "nebula" key the data '
                                    'should now be formatted as a list of '
                                    'single-key dicts.')

    topdata = topdata['nebula']

    ret = []

    for topmatch in topdata:
        for match, data in topmatch.iteritems():
            if __salt__['match.compound'](match):
                ret.extend(data)

    return ret


def _mask_object(object_to_be_masked, topfile):
    '''
    Given an object with potential secrets (or other data that should not be
    returned), mask the contents of that object as configured in the mask
    configuration file. The mask configuration file used is defined by the
    top data in the ``topfile`` argument.

    If multiple mask.yaml files are matched in the topfile, the data within
    them will be recursively merged.

    If no matching mask_files are found in the top.mask file, no masking will
    happen.

    Note that this function has side effects: alterations to
    ``object_to_be_masked`` will be made in place.

    Sample mask.yaml data (with inline documentation):

    .. code-block:: yaml

        # Pattern that will replace whatever is masked
        mask_with: '***masked*by*hubble***'

        # Target and mask strings based on regex patterns
        # Can limit search specific queries and columns

        # Some osquery results are formed as lists of dicts. We can mask
        # based on variable names within these dicts.
        blacklisted_objects:

            - query_names:
              - 'running_procs'
              - 'listening_procs'          # List of name(s) of the osquery to be masked.
                                           # Put '*' to match all queries. Note
                                           # that query_names doesn't support
                                           # full globbing. '*' is just given
                                           # special treatment.
              column: 'environment'  # Column name in the osquery to be masked. No regex or glob support
              attribute_to_check: 'variable_name' # Optional attribute
                                                  # In the inner dict, this is the key
                                                  # to check for blacklisted_patterns
                                                  # Will skipped if column specified is of type 'String'
              attributes_to_mask: # Optional attribute, Values under these keys in the dict will be
                - 'value'  # masked, assuming one of the blacklisted_patterns
                           # is found under attribute_to_check in the same dict
                           # Will be skipped if column specified is of type 'String'
              blacklisted_patterns:  # Strings to look for under attribute_to_check. Conditional Globbing support.
                - 'ETCDCTL_READ_PASSWORD'
                - 'ETCDCTL_WRITE_PASSWORD'
                - '*PASSWORD*'  # Enable globbing by setting 'enable_globbing_in_nebula_masking' to True, default False

    blacklisted_patterns (for blacklisted_objects)

        For objects, the pattern applies to the variable name, and doesn't
        support regex. For example, you might have data formed like this::

            [{ value: 'SOME_PASSWORD', variable_name: 'ETCDCTL_READ_PASSWORD' }]

        The attribute_to_check would be ``variable_name`` and the pattern would
        be ``ETCDCTL_READ_PASSWORD``. The attribute_to_mask would be ``value``.
        All dicts with ``variable_name`` in the list of blacklisted_patterns
        would have the value under their ``value`` key masked.
    '''
    try:
        mask = {}
        if topfile is None:
            # We will maintain backward compatibility by keeping two versions of top files and mask files for now
            # Once all hubble servers are updated, we can remove old version of top file and mask file
            # Similar to what we have for nebula and nebula_v2 for older versions and newer versions of profiles
            topfile = 'salt://hubblestack_nebula_v2/top_v2.mask'
        mask_files = _get_top_data(topfile)
        mask_files = ['salt://hubblestack_nebula_v2/' + mask_file.replace('.', '/') + '.yaml'
                      for mask_file in mask_files]
        if not mask_files:
            mask_files = []
        for fh in mask_files:
            if 'salt://' in fh:
                orig_fh = fh
                fh = __salt__['cp.cache_file'](fh)
            if fh is None:
                log.error('Could not find file {0}.'.format(orig_fh))
                return None
            if os.path.isfile(fh):
                with open(fh, 'r') as f:
                    f_data = yaml.safe_load(f)
                    if not isinstance(f_data, dict):
                        raise CommandExecutionError('File data is not formed as a dict {0}'
                                                    .format(f_data))
                    mask = _dict_update(mask, f_data, recursive_update=True, merge_lists=True)

        log.debug('Masking data: {}'.format(mask))

        # Backwards compatibility with mask_by
        mask_with = mask.get('mask_with', mask.get('mask_by', '******'))

        log.info("Total number of results to check for masking: {0}".format(len(object_to_be_masked)))
        globbing_enabled = __opts__.get('enable_globbing_in_nebula_masking')

        for blacklisted_object in mask.get('blacklisted_objects', []):
            query_names = blacklisted_object['query_names']
            column = blacklisted_object['column'] # Can be converted to list as well in future if need be
            if '*' in query_names:
                # This means wildcard is specified and each event should be masked, if applicable
                for r in object_to_be_masked:
                    if 'action' in r:
                        # This means data is generated by osquery daemon
                        _mask_event_data(r, None, column, blacklisted_object, mask_with, globbing_enabled)
                    else:
                        # This means data is generated by osquery interactive shell
                        for query_name, query_ret in r.iteritems():
                            for query_result in query_ret['data']:
                                if column not in query_result or \
                                        (isinstance(query_result[column], basestring) and
                                        query_result[column].strip() != ''):
                                        # No error here, since we didn't reference a specific query
                                    break
                                if isinstance(query_result[column], basestring):
                                    # If column is of 'string' type, then replace pattern in-place
                                    # No need for recursion here
                                    value = query_result[column]
                                    for pattern in blacklisted_object['blacklisted_patterns']:
                                        value = re.sub(pattern + '()', r'\1' + mask_with + r'\3', value)
                                    query_result[column] = value
                                else:
                                    _recursively_mask_objects(query_result[column], blacklisted_object, mask_with, globbing_enabled)
            else:
                # Perform masking on results of specific queries specified in 'query_names'
                for query_name in query_names:
                    for r in object_to_be_masked:
                        if 'action' in r:
                            # This means data is generated by osquery daemon
                            _mask_event_data(r, query_name, column, blacklisted_object, mask_with, globbing_enabled)
                        else:
                            # This means data is generated by osquery interactive shell
                            for query_result in r.get(query_name, {'data':[]})['data']:
                                if column not in query_result or \
                                        (isinstance(query_result[column], basestring) and
                                         query_result[column].strip() != ''):
                                        # if the column in not present in one data-object, it will
                                        # not be present in others as well. Break in that case.
                                        # This will happen only if mask.yaml is malformed
                                    log.error('masking data references a missing column {0} in query {1}'
                                              .format(column, query_name))
                                    break
                                if isinstance(query_result[column], basestring):
                                    # If column is of 'string' type, then replace pattern in-place
                                    # No need for recursion here
                                    value = query_result[column]
                                    for pattern in blacklisted_object['blacklisted_patterns']:
                                        value = re.sub(pattern + '()', r'\1' + mask_with + r'\3', value)
                                    query_result[column] = value
                                else:
                                    _recursively_mask_objects(query_result[column], blacklisted_object, mask_with, globbing_enabled)
    except Exception as e:
        log.exception('An error occured while masking the passwords: {}'.format(e))

    # Object masked in place, so we don't need to return the object
    return True


def _mask_event_data(object_to_be_masked, query_name, column, blacklisted_object, mask_with, globbing_enabled):
    '''
    This method is responsible for masking potential secrets in event data generated by
    osquery daemon. This will handle logs format of both differential and snapshot types

    Logs generated by 'osqueryi' would not reach here due checks in parent method

    object_to_be_masked
        data structure to mask recursively

    query_name
        Perform masking only if query name in 'object_to_be_masked' matches the 'query_name'

    column
        column in which masking is to be performed

    blacklisted_object
        the blacklisted_objects entry from the mask.yaml

    mask_with
        masked values are replaced with this string

    globbing_enabled
        enable globbing in specified blacklisted patterns of mask file
    '''
    if not query_name:
        query_name = object_to_be_masked['name']

    if object_to_be_masked['action'] == 'snapshot' and query_name == object_to_be_masked['name']:
        # This means we have event data of type 'snapshot'
        for snap_object in object_to_be_masked['snapshot']:
            if column not in snap_object or \
                    (isinstance(snap_object[column], basestring) and
                     snap_object[column].strip() != ''):
                log.error('masking data references a missing column {0} in query {1}'
                          .format(column, query_name))
                break
            if isinstance(snap_object[column], basestring):
                value = snap_object[column]
                for pattern in blacklisted_object['blacklisted_patterns']:
                    value = re.sub(pattern + '()', r'\1' + mask_with + r'\3', value)
                snap_object[column] = value
            else:
                _recursively_mask_objects(snap_object[column], blacklisted_object, mask_with, globbing_enabled)
    elif query_name == object_to_be_masked['name']:
        q_result = object_to_be_masked['columns']
        if column not in q_result or \
                (isinstance(q_result[column], basestring) and
                 q_result[column].strip() != ''):
            log.error('masking data references a missing column {0} in query {1}'
                      .format(column, query_name))
        if isinstance(q_result[column], basestring):
            value = q_result[column]
            for pattern in blacklisted_object['blacklisted_patterns']:
                value = re.sub(pattern + '()', r'\1' + mask_with + r'\3', value)
            q_result[column] = value
        else:
            _recursively_mask_objects(q_result[column], blacklisted_object, mask_with, globbing_enabled)
    else:
        # Unable to match query_name
        log.debug('Skipping masking, as event data is not for query: {0}'.format(query_name))


def _recursively_mask_objects(object_to_mask, blacklisted_object, mask_with, globbing_enabled):
    '''
    This function is used by ``_mask_object()`` to mask passwords contained in
    an osquery data structure (formed as a list of dicts, usually). Since the
    lists can sometimes be nested, recurse through the lists.

    object_to_mask
        data structure to mask recursively

    blacklisted_object
        the blacklisted_objects entry from the mask.yaml

    mask_with
        masked values are replaced with this string
    
    globbing_enabled
        enable globbing in specified blacklisted patterns of mask file
    '''
    if isinstance(object_to_mask, list):
        for child in object_to_mask:
            log.debug("Recursing object {0}".format(child))
            _recursively_mask_objects(child, blacklisted_object, mask_with, globbing_enabled)
    elif globbing_enabled and blacklisted_object['attribute_to_check'] in object_to_mask:
        mask = False
        for blacklisted_pattern in blacklisted_object['blacklisted_patterns']:
            if fnmatch.fnmatch(object_to_mask[blacklisted_object['attribute_to_check']], blacklisted_pattern):
                mask = True
                log.info("Attribute {0} will be masked.".format(object_to_mask[blacklisted_object['attribute_to_check']]))
                break
        if mask:
            for key in blacklisted_object['attributes_to_mask']:
                if key in object_to_mask:
                    object_to_mask[key] = mask_with
    elif (not globbing_enabled) and blacklisted_object['attribute_to_check'] in object_to_mask and \
         object_to_mask[blacklisted_object['attribute_to_check']] in blacklisted_object['blacklisted_patterns']:
        for key in blacklisted_object['attributes_to_mask']:
            if key in object_to_mask:
                object_to_mask[key] = mask_with


def _dict_update(dest, upd, recursive_update=True, merge_lists=False):
    '''
    Recursive version of the default dict.update

    Merges upd recursively into dest

    If recursive_update=False, will use the classic dict.update, or fall back
    on a manual merge (helpful for non-dict types like FunctionWrapper)

    If merge_lists=True, will aggregate list object types instead of replace.
    This behavior is only activated when recursive_update=True. By default
    merge_lists=False.
    '''
    if (not isinstance(dest, collections.Mapping)) \
            or (not isinstance(upd, collections.Mapping)):
        raise TypeError('Cannot update using non-dict types in dictupdate.update()')
    updkeys = list(upd.keys())
    if not set(list(dest.keys())) & set(updkeys):
        recursive_update = False
    if recursive_update:
        for key in updkeys:
            val = upd[key]
            try:
                dest_subkey = dest.get(key, None)
            except AttributeError:
                dest_subkey = None
            if isinstance(dest_subkey, collections.Mapping) \
                    and isinstance(val, collections.Mapping):
                ret = _dict_update(dest_subkey, val, merge_lists=merge_lists)
                dest[key] = ret
            elif isinstance(dest_subkey, list) \
                    and isinstance(val, list):
                if merge_lists:
                    dest[key] = dest.get(key, []) + val
                else:
                    dest[key] = upd[key]
            else:
                dest[key] = upd[key]
        return dest
    else:
        try:
            for k in upd.keys():
                dest[k] = upd[k]
        except AttributeError:
            # this mapping is not a dict
            for k in upd:
                dest[k] = upd[k]
        return dest


def _osqueryd_running_status(pidfile, servicename):
    '''
    This function will check whether osqueryd is running in *nix systems
    '''
    log.info("checking if osqueryd is already running or not")
    osqueryd_running = False
    if os.path.isfile(pidfile):
      try:
        with open(pidfile, 'r') as f:
          xpid = f.readline().strip()
          try:
            xpid = int(xpid)
          except:
            xpid = 0
            log.warn('unable to parse pid="{pid}" in pidfile={file}'.format(pid=xpid,file=pidfile))
          if xpid:
            log.info('pidfile={file} exists and contains pid={pid}'.format(file=pidfile, pid=xpid))
            if os.path.isdir("/proc/{pid}".format(pid=xpid)):
              try:
                with open("/proc/{pid}/cmdline".format(pid=xpid),'r') as f2:
                  cmdline = f2.readline().strip().strip('\x00').replace('\x00',' ')
                  if 'osqueryd' in cmdline:
                    log.info("process folder present and process is osqueryd")
                    osqueryd_running = True
                  else:
                    log.error("process is not osqueryd, attempting to start osqueryd")
              except:
                log.error("process's cmdline cannot be determined, attempting to start osqueryd")
            else:
              log.error("process folder not present, attempting to start osqueryd")
          else:
            log.error("pid cannot be determined, attempting to start osqueryd")
      except:
        log.error("unable to open pidfile, attempting to start osqueryd")
    else:
      cmd = ['pkill', 'hubble_osqueryd']
      __salt__['cmd.run'](cmd, timeout=10000)
      log.error("pidfile not found, attempting to start osqueryd")
    return osqueryd_running


def _osqueryd_restart_required(hashfile, flagfile):
    '''
    This function will check whether osqueryd needs to be restarted
    '''
    log.info("checking if osqueryd needs to be restarted or not")
    try:
        open_file = open(flagfile, 'r')
        file_content = open_file.read().lower().rstrip('\n\r ').strip('\n\r')
        hash_md5 = md5()
        hash_md5.update(file_content.encode('ISO-8859-1'))
        new_hash = hash_md5.hexdigest()

        if not os.path.isfile(hashfile):
            f = open(hashfile, "w")
            f.write(new_hash)
            return False
        else:
            f = open(hashfile, "r")
            old_hash = f.read()
            if old_hash != new_hash:
                log.info('old hash is {0} and new hash is {1}'.format(old_hash, new_hash))
                log.info('changes detected in flag file')
                return True
            else:
                log.info('no changes detected in flag file')
    except:
        log.error("some error occured, unable to determine whether osqueryd need to be restarted, not restarting osqueryd")
    return False


def _osqueryd_running_status_windows(servicename):
    '''
    This function will check whether osqueryd is running in windows systems
    '''
    log.info("checking if osqueryd is already running or not")
    osqueryd_running = False
    cmd_status = "(Get-Service -Name " + servicename + ").Status"
    osqueryd_status = __salt__['cmd.run'](cmd_status, shell='powershell')
    if osqueryd_status == 'Running':
        osqueryd_running = True
        log.info('osqueryd already running')
    else:
        log.info('osqueryd not running')
        osqueryd_running = False
    
    return osqueryd_running


def _start_osqueryd(pidfile, 
                    configfile, 
                    flagfile, 
                    logdir, 
                    databasepath, 
                    servicename):
    '''
    This function will start osqueryd
    ''' 
    log.info("osqueryd is not running, attempting to start osqueryd")
    if salt.utils.platform.is_windows():
        log.error("requesting service manager to start osqueryD")
        cmd = ['net', 'start', servicename]
    else:
        cmd = ['/opt/osquery/hubble_osqueryd', '--pidfile={0}'.format(pidfile), '--logger_path={0}'.format(logdir),
               '--config_path={0}'.format(configfile), '--flagfile={0}'.format(flagfile), 
               '--database_path={0}'.format(databasepath), '--daemonize']
    __salt__['cmd.run'](cmd, timeout=10000)
    log.info("daemonized the osqueryd")


def _restart_osqueryd(pidfile, 
                      configfile, 
                      flagfile, 
                      logdir, 
                      databasepath, 
                      hashfile, 
                      servicename):
    '''
    This function will restart osqueryd
    ''' 
    log.info("osqueryd needs to be restarted, restarting now")

    open_file = open(flagfile, 'r')
    file_content = open_file.read().lower().rstrip('\n\r ').strip('\n\r')
    hash_md5 = md5()
    hash_md5.update(file_content.encode('ISO-8859-1'))
    new_hash = hash_md5.hexdigest()

    f = open(hashfile, "w")
    f.write(new_hash)
    open_file.close()
    f.close()
    if salt.utils.platform.is_windows():
        stop_cmd = ['net', 'stop', servicename]
        __salt__['cmd.run'](stop_cmd, timeout=10000)
        start_cmd = ['net', 'start', servicename]
        __salt__['cmd.run'](start_cmd, timeout=10000)
    else:
        stop_cmd = ['pkill', 'hubble_osqueryd']
        __salt__['cmd.run'](stop_cmd, timeout=10000)
        remove_pidfile_cmd = ['rm', '-rf', '{0}'.format(pidfile)]
        __salt__['cmd.run'](remove_pidfile_cmd, timeout=10000)
        start_cmd = ['/opt/osquery/hubble_osqueryd', '--pidfile={0}'.format(pidfile), '--logger_path={0}'.format(logdir),
                     '--config_path={0}.format(configfile)', '--flagfile={0}'.format(flagfile), 
                     '--database_path={0}'.format(databasepath), '--daemonize']
        __salt__['cmd.run'](start_cmd, timeout=10000)
    log.info("daemonized the osqueryd")


def _parse_log(path_to_logfile, 
               offset,
               backuplogdir,
               logfilethresholdinbytes,
               maxlogfilesizethreshold,
               backuplogfilescount,
               enablediskstatslogging):
    '''
    Parse logs generated by osquery daemon.
    Path to log file to be parsed should be specified
    '''
    event_data = []
    file_offset = offset
    rotateLog = False
    if path.exists(path_to_logfile):
        fileDes = open(path_to_logfile, "r+")
        if fileDes:
            if os.stat(path_to_logfile).st_size > maxlogfilesizethreshold:
                # This is done to handle scenarios where hubble process was in stopped state and
                # osquery daemon was generating logs for that time frame. When hubble is started and
                # this function gets executed, it might be possible that the log file is now huge.
                # In this scenario hubble might take too much time to process the logs which may not be required
                # To handle this, log file size is validated against max threshold size.
                log.info("Log file size is above max threshold size that can be parsed by Hubble.")
                log.info("Log file size: {0}, max threshold: {1}".format(os.stat(path_to_logfile).st_size, 
                                                                         maxlogfilesizethreshold))
                log.info("Rotating log and skipping parsing for this iteration")
                fileDes.close()
                _perform_log_rotation(path_to_logfile, 
                                      file_offset,
                                      backuplogdir,
                                      backuplogfilescount,
                                      enablediskstatslogging,
                                      False)
                file_offset = 0 #Reset file offset to start of file in case original file is rotated
            else:
                if os.stat(path_to_logfile).st_size > logfilethresholdinbytes:
                    rotateLog = True
                fileDes.seek(offset)
                for event in fileDes.readlines():
                    event_data.append(event)
                file_offset = fileDes.tell()
                fileDes.close()
                if rotateLog:
                    log.info('Log file size above threshold, '
                              'going to rotate log file: {0}'.format(path_to_logfile))
                    residue_events = _perform_log_rotation(path_to_logfile, 
                                                        file_offset, 
                                                        backuplogdir, 
                                                        backuplogfilescount,
                                                        enablediskstatslogging,
                                                        True)
                    if residue_events:
                        log.info("Found few residue logs, updating the data object")
                        event_data += residue_events
                    file_offset = 0 #Reset file offset to start of file in case original file is rotated
            _set_cache_offset(path_to_logfile, file_offset)
        else:
            log.error('Unable to open log file for reading: {0}'.format(path_to_logfile))
    else:
        log.error("Log file doesn't exists: {0}".format(path_to_logfile))

    return event_data


def _set_cache_offset(path_to_logfile, offset):
    '''
    Cache file offset in memory
    '''
    cachefilekey = os.path.basename(path_to_logfile)
    __RESULT_LOG_OFFSET__[cachefilekey] = offset


def _get_file_offset(path_to_logfile):
    '''
    Fetch file offset for specified file
    '''
    cachefilekey = os.path.basename(path_to_logfile)
    offset = __RESULT_LOG_OFFSET__.get(cachefilekey, 0)
    return offset


def _perform_log_rotation(path_to_logfile, 
                          offset,
                          backuplogdir,
                          backuplogfilescount,
                          enablediskstatslogging,
                          readResidueEvents):
    '''
    Perform log rotation on specified file and create backup of file under specified backup directory.
    '''
    residue_events = []
    if path.exists(path_to_logfile):
        logfilename = os.path.basename(path_to_logfile)
        if path.exists(backuplogdir):
            listofbackuplogfiles = glob.glob(os.path.normpath(os.path.join(backuplogdir, logfilename)) + "*")

            if listofbackuplogfiles:
                log.info("Backup log file count: {0} and backup count threshold: {1}".format(len(listofbackuplogfiles), 
                                                                                            backuplogfilescount))
                listofbackuplogfiles.sort()
                log.info("Backup log file sorted list: {0}".format(listofbackuplogfiles))
                if(len(listofbackuplogfiles) >= backuplogfilescount):
                    listofbackuplogfiles = listofbackuplogfiles[:len(listofbackuplogfiles) - backuplogfilescount + 1]
                    for dfile in listofbackuplogfiles:
                        salt.utils.files.remove(dfile)
                    log.info("Successfully deleted extra backup log files")

            residue_events = []
            logfilename = os.path.basename(path_to_logfile)
    
            backupLogFile = os.path.normpath(os.path.join(backuplogdir, logfilename) + "-" + str(time.time()))
            salt.utils.files.rename(path_to_logfile, backupLogFile)

            if readResidueEvents:
                residue_events = _read_residue_logs(backupLogFile, offset)

            if enablediskstatslogging:
                # As of now, this method would send disk stats to Splunk (if configured)
                disk_stats = check_disk_usage()
        else:
            log.error("Specified backup log directory does not exists. Log rotation will not be performed.")

    return residue_events


def _read_residue_logs(path_to_logfile, offset):
    '''
    Read any logs that might have been written while creating backup log file
    '''
    event_data= []
    if path.exists(path_to_logfile):
       fileDes = open(path_to_logfile, "r+")
       if fileDes:
           log.info('Checking for any residue logs that might have been '
                     'added while log rotation was being performed')
           fileDes.seek(offset)
           for event in fileDes.readlines():
               event_data.append(event)
           fileDes.close()
    return event_data
