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

import collections
import copy
import glob
import fnmatch
import json
import logging
import re
import time
import os
from os import path
import yaml

import salt.utils
import salt.utils.files
import salt.utils.platform

from hashlib import md5
from salt.exceptions import CommandExecutionError
from hubblestack import __version__
import hubblestack.log

log = logging.getLogger(__name__)

from hubblestack.status import HubbleStatus
hubble_status = HubbleStatus(__name__, 'top', 'queries', 'osqueryd_monitor', 'osqueryd_log_parser')

__virtualname__ = 'nebula'
__RESULT_LOG_OFFSET__ = {}
OSQUERYD_NEEDS_RESTART = False

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
        if not fh:
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
    __opts__['nebula_queries'] = query_data

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

        extensions_loadfile = __opts__.get('osquery_extensions_loadfile')

        # Run the osqueryi query
        if extensions_loadfile:
            cmd = [__grains__['osquerybinpath'], '--extensions_autoload', extensions_loadfile, '--read_max', MAX_FILE_SIZE, '--json', query_sql]
        else:
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
        return None

    if __salt__['config.get']('splunklogging', False):
        log.debug('Logging osquery timing data to splunk')
        timing_data = {'query_run_length': timing,
                       'schedule_time': schedule_time}
        hubblestack.log.emit_to_splunk(timing_data, 'INFO', 'hubblestack.osquery_timing')

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
                     conftopfile=None,
                     flagstopfile=None,
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
        Path to osquery configuration file. If this is specified, conftopfile will be ignored

    conftopfile
        Path to topfile which will be used to dynamically generate osquery conf in JSON format

    flagstopfile
        Path to topfile which will be used to dynamically generate osquery flags

    flagfile
        Path to osquery flag file. If this is specified, flagstopfile will be ignored

    logdir
        Path to log directory where osquery daemon/service will write logs

    pidfile
        pidfile path where osquery daemon will write pid info

    hashfile
        path to hashfile where osquery flagfile's hash would be stored

    daemonize
        daemonize osquery daemon. Default is True. Applicable for posix system only

    '''
    log.info("Starting osqueryd monitor")
    saltenv = __salt__['config.get']('hubblestack:nova:saltenv', 'base')
    osqueryd_path = 'salt://hubblestack_nebula_v2'
    cached = __salt__['cp.cache_dir'](osqueryd_path, saltenv=saltenv)
    log.debug('Cached nebula files to cachedir')
    cachedir = os.path.join(__opts__.get('cachedir'), 'files', saltenv, 'hubblestack_nebula_v2')
    base_path = cachedir
    servicename = "hubble_osqueryd"
    if not logdir:
        logdir = __opts__.get('osquerylogpath')
    if not databasepath:
        databasepath = __opts__.get('osquery_dbpath')
    if salt.utils.platform.is_windows():
        if not pidfile:
            pidfile = os.path.join(base_path, "hubble_osqueryd.pidfile")
        if not configfile:
            if not conftopfile:
                conftopfile = 'salt://hubblestack_nebula_v2/win_top.osqueryconf'
            configfile = _generate_osquery_conf_file(conftopfile)
        if not flagfile:
            if not flagstopfile:
                flagstopfile = 'salt://hubblestack_nebula_v2/win_top.osqueryflags'
            flagfile = _generate_osquery_flags_file(flagstopfile)
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
            pidfile = os.path.join(base_path, "hubble_osqueryd.pidfile")
        if not configfile:
            if not conftopfile:
                conftopfile = 'salt://hubblestack_nebula_v2/top.osqueryconf'
            configfile = _generate_osquery_conf_file(conftopfile)
        if not flagfile:
            if not flagstopfile:
                flagstopfile = 'salt://hubblestack_nebula_v2/top.osqueryflags'
            flagfile = _generate_osquery_flags_file(flagstopfile)
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
                        maxlogfilesizethreshold=None,
                        logfilethresholdinbytes=None,
                        backuplogfilescount=None,
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
        result_logfile = os.path.normpath(os.path.join(osqueryd_logdir, 'osqueryd.results.log'))
        snapshot_logfile = os.path.normpath(os.path.join(osqueryd_logdir, 'osqueryd.snapshots.log'))
    else:
        osquery_base_logdir = __opts__.get('osquerylogpath')
        result_logfile = os.path.normpath(os.path.join(osquery_base_logdir, 'osqueryd.results.log'))
        snapshot_logfile = os.path.normpath(os.path.join(osquery_base_logdir, 'osqueryd.snapshots.log'))

    log.debug("Result log file resolved to: {0}".format(result_logfile))
    log.debug("Snapshot log file resolved to: {0}".format(snapshot_logfile))

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
            ret += r_event_data
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

    path
        Defaults to '/var/log'

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
        per_used = float(used) / total * 100
        log.info("Stats for path: {0}, Total: {1}, Available: {2}, Used: {3}, Use%: {4}".format(path,
                                                                                                total,
                                                                                                avail,
                                                                                                used,
                                                                                                per_used))
        disk_stats = {'Total': total,
                      'Available': avail,
                      'Used': used,
                      'Use_percent': per_used,
                      'Path': path
                      }

        if __salt__['config.get']('splunklogging', False):
            log.debug('Logging disk usage stats to splunk')
            stats = {'disk_stats': disk_stats, 'schedule_time': time.time()}
            hubblestack.log.emit_to_splunk(stats, 'INFO', 'hubblestack.disk_usage')

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

    if not topfile:
        raise CommandExecutionError('Topfile not found.')

    try:
        with open(topfile) as handle:
            topdata = yaml.safe_load(handle)
    except Exception as e:
        raise CommandExecutionError('Could not load topfile: {0}'.format(e))

    if not isinstance(topdata, dict) or 'nebula' not in topdata or \
            not isinstance(topdata['nebula'], list):
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


def _generate_osquery_conf_file(conftopfile):
    '''
    Function to dynamically create osquery configuration file in JSON format.
    This function would load osquery configuration in YAML format and
    make use of topfile to selectively load file(s) based on grains
    '''

    log.info("Generating osquery conf file using topfile: {0}".format(conftopfile))
    saltenv = __salt__['config.get']('hubblestack:nova:saltenv', 'base')
    osqueryd_path = 'salt://hubblestack_nebula_v2'
    cached = __salt__['cp.cache_dir'](osqueryd_path, saltenv=saltenv)
    log.debug('Cached nebula files to cachedir')
    cachedir = os.path.join(__opts__.get('cachedir'), 'files', saltenv, 'hubblestack_nebula_v2')
    base_path = cachedir

    osqd_configs = _get_top_data(conftopfile)
    configfile = os.path.join(base_path, "osquery.conf")
    conf_data = {}
    osqd_configs = ['salt://hubblestack_nebula_v2/' + config.replace('.', '/') + '.yaml'
                    for config in osqd_configs]
    for fh in osqd_configs:
        if 'salt://' in fh:
            orig_fh = fh
            fh = __salt__['cp.cache_file'](fh)
        if not fh:
            log.error('Could not find file {0}.'.format(orig_fh))
            return None
        if os.path.isfile(fh):
            with open(fh, 'r') as f:
                f_data = yaml.safe_load(f)
                if not isinstance(f_data, dict):
                    raise CommandExecutionError('File data is not formed as a dict {0}'
                                                .format(f_data))
                conf_data = _dict_update(conf_data,
                                         f_data,
                                         recursive_update=True,
                                         merge_lists=True)
    if conf_data:
        try:
            log.debug("Writing config to osquery.conf file")
            with open(configfile, "w") as cf:
                json.dump(conf_data, cf)
        except Exception as e:
            log.error("Failed to generate osquery conf file using topfile {0}".format(e))

    return configfile


def _generate_osquery_flags_file(flagstopfile):
    '''
    Function to dynamically create osquery flags file.
    This function would load osquery flags in YAML format and
    make use of topfile to selectively load file(s) based on grains
    '''

    log.info("Generating osquery flags file using topfile: {0}".format(flagstopfile))
    saltenv = __salt__['config.get']('hubblestack:nova:saltenv', 'base')
    osqueryd_path = 'salt://hubblestack_nebula_v2'
    cached = __salt__['cp.cache_dir'](osqueryd_path, saltenv=saltenv)
    log.debug('Cached nebula files to cachedir')
    cachedir = os.path.join(__opts__.get('cachedir'), 'files', saltenv, 'hubblestack_nebula_v2')
    base_path = cachedir

    osqd_flags = _get_top_data(flagstopfile)
    flagfile = os.path.join(base_path, "osquery.flags")
    flags_data = {}
    osqd_flags = ['salt://hubblestack_nebula_v2/' + config.replace('.', '/') + '.yaml'
                  for config in osqd_flags]
    for fh in osqd_flags:
        if 'salt://' in fh:
            orig_fh = fh
            fh = __salt__['cp.cache_file'](fh)
        if not fh:
            log.error('Could not find file {0}.'.format(orig_fh))
            return None
        if os.path.isfile(fh):
            with open(fh, 'r') as f:
                f_data = yaml.safe_load(f)
                if not isinstance(f_data, dict):
                    raise CommandExecutionError('File data is not formed as a dict {0}'
                                                .format(f_data))
                flags_data = _dict_update(flags_data,
                                          f_data,
                                          recursive_update=True,
                                          merge_lists=True)
    if flags_data:
        try:
            log.debug("Writing config to osquery.flags file")
            with open(flagfile, "w") as cf:
                for key in flags_data:
                    propdata = "--" + key + "=" + flags_data.get(key) + "\n"
                    cf.write(propdata)
        except Exception as e:
            log.error("Failed to generate osquery flags file using topfile {0}".format(e))

    return flagfile


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
              custom_mask_column: 'environment'  # Column name which stores environment variables
              custom_mask_key: '__hubble_mask__' # Env variable to look for constructing custom blacklist of patterns
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
            if not fh:
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
        mask_with = mask.get('mask_with', mask.get('mask_by', 'REDACTED'))

        log.info("Total number of results to check for masking: {0}".format(len(object_to_be_masked)))
        globbing_enabled = __opts__.get('enable_globbing_in_nebula_masking')

        for blacklisted_object in mask.get('blacklisted_objects', []):
            query_names = blacklisted_object['query_names']
            column = blacklisted_object['column']  # Can be converted to list as well in future if need be
            # Name of column that stores environment variables
            custom_mask_column = blacklisted_object.get('custom_mask_column', '')
            enable_local_masking = blacklisted_object.get('enable_local_masking', False)
            enable_global_masking = blacklisted_object.get('enable_global_masking', False)

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
                                if enable_local_masking is True and custom_mask_column and custom_mask_column in query_result:
                                    log.debug("Checking if custom mask patterns are set in environment")
                                    mask_column = query_result[custom_mask_column]
                                    if mask_column and isinstance(mask_column, list):
                                        for column_field in mask_column:
                                            try:
                                                if 'variable_name' in column_field and 'value' in column_field and \
                                                        column_field['variable_name'] == blacklisted_object['custom_mask_key']:
                                                    log.debug("Constructing custom blacklisted patterns based on \
                                                              environment variable '{0}'".format(blacklisted_object['custom_mask_key']))
                                                    blacklisted_object['custom_blacklist'] = [p.strip() for p in
                                                                                              column_field['value'].replace(' ', ',').split(',')
                                                                                              if p.strip() and p.strip() != blacklisted_object['custom_mask_key']]
                                                else:
                                                    log.debug("Custom mask variable not set in environment. \
                                                              Custom mask key used: {0}".format(blacklisted_object['custom_mask_key']))
                                            except Exception as e:
                                                log.error("Failed to generate custom blacklisted patterns based on hubble mask key")
                                                log.error("Got error: {0}".format(e))
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
                                    _perform_masking(
                                        query_result[column], blacklisted_object,
                                        mask_with, globbing_enabled)
                                    blacklisted_object.pop('custom_blacklist', None)
            else:
                # Perform masking on results of specific queries specified in 'query_names'
                for query_name in query_names:
                    for r in object_to_be_masked:
                        if 'action' in r:
                            # This means data is generated by osquery daemon
                            _mask_event_data(r, query_name, column, blacklisted_object, mask_with, globbing_enabled)
                        else:
                            # This means data is generated by osquery interactive shell
                            for query_result in r.get(query_name, {'data': []})['data']:
                                if enable_local_masking is True and custom_mask_column and custom_mask_column in query_result:
                                    log.debug("Checking if custom mask patterns are set in environment")
                                    mask_column = query_result[custom_mask_column]
                                    if mask_column and isinstance(mask_column, list):
                                        for column_field in mask_column:
                                            try:
                                                if 'variable_name' in column_field and 'value' in column_field and \
                                                        column_field['variable_name'] == blacklisted_object['custom_mask_key']:
                                                    log.debug("Constructing custom blacklisted patterns based on \
                                                              environment variable '{0}'".format(blacklisted_object['custom_mask_key']))
                                                    blacklisted_object['custom_blacklist'] = [p.strip() for p in
                                                                                              column_field['value'].replace(' ', ',').split(',')
                                                                                              if p.strip() and p.strip() != blacklisted_object['custom_mask_key']]
                                                else:
                                                    log.debug("Custom mask variable not set in environment. \
                                                              Custom mask key used: {0}".format(blacklisted_object['custom_mask_key']))
                                            except Exception as e:
                                                log.error("Failed to generate custom blacklisted patterns based on hubble mask key")
                                                log.error("Got error: {0}".format(e))
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
                                    _perform_masking(
                                        query_result[column], blacklisted_object,
                                        mask_with, globbing_enabled)
                                    blacklisted_object.pop('custom_blacklist', None)
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
    # Name of column that stores environment variables
    custom_mask_column = blacklisted_object.get('custom_mask_column', '')
    enable_local_masking = blacklisted_object.get('enable_local_masking', False)
    enable_global_masking = blacklisted_object.get('enable_global_masking', False)

    if object_to_be_masked['action'] == 'snapshot' and query_name == object_to_be_masked['name']:
        # This means we have event data of type 'snapshot'
        for snap_object in object_to_be_masked['snapshot']:
            if enable_local_masking is True and custom_mask_column and custom_mask_column in snap_object:
                log.debug("Checking if custom mask patterns are set in environment")
                mask_column = snap_object[custom_mask_column]
                if mask_column and isinstance(mask_column, list):
                    for column_field in mask_column:
                        try:
                            if 'variable_name' in column_field and 'value' in column_field and \
                                    column_field['variable_name'] == blacklisted_object['custom_mask_key']:
                                log.debug("Constructing custom blacklisted patterns based on \
                                          environment variable '{0}'".format(blacklisted_object['custom_mask_key']))
                                blacklisted_object['custom_blacklist'] = [p.strip() for p in
                                                                          column_field['value'].replace(' ', ',').split(',')
                                                                          if p.strip() and p.strip() != blacklisted_object['custom_mask_key']]
                            else:
                                log.debug("Custom mask variable not set in environment. \
                                          Custom mask key used: {0}".format(blacklisted_object['custom_mask_key']))
                        except Exception as e:
                            log.error("Failed to generate custom blacklisted patterns based on hubble mask key")
                            log.error("Got error: {0}".format(e))
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
                _perform_masking(snap_object[column], blacklisted_object, mask_with, globbing_enabled)
                blacklisted_object.pop('custom_blacklist', None)
    elif query_name == object_to_be_masked['name']:
        q_result = object_to_be_masked['columns']
        if enable_local_masking is True and custom_mask_column and custom_mask_column in q_result:
            log.debug("Checking if custom mask patterns are set in environment")
            mask_column = q_result[custom_mask_column]
            if mask_column and isinstance(mask_column, list):
                for column_field in mask_column:
                    try:
                        if 'variable_name' in column_field and 'value' in column_field and \
                                column_field['variable_name'] == blacklisted_object['custom_mask_key']:
                            log.debug("Constructing custom blacklisted patterns based on \
                                      environment variable '{0}'".format(blacklisted_object['custom_mask_key']))
                            blacklisted_object['custom_blacklist'] = [p.strip() for p in
                                                                      column_field['value'].replace(' ', ',').split(',')
                                                                      if p.strip() and p.strip() != blacklisted_object['custom_mask_key']]
                        else:
                            log.debug("Custom mask variable not set in environment. \
                                          Custom mask key used: {0}".format(blacklisted_object['custom_mask_key']))
                    except Exception as e:
                        log.error("Failed to generate custom blacklisted patterns based on hubble mask key")
                        log.error("Got error: {0}".format(e))
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
            _perform_masking(q_result[column], blacklisted_object, mask_with, globbing_enabled)
            blacklisted_object.pop('custom_blacklist', None)
    else:
        # Unable to match query_name
        log.debug('Skipping masking, as event data is not for query: {0}'.format(query_name))


def _perform_masking(object_to_mask, blacklisted_object, mask_with, globbing_enabled):
    '''
    This function is used as a wrapper to _recursively_mask_objects function.
    It's main usage is to set 'blacklisted_patterns'. If custom blacklisted patterns are present they will used.

    Fallback to blacklisted_patterns specified in mask file if no custom hubble mask is provided.

    object_to_mask
        data structure to mask recursively

    blacklisted_object
        the blacklisted_objects entry from the mask.yaml

    blacklisted_patterns
        List of blacklisted patterns which will be used to identify if a field is to be masked

    mask_with
        masked values are replaced with this string

    globbing_enabled
        enable globbing in specified blacklisted patterns of mask file
    '''
    enable_local_masking = blacklisted_object.get('enable_local_masking', False)
    enable_global_masking = blacklisted_object.get('enable_global_masking', False)
    blacklisted_patterns = None

    if enable_local_masking is True and enable_global_masking is True:
        # For now, we will be performing masking based on global list as well as dynamic list present in process's environment variable
        # If there's no noticeable performance impact then we will continue using both else switch to using either global blacklist
        # or dynamic blacklist as specified by blacklisted_object['custom_mask_key'] in process's environment
        if 'custom_blacklist' in blacklisted_object and blacklisted_object['custom_blacklist']:
            if blacklisted_object.get('blacklisted_patterns', None):
                blacklisted_patterns = blacklisted_object['blacklisted_patterns'] + blacklisted_object['custom_blacklist']
                blacklisted_patterns = list(set(blacklisted_patterns)) # remove duplicates, if any
                log.debug("Appending custom blacklisted patterns in global blacklist for masking")
            else:
                blacklisted_patterns = blacklisted_object['custom_blacklist']
                log.debug("Local blacklist missing, using global blacklist for masking")
        else:
            if blacklisted_object.get('blacklisted_patterns', None):
                blacklisted_patterns = blacklisted_object['blacklisted_patterns']
                log.debug("No local blacklist found, using global blacklist only for masking")
    elif enable_global_masking is True:
        if blacklisted_object.get('blacklisted_patterns', None):
            blacklisted_patterns = blacklisted_object['blacklisted_patterns']
            log.debug("Only global masking is enabled.")
    elif enable_local_masking is True:
        if 'custom_blacklist' in blacklisted_object and blacklisted_object['custom_blacklist']:
            blacklisted_patterns = blacklisted_object['custom_blacklist']
            log.debug("Only local masking is enabled.")
    else:
        log.debug("Both global and local masking is disabled, skipping masking of results.")

    if blacklisted_patterns:
        _recursively_mask_objects(object_to_mask, blacklisted_object, blacklisted_patterns, mask_with, globbing_enabled)


def _recursively_mask_objects(object_to_mask, blacklisted_object, blacklisted_patterns, mask_with, globbing_enabled):
    '''
    This function is used by ``_mask_object()`` to mask passwords contained in
    an osquery data structure (formed as a list of dicts, usually). Since the
    lists can sometimes be nested, recurse through the lists.

    object_to_mask
        data structure to mask recursively

    blacklisted_object
        the blacklisted_objects entry from the mask.yaml

    blacklisted_patterns
        List of blacklisted patterns which will be used to identify if a field is to be masked

    mask_with
        masked values are replaced with this string

    globbing_enabled
        enable globbing in specified blacklisted patterns of mask file
    '''
    if isinstance(object_to_mask, list):
        for child in object_to_mask:
            log.debug("Recursing object {0}".format(child))
            _recursively_mask_objects(child, blacklisted_object, blacklisted_patterns, mask_with, globbing_enabled)
    elif globbing_enabled and blacklisted_object['attribute_to_check'] in object_to_mask:
        mask = False
        for blacklisted_pattern in blacklisted_patterns:
            if fnmatch.fnmatch(object_to_mask[blacklisted_object['attribute_to_check']], blacklisted_pattern):
                mask = True
                log.info("Attribute {0} will be masked.".format(
                    object_to_mask[blacklisted_object['attribute_to_check']]))
                break
        if mask:
            for key in blacklisted_object['attributes_to_mask']:
                if key in object_to_mask:
                    object_to_mask[key] = mask_with
    elif (not globbing_enabled) and blacklisted_object['attribute_to_check'] in object_to_mask and \
            object_to_mask[blacklisted_object['attribute_to_check']] in blacklisted_patterns:
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
            log.warn('unable to parse pid="{pid}" in pidfile={file}'.format(pid=xpid, file=pidfile))
          if xpid:
            log.info('pidfile={file} exists and contains pid={pid}'.format(file=pidfile, pid=xpid))
            if os.path.isdir("/proc/{pid}".format(pid=xpid)):
              try:
                with open("/proc/{pid}/cmdline".format(pid=xpid), 'r') as f2:
                  cmdline = f2.readline().strip().strip('\x00').replace('\x00', ' ')
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
    if OSQUERYD_NEEDS_RESTART:
        global OSQUERYD_NEEDS_RESTART
        OSQUERYD_NEEDS_RESTART = False
        return True
    try:
        with open(flagfile, "r") as open_file:
            file_content = open_file.read().lower().rstrip('\n\r ').strip('\n\r')
            hash_md5 = md5()
            hash_md5.update(file_content.encode('ISO-8859-1'))
            new_hash = hash_md5.hexdigest()

        if not os.path.isfile(hashfile):
            with open(hashfile, "w") as f:
                f.write(new_hash)
                return False
        else:
            with open(hashfile, "r") as f:
                old_hash = f.read()
                if old_hash != new_hash:
                    log.info('old hash is {0} and new hash is {1}'.format(old_hash, new_hash))
                    log.info('changes detected in flag file')
                    return True
                else:
                    log.info('no changes detected in flag file')
    except:
        log.error(
            "some error occured, unable to determine whether osqueryd need to be restarted, not restarting osqueryd")
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

    with open(flagfile, "r") as open_file:
        file_content = open_file.read().lower().rstrip('\n\r ').strip('\n\r')
        hash_md5 = md5()
        hash_md5.update(file_content.encode('ISO-8859-1'))
        new_hash = hash_md5.hexdigest()

    with open(hashfile, "w") as f:
        f.write(new_hash)
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
        start_cmd = ['/opt/osquery/hubble_osqueryd', '--pidfile={0}'.format(pidfile),
                     '--logger_path={0}'.format(logdir), '--config_path={0}.format(configfile)',
                     '--flagfile={0}'.format(flagfile),
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
        with open(path_to_logfile, "r") as fileDes:
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
                    fileDes.close()  # Closing explicitly to handle File in Use exception in windows
                    _perform_log_rotation(path_to_logfile,
                                          file_offset,
                                          backuplogdir,
                                          backuplogfilescount,
                                          enablediskstatslogging,
                                          False)
                    file_offset = 0  # Reset file offset to start of file in case original file is rotated
                else:
                    if os.stat(path_to_logfile).st_size > logfilethresholdinbytes:
                        rotateLog = True
                    fileDes.seek(offset)
                    for event in fileDes.readlines():
                        event_data.append(event)
                    file_offset = fileDes.tell()
                    fileDes.close()  # Closing explicitly to handle File in Use exception in windows
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
                        file_offset = 0  # Reset file offset to start of file in case original file is rotated
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
                if len(listofbackuplogfiles) >= backuplogfilescount:
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
    event_data = []
    if path.exists(path_to_logfile):
        with open(path_to_logfile, "r") as fileDes:
            if fileDes:
                log.info('Checking for any residue logs that might have been '
                         'added while log rotation was being performed')
                fileDes.seek(offset)
                for event in fileDes.readlines():
                    event_data.append(event)
    return event_data


def query(query):
    '''
    Run the osquery `query` and return the results.

    query
        String containgin `SQL` query to be run by osquery

    '''
    MAX_FILE_SIZE = 104857600
    if 'attach' in query.lower() or 'curl' in query.lower():
        log.critical(
            'Skipping potentially malicious osquery query which contains either \'attach\' or \'curl\': %s', query)
        return None
    query_ret = {'result': True}

    extensions_loadfile = __opts__.get('osquery_extensions_loadfile')

    # Run the osqueryi query
    if extensions_loadfile:
        cmd = [__grains__['osquerybinpath'], '--extensions_autoload', extensions_loadfile, '--read_max', MAX_FILE_SIZE, '--json', query]
    else:
        cmd = [__grains__['osquerybinpath'], '--read_max', MAX_FILE_SIZE, '--json', query]
    res = __salt__['cmd.run_all'](cmd, timeout=10000)
    if res['retcode'] == 0:
        query_ret['data'] = json.loads(res['stdout'])
    else:
        if 'Timed out' in res['stdout']:
            # this is really the best way to tell without getting fancy
            log.error('TIMEOUT during osqueryi execution %s', query)
        query_ret['result'] = False
        query_ret['error'] = res['stderr']

    return query_ret


def extensions(extensions_topfile=None, extensions_loadfile=None):
    '''
    Given a topfile location, parse the topfile and lay down osquery extensions
    and other files as shown in the targeted profiles.

    The default topfile location is
    ``salt://hubblestack_nebula_v2/top.extensions``

    You can also specify a custom extensions loadfile for osquery, otherwise
    the configured path in ``osquery_extensions_loadfile`` will be used.

    If extensions_loadfile is defined, osqueryd will be restarted, if it is
    found to be running.

    Profile example::

        files:
            - path: salt://hubblestack_nebula_v2/extensions/test.ext
              dest: /opt/osquery/extensions/test.ext
              extension_autoload: True   # optional, defaults to False
              mode: '600'                # optional, default shown
              user: root                 # optional, default shown
              group: root                # optional, default shown
            - path: salt://hubblestack_nebula_v2/extensions/conf/test.json
              dest: /opt/osquery/extensions/conf/test.json
              extension_autoload: False  # optional, defaults to False
              mode: '600'                # optional, default shown
              user: root                 # optional, default shown
              group: root                # optional, default shown
    '''
    if salt.utils.is_windows():
        log.error('Windows is not supported for nebula.extensions')
        return False

    if extensions_topfile is None:
        extensions_topfile = 'salt://hubblestack_nebula_v2/top.extensions'

    try:
        topdata = _get_top_data(extensions_topfile)
    except Exception as exc:
        log.info('An error occurred fetching top data for nebula.extensions: {0}'
                 .format(exc))
        return False

    if not topdata:
        return True

    extension_data = {}

    for fh in topdata:
        if 'salt://' in fh:
            orig_fh = fh
            fh = __salt__['cp.cache_file'](fh)
        if not fh:
            log.error('Could not find file {0}.'.format(orig_fh))
            continue
        if os.path.isfile(fh):
            with open(fh, 'r') as f:
                f_data = yaml.safe_load(f)
                if not isinstance(f_data, dict):
                    raise CommandExecutionError('File data is not formed as a dict {0}'
                                                .format(f_data))
                extension_data = _dict_update(extension_data,
                                              f_data,
                                              recursive_update=True,
                                              merge_lists=True)

    files = extension_data.get('files')
    if files and isinstance(files, list):
        if extensions_loadfile is None:
            extensions_loadfile = __opts__.get('osquery_extensions_loadfile')

        autoload = []
        for f in files:
            path = f.get('path')
            dest = f.get('dest')
            if not path or not dest:
                log.error('path or dest missing in files entry: {0}'.format(f))
                continue

            result = _get_file(**f)

            if result and f.get('extension_autoload', False):
                autoload.append(dest)

        if extensions_loadfile:
            try:
                with open(extensions_loadfile, 'w') as fh:
                    for extension in autoload:
                        fh.write(extension)
                        fh.write('\n')
            except Exception as exc:
                log.error('Something went wrong writing osquery extensions.load: {0}'.format(exc))

            # Leave flag to restart osqueryd
            global OSQUERYD_NEEDS_RESTART
            OSQUERYD_NEEDS_RESTART = True


def _get_file(path, dest, mode='600', user='root', group='root', **kwargs):
    '''
    Cache a file from a salt ``path`` to a local ``dest`` with the given
    attributes.
    '''
    try:
        mode = str(mode)
        local_path = __salt__['cp.get_file'](path, dest)
        if not local_path:
            log.error('Couldn\'t cache file: {0}'.format(path))
            return False
        ret = __salt__['file.check_perms'](name=local_path,
                                           ret=None,
                                           user=user,
                                           group=group,
                                           mode=mode)

        return ret['result']
    except Exception as exc:
        log.error('An error occurred getting file {0}: {1}'.format(path, exc))
        return False
